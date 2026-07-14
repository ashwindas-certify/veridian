#!/usr/bin/env python3
"""Phase-3: audit a PSV packet PDF against its backend master record.

Reuses packet_extract.extract (Gemini on Vertex) to read the packet, then
compares that extraction to a backend master_record and emits flags for the
places where the packet (source) disagrees with, or fails to support, the
backend (record)."""
import argparse, json, re, sys
from datetime import datetime
from difflib import SequenceMatcher

import packet_extract

# ---------------------------------------------------------------- normalizers

def norm_state(s):
    return (s or "").strip().upper()

def norm_id(s):
    """License / DEA numbers: drop punctuation and case."""
    return re.sub(r"[^A-Za-z0-9]", "", str(s or "")).upper()

def norm_status(s):
    return (str(s or "").strip().lower())

def norm_amount(s):
    """Coverage amounts -> integer of the digits only ('$2,000,000' -> 2000000)."""
    digits = re.sub(r"[^0-9]", "", str(s or ""))
    return int(digits) if digits else None

def norm_date(s):
    """Parse many shapes ('2027-04-05 00:00:00+00:00', '04/05/2027', ...) to YYYY-MM-DD."""
    if not s:
        return None
    s = str(s).strip()
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    for fmt in ("%m/%d/%Y", "%m-%d-%Y", "%m/%d/%y", "%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return s  # leave as-is if unrecognised

def last_name(full):
    parts = re.sub(r"[.,]", " ", str(full or "")).split()
    return parts[-1].lower() if parts else ""

def names_match(a, b, threshold=0.85):
    a, b = a.lower().strip(), b.lower().strip()
    if not a or not b:
        return False
    if a == b:
        return True
    return SequenceMatcher(None, a, b).ratio() >= threshold

# ---------------------------------------------------------------- helpers

def assigned_states(record):
    """Best-effort set of states this provider is assigned/licensed in."""
    demo = record.get("demographics") or {}
    out = set()
    for key in ("assignedStates", "states"):
        val = demo.get(key)
        if not val:
            continue
        if isinstance(val, list):
            for v in val:
                out.add(norm_state(v))
        else:
            for v in re.split(r"[,;/\s]+", str(val)):
                if v.strip():
                    out.add(norm_state(v))
    return {s for s in out if s}

def _flag(record, packet, element, state, rule, severity, confidence, message):
    demo = record.get("demographics") or {}
    provider = packet.get("provider_name") or " ".join(
        p for p in (demo.get("firstName"), demo.get("lastName")) if p
    )
    return {
        "workflowId": record.get("workflowId"),
        "provider": provider,
        "npi": demo.get("npi") or packet.get("npi"),
        "element": element,
        "state": state,
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "flagClass": "packet-vs-backend",
    }

# ---------------------------------------------------------------- checks

def check_licenses(record, packet):
    flags = []
    packet_by_state = {}
    for pl in packet.get("state_licenses") or []:
        packet_by_state.setdefault(norm_state(pl.get("state")), pl)
    assigned = assigned_states(record)

    for bl in record.get("stateLicenses") or []:
        state = norm_state(bl.get("state"))
        if not state:
            continue
        pl = packet_by_state.get(state)
        if pl is None:
            if state in assigned or not assigned:
                flags.append(_flag(
                    record, packet, "state_license", state,
                    "PACKET_LICENSE_MISSING_IN_PACKET", "high", 0.75,
                    f"Backend has a {state} license ({bl.get('license_number')}) "
                    f"but the packet contains no {state} license.",
                ))
            continue

        diffs = []
        b_num, p_num = norm_id(bl.get("license_number")), norm_id(pl.get("license_number"))
        if b_num and p_num and b_num != p_num:
            diffs.append(f"number backend={bl.get('license_number')} packet={pl.get('license_number')}")
        b_stat = norm_status(bl.get("license_status") or bl.get("status"))
        p_stat = norm_status(pl.get("status"))
        if b_stat and p_stat and b_stat != p_stat:
            diffs.append(f"status backend={bl.get('license_status') or bl.get('status')} packet={pl.get('status')}")
        b_exp, p_exp = norm_date(bl.get("expiration_date")), norm_date(pl.get("expiration_date"))
        if b_exp and p_exp and b_exp != p_exp:
            diffs.append(f"expiration backend={b_exp} packet={p_exp}")
        if diffs:
            flags.append(_flag(
                record, packet, "state_license", state,
                "PACKET_LICENSE_MISMATCH", "high", 0.8,
                f"{state} license disagrees between packet and backend: " + "; ".join(diffs) + ".",
            ))
    return flags

def check_malpractice(record, packet):
    flags = []
    backend_mp = record.get("malpractice") or []
    packet_mp = packet.get("malpractice") or []
    if not backend_mp or not packet_mp:
        return flags  # nothing to compare (doc-presence handled separately)

    for bm in backend_mp:
        b_num = norm_id(bm.get("policy_number"))
        # find best packet match: same policy number, else fall back to first COI
        pm = next((m for m in packet_mp if norm_id(m.get("policy_number")) == b_num and b_num), None)
        pm = pm or packet_mp[0]

        diffs = []
        p_num = norm_id(pm.get("policy_number"))
        if b_num and p_num and b_num != p_num:
            diffs.append(f"policy# backend={bm.get('policy_number')} packet={pm.get('policy_number')}")
        b_exp, p_exp = norm_date(bm.get("expiration_date")), norm_date(pm.get("expiration_date"))
        if b_exp and p_exp and b_exp != p_exp:
            diffs.append(f"expiration backend={b_exp} packet={p_exp}")
        b_occ, p_occ = norm_amount(bm.get("occurrence_coverage_amount")), norm_amount(pm.get("occurrence_amount"))
        if b_occ and p_occ and b_occ != p_occ:
            diffs.append(f"per-occurrence backend={b_occ} packet={p_occ}")
        b_agg, p_agg = norm_amount(bm.get("aggregate_coverage_amount")), norm_amount(pm.get("aggregate_amount"))
        if b_agg and p_agg and b_agg != p_agg:
            diffs.append(f"aggregate backend={b_agg} packet={p_agg}")
        if diffs:
            flags.append(_flag(
                record, packet, "malpractice", None,
                "PACKET_MALPRACTICE_MISMATCH", "medium", 0.7,
                "Malpractice coverage disagrees between packet COI and backend: "
                + "; ".join(diffs) + ".",
            ))
    return flags

def check_documents(record, packet):
    flags = []
    docs = " | ".join(str(d).lower() for d in (packet.get("documents_present") or []))

    def present(*needles):
        return any(n in docs for n in needles)

    if not present("state license", "license report", "license verification", "licensure"):
        flags.append(_flag(
            record, packet, "document", None,
            "PACKET_DOC_MISSING", "high", 0.85,
            "Packet is missing a state license report/verification document.",
        ))
    if not packet.get("npdb_report_present"):
        flags.append(_flag(
            record, packet, "document", None,
            "PACKET_DOC_MISSING", "high", 0.85,
            "Packet is missing the NPDB report (npdb_report_present is not true).",
        ))
    if not present("certificate of insurance", "coi", "insurance", "malpractice"):
        flags.append(_flag(
            record, packet, "document", None,
            "PACKET_DOC_MISSING", "high", 0.85,
            "Packet is missing a certificate of insurance (COI).",
        ))
    return flags

def check_name(record, packet):
    demo = record.get("demographics") or {}
    backend_last = str(demo.get("lastName") or "").strip()
    packet_last = last_name(packet.get("provider_name"))
    if backend_last and packet_last and not names_match(backend_last, packet_last):
        return [_flag(
            record, packet, "name", None,
            "PACKET_NAME_MISMATCH", "high", 0.9,
            f"Packet provider name '{packet.get('provider_name')}' last name "
            f"'{packet_last}' does not match backend lastName '{backend_last}'.",
        )]
    return []

# ---------------------------------------------------------------- entry point

def packet_audit(master_record, pdf_path):
    """Extract the packet at pdf_path and return a list of packet-vs-backend flags."""
    packet = packet_extract.extract(pdf_path)
    flags = []
    flags += check_name(master_record, packet)
    flags += check_licenses(master_record, packet)
    flags += check_malpractice(master_record, packet)
    flags += check_documents(master_record, packet)
    return flags

def _load_records(path="master_records.json"):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def main():
    ap = argparse.ArgumentParser(description="Audit a PSV packet PDF against its backend master record.")
    ap.add_argument("--workflow", required=True, help="workflowId to audit")
    ap.add_argument("--records", default="master_records.json", help="path to master_records.json")
    ap.add_argument("--packets-dir", default="packets", help="directory holding <workflowId>.pdf")
    args = ap.parse_args()

    try:
        records = _load_records(args.records)
    except FileNotFoundError:
        print(f"records file not found: {args.records}", file=sys.stderr)
        sys.exit(1)

    record = next((r for r in records if r.get("workflowId") == args.workflow), None)
    if record is None:
        print(f"no master record for workflowId {args.workflow}", file=sys.stderr)
        sys.exit(1)

    pdf_path = f"{args.packets_dir}/{args.workflow}.pdf"
    import os
    if not os.path.exists(pdf_path):
        print(f"packet PDF not found: {pdf_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Auditing {args.workflow} ({pdf_path}) ...", file=sys.stderr)
    flags = packet_audit(record, pdf_path)
    print(json.dumps(flags, indent=2))

if __name__ == "__main__":
    main()
