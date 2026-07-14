#!/usr/bin/env python3
"""Phase-3: audit a PSV packet PDF against its platform master record.

Reuses packet_extract.extract (Gemini on Vertex) to read the packet, then
compares that extraction to a platform master_record and emits flags for the
places where the packet (source) disagrees with, or fails to support, the
platform (record)."""
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

_SUFFIX = {"jr", "sr", "ii", "iii", "iv", "md", "do", "np", "pa", "phd", "dnp", "aprn", "rn"}

def _name_tokens(s):
    """Alpha tokens of a name, lowercased, dropping single initials and credential suffixes."""
    return {t for t in re.split(r"[^a-z]+", str(s or "").lower())
            if len(t) > 1 and t not in _SUFFIX}

def names_match(a, b, threshold=0.85):
    """Tolerant name match: order-independent and middle-name/initial-tolerant, so
    'MATTHEWS, LINDA JOSEPHINE' matches 'Linda Matthews'. Requires first+last to line up."""
    a, b = str(a or "").lower().strip(), str(b or "").lower().strip()
    if not a or not b:
        return False
    if a == b:
        return True
    ta, tb = _name_tokens(a), _name_tokens(b)
    if ta and tb and (ta <= tb or tb <= ta):    # one name's tokens contained in the other's
        return True
    if len(ta & tb) >= 2:                        # first AND last (or two name parts) in common
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

def _flag(record, packet, element, state, rule, severity, confidence, message, category=None):
    demo = record.get("demographics") or {}
    provider = packet.get("provider_name") or " ".join(
        p for p in (demo.get("firstName"), demo.get("lastName")) if p
    )
    f = {
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
    if category:
        f["category"] = category
    return f

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
                    f"Platform has a {state} license ({bl.get('license_number')}) "
                    f"but the packet contains no {state} license.",
                ))
            continue

        diffs = []
        b_num, p_num = norm_id(bl.get("license_number")), norm_id(pl.get("license_number"))
        if b_num and p_num and b_num != p_num:
            diffs.append(f"number platform={bl.get('license_number')} packet={pl.get('license_number')}")
        b_stat = norm_status(bl.get("license_status") or bl.get("status"))
        p_stat = norm_status(pl.get("status"))
        if b_stat and p_stat and b_stat != p_stat:
            diffs.append(f"status platform={bl.get('license_status') or bl.get('status')} packet={pl.get('status')}")
        b_exp, p_exp = norm_date(bl.get("expiration_date")), norm_date(pl.get("expiration_date"))
        if b_exp and p_exp and b_exp != p_exp:
            diffs.append(f"expiration platform={b_exp} packet={p_exp}")
        if diffs:
            flags.append(_flag(
                record, packet, "state_license", state,
                "PACKET_LICENSE_MISMATCH", "high", 0.8,
                f"{state} license disagrees between packet and platform: " + "; ".join(diffs) + ".",
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
            diffs.append(f"policy# platform={bm.get('policy_number')} packet={pm.get('policy_number')}")
        b_exp, p_exp = norm_date(bm.get("expiration_date")), norm_date(pm.get("expiration_date"))
        if b_exp and p_exp and b_exp != p_exp:
            diffs.append(f"expiration platform={b_exp} packet={p_exp}")
        b_occ, p_occ = norm_amount(bm.get("occurrence_coverage_amount")), norm_amount(pm.get("occurrence_amount"))
        if b_occ and p_occ and b_occ != p_occ:
            diffs.append(f"per-occurrence platform={b_occ} packet={p_occ}")
        b_agg, p_agg = norm_amount(bm.get("aggregate_coverage_amount")), norm_amount(pm.get("aggregate_amount"))
        if b_agg and p_agg and b_agg != p_agg:
            diffs.append(f"aggregate platform={b_agg} packet={p_agg}")
        if diffs:
            flags.append(_flag(
                record, packet, "malpractice", None,
                "PACKET_MALPRACTICE_MISMATCH", "medium", 0.7,
                "Malpractice coverage disagrees between packet COI and platform: "
                + "; ".join(diffs) + ".",
            ))

    # NCQA: the COI must show the provider is covered. Flag if a named insured is present and does
    # not match the applicant (may be group/entity coverage -> warning to verify, not a hard error).
    applicant = _backend_name(record)
    insured = [m.get("insured_name") for m in packet_mp if m.get("insured_name")]
    if applicant and insured and not any(names_match(applicant, n) for n in insured):
        flags.append(_flag(
            record, packet, "malpractice", None,
            "PACKET_MALPRACTICE_NAME_NOT_MATCHED", "medium", 0.65,
            f"Malpractice COI names '{insured[0]}', which does not match the applicant "
            f"'{applicant}' — confirm the provider is covered individually or under this group.",
            category="Malpractice Insurance"))
    return flags

def check_board_certs(record, packet):
    """Board-certification value MISMATCH (expiration) between packet and platform, per specialty."""
    flags = []
    platform = record.get("boardCertifications") or []
    pkt = packet.get("board_certifications") or []
    if not platform or not pkt:
        return flags
    pkt_by_spec = {norm_status(p.get("specialty")): p for p in pkt}
    for bc in platform:
        pc = pkt_by_spec.get(norm_status(bc.get("specialty"))) or (pkt[0] if len(pkt) == 1 else None)
        if not pc:
            continue
        b_exp, p_exp = norm_date(bc.get("expiration_date")), norm_date(pc.get("expiration_date"))
        if b_exp and p_exp and b_exp != p_exp:
            flags.append(_flag(
                record, packet, "boardCertifications", None,
                "PACKET_BOARDCERT_MISMATCH", "medium", 0.7,
                f"Board certification ({bc.get('specialty') or ''}) expiration disagrees between "
                f"packet and platform: platform={b_exp} packet={p_exp}.", category="Board Certifications"))
    return flags

def check_documents(record, packet):
    """Missing-document checks. A document counts as present via ANY signal — the documents_present
    list, the element block actually read from the packet, OR the platform element having rows —
    so we don't false-flag a document the AI read but labelled differently."""
    flags = []
    def _doc_text(d):
        return f"{d.get('label', '')} {d.get('category', '')}" if isinstance(d, dict) else str(d)
    docs = " | ".join(_doc_text(d).lower() for d in (packet.get("documents_present") or []))
    def present(*needles):
        return any(n in docs for n in needles)
    npdb = packet.get("npdb") or {}

    license_ok = present("state license", "license report", "license verification", "licensure") \
        or bool(packet.get("state_licenses")) or bool(record.get("stateLicenses"))
    npdb_ok = bool(packet.get("npdb_report_present")) or bool(npdb.get("present")) \
        or present("npdb", "national practitioner", "data bank") \
        or bool(npdb.get("report_count")) or bool(record.get("npdb"))
    coi_ok = present("certificate of insurance", "coi", "insurance", "malpractice", "liability") \
        or bool(packet.get("malpractice")) or bool(record.get("malpractice"))

    if not license_ok:
        flags.append(_flag(record, packet, "document", None, "PACKET_DOC_MISSING", "high", 0.8,
            "Packet is missing a state license report/verification document."))
    if not npdb_ok:
        flags.append(_flag(record, packet, "document", None, "PACKET_DOC_MISSING", "high", 0.8,
            "Packet is missing the NPDB report."))
    if not coi_ok:
        flags.append(_flag(record, packet, "document", None, "PACKET_DOC_MISSING", "high", 0.8,
            "Packet is missing a certificate of insurance (COI)."))
    return flags

def _backend_name(record):
    demo = record.get("demographics") or {}
    return " ".join(p for p in (demo.get("firstName"), demo.get("lastName")) if p).strip()

def check_demographics(record, packet):
    """Demographic MISMATCH checks (not just presence): name + NPI on the packet, plus the
    name printed on each source document (license / DEA certificate) vs the applicant."""
    flags = []
    demo = record.get("demographics") or {}
    b_name = _backend_name(record)
    b_last = str(demo.get("lastName") or "").strip()
    b_npi = norm_id(demo.get("npi"))

    # 1) provider name on the packet vs platform (tolerant, last-name level)
    p_last = last_name(packet.get("provider_name"))
    if b_last and p_last and not names_match(b_last, p_last):
        flags.append(_flag(
            record, packet, "demographics", None,
            "PACKET_NAME_MISMATCH", "high", 0.9,
            f"Packet provider name '{packet.get('provider_name')}' (last '{p_last}') "
            f"does not match platform lastName '{b_last}'.", category="Provider Demographics"))

    # 2) NPI on the packet vs platform
    p_npi = norm_id(packet.get("npi"))
    if b_npi and p_npi and b_npi != p_npi:
        flags.append(_flag(
            record, packet, "demographics", None,
            "PACKET_NPI_MISMATCH", "high", 0.9,
            f"NPI on the packet ({packet.get('npi')}) does not match the platform NPI "
            f"({demo.get('npi')}).", category="Provider Demographics"))

    # 3) name printed on each source document vs the applicant
    def name_on_doc(doc_label, printed):
        if b_name and printed and not names_match(b_name, printed):
            flags.append(_flag(
                record, packet, "demographics", None,
                "PACKET_DOC_NAME_MISMATCH", "medium", 0.75,
                f"Name on the {doc_label} ('{printed}') does not match the applicant '{b_name}'.",
                category="Provider Demographics"))
    for pl in packet.get("state_licenses") or []:
        name_on_doc(f"{norm_state(pl.get('state')) or ''} license document".strip(), pl.get("holder_name"))
    for d in packet.get("dea") or []:
        name_on_doc("DEA certificate", d.get("registrant_name"))
    return flags

def check_dea(record, packet):
    """DEA MISMATCH / missing-in-packet vs platform, per registration."""
    flags = []
    platform = record.get("dea") or []
    if not platform:
        return flags
    pkt = packet.get("dea") or []
    pkt_by_num = {norm_id(d.get("number")): d for d in pkt if d.get("number")}
    for bd in platform:
        b_num = norm_id(bd.get("dea_number") or bd.get("number"))
        pd = pkt_by_num.get(b_num) if b_num else None
        if pd is None:  # fall back to a same-state DEA in the packet
            pd = next((d for d in pkt if norm_state(d.get("state")) == norm_state(bd.get("state"))
                       and norm_state(bd.get("state"))), None)
        if pd is None:
            flags.append(_flag(
                record, packet, "dea", norm_state(bd.get("state")) or None,
                "PACKET_DEA_MISSING_IN_PACKET", "medium", 0.7,
                f"Platform has a DEA registration ({bd.get('dea_number') or bd.get('number')}) "
                f"not found in the packet.", category="DEA / CDS"))
            continue
        diffs = []
        p_num = norm_id(pd.get("number"))
        if b_num and p_num and b_num != p_num:
            diffs.append(f"number platform={bd.get('dea_number') or bd.get('number')} packet={pd.get('number')}")
        b_exp, p_exp = norm_date(bd.get("expiration_date")), norm_date(pd.get("expiration_date"))
        if b_exp and p_exp and b_exp != p_exp:
            diffs.append(f"expiration platform={b_exp} packet={p_exp}")
        b_st, p_st = norm_state(bd.get("state")), norm_state(pd.get("state"))
        if b_st and p_st and b_st != p_st:
            diffs.append(f"state platform={b_st} packet={p_st}")
        if diffs:
            flags.append(_flag(
                record, packet, "dea", b_st or None,
                "PACKET_DEA_MISMATCH", "high", 0.8,
                "DEA registration disagrees between packet and platform: "
                + "; ".join(diffs) + ".", category="DEA / CDS"))
    return flags

def check_npdb(record, packet):
    """NPDB report identity MISMATCH: the report in the packet must be about THIS applicant."""
    flags = []
    npdb = packet.get("npdb") or {}
    if not (npdb.get("present") or packet.get("npdb_report_present")):
        return flags  # doc-presence handled by check_documents
    demo = record.get("demographics") or {}
    b_name = _backend_name(record)
    b_npi = norm_id(demo.get("npi"))
    diffs = []
    subj = npdb.get("subject_name")
    if b_name and subj and not names_match(b_name, subj):
        diffs.append(f"subject name report='{subj}' applicant='{b_name}'")
    p_npi = norm_id(npdb.get("npi"))
    if b_npi and p_npi and b_npi != p_npi:
        diffs.append(f"NPI report={npdb.get('npi')} platform={demo.get('npi')}")
    if diffs:
        flags.append(_flag(
            record, packet, "npdb", None,
            "PACKET_NPDB_MISMATCH", "high", 0.85,
            "NPDB report identity does not match the applicant: " + "; ".join(diffs) + ".",
            category="NPDB"))
    return flags

# ---------------------------------------------------------------- entry point

def packet_audit(master_record, pdf_path, packet=None):
    """Extract the packet at pdf_path and return a list of packet-vs-platform flags.
    Pass ``packet`` (a packet_extract.extract result) to reuse an existing read."""
    packet = packet if packet is not None else packet_extract.extract(pdf_path)
    flags = []
    flags += check_demographics(master_record, packet)
    flags += check_licenses(master_record, packet)
    flags += check_dea(master_record, packet)
    flags += check_npdb(master_record, packet)
    flags += check_board_certs(master_record, packet)
    flags += check_malpractice(master_record, packet)
    flags += check_documents(master_record, packet)
    return flags

def _load_records(path="master_records.json"):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def main():
    ap = argparse.ArgumentParser(description="Audit a PSV packet PDF against its platform master record.")
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
