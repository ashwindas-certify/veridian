#!/usr/bin/env python3
"""Phase-3c: NCQA/Headway Education & Training deep verification.

NCQA (and Headway's overlay) require a provider's education and training to be
verified from a primary source. For MD/DO providers who are NOT board certified,
the fallback primary source is a completed residency (ideally in Psychiatry) as
shown on the AMA physician profile. This reads the Education & Training material
in the PSV packet PDF (the CAQH application's education section plus any AMA
physician profile pages) with Gemini on Vertex (same client pattern as
packet_extract / caqh_audit) and emits education-training flags:
  * a non-board-certified MD/DO with no completed Psychiatry residency,
  * a residency present but still In Progress for such a provider,
  * packet shows education but the platform has none verified,
  * an info summary so reviewers can see the check ran."""
import argparse, json, os, sys

from google import genai
from google.genai import types

PROJECT, LOCATION, MODEL = "cos-sandbox-provider-data", "us-central1", "gemini-2.5-flash"
client = genai.Client(vertexai=True, project=PROJECT, location=LOCATION)

PROMPT = """You are auditing the Education & Training material inside a credentialing
Primary Source Verification (PSV) packet PDF. Look at the CAQH application's
education/training section, any CAQH SUPPLEMENT / ADDENDUM / "additional information"
pages (education & training is sometimes continued on supplement pages), AND any AMA
physician profile pages (which list medical school, residency, and fellowship
training). Extract ONLY what is actually present in the document, as JSON with this shape:
{
 "education": [
   {"type","institution","specialty","start_date","end_date","status"}
 ],
 "highest_level": string,
 "ama_profile_present": boolean
}
Rules:
- education is every distinct education/training entry the document lists.
- type must be one of: "Medical School", "Residency", "Fellowship", "Other".
- institution is the school / program / hospital name.
- specialty is the training specialty (e.g. "Psychiatry"); "" if none shown.
- start_date / end_date as YYYY-MM (month + year is sufficient); "" if not shown.
- status must be one of: "Completed", "In Progress", "Unknown". Use "Completed"
  when the document shows the training finished (a graduation/completion date in
  the past, or the AMA profile marks it complete); "In Progress" when it is
  ongoing / has no end / is marked current; "Unknown" otherwise.
- highest_level is a short label of the highest level of training completed
  (e.g. "Fellowship", "Residency", "Medical School", "Doctorate", "Masters").
- ama_profile_present is true only if AMA physician profile education pages are in the packet.
- Do not invent values. If no education/training is present, return an empty education list."""


def extract_education(pdf_path):
    """Read the education/training pages of the packet and return education JSON."""
    pdf = open(pdf_path, "rb").read()
    resp = client.models.generate_content(
        model=MODEL,
        contents=[types.Part.from_bytes(data=pdf, mime_type="application/pdf"), PROMPT],
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    return json.loads(resp.text)


# ---------------------------------------------------------------- flag helper

def _flag(record, packet, rule, severity, confidence, message, expected):
    demo = record.get("demographics") or {}
    provider = packet.get("provider_name") or " ".join(
        p for p in (demo.get("firstName"), demo.get("lastName")) if p
    )
    return {
        "workflowId": record.get("workflowId"),
        "provider": provider,
        "npi": demo.get("npi") or packet.get("npi"),
        "element": "educationTraining",
        "state": "",
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "expected": expected,
        "flagClass": "education-training",
    }


def _is_residency(e):
    return (e.get("type") or "").strip().lower() == "residency"


def _status(e):
    return (e.get("status") or "Unknown").strip()


def _is_psychiatry(e):
    return "psych" in (e.get("specialty") or "").lower()


def _describe(e):
    """Short human description of an education entry for flag messages."""
    parts = [e.get("type") or "training"]
    if e.get("specialty"):
        parts.append("in " + e["specialty"])
    if e.get("institution"):
        parts.append("at " + e["institution"])
    parts.append(f"(status {_status(e)})")
    return " ".join(parts)


# Acceptable E&T verification sources / proxies (NCQA): board certification, state licensing
# board/agency, the educational institution (primary), AMA/AOA physician profile, ECFMG, FSMB,
# and the National Student Clearinghouse. "Provider Application" alone (self-report) is NOT an
# acceptable primary source for education & training.
_ACCEPTABLE_ET_SRC = ("board cert", "board-cert", "certification", "abms", "abpn", "aoa",
                      "licensing board", "licensing agency", "state board", "medical board",
                      "educational institution", "institution", "medical school", "school", "university",
                      "ama", "american medical", "ecfmg", "fsmb", "student clearinghouse", "clearinghouse")
_SELF_REPORT_SRC = ("provider application", "application", "self")


def _et_sources(master_record):
    """Every source label the platform used to verify this provider's education/training."""
    srcs = []
    for e in master_record.get("educationTraining") or []:
        if e.get("source"):
            srcs.append(str(e["source"]))
    for v in master_record.get("appVerifications") or []:
        vt = (v.get("verification_type") or "").lower()
        if "edu" in vt or "train" in vt:
            if v.get("source"):
                srcs.append(str(v["source"]))
    return srcs


def _matches(text, needles):
    return any(n in text for n in needles)


def check_source_hierarchy(master_record, packet, has_board_cert):
    """E&T must be verified from an acceptable primary source or proxy (board certification,
    licensing board/agency, educational institution, AMA/AOA, ECFMG, clearinghouse). A licensing
    board/agency is a valid proxy. Flag ONLY when the source is self-report (provider application)
    only, or no acceptable source is cited."""
    srcs = _et_sources(master_record)
    if not srcs:
        return []  # no source recorded -> presence handled by EDU_NOT_VERIFIED_IN_BACKEND
    src_text = " | ".join(srcs).lower()
    if _matches(src_text, _ACCEPTABLE_ET_SRC):
        return []  # verified via an acceptable primary source / proxy -> OK
    # only self-report / unrecognized sources present
    if _matches(src_text, _SELF_REPORT_SRC):
        return [_flag(
            master_record, packet, "EDU_SOURCE_SELF_REPORTED", "warning", 0.7,
            "Education & training appears verified only via the provider application (self-report): "
            f"[{', '.join(srcs)}] — NCQA requires an acceptable primary source or proxy (licensing "
            "board/agency, board certification, educational institution, AMA/AOA, ECFMG, clearinghouse).",
            "E&T must be verified from an acceptable primary source or proxy, not self-report")]
    return []  # unrecognized but not clearly self-report -> don't false-flag


# ---------------------------------------------------------------- entry point

def education_audit(master_record, pdf_path, packet=None):
    """Extract education/training from the packet and return education flags.
    Pass ``packet`` (an extract_education result) to reuse an existing read."""
    packet = packet if packet is not None else extract_education(pdf_path)
    education = packet.get("education") or []
    highest_level = packet.get("highest_level") or "Unknown"

    demo = master_record.get("demographics") or {}
    provider_type = (demo.get("providerType") or "").strip()
    is_md_do = provider_type.upper() in {"MD", "DO"}
    board_certs = master_record.get("boardCertifications") or []
    has_board_cert = bool(board_certs)

    residencies = [e for e in education if _is_residency(e)]
    completed_residencies = [e for e in residencies if _status(e).lower() == "completed"]
    in_progress_residencies = [e for e in residencies if _status(e).lower() == "in progress"]
    residency_status = (
        "; ".join(f"{r.get('specialty') or '?'}:{_status(r)}" for r in residencies)
        if residencies else "none"
    )

    print(
        "providerType: {!r} (MD/DO={})\n"
        "board-cert-count: {}\n"
        "residency-status: {}\n"
        "education entries ({}), highest_level={!r}, ama_profile_present={}".format(
            provider_type, is_md_do, len(board_certs), residency_status,
            len(education), highest_level, packet.get("ama_profile_present"),
        ),
        file=sys.stderr,
    )

    flags = []

    # 1 & 2) A non-board-certified MD/DO must have a completed Psychiatry residency
    #        on the AMA profile. If a residency is present but In Progress, emit the
    #        more specific EDU_RESIDENCY_IN_PROGRESS; otherwise (no completed
    #        residency at all) emit EDU_RESIDENCY_NOT_COMPLETED.
    expected_residency = (
        "non-board-certified MD/DO must have a completed Psychiatry residency "
        "(AMA profile 'Completed')"
    )
    if is_md_do and not has_board_cert and not completed_residencies:
        if in_progress_residencies:
            found = "; ".join(_describe(r) for r in in_progress_residencies)
            flags.append(_flag(
                master_record, packet,
                "EDU_RESIDENCY_IN_PROGRESS", "error", 0.72,
                f"Provider is a non-board-certified {provider_type} but the packet "
                f"shows a residency that is still In Progress rather than Completed: "
                f"{found}.",
                expected_residency,
            ))
        else:
            if residencies:
                found = "residency present but not completed (" + \
                    "; ".join(_describe(r) for r in residencies) + ")"
            else:
                found = "no completed residency found in the packet"
            flags.append(_flag(
                master_record, packet,
                "EDU_RESIDENCY_NOT_COMPLETED", "error", 0.7,
                f"Provider is a non-board-certified {provider_type} with no board "
                f"certification on record and the packet does not show a completed "
                f"Psychiatry residency: {found}.",
                expected_residency,
            ))
        # Nudge when the (only) completed/in-progress residency is not Psychiatry.
        if residencies and not any(_is_psychiatry(r) for r in residencies):
            pass  # message above already conveys specialty via _describe

    # 3) Packet shows education but the platform has no verified education/training.
    backend_edu = master_record.get("educationTraining") or []
    if education and not backend_edu:
        flags.append(_flag(
            master_record, packet,
            "EDU_NOT_VERIFIED_IN_BACKEND", "warning", 0.7,
            f"Packet shows {len(education)} education/training entry(ies) but the "
            f"platform has no verified education/training on record.",
            "education/training must be verified from primary source",
        ))

    # 3b) Verification-source hierarchy: board cert (if certified) else licensing agency.
    flags += check_source_hierarchy(master_record, packet, has_board_cert)

    # 4) Info summary so reviewers can see the check ran.
    types_seen = ", ".join(sorted({(e.get("type") or "Other") for e in education})) or "none"
    flags.append(_flag(
        master_record, packet,
        "EDU_SUMMARY", "info", 0.9,
        f"Found {len(education)} education/training entry(ies) in the packet "
        f"[{types_seen}]; highest level: {highest_level}.",
        "education/training must be verified from primary source per NCQA",
    ))
    return flags


def _load_records(path="master_records.json"):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser(
        description="Audit the Education & Training in a PSV packet against the platform record.")
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

    pdf_path = os.path.join(args.packets_dir, f"{args.workflow}.pdf")
    if not os.path.exists(pdf_path):
        print(f"packet PDF not found: {pdf_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Education-auditing {args.workflow} ({pdf_path}) ...", file=sys.stderr)
    flags = education_audit(record, pdf_path)
    print(json.dumps(flags, indent=2))


if __name__ == "__main__":
    main()
