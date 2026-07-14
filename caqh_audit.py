#!/usr/bin/env python3
"""Phase-3b: CAQH work-history audit.

NCQA requires the provider's self-reported work history (the CAQH application,
which lives inside the PSV packet PDF) to be reconciled against what the backend
actually verified. This reads the CAQH application pages with Gemini on Vertex
(same client pattern as packet_extract) and emits work-history flags:
  * unexplained employment gaps > 180 days in the CAQH work history,
  * packet shows work history but backend workHistory is empty,
  * an info summary so reviewers can see the check ran."""
import argparse, json, os, re, sys
from datetime import datetime

from google import genai
from google.genai import types

PROJECT, LOCATION, MODEL = "cos-sandbox-provider-data", "us-central1", "gemini-2.5-flash"
client = genai.Client(vertexai=True, project=PROJECT, location=LOCATION)

GAP_THRESHOLD_DAYS = 180

PROMPT = """You are auditing the CAQH application inside a credentialing Primary
Source Verification (PSV) packet PDF. Focus ONLY on the CAQH application pages
(the provider's self-reported work / employment history and any disclosed gaps
in employment). Extract ONLY what is actually present in the document, as JSON
with this shape:
{
 "work_history": [
   {"employer","role","start_date","end_date","is_current"}
 ],
 "gaps_disclosed": [
   {"start_date","end_date","explanation"}
 ],
 "disclosure_answers": [
   {"question","answer","unfavorable"}
 ]
}
Rules:
- work_history is every distinct employment period the provider lists.
- is_current is a boolean: true if the provider is still employed there (no end date / "present").
- gaps_disclosed are employment gaps the provider explicitly acknowledged/explained on the CAQH application.
- disclosure_answers is every attestation / disclosure question the CAQH application
  actually asks (e.g. malpractice claims, license actions/limitations, criminal
  history, sanctions/exclusions, hospital privilege actions, chemical dependency /
  impairment, physical or mental conditions affecting practice, etc.).
  * question: a short paraphrase of the disclosure question.
  * answer: "yes" or "no" (the provider's answer as shown).
  * unfavorable: boolean true when the answer indicates a potential issue, i.e. an
    adverse/"yes" answer to an adverse-history question (malpractice, license action,
    criminal, sanction, exclusion, impairment, etc.). A benign/"no" answer is
    unfavorable=false.
  Only include disclosure questions actually present in the CAQH application.
- Dates as YYYY-MM (month and year is sufficient per NCQA); use YYYY-MM-DD only if a full date is shown.
- Do not invent values. If the CAQH work history is not present, return empty lists."""


def extract_caqh(pdf_path):
    """Read the CAQH application pages of the packet and return work history JSON."""
    pdf = open(pdf_path, "rb").read()
    resp = client.models.generate_content(
        model=MODEL,
        contents=[types.Part.from_bytes(data=pdf, mime_type="application/pdf"), PROMPT],
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    return json.loads(resp.text)


# ---------------------------------------------------------------- date helpers

def parse_date(s, end=False):
    """Parse YYYY-MM or YYYY-MM-DD (tolerant) to a datetime; None if unparseable.

    For YYYY-MM we anchor to the first day of the month (or last, when end=True)
    so gap arithmetic between periods is sensible."""
    if not s:
        return None
    s = str(s).strip()
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    m = re.match(r"^(\d{4})-(\d{1,2})$", s)
    if m:
        year, month = int(m.group(1)), int(m.group(2))
        if not 1 <= month <= 12:
            return None
        if end:
            # last day of that month
            if month == 12:
                return datetime(year, 12, 31)
            nxt = datetime(year, month + 1, 1)
            return datetime.fromordinal(nxt.toordinal() - 1)
        return datetime(year, month, 1)
    m = re.match(r"^(\d{4})$", s)
    if m:
        year = int(m.group(1))
        return datetime(year, 12, 31) if end else datetime(year, 1, 1)
    return None


def fmt(dt):
    return dt.strftime("%Y-%m") if dt else "?"


# ---------------------------------------------------------------- flag helper

def _flag(record, packet, rule, severity, confidence, message):
    demo = record.get("demographics") or {}
    provider = packet.get("provider_name") or " ".join(
        p for p in (demo.get("firstName"), demo.get("lastName")) if p
    )
    return {
        "workflowId": record.get("workflowId"),
        "provider": provider,
        "npi": demo.get("npi") or packet.get("npi"),
        "element": "workHistory",
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "flagClass": "caqh-vs-verified",
    }


def _disclosed_covers(gap_start, gap_end, gaps_disclosed):
    """True if a disclosed gap with a non-empty explanation overlaps this gap."""
    for g in gaps_disclosed or []:
        expl = (g.get("explanation") or "").strip()
        if not expl:
            continue
        d_start = parse_date(g.get("start_date"))
        d_end = parse_date(g.get("end_date"), end=True)
        # If either disclosed bound is missing, treat a present explanation as
        # covering (provider acknowledged a gap); otherwise require overlap.
        if d_start is None or d_end is None:
            return True
        if d_start <= gap_end and d_end >= gap_start:
            return True
    return False


def _backend_verdict(master_record, keyword):
    """Return the explanation of the first appVerifications row whose
    verification_type contains ``keyword`` (case-insensitive), or None."""
    for row in master_record.get("appVerifications") or []:
        vtype = (row.get("verification_type") or "").lower()
        if keyword in vtype:
            return row.get("explanation")
    return None


def _says_no_gap(explanation):
    """Backend work-history verdict asserts there is NO employment gap."""
    e = (explanation or "").lower()
    return "no" in e and "gap" in e


def _says_favourable(explanation):
    """Backend disclosure verdict asserts the questions were answered favourably
    / with no adverse answer."""
    e = (explanation or "").lower()
    if "favourabl" in e or "favorabl" in e:
        return True
    # e.g. "no adverse disclosures", "no adverse answers"
    return "no" in e and "advers" in e


# ---------------------------------------------------------------- entry point

def caqh_audit(master_record, pdf_path):
    """Extract the CAQH work history from the packet and return work-history flags."""
    packet = extract_caqh(pdf_path)
    work_history = packet.get("work_history") or []
    gaps_disclosed = packet.get("gaps_disclosed") or []
    disclosure_answers = packet.get("disclosure_answers") or []
    flags = []

    # Backend verdicts (from edit_providers_application_verifications rows).
    wh_verdict = _backend_verdict(master_record, "work")
    disc_verdict = _backend_verdict(master_record, "disclosure")
    unfavorable = [d for d in disclosure_answers if d.get("unfavorable")]

    print(
        "backend work-history verdict: {!r}\n"
        "backend disclosure verdict:   {!r}\n"
        "AI disclosure_answers ({}): {}\n"
        "AI unfavorable answers: {}".format(
            wh_verdict, disc_verdict, len(disclosure_answers),
            json.dumps(disclosure_answers),
            json.dumps([d.get("question") for d in unfavorable]),
        ),
        file=sys.stderr,
    )

    # Build sortable employment periods with parsed dates.
    periods = []
    for wh in work_history:
        start = parse_date(wh.get("start_date"))
        end = None if wh.get("is_current") else parse_date(wh.get("end_date"), end=True)
        periods.append({"start": start, "end": end, "is_current": wh.get("is_current"), "raw": wh})
    dated = [p for p in periods if p["start"] is not None]
    dated.sort(key=lambda p: p["start"])

    # 1) Unexplained gaps > 180 days between consecutive employment periods.
    unexplained_gaps = []  # (gap_days, gap_start, gap_end, prev_employer, cur_employer)
    for i in range(1, len(dated)):
        prev, cur = dated[i - 1], dated[i]
        prev_end = prev["end"]
        if prev_end is None:  # prev is still current -> overlapping, no gap
            continue
        gap_days = (cur["start"] - prev_end).days
        if gap_days > GAP_THRESHOLD_DAYS:
            gap_start, gap_end = prev_end, cur["start"]
            if not _disclosed_covers(gap_start, gap_end, gaps_disclosed):
                unexplained_gaps.append((
                    gap_days, gap_start, gap_end,
                    prev["raw"].get("employer"), cur["raw"].get("employer"),
                ))
                flags.append(_flag(
                    master_record, packet,
                    "CAQH_WORKHISTORY_GAP_UNEXPLAINED", "error", 0.7,
                    f"CAQH work history shows an unexplained employment gap of "
                    f"{gap_days} days ({fmt(gap_start)} to {fmt(gap_end)}), between "
                    f"'{prev['raw'].get('employer')}' and '{cur['raw'].get('employer')}', "
                    f"with no matching explained gap disclosed on the application.",
                ))

    # 2) Packet shows work history but backend verified work history is empty.
    backend_wh = master_record.get("workHistory") or []
    if work_history and not backend_wh:
        flags.append(_flag(
            master_record, packet,
            "CAQH_NOT_VERIFIED_IN_BACKEND", "warning", 0.75,
            f"CAQH application lists {len(work_history)} employment period(s) but the "
            f"backend has no verified work history on record.",
        ))

    # 3) Backend "Work History" verdict says NO gap, but the AI found an
    #    unexplained gap > 180 days -> the verified verdict contradicts the packet.
    if unexplained_gaps and wh_verdict is not None and _says_no_gap(wh_verdict):
        biggest = max(unexplained_gaps, key=lambda g: g[0])
        gap_days, gap_start, gap_end, prev_emp, cur_emp = biggest
        flags.append(_flag(
            master_record, packet,
            "WORKHISTORY_VERDICT_MISMATCH", "error", 0.7,
            f"Backend work-history verdict says no employment gap "
            f"(explanation: {wh_verdict!r}), but the CAQH application shows an "
            f"unexplained {gap_days}-day gap ({fmt(gap_start)} to {fmt(gap_end)}), "
            f"between '{prev_emp}' and '{cur_emp}'.",
        ))

    # 4) Backend "Disclosure" verdict says answered favourably, but the AI found
    #    at least one unfavorable disclosure answer -> contradiction.
    disclosure_mismatch = bool(unfavorable) and disc_verdict is not None and _says_favourable(disc_verdict)
    if disclosure_mismatch:
        qs = "; ".join(str(d.get("question")) for d in unfavorable)
        flags.append(_flag(
            master_record, packet,
            "DISCLOSURE_VERDICT_MISMATCH", "error", 0.7,
            f"Backend disclosure verdict says answered favourably "
            f"(explanation: {disc_verdict!r}), but the CAQH application has "
            f"{len(unfavorable)} unfavorable disclosure answer(s): {qs}.",
        ))

    # 5) AI found an unfavorable disclosure answer regardless of backend; surface
    #    for review, unless already covered by the mismatch above.
    if unfavorable and not disclosure_mismatch:
        qs = "; ".join(str(d.get("question")) for d in unfavorable)
        flags.append(_flag(
            master_record, packet,
            "DISCLOSURE_UNFAVORABLE_FOUND", "warning", 0.65,
            f"CAQH application has {len(unfavorable)} unfavorable disclosure "
            f"answer(s) that should be reviewed: {qs}.",
        ))

    # 6) Info summary so reviewers can see the check ran.
    flags.append(_flag(
        master_record, packet,
        "CAQH_WORKHISTORY_SUMMARY", "info", 0.9,
        f"Found {len(work_history)} employment period(s), "
        f"{len(gaps_disclosed)} disclosed gap(s), and "
        f"{len(disclosure_answers)} disclosure answer(s) "
        f"({len(unfavorable)} unfavorable) in the CAQH application.",
    ))
    return flags


def _load_records(path="master_records.json"):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser(
        description="Audit the CAQH application work history in a PSV packet against the backend record.")
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

    print(f"CAQH-auditing {args.workflow} ({pdf_path}) ...", file=sys.stderr)
    flags = caqh_audit(record, pdf_path)
    print(json.dumps(flags, indent=2))


if __name__ == "__main__":
    main()
