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

def caqh_audit(master_record, pdf_path, packet=None):
    """Extract the CAQH work history from the packet and return work-history flags.
    Pass ``packet`` (e.g. an extract_caqh_full result) to reuse an existing read."""
    packet = packet if packet is not None else extract_caqh(pdf_path)
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


# ---------------------------------------------------------------- full CAQH read

FULL_PROMPT = """You are auditing a credentialing Primary Source Verification (PSV)
packet PDF. Read the CAQH application AND the supporting-document/attachment pages.
Extract ONLY what is actually present, as JSON with EXACTLY this shape:
{
 "demographics": {"first_name","last_name","npi","caqh_id","dob","gender","provider_type","phone","email","address"},
 "attestation_date": string,
 "specialties": [{"name","board_certified"}],
 "professional_ids": [{"type","number","state"}],
 "state_licenses": [{"state","number","expiration_date"}],
 "dea": [{"number","state","expiration_date"}],
 "board_certifications": [{"board","specialty","status","expiration_date"}],
 "education_training": [{"type","institution","specialty","start_date","end_date"}],
 "work_history": [{"employer","role","start_date","end_date","is_current"}],
 "hospital_affiliations": [{"name","status"}],
 "malpractice_insurance": [{"carrier","policy_number","per_occurrence","aggregate","effective_date","expiration_date"}],
 "disclosure_answers": [{"question","answer","unfavorable"}],
 "supporting_documents": [{"name","present"}]
}
Rules:
- demographics.caqh_id is the CAQH Provider ID printed on the application; provider_type is the
  provider's degree/type (e.g. MD, DO, NP, PA); dob as YYYY-MM-DD.
- attestation_date is the date the provider signed/attested the CAQH application (YYYY-MM-DD).
- professional_ids: NPI, DEA, CDS, license numbers etc. as the provider self-reports them.
- board_certifications.status: e.g. "Certified", "Board Eligible", "Not Certified".
- education_training.type: e.g. "Medical School", "Residency", "Fellowship", "Internship".
- disclosure_answers: every attestation/disclosure question the CAQH application asks;
  answer is "yes"/"no"; unfavorable=true when a "yes" indicates a potential issue.
- supporting_documents: for each document/attachment the packet is expected to include
  (e.g. state license, DEA certificate, malpractice face sheet / COI, board certificate,
  diploma, W-9, CV), set present=true if a copy actually appears in the packet, else false.
- Dates as YYYY-MM (YYYY-MM-DD only if a full date is shown). Do not invent values;
  use empty string / empty list when something is absent."""


def extract_caqh_full(pdf_path):
    """Read ALL CAQH elements + supporting-document presence from the packet PDF."""
    pdf = open(pdf_path, "rb").read()
    resp = client.models.generate_content(
        model=MODEL,
        contents=[types.Part.from_bytes(data=pdf, mime_type="application/pdf"), FULL_PROMPT],
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    return json.loads(resp.text)


# Map each CAQH element to the backend master-record key it should reconcile against.
_ELEMENT_MAP = [
    ("demographics",          "demographics",       "Demographics"),
    ("specialties",           "specialties",        "Specialties"),
    ("state_licenses",        "stateLicenses",      "State Licenses"),
    ("dea",                   "dea",                "DEA / CDS"),
    ("board_certifications",  "boardCertifications", "Board Certifications"),
    ("education_training",    "educationTraining",  "Education & Training"),
    ("work_history",          "workHistory",        "Work History"),
    ("hospital_affiliations", "hospitalAffiliation", "Hospital Affiliations"),
    ("malpractice_insurance", "malpractice",        "Malpractice Insurance"),
]


def _count(v):
    """Normalize a backend/CAQH element value to a presence count."""
    if v is None:
        return 0
    if isinstance(v, list):
        return len([x for x in v if x])
    if isinstance(v, dict):
        return 1 if any(x not in (None, "", [], {}) for x in v.values()) else 0
    return 1 if v else 0


# Which fields to show as the human "what we found" summary, per element (CAQH keys / backend keys).
_SUMM_KEYS = {
    "demographics": ["first_name", "last_name"], "specialties": ["name"],
    "state_licenses": ["state", "number"], "dea": ["number", "state"],
    "board_certifications": ["board", "specialty", "status"],
    "education_training": ["type", "institution"], "work_history": ["employer"],
    "hospital_affiliations": ["name"], "malpractice_insurance": ["carrier", "policy_number"],
}
_BE_SUMM_KEYS = {
    "demographics": ["firstName", "lastName"], "specialties": ["name", "specialty"],
    "stateLicenses": ["state", "license_number"], "dea": ["state", "dea_number"],
    "boardCertifications": ["specialty", "status"],
    "educationTraining": ["type", "degree", "institution"],
    "workHistory": ["employer", "organization", "name"], "hospitalAffiliation": ["name", "hospital_name"],
    "malpractice": ["carrier", "policy_number"],
}


def _summarize(val, keys):
    """Short human string of what an element holds, e.g. 'FL, 12345; CA, 67890'."""
    def one(x):
        if isinstance(x, dict):
            return ", ".join(str(x.get(k)) for k in keys if x.get(k))
        return str(x) if x else ""
    if isinstance(val, dict):
        return one(val) or "—"
    if isinstance(val, list):
        parts = [one(x) for x in val if one(x)]
        shown = "; ".join(parts[:4])
        if len(parts) > 4:
            shown += f" +{len(parts) - 4} more"
        return shown or "—"
    return str(val) if val else "—"


# Supporting-document categories -> keywords. We reconcile by CATEGORY (not exact label)
# so packet/BQ label differences don't produce false mismatches.
_DOC_CATS = [
    ("State License",        ["license", "licensure"]),
    ("DEA / CDS",            ["dea", "cds", "controlled substance"]),
    ("Malpractice / COI",    ["malpractice", "coi", "liability", "face sheet", "certificate of insurance", "insurance"]),
    ("Board Certification",  ["board", "abms", "aoa", "certification cert", "board cert"]),
    ("Diploma / Education",  ["diploma", "degree", "medical school", "residency", "fellowship", "ecfmg", "transcript"]),
    ("CV / Resume",          ["cv", "curriculum vitae", "resume"]),
    ("W-9 / Tax",            ["w-9", "w9", "tax"]),
    ("Attestation / Release", ["attestation", "release", "authorization", "consent"]),
]


def _doc_cats(text):
    """Return the set of document categories a piece of label text matches."""
    t = (text or "").lower()
    return {label for label, kws in _DOC_CATS if any(k in t for k in kws)}


def compare_caqh_elements(master, full):
    """Per-element: what CAQH self-reports vs what the backend (BQ) has, plus supporting-doc
    reconciliation between the packet PDF and the BQ document list. Returns
    (element_rows, doc_rows). Never raises — presence/category-level reconciliation."""
    master = master or {}
    element_rows = []
    for caqh_key, be_key, label in _ELEMENT_MAP:
        caqh_val = full.get(caqh_key)
        be_val = master.get(be_key)
        c, b = _count(caqh_val), _count(be_val)
        if c and not b:
            status, note = "review", "self-reported on CAQH, not found in platform data"
        elif b and not c:
            status, note = "review", "in platform data, not read from CAQH"
        elif not c and not b:
            status, note = "na", "not present in either source"
        else:
            status, note = "ok", "present in both CAQH and platform"
        element_rows.append({"element": label, "caqhCount": c, "backendCount": b,
                             "status": status, "note": note,
                             "caqhFound": _summarize(caqh_val, _SUMM_KEYS.get(caqh_key, [])),
                             "backendFound": _summarize(be_val, _BE_SUMM_KEYS.get(be_key, []))})

    # --- supporting documents: packet (AI) vs BQ, reconciled by category ---
    packet_cats = set()
    for d in full.get("supporting_documents") or []:
        if d.get("present"):
            packet_cats |= _doc_cats(d.get("name"))
    bq_cats = set()
    for row in master.get("supportingDocuments") or []:
        label_text = " ".join(str(row.get(k) or "") for k in
                              ("document_name", "sub_collection_name", "original_file_name", "description"))
        bq_cats |= _doc_cats(label_text)

    doc_rows = []
    for label, _ in _DOC_CATS:
        inP, inB = label in packet_cats, label in bq_cats
        if inP and inB:
            status, note = "ok", "present in packet and recorded in platform (BQ)"
        elif inP and not inB:
            status, note = "review", "attached to packet but not recorded in platform (BQ)"
        elif inB and not inP:
            status, note = "review", "recorded in platform (BQ) but not found in the packet"
        else:
            continue  # neither source references this doc type — nothing to reconcile
        doc_rows.append({"name": label, "inPacket": inP, "inBackend": inB,
                         "present": inP, "status": status, "note": note})
    return element_rows, doc_rows


# ---------------------------------------------------------------- application-driven applicability

def _is_board_certified(bc):
    """True if the CAQH board-cert list contains a genuinely certified entry."""
    for b in bc or []:
        st = str(b.get("status", "")).lower()
        if "cert" in st and "not" not in st and "eligible" not in st:
            return True
    # listed a board with no status field at all -> treat as claimed
    if bc and not any("status" in b for b in bc):
        return True
    return False


def applicability(full):
    """From what the provider self-reports on CAQH, which OPTIONAL elements they actually
    have. Absence of an element the provider does NOT claim is expected, not a flag.
    (Malpractice / demographics / licenses are always required and never suppressed.)"""
    full = full or {}
    prof = full.get("professional_ids") or []
    has_dea = bool(full.get("dea")) or any(
        "dea" in str(p.get("type", "")).lower() or "cds" in str(p.get("type", "")).lower() for p in prof)
    return {
        "boardCertifications": _is_board_certified(full.get("board_certifications")),
        "dea": has_dea,
        "hospitalAffiliation": bool(full.get("hospital_affiliations")),
    }


_ABSENCE_RULE_TOKENS = ("MISSING", "ABSENT", "NOT_PRESENT", "NOT_FOUND", "_REQUIRED", "NO_")
# element/rule keyword -> applicability key (only the truly OPTIONAL elements)
_APPL_ELEM = {"board": "boardCertifications", "dea": "dea",
              "hospital": "hospitalAffiliation", "affiliation": "hospitalAffiliation"}


def _is_absence_flag(f):
    """Heuristic: does this flag say an element is MISSING/absent (vs a value mismatch)?"""
    rule = (f.get("rule") or "").upper()
    msg = (f.get("message") or "").lower()
    if "mismatch" in msg or "disagree" in msg:
        return False
    if any(t in rule for t in _ABSENCE_RULE_TOKENS):
        return True
    return "missing" in msg or "not found" in msg or "absent" in msg or "no copy" in msg


def suppress_by_applicability(flags, appl):
    """Drop 'element absent/missing' flags for OPTIONAL elements the provider does not claim on
    their CAQH application (branching: no board cert claimed -> absence isn't an error)."""
    if not appl:
        return flags
    out = []
    for f in flags:
        el = (f.get("element") or "").lower()
        rule = (f.get("rule") or "").lower()
        akey = next((ak for kw, ak in _APPL_ELEM.items() if kw in el or kw in rule), None)
        if akey and _is_absence_flag(f) and not appl.get(akey, True):
            continue  # provider doesn't claim this element -> absence is expected
        out.append(f)
    return out


def _assert_flag(master, element, state, rule, severity, conf, message, category):
    demo = master.get("demographics") or {}
    return {"workflowId": master.get("workflowId"),
            "provider": " ".join(p for p in (demo.get("firstName"), demo.get("lastName")) if p),
            "npi": demo.get("npi"), "element": element, "state": state, "rule": rule,
            "severity": severity, "confidence": conf, "message": message, "category": category,
            "flagClass": "application-asserts-vs-backend"}


def assertion_flags(master, full):
    """Where the CAQH application ASSERTS an element (or a state to be credentialed in) that the
    backend/platform does NOT have -> flag. This is the other half of branching applicability:
    if the provider attests to it and it's missing in platform data, we flag it."""
    master = master or {}
    full = full or {}
    flags = []
    empty = lambda k: not (master.get(k))

    # state licenses the provider lists on CAQH but that platform data lacks
    be_states = {(l.get("state") or "").strip().upper() for l in (master.get("stateLicenses") or [])}
    for l in full.get("state_licenses") or []:
        st = (l.get("state") or "").strip().upper()
        if st and st not in be_states:
            flags.append(_assert_flag(
                master, "stateLicenses", st, "APP_ASSERTS_LICENSE_MISSING_IN_PLATFORM", "error", 0.8,
                f"Provider's CAQH application lists a {st} license ({l.get('number', '')}) "
                f"not found in platform data.", "State Licenses"))

    if _is_board_certified(full.get("board_certifications")) and empty("boardCertifications"):
        flags.append(_assert_flag(
            master, "boardCertifications", None, "APP_ASSERTS_BOARDCERT_MISSING_IN_PLATFORM", "error", 0.75,
            "Provider's CAQH application reports a board certification not found in platform data.",
            "Board Certifications"))

    prof = full.get("professional_ids") or []
    if (full.get("dea") or any("dea" in str(p.get("type", "")).lower() for p in prof)) and empty("dea"):
        flags.append(_assert_flag(
            master, "dea", None, "APP_ASSERTS_DEA_MISSING_IN_PLATFORM", "error", 0.75,
            "Provider's CAQH application reports a DEA registration not found in platform data.",
            "DEA / CDS"))

    if full.get("hospital_affiliations") and empty("hospitalAffiliation"):
        flags.append(_assert_flag(
            master, "hospitalAffiliation", None, "APP_ASSERTS_AFFILIATION_MISSING_IN_PLATFORM", "warning", 0.65,
            "Provider's CAQH application lists hospital affiliation(s) not found in platform data.",
            "Hospital Affiliations"))

    if full.get("malpractice_insurance") and empty("malpractice"):
        flags.append(_assert_flag(
            master, "malpractice", None, "APP_ASSERTS_MALPRACTICE_MISSING_IN_PLATFORM", "error", 0.75,
            "Provider's CAQH application reports malpractice insurance not found in platform data.",
            "Malpractice Insurance"))
    return flags


# Which packet_extract key + fields represent each element as a SUPPORTING DOCUMENT read.
_PKT_KEY = {"state_licenses": "state_licenses", "dea": "dea",
            "board_certifications": "board_certifications", "malpractice_insurance": "malpractice"}
_PKT_SUMM_KEYS = {"state_licenses": ["state", "license_number"], "dea": ["number", "state"],
                  "board_certifications": ["specialty"], "malpractice": ["carrier", "policy_number"]}


def three_way_compare(master, packet, full):
    """Element-level comparison across all three sources: platform (BQ) vs supporting documents
    (packet_extract read of the actual license/DEA/COI images) vs CAQH application. Returns rows
    with a short 'found' string per source and an alignment status."""
    master = master or {}
    packet = packet or {}
    full = full or {}
    rows = []
    for caqh_key, be_key, label in _ELEMENT_MAP:
        caqh_val, be_val = full.get(caqh_key), master.get(be_key)
        c, b = _count(caqh_val), _count(be_val)
        # supporting-document source (only elements that appear as their own document in the packet)
        if caqh_key == "demographics":
            docs_found = packet.get("provider_name") or ""
            pc = 1 if docs_found else 0
        elif caqh_key in _PKT_KEY:
            pk = _PKT_KEY[caqh_key]
            docs_found = _summarize(packet.get(pk), _PKT_SUMM_KEYS.get(pk, []))
            pc = _count(packet.get(pk))
        else:
            docs_found, pc = None, None  # not separately imaged as a document

        counts = [x for x in (b, c, pc) if x is not None]
        present = [x > 0 for x in counts]
        if not any(present):
            status = "na"
        elif all(present):
            status = "ok"
        else:
            status = "review"  # present in some sources but not others
        rows.append({"element": label,
                     "platform": _summarize(be_val, _BE_SUMM_KEYS.get(be_key, [])),
                     "docs": (docs_found if pc is not None else "—"),
                     "caqh": _summarize(caqh_val, _SUMM_KEYS.get(caqh_key, [])),
                     "platformCount": b, "docCount": pc, "caqhCount": c, "status": status})
    return rows


# --------------------------------------------- per-element verification matrix
# (label, backend_key, caqh_key, packet_key, supporting-doc category)
_MATRIX_ELEMENTS = [
    ("Demographics", "demographics", "demographics", None, None),
    ("Attestation", "__attestation__", "attestation_date", None, None),
    ("Specialties", "specialties", "specialties", None, None),
    ("Professional IDs", "professionalIds", "professional_ids", None, None),
    ("State Licenses", "stateLicenses", "state_licenses", "state_licenses", "State License"),
    ("DEA / CDS", "dea", "dea", "dea", "DEA / CDS"),
    ("Board Certifications", "boardCertifications", "board_certifications", "board_certifications", "Board Certification"),
    ("NPDB", "npdb", None, None, None),
    ("Licensure Actions", "licensureActions", None, None, None),
    ("Sanctions", "sanctions", None, None, None),
    ("Malpractice Insurance", "malpractice", "malpractice_insurance", "malpractice", "Malpractice / COI"),
    ("Application Verifications", "appVerifications", None, None, None),
    ("Education & Training", "educationTraining", "education_training", None, "Diploma / Education"),
    ("Hospital Affiliations", "hospitalAffiliation", "hospital_affiliations", None, None),
    ("Supporting Documents", "__docs__", None, None, None),
]
_DATE_FIELDS = ("issue_date", "effective_date", "expiration_date", "report_date",
                "verified_at", "verified_date")
# Elements that are primary-source verified (so a missing source/verification timestamp matters).
# Demographics / specialties / work history are not verified this way, so we don't penalize them.
_VERIFIABLE = {"stateLicenses", "dea", "boardCertifications", "malpractice",
               "educationTraining", "npdb", "sanctions", "licensureActions"}


# Keywords to attribute a flag/finding to a matrix element.
_ELEM_MATCH = {
    "Demographics": ("demographic", "name", "npi", "dob", "gender"),
    "Attestation": ("attestation",),
    "Specialties": ("special",),
    "Professional IDs": ("professionalid", "profid"),
    "State Licenses": ("license", "statelicense"),
    "DEA / CDS": ("dea", "cds"),
    "Board Certifications": ("board",),
    "NPDB": ("npdb",),
    "Licensure Actions": ("licensureaction", "action"),
    "Sanctions": ("sanction",),
    "Malpractice Insurance": ("malpractice", "coi", "coverage"),
    "Application Verifications": ("appverification", "applicationverification", "verification", "disclosure", "workhistory"),
    "Education & Training": ("educ", "edu", "training", "residency"),
    "Hospital Affiliations": ("hospital", "affiliation"),
    "Supporting Documents": ("document", "packetdoc"),
}

def _findings_for(label, flags):
    kws = _ELEM_MATCH.get(label, ())
    out = []
    for f in flags or []:
        if (f.get("severity") or "") == "info":
            continue
        hay = _fn(f.get("element")) + " " + _fn(f.get("rule")) + " " + _fn(f.get("category"))
        if any(k in hay for k in kws):
            out.append(f.get("message"))
    return out

def _fn(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())

# Identifier fields per element (backend vs packet) for value-level matching, and which elements
# carry an expiration we can check for "active vs expired".
_BE_ID = {"stateLicenses": "license_number", "dea": "dea_number", "malpractice": "policy_number"}
_PKT_ID = {"state_licenses": "license_number", "dea": "number", "malpractice": "policy_number"}
_ACTIVE_ELEMS = {"stateLicenses", "dea", "boardCertifications", "malpractice"}

def _item_label(be_key, r):
    j = lambda *ks: " · ".join(str(r.get(k)) for k in ks if r.get(k))
    return ({
        "demographics": j("firstName", "lastName"),
        "stateLicenses": j("state", "license_number"),
        "dea": j("dea_number", "state"),
        "boardCertifications": j("specialty", "status") or r.get("board"),
        "malpractice": j("carrier", "policy_number"),
        "educationTraining": j("type", "institution") or r.get("degree"),
        "professionalIds": j("type", "number"),
        "specialties": r.get("name") or r.get("specialty"),
        "hospitalAffiliation": r.get("name") or r.get("hospital_name"),
        "workHistory": r.get("employer") or r.get("organization"),
        "npdb": r.get("report_type"),
        "sanctions": r.get("sanction_type") or r.get("type_of_action") or r.get("type"),
        "licensureActions": r.get("type_of_action") or r.get("action") or r.get("type"),
    }.get(be_key) or (be_key + " entry"))

def _match_pkt(be_key, r, pkt_rows, pkt_key):
    """Best-effort match a backend row to the corresponding document row (by identifier, then state)."""
    idf, pidf = _BE_ID.get(be_key), _PKT_ID.get(pkt_key)
    if idf and pidf and _fn(r.get(idf)):
        for x in pkt_rows:
            if _fn(x.get(pidf)) == _fn(r.get(idf)):
                return x
    if _fn(r.get("state")):
        for x in pkt_rows:
            if _fn(x.get("state")) == _fn(r.get("state")):
                return x
    return pkt_rows[0] if len(pkt_rows) == 1 else None

def element_matrix(master, packet, full, required_set, doc_rows=None, flags=None):
    """For each element: is it REQUIRED (provider type) or ATTESTED (CAQH) → expected-but-missing;
    is a supporting DOCUMENT required and present; are the DATES (issue/expiration/report/verified)
    consistent between platform and the document; is the SOURCE + verification timestamp recorded
    (confirming we actually pulled the primary source)."""
    master = master or {}; packet = packet or {}; full = full or {}
    required_set = set(required_set or [])
    doc_cats_present = {d["name"] for d in (doc_rows or []) if d.get("inBackend") or d.get("inPacket")}
    out = []
    ASOF = datetime.now()
    _blank = {"verified": None, "verifiedNote": "—", "sourceOk": None, "sourceNote": "—",
              "activeOk": None, "activeNote": "—", "valueOk": None, "valueNote": "—", "items": []}
    for label, be_key, caqh_key, pkt_key, doc_cat in _MATRIX_ELEMENTS:
        if be_key == "__attestation__":     # workflow attestation date, platform vs CAQH
            demo = master.get("demographics") or {}
            plat, capp = demo.get("attestationDate"), full.get("attestation_date")
            be_present, attested = bool(plat), bool(capp)
            expected_missing = not be_present
            if plat and capp:
                dates_ok = _date10(plat) == _date10(capp)
                dates_note = ("attestation date matches CAQH" if dates_ok
                              else f"platform {_date10(plat)} vs CAQH {_date10(capp)}")
            else:
                dates_note, dates_ok = "—", None
            findings = _findings_for(label, flags)
            status = ("error" if expected_missing else
                      "review" if (dates_ok is False or findings) else "ok")
            out.append({"element": label, "required": True, "requiredWhy": "attestation always required",
                        "attested": attested, "inPlatform": be_present, "expectedButMissing": expected_missing,
                        "docRequired": False, "docPresent": None, "datesNote": dates_note,
                        "datesOk": dates_ok, "findings": findings, "status": status, **_blank})
            continue
        if be_key == "__docs__":            # supporting documents reconciliation summary
            drows = doc_rows or []
            drev = [d for d in drows if d.get("status") == "review"]
            present_any = any(d.get("inPacket") or d.get("inBackend") for d in drows)
            findings = [f"{d['name']}: {d.get('note', '')}" for d in drev]
            status = "review" if drev else ("ok" if drows else "na")
            out.append({"element": label, "required": True, "requiredWhy": "required for PSV",
                        "attested": None, "inPlatform": present_any, "expectedButMissing": False,
                        "docRequired": True, "docPresent": present_any, "datesNote": "—",
                        "datesOk": None, "findings": findings, "status": status, **_blank})
            continue
        be_rows = master.get(be_key) or []
        be_rows = be_rows if isinstance(be_rows, list) else [be_rows]
        be_present = _count(master.get(be_key)) > 0
        attested = bool(full.get(caqh_key)) if caqh_key else False
        req_type = be_key in required_set
        required = req_type or attested
        why = []
        if req_type: why.append("required for provider type")
        if attested: why.append("attested in CAQH")
        required_why = " · ".join(why) if why else "not required"
        expected_missing = required and not be_present

        # supporting document required / present
        if doc_cat:
            doc_required = required
            doc_present = (doc_cat in doc_cats_present) or (bool(packet.get(pkt_key)) if pkt_key else False)
        else:
            doc_required, doc_present = False, None

        # ---- verify EVERY entry individually ----
        pkt_rows = (packet.get(pkt_key) or []) if pkt_key else []
        verifiable = be_key in _VERIFIABLE
        items = []
        for r in be_rows:
            exp_raw = r.get("expiration_date"); exp = parse_date(exp_raw)
            vat = r.get("verified_at") or r.get("verified_date")
            it = {"label": _item_label(be_key, r),
                  "verified": (bool(vat) if verifiable else None),
                  "verifiedAt": (_date10(vat) if vat else ""),
                  "source": ((str(r.get("source")) if r.get("source") else "") if verifiable else ""),
                  "active": (None if exp is None else exp >= ASOF),
                  "expiration": (_date10(exp_raw) if exp_raw else ""),
                  "valueOk": None, "datesOk": None, "docExpiration": ""}
            pm = _match_pkt(be_key, r, pkt_rows, pkt_key) if pkt_rows else None
            if pm:
                idf, pidf = _BE_ID.get(be_key), _PKT_ID.get(pkt_key)
                if idf and pidf and r.get(idf) and pm.get(pidf):
                    it["valueOk"] = (_fn(r.get(idf)) == _fn(pm.get(pidf)))
                be_e, pk_e = _date10(exp_raw), _date10(pm.get("expiration_date"))
                it["docExpiration"] = pk_e
                if be_e and pk_e:
                    it["datesOk"] = (be_e == pk_e)
            items.append(it)

        def _agg(key):
            vals = [it[key] for it in items if it.get(key) is not None]
            return None if not vals else all(vals)

        # aggregates across all entries
        if not verifiable or not items:
            verified, verified_note, source_ok, source_note = None, "—", None, "—"
        else:
            verified = _agg("verified")
            vdates = sorted(it["verifiedAt"] for it in items if it["verifiedAt"])
            n_unverified = sum(1 for it in items if it["verified"] is False)
            verified_note = (f"all {len(items)} verified (earliest {vdates[0]})" if verified and vdates
                             else f"{n_unverified} of {len(items)} not verified" if n_unverified else "no verification timestamp")
            source_ok = all(bool(it["source"]) for it in items)
            srcset = [it["source"] for it in items if it["source"]]
            source_note = (f"{srcset[0]}" + (f" +{len(set(srcset)) - 1} more" if len(set(srcset)) > 1 else "")) if srcset else "no source recorded"
        active_ok = _agg("active") if be_key in _ACTIVE_ELEMS else None
        active_note = ("—" if active_ok is None else "all active" if active_ok
                       else "EXPIRED: " + ", ".join(it["label"] for it in items if it.get("active") is False))
        value_ok = _agg("valueOk")
        value_note = ("—" if value_ok is None else "identifiers match document" if value_ok
                      else "differs: " + ", ".join(it["label"] for it in items if it.get("valueOk") is False))
        dates_ok = _agg("datesOk")
        dates_note = ("—" if dates_ok is None else "dates match document" if dates_ok
                      else "differs: " + ", ".join(it["label"] for it in items if it.get("datesOk") is False))

        findings = _findings_for(label, flags)
        if expected_missing:
            status = "error"
        elif active_ok is False:
            status = "error"          # an expired required credential is critical
        elif (doc_required and not doc_present) or dates_ok is False or value_ok is False \
                or source_ok is False or verified is False or findings:
            status = "review"
        elif not required and not be_present:
            status = "na"
        else:
            status = "ok"
        out.append({"element": label, "required": required, "requiredWhy": required_why,
                    "attested": (attested if caqh_key else None),
                    "inPlatform": be_present, "expectedButMissing": expected_missing,
                    "verified": verified, "verifiedNote": verified_note,
                    "sourceOk": source_ok, "sourceNote": source_note,
                    "activeOk": active_ok, "activeNote": active_note,
                    "valueOk": value_ok, "valueNote": value_note,
                    "docRequired": doc_required, "docPresent": doc_present,
                    "datesNote": dates_note, "datesOk": dates_ok,
                    "findings": findings, "items": items, "status": status})
    return out


# --------------------------------------------- demographics / attestation: platform vs CAQH

def _date10(s):
    m = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", str(s or ""))
    if m:
        return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return str(s or "").strip()


def _norm_gender(s):
    s = str(s or "").strip().lower()
    return s[0] if s else ""


def demographic_compare(master, full):
    """Checklist rows comparing platform (BQ) vs CAQH application for the identity fields the
    user called out: CAQH ID, DOB, gender, provider type, and attestation date."""
    demo = (master or {}).get("demographics") or {}
    cd = (full or {}).get("demographics") or {}

    def row(field, pv, cv, kind="str"):
        p, c = str(pv or "").strip(), str(cv or "").strip()
        if kind == "date":
            p, c = _date10(pv), _date10(cv)
        if not p and not c:
            status = "na"
        elif not p or not c:
            status = "review"  # present in only one source
        elif kind == "gender":
            status = "ok" if _norm_gender(pv) == _norm_gender(cv) else "review"
        else:
            status = "ok" if p.lower().replace(" ", "") == c.lower().replace(" ", "") else "review"
        return {"field": field, "platform": p or "—", "caqh": c or "—", "status": status}

    return [
        row("CAQH ID", demo.get("caqhId"), cd.get("caqh_id")),
        row("Date of birth", demo.get("dateOfBirth"), cd.get("dob"), "date"),
        row("Gender", demo.get("gender"), cd.get("gender"), "gender"),
        row("Provider type", demo.get("providerType"), cd.get("provider_type")),
        row("Attestation date", demo.get("attestationDate"), full.get("attestation_date"), "date"),
    ]


def demographic_flags(master, full):
    """Flags for demographic/attestation fields that DISAGREE between platform and CAQH
    (both present but different). Present-in-one-only is left to the checklist, not flagged."""
    flags = []
    for r in demographic_compare(master, full):
        if r["status"] == "review" and r["platform"] != "—" and r["caqh"] != "—":
            rule = ("ATTESTATION_DATE_MISMATCH" if r["field"] == "Attestation date"
                    else "DEMOGRAPHIC_MISMATCH_" + r["field"].upper().replace(" ", "_"))
            flags.append(_assert_flag(
                master, "demographics", None, rule, "warning", 0.75,
                f"{r['field']} disagrees between platform ({r['platform']}) and CAQH "
                f"application ({r['caqh']}).", "Provider Demographics"))
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
