#!/usr/bin/env python3
"""NCQA credentialing checks that span the packet + platform record and were not covered by the
per-element reconciliation. These close known NCQA gaps:

  * Attestation recency — the signed attestation must be current relative to the credentialing
    decision (NCQA: verification/attestation within the client's window, default 180 days).
  * Malpractice claims history — NPDB payments / disclosed malpractice claims must be reviewed.
  * Sanctions/exclusion screening completeness — OIG-LEIE and SAM/EPLS (and Medicaid) must be checked.
  * License restriction/limitation — an active-but-restricted/probation license needs review.

All checks are conservative (warning/info where ambiguous) to avoid false errors.
"""
import re
from datetime import datetime


def _d(s):
    m = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", str(s or ""))
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _flag(record, element, rule, severity, conf, message, category, state=""):
    demo = record.get("demographics") or {}
    return {"workflowId": record.get("workflowId"),
            "provider": " ".join(p for p in (demo.get("firstName"), demo.get("lastName")) if p),
            "npi": demo.get("npi"), "element": element, "state": state, "rule": rule,
            "severity": severity, "confidence": conf, "message": message, "category": category,
            "flagClass": "ncqa"}


def check_attestation_recency(record, days=180):
    """Attestation must be signed within `days` of the credentialing decision / PSV-complete date."""
    demo = record.get("demographics") or {}
    tl = record.get("timeline") or {}
    att = _d(demo.get("attestationDate") or tl.get("attestationDate"))
    decision = _d(tl.get("psvCompleteDate") or tl.get("decisionDate") or tl.get("receivedForCredentialingDate"))
    if not att:
        return [_flag(record, "attestation", "ATTESTATION_MISSING", "error", 0.7,
                      "No signed attestation date on record — NCQA requires a current, signed attestation.",
                      "Workflow Guideline")]
    if att and decision and (decision - att).days > days:
        return [_flag(record, "attestation", "ATTESTATION_STALE", "error", 0.75,
                      f"Attestation signed {att.date()} is {(decision - att).days} days before the "
                      f"credentialing decision {decision.date()} — exceeds the {days}-day currency window.",
                      "Workflow Guideline")]
    return []


def check_malpractice_history(record, packet):
    """NPDB payments / disclosed malpractice claims must be reviewed (NCQA malpractice-history element)."""
    flags = []
    npdb = (packet or {}).get("npdb") or {}
    cnt = npdb.get("report_count")
    try:
        cnt = int(cnt) if cnt not in (None, "") else 0
    except (TypeError, ValueError):
        cnt = 0
    if cnt > 0:
        flags.append(_flag(record, "npdb", "NPDB_HISTORY_REVIEW", "warning", 0.7,
                     f"NPDB report shows {cnt} report(s)/disclosure(s) — review malpractice payment / "
                     f"adverse-action history per NCQA.", "NPDB"))
    return flags


_REQUIRED_SCREENS = {"OIG": ["oig", "leie"], "SAM": ["sam", "epls", "excluded parties"]}

def check_sanctions_screening(record, packet):
    """OIG-LEIE and SAM/EPLS exclusion screening must be present (Medicare/Medicaid sanctions)."""
    screened = [str(s).lower() for s in ((packet or {}).get("sanctions_screened") or [])]
    have = " | ".join(screened)
    missing = [name for name, kws in _REQUIRED_SCREENS.items() if not any(k in have for k in kws)]
    if not screened:
        return [_flag(record, "sanctions", "SANCTIONS_SCREENING_MISSING", "warning", 0.65,
                      "No OIG/SAM exclusion screening found in the packet — NCQA requires Medicare/"
                      "Medicaid sanctions screening (OIG-LEIE and SAM/EPLS).", "Sanctions")]
    if missing:
        return [_flag(record, "sanctions", "SANCTIONS_SCREENING_INCOMPLETE", "warning", 0.65,
                      f"Exclusion screening is missing: {', '.join(missing)} — NCQA requires OIG-LEIE "
                      f"and SAM/EPLS.", "Sanctions")]
    return []


_RESTRICTION_WORDS = ("restrict", "probation", "limitation", "conditional", "suspend", "encumber",
                      "reprimand", "surrender")

def check_license_restrictions(record):
    """An active license whose status/flags indicate a restriction/probation needs review."""
    flags = []
    for lic in record.get("stateLicenses") or []:
        status = str(lic.get("license_status") or lic.get("status") or "").lower()
        flagdesc = str(lic.get("flag_description") or "").lower()
        blob = status + " " + flagdesc
        if any(w in blob for w in _RESTRICTION_WORDS):
            st = (lic.get("state") or "").upper()
            flags.append(_flag(record, "stateLicenses", "LICENSE_RESTRICTED", "error", 0.7,
                         f"{st} license appears restricted/encumbered (status: {lic.get('license_status') or lic.get('status')}"
                         + (f"; {lic.get('flag_description')}" if lic.get('flag_description') else "")
                         + ") — NCQA requires review of any license restriction/limitation.",
                         "State Licenses", state=st))
    return flags


def ncqa_checks(record, packet, attestation_days=180):
    """Run all cross-element NCQA checks and return the combined flags."""
    flags = []
    flags += check_attestation_recency(record, attestation_days)
    flags += check_malpractice_history(record, packet)
    flags += check_sanctions_screening(record, packet)
    flags += check_license_restrictions(record)
    return flags
