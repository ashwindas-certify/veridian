#!/usr/bin/env python3
"""Run the NCQA rule catalog over backend master records -> flags.
Flag classes: validity, data-entry/consistency, completeness (missing data/doc),
name-mismatch. Each flag carries a confidence; each provider gets an audit confidence.
Rules live in rules_catalog.json (data, not code); deterministic execution here.
"""
import json, csv, re, sys
from datetime import datetime, timedelta
from collections import Counter

import os as _os
_DIR = _os.path.dirname(_os.path.abspath(__file__))
CAT = json.load(open(_os.path.join(_DIR, "rules_catalog.json")))
# merge auto-generated per-field "missing" rules (built from the real element-table columns)
_gen = _os.path.join(_DIR, "generated_missing_rules.json")
if _os.path.exists(_gen):
    try: CAT["rules"] += json.load(open(_gen))
    except Exception as _e: print("[warn] generated rules load:", _e)
ASOF = datetime.strptime(CAT["asof"], "%Y-%m-%d").date()
# deep-copied so per-client overlays never mutate the pristine base (matters for the web server)
_BASE_D = json.loads(json.dumps(CAT["clientDefaults"]))
_BASE_REQ = json.loads(json.dumps(CAT["requiredElements"]))
_BASE_PRESCRIBER = {t.lower() for t in CAT["prescriberTypes"]}
D = dict(_BASE_D)
REQ = dict(_BASE_REQ)
PRESCRIBER = set(_BASE_PRESCRIBER)
STOP = set(CAT["docKeywordStoplist"])
CONF_DETERMINISTIC = 0.98
CONF_FILENAME_HEURISTIC = 0.55

# supporting_documents categories we can actually inventory (others => Phase-2 packet detection)
DOC_CATEGORY = {"stateLicenses": "state-licenses", "dea": "dea-data", "educationTraining": "education-trainings"}

def parse_date(v):
    if not v: return None
    s = str(v).strip().replace("T", " ").split(" ")[0].split("+")[0]
    for fmt in ("%Y-%m-%d", "%m-%d-%Y", "%m/%d/%Y"):
        try: return datetime.strptime(s, fmt).date()
        except ValueError: pass
    return None

def parse_money(v):
    if v is None: return None
    d = re.sub(r"[^0-9]", "", str(v)); return int(d) if d else None

def norm_name(s): return re.sub(r"[^a-z]", "", (s or "").lower())

# ---- row-scope primitives: True = PASS (no flag) ----
def status_in(row, r, c): return (row.get(r["field"]) or "").strip().lower() in {s.lower() for s in D[r["params_ref"]]}
def not_expired(row, r, c):
    d = parse_date(row.get(r["field"])); return d is None or d >= ASOF
def coverage_min(row, r, c):
    if D.get("malpractice_coverage_matrix"): return True  # client uses matrix -> flat rule yields
    if str(row.get("unlimited_coverage")).lower() == "true": return True
    a = parse_money(row.get(r["field"])); return a is not None and a >= D[r["params_ref"]]
def active_but_expired(row, r, c):
    active = (row.get(r["status_field"]) or "").strip().lower() in {s.lower() for s in D[r["params_ref"]]}
    d = parse_date(row.get(r["field"])); return not (active and d is not None and d < ASOF)
def field_present(row, r, c): return bool(str(row.get(r["field"]) or "").strip())
def date_order(row, r, c):
    a = parse_date(row.get(r["before_field"])); b = parse_date(row.get(r["field"])); return not (a and b and a > b)
def date_not_future(row, r, c):
    d = parse_date(row.get(r["field"])); return d is None or d <= ASOF
def verified(row, r, c): return bool(str(row.get("verified_at") or "").strip())
def name_matches(row, r, c):
    rn = norm_name(row.get("last_name")); return (not rn) or rn == c["last"]
def value_in_ok(row, r, c):
    """Pass (no flag) if field value is one of the 'clean' outcomes; flag = a real hit."""
    return (row.get(r["field"]) or "").strip() in r["ok_values"]
def value_not_in(row, r, c):
    """Flag if the field's value IS one of bad_values (e.g. status is 'Cancelled')."""
    return (row.get(r["field"]) or "").strip() not in r.get("bad_values", [])
def adverse_requires_doc(row, r, c):
    """If a finding is adverse (value NOT in the clean set), a supporting document must be
    attached to the record (document_id/file_type/document_name). Clean findings need none."""
    if (row.get(r["field"]) or "").strip() in r["ok_values"]:
        return True
    return bool(str(row.get("document_id") or "").strip() or str(row.get("file_type") or "").strip()
                or str(row.get("document_name") or "").strip())
def gap_explained(row, r, c):
    s = parse_date(row.get("workHistory_gapStartDate")); e = parse_date(row.get("workHistory_gapEndDate"))
    if not (s and e): return True
    # per-state gap threshold (Headway: IL 30d, NC 90d, else 180d)
    by_state = D.get("workhistory_gap_days_by_state") or {}
    st = (parse_states(c["master"]["demographics"].get("assignedStates") or c["master"]["demographics"].get("states")) or [None])[0]
    max_gap = by_state.get(st, by_state.get("default", r.get("max_gap_days", 180)))
    if (e - s).days <= max_gap: return True
    return bool(str(row.get("workHistory_explanation") or row.get("explanation") or "").strip())
def verified_within(row, r, c):
    """Flag if a present verification is older than the client's recency window (staleness only)."""
    d = parse_date(row.get("verified_at"))
    return d is None or (ASOF - d).days <= D[r["days_ref"]]
def expiring_soon(row, r, c):
    days = D.get(r["days_ref"], 0)
    if not days: return True  # window disabled for this client
    d = parse_date(row.get(r["field"]))
    if d is None: return True
    return not (ASOF <= d <= ASOF + timedelta(days=days))  # flag if expiring within window
def coverage_min_matrix(row, r, c):
    """Client coverage matrix by state x prescriber (Headway). Falls back to pass if no matrix."""
    if str(row.get("unlimited_coverage")).lower() == "true": return True
    mat = D.get("malpractice_coverage_matrix")
    if not mat: return True  # no matrix -> flat coverage_min rules handle it
    dem = c["master"]["demographics"]
    st = (parse_states(dem.get("assignedStates") or dem.get("states")) or [None])[0]
    entry = mat.get(st) or mat.get("default") or {}
    mins = entry.get("all") or (entry.get("prescriber") if is_prescriber(dem["providerType"]) else entry.get("nonprescriber"))
    if not mins: return True
    occ = parse_money(row.get("occurrence_coverage_amount")); agg = parse_money(row.get("aggregate_coverage_amount"))
    return (occ is not None and occ >= mins[0]) and (agg is not None and agg >= mins[1])

PRIMS = {"status_in": status_in, "not_expired": not_expired, "coverage_min": coverage_min,
    "active_but_expired": active_but_expired, "field_present": field_present, "date_order": date_order,
    "date_not_future": date_not_future, "verified": verified, "name_matches": name_matches,
    "value_in_ok": value_in_ok, "value_not_in": value_not_in, "gap_explained": gap_explained,
    "adverse_requires_doc": adverse_requires_doc, "verified_within": verified_within,
    "expiring_soon": expiring_soon, "coverage_min_matrix": coverage_min_matrix}

def parse_states(v):
    if not v: return []
    return [s.strip().upper() for s in re.split(r"[,;/]", str(v)) if s.strip()]
def is_prescriber(ptype):
    return (ptype or "").upper() in {t.upper() for t in PRESCRIBER}

def expected_for(r):
    """The guideline requirement a rule enforces, in plain words (shown alongside the finding)."""
    if r.get("expected"): return r["expected"]  # rule-specific override
    ch = r["check"]
    return {
        "not_expired": "must be current — not past its expiration date",
        "status_in": "status must be active (" + ", ".join(D.get("active_license_statuses", []) or []) + ")",
        "coverage_min": ("coverage must be at least ${:,}".format(D.get(r.get("params_ref"))) if isinstance(D.get(r.get("params_ref")), (int, float)) else "coverage must meet the client minimum"),
        "coverage_min_matrix": "coverage must meet the client's minimum for the provider's state and type",
        "active_but_expired": "a record marked active must not have a past expiration date",
        "field_present": f"'{r.get('field')}' must be present",
        "date_order": "issue/effective date must be on or before the expiration date",
        "date_not_future": f"'{r.get('field')}' must not be a future date",
        "verified": "must be primary-source verified (carry a verification date)",
        "verified_within": f"must be verified within the last {D.get(r.get('days_ref'))} days",
        "expiring_soon": f"must not be expiring within {D.get(r.get('days_ref'))} days of PSV",
        "value_in_ok": "must return no match / no adverse action",
        "adverse_requires_doc": "an adverse finding must have a supporting document attached",
        "gap_explained": "employment gaps beyond the allowed window must have a written explanation",
        "name_matches": "the record's name must match the provider",
    }.get(ch, "must meet the guideline")

DISABLED_RULES = set()  # per-client rule toggles (rule ids disabled for the active client)
CUSTOM_RULES = []        # per-client custom rules authored in plain English (via AI)

def apply_client_overlay(overlay):
    """Merge a per-client overlay (clients/<name>.json) over the base defaults."""
    global DISABLED_RULES, D, REQ, PRESCRIBER, CUSTOM_RULES
    # reset to pristine base first so repeated calls (web server) don't accumulate
    D = dict(_BASE_D); REQ = dict(_BASE_REQ); PRESCRIBER = set(_BASE_PRESCRIBER); DISABLED_RULES = set(); CUSTOM_RULES = []
    if not overlay: return
    CUSTOM_RULES = overlay.get("customRules", [])
    D.update(overlay.get("overrides", {}))
    REQ.update(overlay.get("requiredElements", {}))
    D["malpractice_coverage_matrix"] = overlay.get("malpractice_coverage_matrix", D.get("malpractice_coverage_matrix"))
    if overlay.get("workhistory_gap_days_by_state"): D["workhistory_gap_days_by_state"] = overlay["workhistory_gap_days_by_state"]
    if overlay.get("cds_required_states"): D["cds_required_states"] = overlay["cds_required_states"]
    for t in overlay.get("overrides", {}).get("prescriber_types_client", []):
        PRESCRIBER.add(t.lower())
    DISABLED_RULES = set(overlay.get("disabledRules", []))

def categorize(rid):
    """Bucket a rule id into one of the config-page categories."""
    if rid.startswith("DEMOGRAPHICS"): return "Provider Demographics"
    if rid.startswith("FILE_TYPE"): return "File Type (Clean / Non-Clean)"
    if any(k in rid for k in ("VERIFICATION_STALE", "EXPIRING_SOON", "COVERAGE_BELOW_CLIENT",
                              "CDS", "DEA_STATE_MISMATCH", "ATTESTATION", "RECRED")):
        return "Workflow Guideline"
    if "NO_DOCUMENT" in rid or rid.startswith("MISSING"):
        return "Missing Documents / Completeness"
    if any(k in rid for k in ("ACTIVE_BUT_EXPIRED", "IN_FUTURE", "AFTER_EXPIRATION",
                              "ISSUE_AFTER", "_MISSING")) or rid.endswith("_MISSING"):
        return "Data Entry / Validation"
    return "NCQA"

def humanize(rid):
    """Rule id -> plain-English title, e.g. STATE_LICENSE_ACTIVE_BUT_EXPIRED -> 'State license active but expired'."""
    s = rid.replace("_", " ").lower()
    return s[:1].upper() + s[1:]

# code-driven (non-catalog) checks that also appear on the config page: (id, element, severity, guideline)
CODE_RULES = [
    ("MISSING_STATELICENSES", "stateLicenses", "error", "a state license record is required"),
    ("MISSING_MALPRACTICE", "malpractice", "error", "a malpractice / professional-liability record is required"),
    ("MISSING_SPECIALTIES", "specialties", "error", "a specialty record is required"),
    ("MISSING_EDUCATIONTRAINING", "educationTraining", "error", "education & training is required (initial; per client also recred)"),
    ("MISSING_BOARDCERTIFICATIONS", "boardCertifications", "error", "board certification is required for prescriber types"),
    ("MISSING_WORKHISTORY", "workHistory", "error", "work history is required (per client / cycle / state)"),
    ("MISSING_NPDB", "npdb", "error", "an NPDB query record is required"),
    ("MISSING_SANCTIONS", "sanctions", "error", "sanction screening records are required"),
    ("MISSING_LICENSE_FOR_ASSIGNED_STATE", "stateLicenses", "error", "an active license is required in each assigned/credentialing state"),
    ("MISSING_DEA", "dea", "error", "prescribers (MD/DO/NP…) must have an active DEA/CDS on file"),
    ("DEA_STATE_MISMATCH", "dea", "info", "DEA should be registered in the assigned state"),
    ("ATTESTATION_MISSING", "attestation", "error", "the application must carry a signed attestation date"),
    ("ATTESTATION_STALE", "attestation", "error", "attestation must be current (within the client's day window)"),
    ("RECRED_OVERDUE", "credentialingTimeline", "warning", "next credentialing date must be in the future (recred cycle ≤ 36 months)"),
    ("BOARD_CERT_SPECIALTY_MISMATCH", "boardCertifications", "info", "board certification specialty should match a listed provider specialty"),
    ("FILE_TYPE_SHOULD_BE_NONCLEAN", "fileType", "error", "a file with any licensure action, sanction match, or NPDB report must be flagged Non-Clean"),
]
def list_rules():
    """Every rule (catalog + code-driven) with a plain-English label + guideline, for the config UI."""
    out = []
    for r in CAT["rules"]:
        if "id" not in r: continue
        out.append({"id": r["id"], "label": humanize(r["id"]), "element": r["element"], "severity": r["severity"],
                    "category": categorize(r["id"]), "guideline": expected_for(r), "enabled": r["id"] not in DISABLED_RULES})
    for rid, el, sev, exp in CODE_RULES:
        out.append({"id": rid, "label": humanize(rid), "element": el, "severity": sev, "category": categorize(rid),
                    "guideline": exp, "enabled": rid not in DISABLED_RULES})
    for r in CUSTOM_RULES:
        out.append({"id": r["id"], "label": humanize(r["id"]), "element": r.get("element"),
                    "severity": r.get("severity", "info"), "category": "Custom (AI-authored)",
                    "guideline": r.get("expected") or "", "enabled": r["id"] not in DISABLED_RULES,
                    "custom": True, "addedAt": r.get("addedAt")})
    return out

DEDUP_KEYS = {"stateLicenses": ("state","license_number"), "dea": ("dea_number","state"),
    "malpractice": ("policy_number",), "boardCertifications": ("specialty","sub_specialty","certificate_type"),
    "specialties": ("specialty",), "educationTraining": ("type","institution"), "hospitalAffiliation": ("name",)}
def _rec(row): return str(row.get("updated_at") or row.get("verified_at") or row.get("timestamp") or "")
def dedup(el, rows):
    keys = DEDUP_KEYS.get(el)
    if not keys: return rows
    best = {}
    for r in rows:
        k = tuple(str(r.get(f) or "") for f in keys)
        if k not in best or _rec(r) > _rec(best[k]): best[k] = r
    return list(best.values())

def fmt(msg, row, r):
    class DD(dict):
        def __missing__(self, k): return row.get(k, "")
    ctx = DD(row); ctx["value"] = row.get(r.get("field",""), ""); ctx["status"] = row.get(r.get("status_field",""), "")
    try: return msg.format_map(ctx)
    except Exception: return msg

def required_for(ptype, cycle=None, states=None):
    req = list(REQ.get("*", []))
    if is_prescriber(ptype): req += REQ.get("prescriber", [])
    # recredentialing: some elements (education/training, work history) are not re-verified,
    # except work history is still required at recred for certain states (Headway: TX/OK/MT/NM/IL)
    if cycle and "recred" in str(cycle).lower():
        exclude = set(REQ.get("recredExclude", ["educationTraining"]))
        wh_states = set(REQ.get("recredWorkHistoryStates", []))
        if "workHistory" in exclude and states and (set(states) & wh_states):
            exclude.discard("workHistory")
        req = [e for e in req if e not in exclude]
    return req

def evaluate(master):
    """Run the rule catalog over a list of master records. Returns (flags, prov_conf)."""
    flags = []; prov_conf = {}
    for m in master:
        dem = m["demographics"]
        ctx = {"last": norm_name(dem["lastName"]), "first": norm_name(dem["firstName"]), "master": m}
        base = {"workflowId": m["workflowId"], "provider": f'{dem["firstName"]} {dem["lastName"]}',
                "org": m["org"], "npi": dem["npi"], "providerType": dem["providerType"]}
        deduped = {el: dedup(el, m.get(el, [])) for el in DEDUP_KEYS}
        deduped["demographics"] = [dem]  # single-row element so demographics rules can run

        def add(element, rule_id, sev, msg, conf, who="(n/a)", when="", state="", expected=""):
            if rule_id in DISABLED_RULES: return  # per-client toggle
            flags.append({**base, "flagClass": "", "element": element, "state": state or "", "rule": rule_id,
                          "severity": sev, "confidence": conf, "message": msg, "expected": expected,
                          "verified_by": who or "(none)", "verified_at": str(when or "")[:10]})

        # ---- row-scope rules (validity, data-entry, name) ----
        for rule in CAT["rules"] + CUSTOM_RULES:
            if "id" not in rule: continue
            prim = PRIMS.get(rule["check"])
            if not prim: continue
            for row in deduped.get(rule["element"], m.get(rule["element"], [])):
                if prim(row, rule, ctx): continue
                add(rule["element"], rule["id"], rule["severity"], fmt(rule["message"], row, rule),
                    CONF_DETERMINISTIC, row.get("verified_by"), row.get("verified_at"),
                    state=row.get("state", ""), expected=expected_for(rule))

        # ---- completeness: missing required DATA (element has 0 rows) ----
        req = required_for(dem["providerType"], dem.get("credentialingCycle"),
                           parse_states(dem.get("assignedStates") or dem.get("states")))
        evaluable = 0
        for el in req:
            if deduped.get(el, m.get(el, [])):
                evaluable += 1
            else:
                add(el, "MISSING_" + el.upper(), "error",
                    f"COMPLETENESS: required element '{el}' has no record in backend", CONF_DETERMINISTIC,
                    expected=f"'{el}' is a required element for this provider type / credentialing cycle")

        # ---- state-aware completeness: license per assigned state; DEA for prescribers ----
        assigned = parse_states(dem.get("assignedStates") or dem.get("states"))
        lic_states = {(r.get("state") or "").upper() for r in deduped.get("stateLicenses", []) if r.get("state")}
        for st in assigned:
            if st not in lic_states:
                add("stateLicenses", "MISSING_LICENSE_FOR_ASSIGNED_STATE", "error",
                    f"COMPLETENESS: no state license on file for assigned state {st}", CONF_DETERMINISTIC, state=st,
                    expected=f"an active license is required in each assigned/credentialing state ({st})")
        if is_prescriber(dem["providerType"]):
            if not deduped.get("dea"):
                add("dea", "MISSING_DEA", "error",
                    "COMPLETENESS: prescriber has no DEA/CDS on file", CONF_DETERMINISTIC,
                    expected="prescribers (MD/DO/NP…) must have an active DEA/CDS on file")
            else:
                dea_states = {(r.get("state") or "").upper() for r in deduped.get("dea", []) if r.get("state")}
                for st in assigned:
                    if dea_states and st not in dea_states:
                        add("dea", "DEA_STATE_MISMATCH", "info",
                            f"DEA not registered in assigned state {st} (verify if required)", 0.70, state=st,
                            expected=f"DEA should be registered in the assigned state ({st})")

        # ---- attestation + time-limit rules (NCQA), from workflow timeline ----
        tl = m.get("timeline") or {}
        att = parse_date(tl.get("attestationDate"))
        decision = parse_date(tl.get("decisionDate"))
        ref, ref_lbl = (decision, "decision") if decision else (ASOF, "today")
        if not att:
            add("attestation", "ATTESTATION_MISSING", "error", "NCQA: no attestation date on file", CONF_DETERMINISTIC,
                expected="application must carry a signed attestation date")
        elif (ref - att).days > D["attestation_max_age_days"]:
            add("attestation", "ATTESTATION_STALE", "error",
                f"NCQA: attestation {att} is older than {D['attestation_max_age_days']} days at {ref_lbl}", 0.9,
                expected=f"attestation must be within {D['attestation_max_age_days']} days of the credentialing decision")
        nxt = parse_date(tl.get("nextCredentialingDate"))
        if nxt and nxt < ASOF:
            add("credentialingTimeline", "RECRED_OVERDUE", "warning",
                f"Recredentialing overdue (next credentialing date {nxt} has passed)", 0.9,
                expected="next credentialing date must be in the future (recred cycle ≤ 36 months)")

        # ---- board certification specialty must match a provider specialty (cross-element) ----
        specs = {re.sub(r'[^a-z]', '', (s.get('specialty') or '').lower()) for s in deduped.get("specialties", [])}
        specs.discard("")
        bcs = deduped.get("boardCertifications", [])
        if bcs and specs and not any(re.sub(r'[^a-z]', '', (b.get('specialty') or '').lower()) in specs for b in bcs):
            add("boardCertifications", "BOARD_CERT_SPECIALTY_MISMATCH", "info",
                "Board certification specialty does not match any listed provider specialty", 0.60,
                expected="board certification specialty should match a listed provider specialty (e.g. Psychiatry-Mental Health)")

        # ---- Clean vs Non-Clean file type: any adverse finding => must be Non-Clean ----
        adverse = []
        for row in deduped.get("sanctions", []):
            if (row.get("type_of_action") or "").strip() not in ("No Match Found", "No Record Found", "Clear", ""):
                adverse.append(f"sanction {row.get('sanction_type') or ''} {row.get('type_of_action')}".strip())
        for row in deduped.get("licensureActions", []):
            if (row.get("action_type") or "").strip() not in ("No Action", "None", ""):
                adverse.append(f"licensure action {row.get('state') or ''}".strip())
        for row in deduped.get("npdb", []):
            if (row.get("report_type") or "").strip() not in ("No Report Found", "None", ""):
                adverse.append(f"NPDB {row.get('report_type')}")
        ft = (dem.get("fileType") or "").strip()
        if adverse and ft.lower() == "clean":
            add("fileType", "FILE_TYPE_SHOULD_BE_NONCLEAN", "error",
                f"FILE TYPE: file marked 'Clean' but adverse findings present ({'; '.join(adverse[:4])})", 0.9,
                expected="a file with any licensure board action, sanction Match Found, or NPDB report must be flagged Non-Clean")

        # NOTE: document PRESENCE/NAME checks require reading the packet PDF (Phase 2) -- the
        # supporting_documents table labels are unreliable, so table-based doc checks were removed.

        # ---- per-provider audit confidence = coverage of required elements we could evaluate ----
        prov_conf[m["workflowId"]] = round(evaluable / max(len(req), 1), 2)

    # classify flag by rule name prefix for reporting
    for f in flags:
        r = f["rule"]
        f["flagClass"] = ("file-type" if r.startswith("FILE_TYPE") else
                          "completeness" if r.startswith("MISSING") else
                          "adverse-action" if ("SANCTION" in r or "ADVERSE_ACTION" in r or "NPDB_REPORT" in r) else
                          "work-history" if "WORK_HISTORY" in r else
                          "name-mismatch" if "NAME_MISMATCH" in r else
                          "data-entry" if ("ACTIVE_BUT_EXPIRED" in r or "FUTURE" in r or "AFTER" in r) else
                          "validity")
    return flags, prov_conf

def main():
    master = json.load(open("master_records.json"))
    flags, prov_conf = evaluate(master)
    json.dump({"flags": flags, "providerAuditConfidence": prov_conf}, open("flags.json", "w"), indent=2)
    cols = ["workflowId","provider","npi","org","providerType","flagClass","element","state","rule",
            "severity","confidence","message","verified_by","verified_at"]
    for path in ("flags.csv", "flags_out.csv"):
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=cols); w.writeheader(); w.writerows(flags)
            break
        except PermissionError:
            print(f"[warn] {path} locked (open elsewhere?), trying fallback", file=sys.stderr)

    print(f"TOTAL FLAGS: {len(flags)} across {len({f['workflowId'] for f in flags})}/{len(master)} providers")
    print("By class:", dict(Counter(f["flagClass"] for f in flags)))
    print("By severity:", dict(Counter(f["severity"] for f in flags)))
    print("\nBy rule:")
    for r, n in Counter(f["rule"] for f in flags).most_common(): print(f"  {n:3d}  {r}")
    print("\nPer-provider audit confidence (coverage of required elements):")
    for m in master:
        print(f"  {m['demographics']['lastName']:16s} {prov_conf[m['workflowId']]:.2f}")
    print("\n--- sample completeness / name flags ---")
    for f in flags:
        if f["flagClass"] in ("completeness", "name-mismatch"):
            print(f'  [{f["severity"]:7s} c={f["confidence"]}] {f["provider"]:20s} {f["message"]}')

if __name__ == "__main__":
    main()
