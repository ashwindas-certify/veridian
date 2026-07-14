#!/usr/bin/env python3
"""PSV Audit web app: client selector, audit runner, per-client rule config, help-bot.
Run:  cd ~/Downloads/psv_audit && python -m uvicorn app:app --port 8000
"""
import os, json, glob, urllib.request, threading, uuid
from collections import Counter
from datetime import datetime, timezone

JOBS = {}  # in-memory job queue: jobId -> {type,client,org,status,processed,total,flags,note,startedAt,finishedAt}

HISTORY = "audit_history.jsonl"                 # local mirror (instant reads)
HISTORY_TABLE = "certifyos-production-platform.psv_audit.audit_history"   # durable BQ log

def record_history(org, client, summary, flags, run_mode="audit"):
    """Persist this run's flags to the BQ history table (durable) + local JSONL mirror (instant)."""
    ts = datetime.now(timezone.utc).isoformat()
    resp = {s["workflowId"]: s.get("responsible") for s in summary}
    rows = [{"run_ts": ts, "run_mode": run_mode, "org": org, "client": client,
             "workflow_id": f.get("workflowId"), "provider": f.get("provider"), "npi": f.get("npi"),
             "responsible": resp.get(f.get("workflowId"), "(unassigned)"), "severity": f.get("severity"),
             "category": f.get("category") or reconcile.categorize(f.get("rule", "")), "element": f.get("element"),
             "rule": f.get("rule"), "confidence": f.get("confidence"), "message": f.get("message"),
             "flag_class": f.get("flagClass")} for f in flags]
    if not rows: return []
    try:
        master_record._client.insert_rows_json(HISTORY_TABLE, rows)  # streaming insert
    except Exception as e:
        print("[warn] BQ history insert failed:", str(e)[:150])
    with open(HISTORY, "a", encoding="utf-8") as fh:
        for r in rows: fh.write(json.dumps(r) + "\n")
    return rows

JOB_RESULTS = {}  # jobId -> list of flag rows (for per-request export)

def read_history(org=None):
    """Union durable BQ history + local mirror, deduped to the latest row per (workflow, rule)."""
    rows = []
    try:
        sql = f"SELECT run_ts, org, client, workflow_id, responsible, severity, category, element, rule FROM `{HISTORY_TABLE}`"
        if org: sql += f" WHERE org = '{org}'"
        rows = [dict(r) for r in master_record._client.query(sql).result()]
    except Exception as e:
        print("[warn] BQ history read failed, using local mirror:", str(e)[:120])
    if os.path.exists(HISTORY):
        for l in open(HISTORY, encoding="utf-8"):
            if l.strip():
                d = json.loads(l)
                if not org or d.get("org") == org: rows.append(d)
    latest = {}
    for r in rows:
        wid = r.get("workflow_id") or r.get("workflowId")
        r = {"workflowId": wid, "responsible": r.get("responsible"), "severity": r.get("severity"),
             "category": r.get("category"), "element": r.get("element"), "rule": r.get("rule"),
             "ts": str(r.get("run_ts") or r.get("ts") or "")}
        latest[(wid, r["rule"])] = r
    return list(latest.values())
os.chdir(os.path.dirname(os.path.abspath(__file__)))
import io, csv as _csv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from google import genai
from google.genai import types

import reconcile, master_record, audit, packet_audit, caqh_audit, rules_engine_results, education_audit

app = FastAPI(title="PSV Audit")
CLIENTS = "clients"
PACKETS = "packets"
NG_API = "https://ng-api-production.certifyos.com"
GENAI = genai.Client(vertexai=True, project="cos-sandbox-provider-data", location="us-central1")

def client_files():
    out = []
    for p in glob.glob(os.path.join(CLIENTS, "*.json")):
        if p.endswith(".generated.json"): continue
        o = json.load(open(p, encoding="utf-8"))
        out.append({"file": p, "name": o.get("clientName", os.path.basename(p)[:-5]),
                    "orgIds": o.get("orgIds", []), "overlay": o})
    return out

def find_client(org):
    for c in client_files():
        if org in c["orgIds"]: return c
    return None

# ---------- API ----------
_CLIENTS_CACHE = None
@app.get("/api/clients")
def clients():
    """All clients that have PSV-complete files (names from the organizations table),
    flagged with whether they have a custom rule overlay. Cached after first load."""
    global _CLIENTS_CACHE
    if _CLIENTS_CACHE is None:
        sql = """
        WITH latest AS (
          SELECT organization_id, onStep_title,
                 ROW_NUMBER() OVER (PARTITION BY credentialing_workflows_id ORDER BY timestamp DESC) rn
          FROM `certifyos-production-platform.appdb_data.credentialing_workflows`
          WHERE operation != 'delete' )
        SELECT organization_id org, COUNT(*) n FROM latest
        WHERE rn = 1 AND onStep_title = 'PSV complete by CertifyOS' AND organization_id IS NOT NULL
        GROUP BY org ORDER BY n DESC LIMIT 300"""
        rows = master_record.bq_json(sql)
        names = audit.fetch_org_names({r["org"] for r in rows})
        overlay_orgs = {oid for c in client_files() for oid in c["orgIds"]}
        _CLIENTS_CACHE = [{"orgId": r["org"], "name": names.get(r["org"], r["org"]),
                           "count": r["n"], "hasOverlay": r["org"] in overlay_orgs} for r in rows]
    return _CLIENTS_CACHE

@app.get("/api/rules")
def rules(org: str):
    c = find_client(org)
    grouped = {}
    with _ENGINE_LOCK:
        reconcile.apply_client_overlay(c["overlay"] if c else None)
        rules_list = reconcile.list_rules()
    for r in rules_list:
        grouped.setdefault(r["category"], []).append(r)
    return {"client": c["name"] if c else org, "categories": grouped,
            "guidelinesUrl": (c["overlay"].get("guidelinesUrl", "") if c else "")}

class GuidelinesReq(BaseModel):
    org: str; docUrl: str
@app.post("/api/refresh-guidelines")
def refresh_guidelines(rq: GuidelinesReq):
    """Re-read the client's guidelines Google Doc and regenerate the rule overlay via Gemini,
    preserving orgIds / custom rules / disabled toggles."""
    import refresh_rules as rr
    c = find_client(rq.org)
    if not c: return {"ok": False, "reason": "This client has no config yet."}
    try:
        text = rr.read_doc(rr.doc_id(rq.docUrl))
    except Exception as e:
        return {"ok": False, "reason": "Couldn't read the doc (is it shared with the service account?): " + str(e)[:120]}
    try:
        prompt = rr.PROMPT.format(vocab=json.dumps(rr.VOCAB), guidelines=text[:60000])
        resp = GENAI.models.generate_content(model=rr.MODEL, contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0))
        gen = json.loads(resp.text)
    except Exception as e:
        return {"ok": False, "reason": "AI generation failed: " + str(e)[:120]}
    o = c["overlay"]
    o["overrides"] = gen.get("overrides", o.get("overrides", {}))
    if gen.get("requiredElements"): o["requiredElements"] = gen["requiredElements"]
    for k in ("malpractice_coverage_matrix", "workhistory_gap_days_by_state", "cds_required_states"):
        if gen.get(k) is not None: o[k] = gen[k]
    if gen.get("packetChecks"): o["packetChecks"] = gen["packetChecks"]
    o["guidelinesUrl"] = rq.docUrl
    json.dump(o, open(c["file"], "w", encoding="utf-8"), indent=2)
    try: open(os.path.join(CLIENTS, f"{c['name'].lower()}.guidelines.txt"), "w", encoding="utf-8").write(text)
    except Exception: pass
    return {"ok": True, "overrides": list(o.get("overrides", {}).keys()), "packetChecks": len(o.get("packetChecks", []))}

class Toggle(BaseModel):
    org: str; ruleId: str; enabled: bool
@app.post("/api/rules/toggle")
def toggle(t: Toggle):
    c = find_client(t.org)
    if not c: return JSONResponse({"error": "no client overlay for org"}, status_code=404)
    o = c["overlay"]; dis = set(o.get("disabledRules", []))
    dis.discard(t.ruleId) if t.enabled else dis.add(t.ruleId)
    o["disabledRules"] = sorted(dis)
    json.dump(o, open(c["file"], "w", encoding="utf-8"), indent=2)
    return {"ok": True, "disabledRules": o["disabledRules"]}

_ENGINE_LOCK = threading.Lock()  # guards the shared rule-engine config during evaluate

def core_audit(org, npis=None, assignedTo="", limit=200):
    """Resolve workflows + run the backend rule engine. Returns (wfs, master, flags, conf).
    BQ work runs concurrently; only apply-overlay+evaluate is serialized (shared globals)."""
    wfs = audit.resolve_workflows(org, npis or None, limit=limit)
    if assignedTo:
        k = assignedTo.lower()
        wfs = [w for w in wfs if k in (w["responsible"] or "").lower()]
    if not wfs:
        return [], [], [], {}
    master = master_record.build_master(wfs)                      # slow BQ, no shared state
    overlay = find_client(org)["overlay"] if find_client(org) else None
    with _ENGINE_LOCK:                                            # config-sensitive critical section
        reconcile.apply_client_overlay(overlay)
        flags, conf = reconcile.evaluate(master)
    return wfs, master, flags, conf

def download_packet(wid, org, path):
    """Fetch the PSV packet PDF for a workflow via psvFileSignedUrl (see download_packets.py)."""
    token = open(".token", encoding="utf-8").read().strip()
    req = urllib.request.Request(f"{NG_API}/credentialing-workflows/{wid}",
        headers={"Authorization": "Bearer " + token, "organization-id": org or ""})
    with urllib.request.urlopen(req, timeout=60) as r:
        wf = json.load(r)
    signed = wf.get("psvFileSignedUrl")
    if not signed:
        raise RuntimeError("no psvFileSignedUrl on workflow")
    with urllib.request.urlopen(signed, timeout=180) as r, open(path, "wb") as f:
        f.write(r.read())

def deep_packet_audit(wfs, master):
    """Per-workflow DEEP checks: packet-vs-backend + CAQH work-history (both read the PDF via
    Gemini, downloading it if absent) + surface CertifyOS's own rulesEngineResults (API).
    Returns (extra_flags, notes) where notes records per-workflow failures."""
    os.makedirs(PACKETS, exist_ok=True)
    org_by_wf = {w["workflowId"]: w.get("org") for w in wfs}
    flags, notes = [], []
    for m in master:
        wid = m["workflowId"]; org = org_by_wf.get(wid)
        path = os.path.join(PACKETS, f"{wid}.pdf")
        try:  # packet-vs-backend + CAQH need the PDF
            if not os.path.exists(path):
                download_packet(wid, org, path)
            _sevmap = {"high": "error", "medium": "warning", "low": "info"}
            for pf in packet_audit.packet_audit(m, path):
                pf["severity"] = _sevmap.get(pf.get("severity"), pf.get("severity"))
                flags.append(pf)
            flags += caqh_audit.caqh_audit(m, path)
            flags += education_audit.education_audit(m, path)
        except Exception as e:
            notes.append({"workflowId": wid, "error": f"packet: {type(e).__name__}: {str(e)[:200]}"})
        try:  # CertifyOS's own rules engine (API, no packet)
            flags += rules_engine_results.rules_engine_flags(wid, org)
        except Exception as e:
            notes.append({"workflowId": wid, "error": f"rules-engine: {type(e).__name__}: {str(e)[:150]}"})
    return flags, notes

ELEMENT_LIST = ["demographics","stateLicenses","dea","boardCertifications","malpractice","specialties","educationTraining",
                "npdb","sanctions","licensureActions","workHistory","hospitalAffiliation"]
_FIELD_SKIP = {"document_id","document_name","event_id","operation","timestamp","edit_provider_id","created_at",
               "created_by","created_by_name","updated_at","updated_by","organization_id","provider_id","is_current"}

def _seed_fields():
    """Prebuild element -> field list from the already-generated rules (no live BQ calls)."""
    m = {"demographics": ["npi", "firstName", "lastName", "providerType", "states"]}
    try:
        for r in json.load(open("generated_missing_rules.json")):
            m.setdefault(r["element"], [])
            if r["field"] not in m[r["element"]]: m[r["element"]].append(r["field"])
    except Exception: pass
    return m
_FIELDS_CACHE = _seed_fields()
@app.get("/api/element-fields")
def element_fields(element: str):
    """Column names for an element (for the screener rule builder). Served from cache (instant)."""
    if element in _FIELDS_CACHE: return sorted(_FIELDS_CACHE[element])
    tbl = master_record.ELEMENTS.get(element)
    if not tbl: return []
    try:
        cols = sorted(f.name for f in master_record._client.get_table(
            f"certifyos-production-platform.appdb_data.{tbl}").schema if f.name not in _FIELD_SKIP)
        _FIELDS_CACHE[element] = cols
        return cols
    except Exception as e:
        print("[warn] element-fields:", str(e)[:120]); return []

def build_structured(rq):
    """Assemble a rule spec from screener-style pickers (element/field/condition/value) — deterministic, no AI."""
    el, fld, cond, val = rq.element, rq.field, rq.condition, (rq.value or "")
    vals = [v.strip() for v in val.split(",") if v.strip()]
    base = {"element": el, "field": fld, "severity": "warning", "source": "custom"}
    if cond == "empty":
        base.update(check="field_present", severity="warning",
                    message=f"{el} '{fld}' is missing", expected=f"'{fld}' must be populated")
    elif cond == "must_be_one_of":
        base.update(check="value_in_ok", ok_values=vals,
                    message=f"{el} {fld} '{{{fld}}}' is not allowed", expected=f"'{fld}' must be one of: {', '.join(vals)}")
    elif cond == "flag_if_one_of":
        base.update(check="value_not_in", bad_values=vals,
                    message=f"{el} {fld} '{{{fld}}}' is flagged", expected=f"'{fld}' must NOT be any of: {', '.join(vals)}")
    elif cond == "expired":
        base.update(check="not_expired", message=f"{el} {fld} is expired", expected=f"'{fld}' must not be in the past")
    elif cond == "future_date":
        base.update(check="date_not_future", message=f"{el} {fld} {{{fld}}} is a future date", expected=f"'{fld}' must not be in the future")
    elif cond == "not_verified":
        base.update(check="verified", message=f"{el} not verified", expected="must carry a verification date")
    else:
        return None
    base["id"] = f"{el.upper()}_{fld.upper()}_{cond.upper()}".replace("__", "_")
    return base

class AddRuleReq(BaseModel):
    org: str; text: str = ""; element: str = ""; field: str = ""; condition: str = ""; value: str = ""
@app.post("/api/add-rule")
def add_rule(rq: AddRuleReq):
    """Add a rule to a client's overlay — either structured (screener pickers) or plain-English (Gemini)."""
    c = find_client(rq.org)
    if not c:
        return {"ok": False, "reason": "This client has no config yet — run an audit for them once, then add rules."}
    if rq.condition:  # ---- screener-style structured builder (deterministic) ----
        spec = build_structured(rq)
        if not spec or spec.get("check") not in reconcile.PRIMS:
            return {"ok": False, "reason": "Pick an element, field and condition."}
        spec["expected"] = spec.get("expected", "")
        spec["addedAt"] = datetime.now(timezone.utc).isoformat()[:16].replace("T", " ")
        o = c["overlay"]; existing = {x.get("id") for x in o.get("customRules", [])}
        if spec["id"] in existing: spec["id"] += "_2"
        o.setdefault("customRules", []).append(spec)
        json.dump(o, open(c["file"], "w", encoding="utf-8"), indent=2)
        return {"ok": True, "rule": spec}
    elements = ELEMENT_LIST
    checks = {"field_present":"flag if a field is empty (needs: field)",
        "not_expired":"flag if a date field is in the past (needs: field = an expiration date)",
        "date_not_future":"flag if a date field is in the future (needs: field)",
        "date_order":"flag if before_field is after field (needs: field, before_field)",
        "verified":"flag if there is no verified_at date (no field needed)",
        "value_in_ok":"flag UNLESS a field's value is one of ok_values (needs: field, ok_values=array of acceptable strings)"}
    prompt = (f"Convert this plain-English credentialing rule into ONE JSON rule for an automated audit engine.\n"
        f"Return strict JSON: {{\"id\":\"UPPER_SNAKE_CASE\",\"element\":one of {elements},\"check\":one of {list(checks)},"
        f"\"field\":\"row field the check reads e.g. expiration_date/license_status/policy_number/verified_at/state\","
        f"\"before_field\":\"only for date_order\",\"ok_values\":[\"only for value_in_ok\"],"
        f"\"severity\":\"error|warning|info\",\"message\":\"short finding text, may use {{field}} placeholders\","
        f"\"expected\":\"plain-English guideline\",\"supported\":true}}.\n"
        f"Check meanings: {json.dumps(checks)}.\n"
        f"If it cannot be expressed with these checks, set supported=false and explain in message.\nRULE: {rq.text}")
    r = GENAI.models.generate_content(model="gemini-2.5-flash", contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0))
    spec = json.loads(r.text)
    if spec.get("supported") is False or spec.get("check") not in reconcile.PRIMS or spec.get("element") not in elements:
        return {"ok": False, "reason": spec.get("message") or "Could not express this rule with the available checks.", "spec": spec}
    if spec.get("check") == "value_in_ok" and not spec.get("ok_values"):
        return {"ok": False, "reason": "This rule needs a set of acceptable values; please rephrase."}
    for k in ("supported",): spec.pop(k, None)
    spec["addedAt"] = datetime.now(timezone.utc).isoformat()[:16].replace("T", " ")
    spec["source"] = "custom"
    o = c["overlay"]; existing = {x.get("id") for x in o.get("customRules", [])}
    if spec["id"] in existing: spec["id"] += "_2"
    o.setdefault("customRules", []).append(spec)
    json.dump(o, open(c["file"], "w", encoding="utf-8"), indent=2)
    return {"ok": True, "rule": spec}

class DeleteRuleReq(BaseModel):
    org: str; ruleId: str
@app.post("/api/rules/delete")
def delete_rule(rq: DeleteRuleReq):
    """Remove a UI-added custom rule from the client's overlay."""
    c = find_client(rq.org)
    if not c: return {"ok": False, "reason": "no client config"}
    o = c["overlay"]; before = len(o.get("customRules", []))
    o["customRules"] = [r for r in o.get("customRules", []) if r.get("id") != rq.ruleId]
    o["disabledRules"] = [d for d in o.get("disabledRules", []) if d != rq.ruleId]
    json.dump(o, open(c["file"], "w", encoding="utf-8"), indent=2)
    return {"ok": True, "removed": before - len(o["customRules"])}

class AuditReq(BaseModel):
    org: str; npis: str = ""; assignedTo: str = ""; limit: int = 200; deepPacket: bool = False
JOB_FULL = {}  # jobId -> full audit result (summary+flags) for async retrieval

def do_audit(org, npis, assignedTo, limit, deep, jid=None):
    """Shared audit: resolve -> master -> rules (+deep) -> summary + flags + history rows."""
    wfs, master, flags, conf = core_audit(org, npis or None, assignedTo, limit)
    client = audit.fetch_org_names({org}).get(org, org)
    if jid: JOBS[jid]["client"] = client; JOBS[jid]["total"] = len(wfs)
    if not wfs: return {"client": client, "summary": [], "flags": [], "note": "no matching PSV-complete workflows"}
    packet_notes = []
    if deep:
        acc = list(flags)
        for i, m in enumerate(master):
            pf, pn = deep_packet_audit([w for w in wfs if w["workflowId"] == m["workflowId"]], [m])
            acc += pf; packet_notes += pn
            if jid: JOBS[jid]["processed"] = i + 1
        flags = acc
    elif jid: JOBS[jid]["processed"] = len(wfs)
    by = {}
    for f in flags: by.setdefault(f["workflowId"], []).append(f)
    summary = []
    for w in wfs:
        fl = by.get(w["workflowId"], []); errs = sum(1 for f in fl if f["severity"] == "error")
        summary.append({"provider": f'{w["first"]} {w["last"]}', "npi": w["npi"], "type": w["type"],
            "states": w.get("states"), "responsible": w.get("responsible"),
            "auditConfidence": conf.get(w["workflowId"]), "errors": errs, "flags": len(fl),
            "status": "REVIEW" if errs else ("CHECK" if fl else "CLEAN"), "workflowId": w["workflowId"]})
    rows = record_history(org, client, summary, flags)
    return {"client": client, "summary": summary, "flags": flags, "packetNotes": packet_notes, "_rows": rows}

def _audit_worker(jid, a):
    j = JOBS[jid]
    try:
        npis = [n.strip() for n in a.npis.replace("\n", ",").split(",") if n.strip()]
        res = do_audit(a.org, npis, a.assignedTo, a.limit, a.deepPacket, jid)
        JOB_RESULTS[jid] = res.pop("_rows", [])
        JOB_FULL[jid] = res
        j.update(status="done", flags=len(res.get("flags", [])),
                 providersWithErrors=len({f["workflowId"] for f in res.get("flags", []) if f["severity"] == "error"}),
                 finishedAt=datetime.now(timezone.utc).isoformat())
    except Exception as e:
        JOB_FULL[jid] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
        j.update(status="failed", note=str(e)[:150], finishedAt=datetime.now(timezone.utc).isoformat())

@app.post("/api/audit-async")
def run_audit_async(a: AuditReq):
    """Start an interactive audit as a background job (no long-held request). Returns jobId to poll."""
    if sum(1 for j in JOBS.values() if j["status"] == "running") >= MAX_CONCURRENT_JOBS:
        return {"error": f"Up to {MAX_CONCURRENT_JOBS} audits can run at once — please wait for one to finish."}
    jid = uuid.uuid4().hex[:8]
    JOBS[jid] = {"id": jid, "type": "audit", "org": a.org, "client": a.org, "status": "running",
                 "processed": 0, "total": None, "flags": 0, "note": "",
                 "startedAt": datetime.now(timezone.utc).isoformat(), "finishedAt": None,
                 "mode": "deep" if a.deepPacket else "standard"}
    threading.Thread(target=_audit_worker, args=(jid, a), daemon=True).start()
    return {"jobId": jid}

@app.get("/api/job-result/{jid}")
def job_result(jid: str):
    return JOB_FULL.get(jid, {"pending": True})

@app.post("/api/audit")
def run_audit(a: AuditReq):
    npis = [n.strip() for n in a.npis.replace("\n", ",").split(",") if n.strip()]
    res = do_audit(a.org, npis, a.assignedTo, a.limit, a.deepPacket)
    if res.get("note") and not res.get("summary"): return res
    jid = uuid.uuid4().hex[:8]; ts = datetime.now(timezone.utc).isoformat()
    JOBS[jid] = {"id": jid, "type": "audit", "org": a.org, "client": res["client"], "status": "done",
                 "processed": len(res["summary"]), "total": len(res["summary"]), "flags": len(res["flags"]),
                 "note": "", "startedAt": ts, "finishedAt": ts, "mode": "deep" if a.deepPacket else "standard"}
    JOB_RESULTS[jid] = res.pop("_rows", [])
    res["jobId"] = jid
    return res

def _pipeline_worker(jid, org, limit, deep):
    j = JOBS[jid]
    try:
        client = audit.fetch_org_names({org}).get(org, org); j["client"] = client
        wfs, master, flags, conf = core_audit(org, None, "", limit)
        j["total"] = len(wfs)
        if not wfs:
            j.update(status="done", note="no PSV-complete files", finishedAt=datetime.now(timezone.utc).isoformat()); return
        if deep:
            for i, m in enumerate(master):
                pf, _ = deep_packet_audit([w for w in wfs if w["workflowId"] == m["workflowId"]], [m])
                flags += pf; j["processed"] = i + 1
        else:
            j["processed"] = len(wfs)
        summary = [{"workflowId": w["workflowId"], "responsible": w.get("responsible")} for w in wfs]
        JOB_RESULTS[jid] = record_history(org, client, summary, flags, run_mode="pipeline")
        j.update(status="done", flags=len(flags),
                 providersWithErrors=len({f["workflowId"] for f in flags if f["severity"] == "error"}),
                 finishedAt=datetime.now(timezone.utc).isoformat())
    except Exception as e:
        j.update(status="failed", note=f"{type(e).__name__}: {str(e)[:200]}", finishedAt=datetime.now(timezone.utc).isoformat())

class PipelineReq(BaseModel):
    org: str; limit: int = 2000; deepPacket: bool = False
MAX_CONCURRENT_JOBS = 3
@app.post("/api/pipeline")
def run_pipeline(p: PipelineReq):
    """Kick off a batch audit of ALL PSV-complete files as a background JOB; returns jobId to poll."""
    if sum(1 for j in JOBS.values() if j["status"] == "running") >= MAX_CONCURRENT_JOBS:
        return {"error": f"Up to {MAX_CONCURRENT_JOBS} audits can run at once — please wait for one to finish."}
    jid = uuid.uuid4().hex[:8]
    JOBS[jid] = {"id": jid, "type": "pipeline", "org": p.org, "client": p.org, "status": "running",
                 "processed": 0, "total": None, "flags": 0, "note": "",
                 "startedAt": datetime.now(timezone.utc).isoformat(), "finishedAt": None,
                 "mode": "deep" if p.deepPacket else "standard"}
    threading.Thread(target=_pipeline_worker, args=(jid, p.org, p.limit, p.deepPacket), daemon=True).start()
    return {"jobId": jid}

@app.get("/api/jobs")
def jobs():
    """Recent audit jobs for the queue bar (most recent first)."""
    js = sorted(JOBS.values(), key=lambda j: j["startedAt"], reverse=True)[:15]
    now = datetime.now(timezone.utc)
    for j in js:
        end = datetime.fromisoformat(j["finishedAt"]) if j.get("finishedAt") else now
        j["elapsedSec"] = int((end - datetime.fromisoformat(j["startedAt"])).total_seconds())
    return js

@app.get("/api/dashboard")
def dashboard(org: str = None):
    """Accountability dashboard aggregated from HISTORY (past audit/pipeline runs) -- not a live audit."""
    rows = read_history(org if org and org != "ALL" else None)
    def ranked(c): return [{"key": k, "count": n} for k, n in c.most_common()]
    wfset = {r["workflowId"] for r in rows}
    err_wfs = {r["workflowId"] for r in rows if r.get("severity") == "error"}
    last = max((r.get("ts", "") for r in rows), default="")
    names = audit.fetch_org_names({org}) if org and org != "ALL" else {}
    return {"client": names.get(org, org) if org and org != "ALL" else "All clients",
        "totals": {"providersFlagged": len(wfset), "providersWithErrors": len(err_wfs),
                   "totalFlags": len(rows), "lastRun": last[:19].replace("T", " ")},
        "byAnalyst": ranked(Counter(r.get("responsible") or "(unassigned)" for r in rows)),
        "bySeverity": ranked(Counter(r.get("severity") for r in rows)),
        "byCategory": ranked(Counter(r.get("category") or "(none)" for r in rows)),
        "byElement": ranked(Counter(r.get("element") or "(none)" for r in rows)),
        "byRule": ranked(Counter(r.get("rule") for r in rows))}

_RECORDS_CACHE = {}
@app.get("/api/records")
def records(org: str, limit: int = 3000):
    """All auditable PSV-complete files for a client (browse + filter). Cached."""
    if org not in _RECORDS_CACHE:
        wfs = audit.resolve_workflows(org, None, limit=limit)
        _RECORDS_CACHE[org] = [{"workflowId": w["workflowId"], "provider": f'{w["first"]} {w["last"]}',
            "npi": w["npi"], "type": w["type"], "fileType": w.get("fileType"), "cycle": w.get("cycle"),
            "states": w.get("states"), "responsible": w.get("responsible")} for w in wfs]
    return _RECORDS_CACHE[org]

_ANALYSTS_CACHE = {}
@app.get("/api/analysts")
def analysts(org: str, limit: int = 1000):
    """Distinct responsible analysts (last PSV-complete owner) for the client, with file counts. Cached."""
    if org in _ANALYSTS_CACHE: return _ANALYSTS_CACHE[org]
    wfs = audit.resolve_workflows(org, None, limit=limit)
    c = Counter(w.get("responsible") or "(unassigned)" for w in wfs)
    res = [{"name": k, "count": n} for k, n in c.most_common()]
    _ANALYSTS_CACHE[org] = res
    return res

@app.get("/api/clientfacts")
def clientfacts(org: str):
    """Quick facts to show while an audit runs: this client's key rules + NCQA standards."""
    c = find_client(org)
    with _ENGINE_LOCK:
        reconcile.apply_client_overlay(c["overlay"] if c else None)
        rules = reconcile.list_rules()
    active = sum(1 for r in rules if r["enabled"])
    name = c["name"] if c else org
    facts = [f"{active} of {len(rules)} rules active for {name}"]
    if c:
        ov = c["overlay"].get("overrides", {})
        if ov.get("attestation_max_age_days"): facts.append(f"{name}: attestation must be ≤ {ov['attestation_max_age_days']} days old")
        if ov.get("license_verified_within_days"): facts.append(f"{name}: licenses verified within {ov['license_verified_within_days']} days")
        if ov.get("npdb_verified_within_days"): facts.append(f"{name}: NPDB verified within {ov['npdb_verified_within_days']} days")
        if c["overlay"].get("malpractice_coverage_matrix"): facts.append(f"{name}: malpractice limits vary by state (FL 100k/300k, else 1M/3M prescriber)")
    facts += [
        "NCQA: license, DEA, board cert, malpractice, sanctions, NPDB & work history are primary-source verified",
        "NCQA: employment gaps > 6 months need a written explanation",
        "NCQA: sanctions screened across OIG, SAM/GSA, OFAC, Medicaid exclusions & CMS preclusion",
        "NCQA: PSV must be completed within 180 days of the credentialing decision",
    ]
    return {"client": name, "facts": facts}

class Ask(BaseModel):
    org: str; question: str
@app.post("/api/ask")
def ask(q: Ask):
    c = find_client(q.org)
    gpath = os.path.join(CLIENTS, f"{(c['name'] if c else '').lower()}.guidelines.txt")
    if not (c and os.path.exists(gpath)):
        return {"answer": "No guidelines on file for this client.", "confidence": 0.0, "escalate": True}
    guidelines = open(gpath, encoding="utf-8").read()[:60000]
    prompt = (f"You are a friendly, conversational credentialing help-bot for the health plan '{c['name']}'. "
        f"You can chat naturally like an assistant. First decide whether the user's message is a QUESTION ABOUT "
        f"CREDENTIALING GUIDELINES, or just conversation/greeting/small-talk/meta.\n"
        f"Return strict JSON: {{\"answer\": string, \"is_question\": boolean, \"confidence\": 0..1, \"citation\": short quote or \"\"}}.\n"
        f"- If it's conversation or a greeting (e.g. 'hi', 'thanks', 'what can you do'), reply warmly and briefly, "
        f"set is_question=false, confidence=1, citation=\"\".\n"
        f"- If it's a guidelines question, answer ONLY from the guidelines below; set is_question=true and set "
        f"confidence to how well the guidelines actually answer it (low if not covered).\n\n"
        f"GUIDELINES:\n{guidelines}\n\nUSER MESSAGE: {q.question}")
    r = GENAI.models.generate_content(model="gemini-2.5-flash", contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.3))
    d = json.loads(r.text)
    d["escalate"] = bool(d.get("is_question") and d.get("confidence", 0) < 0.6)
    if d["escalate"]:
        d["answer"] = (d.get("answer", "") + "\n\n⚠ I'm not fully sure on this — please confirm with your team lead.").strip()
    return d

@app.get("/api/jobs/{jid}/export.csv")
def job_export(jid: str):
    """Export a single request's (job's) findings as CSV."""
    rows = JOB_RESULTS.get(jid, [])
    cols = ["run_ts","client","workflow_id","provider","npi","responsible","severity","category","element","rule","confidence","message"]
    buf = io.StringIO(); w = _csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore"); w.writeheader()
    for r in rows: w.writerow({k: ("" if r.get(k) is None else str(r.get(k))) for k in cols})
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=veridian_{jid}.csv"})

@app.get("/api/history.csv")
def history_csv(org: str = None):
    """Export the full audit history (BQ) as a CSV download."""
    cols = ["run_ts","run_mode","client","org","workflow_id","provider","npi","responsible",
            "severity","category","element","rule","confidence","message"]
    sql = f"SELECT {','.join(cols)} FROM `{HISTORY_TABLE}`"
    if org and org != "ALL": sql += f" WHERE org = '{org}'"
    sql += " ORDER BY run_ts DESC"
    try:
        rows = [dict(r) for r in master_record._client.query(sql).result()]
    except Exception as e:
        rows = []; print("[warn] history.csv:", str(e)[:120])
    buf = io.StringIO(); w = _csv.DictWriter(buf, fieldnames=cols); w.writeheader()
    for r in rows: w.writerow({k: ("" if r.get(k) is None else str(r.get(k))) for k in cols})
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=credcheck_history.csv"})

@app.get("/", response_class=HTMLResponse)
def index():
    return open("static/index.html", encoding="utf-8").read()
