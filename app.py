#!/usr/bin/env python3
"""PSV Audit web app: client selector, audit runner, per-client rule config, help-bot.
Run:  cd ~/Downloads/psv_audit && python -m uvicorn app:app --port 8000
"""
import os, json, glob, urllib.request, urllib.error, re, threading, uuid, time
from collections import Counter
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

JOBS = {}  # in-memory job queue: jobId -> {type,client,org,status,processed,total,flags,note,startedAt,finishedAt}
DEEP_CONCURRENCY = int(os.environ.get("DEEP_CONCURRENCY", "6"))  # files read in parallel per run

HISTORY = "audit_history.jsonl"                 # local mirror (instant reads)
HISTORY_TABLE = "certifyos-production-platform.psv_audit.audit_history"   # durable BQ log

def record_history(org, client, summary, flags, run_mode="audit"):
    """Persist this run's flags to the BQ history table (durable) + local JSONL mirror (instant)."""
    ts = datetime.now(timezone.utc).isoformat()
    resp = {s["workflowId"]: s.get("responsible") for s in summary}
    rows = [{"run_ts": ts, "run_mode": run_mode, "org": org, "client": client,
             "workflow_id": f.get("workflowId"), "provider": f.get("provider"), "npi": f.get("npi"),
             "state": f.get("state"), "provider_type": f.get("providerType"),
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

EXTRACT_TABLE = "certifyos-production-platform.psv_audit.application_extractions"  # AI reads of the packet
EXTRACT_MIRROR = "application_extractions.jsonl"                                    # local mirror
_EXTRACT_CACHE = {}  # (workflowId, etype) -> last AI extraction, so insights reuse the audit's read

def _load_extraction_bq(wid, etype):
    """Most recent stored AI extraction for a workflow, so re-runs skip the Gemini read."""
    try:
        job = master_record._client.query(
            f"SELECT data FROM `{EXTRACT_TABLE}` WHERE workflow_id=@w AND extraction_type=@t "
            f"ORDER BY run_ts DESC LIMIT 1",
            job_config=bigquery.QueryJobConfig(query_parameters=[
                bigquery.ScalarQueryParameter("w", "STRING", wid),
                bigquery.ScalarQueryParameter("t", "STRING", etype)]))
        for r in job.result():
            return json.loads(r["data"])
    except Exception as e:
        print("[warn] extraction load failed:", str(e)[:100])
    return None

def get_extraction(wid, etype):
    """In-memory cache -> BQ -> None. Packet PDFs are stable for PSV-complete files, so reusing a
    prior read is safe and makes re-runs near-instant (backend/BQ data is always re-fetched fresh)."""
    if (wid, etype) in _EXTRACT_CACHE:
        return _EXTRACT_CACHE[(wid, etype)]
    d = _load_extraction_bq(wid, etype)
    if d is not None:
        _EXTRACT_CACHE[(wid, etype)] = d
    return d

def record_extraction(org, client, wid, npi, etype, data):
    """Persist everything the AI read from the application PDF (CAQH, education, packet) to BQ."""
    _EXTRACT_CACHE[(wid, etype)] = data  # reuse for on-demand insights (no re-read)
    ts = datetime.now(timezone.utc).isoformat()
    row = {"run_ts": ts, "org": org, "client": client, "workflow_id": wid, "npi": npi,
           "extraction_type": etype, "data": json.dumps(data, default=str)}
    try:
        master_record._client.insert_rows_json(EXTRACT_TABLE, [row])  # streaming insert
    except Exception as e:
        print("[warn] BQ extraction insert failed:", str(e)[:150])
    try:
        with open(EXTRACT_MIRROR, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception:
        pass
    return row

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
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from pydantic import BaseModel
from google import genai
from google.genai import types
from google.cloud import bigquery

import reconcile, master_record, audit, packet_audit, caqh_audit, rules_engine_results, education_audit, packet_extract, combined_extract, ncqa_checks

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

CONFIG_TABLE = "certifyos-production-platform.psv_audit.client_config"  # durable client-config snapshots
_CFG_CACHE = {}  # org -> overlay dict. BQ is the source of truth; this avoids a BQ read per call.

def _bq_load_config(org):
    """Latest persisted config for this org from BQ (survives restarts / redeploys)."""
    try:
        job = master_record._client.query(
            f"SELECT config FROM `{CONFIG_TABLE}` WHERE org=@o ORDER BY updated_ts DESC LIMIT 1",
            job_config=bigquery.QueryJobConfig(
                query_parameters=[bigquery.ScalarQueryParameter("o", "STRING", org)]))
        for r in job.result():
            return json.loads(r["config"])
    except Exception as e:
        print("[warn] BQ config load failed:", str(e)[:120])
    return None

def _persist_overlay(c, org):
    """Persist a client's overlay to BQ (durable, source of truth) + local JSON mirror + cache."""
    o = c["overlay"]
    try:
        json.dump(o, open(c["file"], "w", encoding="utf-8"), indent=2)  # local mirror
    except Exception:
        pass
    ts = datetime.now(timezone.utc).isoformat()
    try:
        master_record._client.insert_rows_json(CONFIG_TABLE, [{
            "updated_ts": ts, "org": org, "client": c.get("name") or o.get("clientName"),
            "config": json.dumps(o, default=str)}])
    except Exception as e:
        print("[warn] BQ config persist failed:", str(e)[:120])
    for oid in (c.get("orgIds") or [org]):
        _CFG_CACHE[oid] = o
    return ts

_CRIT_CRITICAL = ("SANCTION", "ADVERSE", "NPDB_REPORT", "NPDB_MISMATCH", "EXCLUSION", "EXPIR",
                  "MISSING_STATELICENSE", "MISSING_LICENSE", "MISSING_DEA", "MISSING_MALPRACTICE",
                  "MISSING_NPDB", "NPI_MISMATCH", "NAME_MISMATCH", "ASSERTS_LICENSE", "ASSERTS_MALPRACTICE")
_CRIT_HIGH = ("MISMATCH", "GAP_UNEXPLAINED", "ASSERTS", "NOT_COMPLETED", "COVERAGE", "HIERARCHY",
              "MISSING_", "EXPECTED")

def _criticality(f):
    """For error flags only: how critical (critical / high / medium). Warnings/info get None."""
    if f.get("severity") != "error":
        return None
    r = (f.get("rule") or "").upper(); m = (f.get("message") or "").upper()
    if any(k in r or k in m for k in _CRIT_CRITICAL):
        return "critical"
    if any(k in r for k in _CRIT_HIGH):
        return "high"
    return "medium"

def _apply_criticality(flags):
    for f in flags:
        c = _criticality(f)
        if c: f["criticality"] = c
    return flags

# Redundant license status/expiry rules that describe the same "not active/current" problem.
# Keep only the single most-informative one per (workflow, state). Priority: active-but-expired
# (says both) > expired (concrete date) > status-not-active.
_LIC_EXPIRY_PRI = {"STATE_LICENSE_ACTIVE_BUT_EXPIRED": 0, "STATE_LICENSE_NOT_EXPIRED": 1,
                   "STATE_LICENSE_STATUS_ACTIVE": 2}

def _collapse_license_flags(flags):
    groups = {}
    for f in flags:
        if f.get("rule") in _LIC_EXPIRY_PRI:
            groups.setdefault((f.get("workflowId"), (f.get("state") or "").upper()), []).append(f)
    drop = set()
    for fs in groups.values():
        if len(fs) > 1:
            for f in sorted(fs, key=lambda x: _LIC_EXPIRY_PRI[x["rule"]])[1:]:
                drop.add(id(f))
    return [f for f in flags if id(f) not in drop]

_USER_NAME_CACHE = {}
def _resolve_user_names(ids):
    """Map CertifyOS user ids -> 'First Last' (from appdb_data.users), cached."""
    want = {i for i in ids if i}
    miss = [i for i in want if i not in _USER_NAME_CACHE]
    if miss:
        try:
            inlist = ",".join("'%s'" % i.replace("'", "") for i in miss)
            for r in master_record._client.query(
                f"SELECT document_id, first_name, last_name FROM "
                f"`certifyos-production-platform.appdb_data.users` WHERE document_id IN ({inlist})").result():
                nm = " ".join(x for x in (r["first_name"], r["last_name"]) if x).strip()
                _USER_NAME_CACHE[r["document_id"]] = nm or r["document_id"]
        except Exception as e:
            print("[warn] user-name resolve failed:", str(e)[:100])
    return {i: _USER_NAME_CACHE.get(i, i) for i in want}

def _gap_map(org):
    """Client's per-state work-history gap thresholds (days), or None for the NCQA default."""
    c = find_client(org)
    return (c["overlay"].get("workhistory_gap_days_by_state") if c else None)

def find_client(org):
    for c in client_files():
        if org in c["orgIds"]:
            if org in _CFG_CACHE:
                c["overlay"] = _CFG_CACHE[org]           # in-process cache
            else:
                bqcfg = _bq_load_config(org)             # durable BQ snapshot beats the JSON file
                if bqcfg:
                    bqcfg.setdefault("orgIds", c["overlay"].get("orgIds", []))
                    bqcfg.setdefault("clientName", c["overlay"].get("clientName"))
                    c["overlay"] = bqcfg
                _CFG_CACHE[org] = c["overlay"]
            return c
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
    _persist_overlay(c, rq.org)
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
    _persist_overlay(c, t.org)
    return {"ok": True, "disabledRules": o["disabledRules"]}

class SaveConfigReq(BaseModel):
    org: str
@app.post("/api/config/save")
def save_config(rq: SaveConfigReq):
    """Explicit 'Save changes': persist the client's current rule config to BQ (durable snapshot)."""
    c = find_client(rq.org)
    if not c: return {"ok": False, "reason": "This client has no config yet."}
    o = c["overlay"]
    ts = _persist_overlay(c, rq.org)
    return {"ok": True, "savedAt": ts, "disabledRules": len(o.get("disabledRules", [])),
            "customRules": len(o.get("customRules", []))}

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

AUTH_FILE = ".auth.json"      # gitignored: {"email","password"} for auto-login
_TOKEN = {"v": None}          # cached CertifyOS auth token (refreshed on expiry)

def _login():
    """Log in with stored credentials -> fresh auth_token (cookie); cache + mirror to .token."""
    creds = json.load(open(AUTH_FILE, encoding="utf-8"))
    body = json.dumps({"email": creds["email"], "password": creds["password"]}).encode()
    req = urllib.request.Request(f"{NG_API}/auth-tokens", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        cookie = r.headers.get("Set-Cookie") or ""
    m = re.search(r"auth_token=([^;]+)", cookie)
    if not m:
        raise RuntimeError("login succeeded but no auth_token cookie returned")
    _TOKEN["v"] = m.group(1)
    try: open(".token", "w", encoding="utf-8").write(_TOKEN["v"])   # so other modules pick it up
    except Exception: pass
    return _TOKEN["v"]

def get_token(force=False):
    """Current CertifyOS token: cache -> .token -> fresh login. force=True re-logs in."""
    if force:
        return _login()
    if _TOKEN["v"]:
        return _TOKEN["v"]
    try:
        t = open(".token", encoding="utf-8").read().strip()
        if t:
            _TOKEN["v"] = t; return t
    except Exception:
        pass
    return _login()

def authed_open(url, org=None, timeout=60, _retried=False):
    """Open an ng-api URL with the current token; on 401/403, re-login once and retry."""
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + get_token(),
                                               "organization-id": org or ""})
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403) and not _retried:
            get_token(force=True)
            return authed_open(url, org, timeout, _retried=True)
        raise

def download_packet(wid, org, path):
    """Fetch the PSV packet PDF for a workflow via psvFileSignedUrl (see download_packets.py)."""
    with authed_open(f"{NG_API}/credentialing-workflows/{wid}", org, timeout=60) as r:
        wf = json.load(r)
    signed = wf.get("psvFileSignedUrl")
    if not signed:
        raise RuntimeError("no psvFileSignedUrl on workflow")
    with urllib.request.urlopen(signed, timeout=180) as r, open(path, "wb") as f:
        f.write(r.read())

# Ordered verification steps shown as the live progress timeline for each file.
DEEP_STEPS = ["Packet documents (licenses · DEA · board · malpractice · NPDB)",
              "CAQH application (all elements · demographics · attestation)",
              "Education & training",
              "Client rule engine"]

def _init_steps(jid, who):
    if jid and jid in JOBS:
        JOBS[jid]["steps"] = [{"name": n, "status": "pending"} for n in DEEP_STEPS]
        JOBS[jid]["stepFor"] = who

def _set_step(jid, idx, status):
    if jid and jid in JOBS and JOBS[jid].get("steps"):
        JOBS[jid]["steps"][idx]["status"] = status

def deep_packet_audit(wfs, master, jid=None):
    """Per-workflow DEEP checks: packet-vs-backend + CAQH (all elements) + Education & Training +
    CertifyOS's own rulesEngineResults. Reads the PDF via Gemini (downloading if absent) and
    reports a per-step progress timeline on the job. Returns (extra_flags, notes, appl_by_wf)."""
    os.makedirs(PACKETS, exist_ok=True)
    org_by_wf = {w["workflowId"]: w.get("org") for w in wfs}
    flags, notes, appl_by_wf = [], [], {}
    _sevmap = {"high": "error", "medium": "warning", "low": "info"}
    for m in master:
        wid = m["workflowId"]; org = org_by_wf.get(wid)
        path = os.path.join(PACKETS, f"{wid}.pdf")
        _init_steps(jid, (m.get("demographics") or {}).get("lastName") or wid)
        try:
            # reuse prior AI reads if we have them; only read the PDF when something is missing
            pkt = get_extraction(wid, "packet")
            full = get_extraction(wid, "caqh")
            edu = get_extraction(wid, "education")
            if pkt is None or full is None or edu is None:
                if not os.path.exists(path):
                    download_packet(wid, org, path)
                _set_step(jid, 0, "running"); _set_step(jid, 1, "running"); _set_step(jid, 2, "running")
                try:                                    # ONE PDF read for all three sections
                    cpkt, ccaqh, cedu = combined_extract.combined_extract(path)
                except Exception as ex2:
                    notes.append({"workflowId": wid, "error": f"read: {type(ex2).__name__}: {str(ex2)[:150]}"})
                    cpkt, ccaqh, cedu = {}, {}, {}
                if pkt is None and cpkt:
                    pkt = cpkt; record_extraction(org, org, wid, m.get("npi"), "packet", pkt)
                if full is None and ccaqh:
                    full = ccaqh; record_extraction(org, org, wid, m.get("npi"), "caqh", full)
                if edu is None and cedu:
                    edu = cedu; record_extraction(org, org, wid, m.get("npi"), "education", edu)
            for i in (0, 1, 2):
                _set_step(jid, i, "done")
            # fast checks over the (cached or fresh) extractions
            if pkt is not None:
                for pf in packet_audit.packet_audit(m, path, packet=pkt):
                    pf["severity"] = _sevmap.get(pf.get("severity"), pf.get("severity"))
                    flags.append(pf)
                flags += ncqa_checks.ncqa_checks(m, pkt)   # attestation recency, malpractice hx, sanctions, restrictions
            if full is not None:
                flags += caqh_audit.caqh_audit(m, path, packet=full, gap_days_by_state=_gap_map(org))
                appl_by_wf[wid] = caqh_audit.applicability(full)
                _dem = m.get("demographics") or {}
                _req = reconcile.required_for(_dem.get("providerType"), _dem.get("credentialingCycle"),
                                              reconcile.parse_states(_dem.get("assignedStates") or _dem.get("states")))
                flags += caqh_audit.assertion_flags(m, full, required=_req)
                flags += caqh_audit.demographic_flags(m, full)
            if edu is not None:
                flags += education_audit.education_audit(m, path, packet=edu)
        except Exception as e:
            notes.append({"workflowId": wid, "error": f"packet: {type(e).__name__}: {str(e)[:200]}"})
        # 4) CertifyOS's own rules engine (API, no packet)
        _set_step(jid, 3, "running")
        try:
            flags += rules_engine_results.rules_engine_flags(wid, org)
        except Exception as e:
            notes.append({"workflowId": wid, "error": f"rules-engine: {type(e).__name__}: {str(e)[:150]}"})
        _set_step(jid, 3, "done")
    return flags, notes, appl_by_wf

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
        _persist_overlay(c, rq.org)
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
    _persist_overlay(c, rq.org)
    return {"ok": True, "rule": spec}

class BulkToggle(BaseModel):
    org: str; ruleIds: list = []; enabled: bool = True
@app.post("/api/rules/toggle-bulk")
def toggle_bulk(t: BulkToggle):
    """Enable/disable many rules at once (per-section 'toggle all')."""
    c = find_client(t.org)
    if not c: return {"ok": False, "reason": "no client config"}
    o = c["overlay"]; dis = set(o.get("disabledRules", []))
    for rid in t.ruleIds:
        dis.discard(rid) if t.enabled else dis.add(rid)
    o["disabledRules"] = sorted(dis)
    _persist_overlay(c, t.org)
    return {"ok": True, "count": len(t.ruleIds)}

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
    _persist_overlay(c, rq.org)
    return {"ok": True, "removed": before - len(o["customRules"])}

class AuditReq(BaseModel):
    org: str; npis: str = ""; assignedTo: str = ""; limit: int = 200; deepPacket: bool = False
    scope: str = "full"   # "full" or "education" (E&T-only fast run)
JOB_FULL = {}  # jobId -> full audit result (summary+flags) for async retrieval

def _education_only_run(org, npis, assignedTo, limit, jid=None):
    """Fast, scoped run: Education & Training only (one targeted read per file, no packet/CAQH/rules)."""
    wfs = audit.resolve_workflows(org, npis or None, limit=limit)
    if assignedTo:
        k = assignedTo.lower(); wfs = [w for w in wfs if k in (w["responsible"] or "").lower()]
    client = audit.fetch_org_names({org}).get(org, org)
    if jid: JOBS[jid]["client"] = client; JOBS[jid]["total"] = len(wfs)
    if not wfs: return {"client": client, "summary": [], "flags": [], "note": "no matching PSV-complete workflows"}
    master = master_record.build_master(wfs)
    wf_by_id = {w["workflowId"]: w for w in wfs}
    os.makedirs(PACKETS, exist_ok=True)
    flags = []; prog_lock = threading.Lock(); done = [0]
    def run_one(m):
        t0 = time.perf_counter(); wid = m["workflowId"]; org2 = wf_by_id[wid].get("org") or org
        f, note = [], None
        try:
            edu = get_extraction(wid, "education")
            if edu is None:
                path = os.path.join(PACKETS, f"{wid}.pdf")
                if not os.path.exists(path): download_packet(wid, org2, path)
                edu = education_audit.extract_education(path)
                record_extraction(org2, org2, wid, m.get("npi"), "education", edu)
            f = education_audit.education_audit(m, None, packet=edu)
        except Exception as e:
            note = {"workflowId": wid, "error": f"education: {type(e).__name__}: {str(e)[:150]}"}
        return m, f, note, round(time.perf_counter() - t0, 1)
    notes = []
    with ThreadPoolExecutor(max_workers=DEEP_CONCURRENCY) as ex:
        for fut in as_completed([ex.submit(run_one, m) for m in master]):
            m, f, note, sec = fut.result(); flags += f
            if note: notes.append(note)
            dem = m.get("demographics") or {}
            with prog_lock:
                done[0] += 1
                if jid:
                    JOBS[jid]["processed"] = done[0]
                    JOBS[jid].setdefault("timings", []).append({
                        "provider": f'{dem.get("firstName", "")} {dem.get("lastName", "")}'.strip() or m["workflowId"],
                        "wid": m["workflowId"], "sec": sec,
                        "errors": sum(1 for x in f if x.get("severity") == "error")})
    _apply_criticality(flags)
    by = {}
    for x in flags: by.setdefault(x["workflowId"], []).append(x)
    summary = []
    for w in wfs:
        fl = by.get(w["workflowId"], []); errs = sum(1 for x in fl if x["severity"] == "error")
        summary.append({"provider": f'{w["first"]} {w["last"]}', "npi": w["npi"], "type": w["type"],
            "states": w.get("states"), "responsible": w.get("responsible"), "auditConfidence": None,
            "errors": errs, "flags": len(fl),
            "status": "REVIEW" if errs else ("CHECK" if fl else "CLEAN"), "workflowId": w["workflowId"]})
    rows = record_history(org, client, summary, flags, run_mode="education")
    return {"client": client, "summary": summary, "flags": flags, "packetNotes": notes,
            "master": master if len(master) <= 30 else None, "_rows": rows}

def do_audit(org, npis, assignedTo, limit, deep, jid=None, scope="full"):
    """Shared audit: resolve -> master -> rules (+deep) -> summary + flags + history rows."""
    if scope == "education":
        return _education_only_run(org, npis, assignedTo, limit, jid)
    deep = True  # AI extraction (documents + applications) is always on
    wfs, master, flags, conf = core_audit(org, npis or None, assignedTo, limit)
    client = audit.fetch_org_names({org}).get(org, org)
    if jid: JOBS[jid]["client"] = client; JOBS[jid]["total"] = len(wfs)
    if not wfs: return {"client": client, "summary": [], "flags": [], "note": "no matching PSV-complete workflows"}
    packet_notes = []
    if deep:
        acc = list(flags); appl_by_wf = {}; prog_lock = threading.Lock(); done = [0]
        wf_by_id = {w["workflowId"]: w for w in wfs}
        def run_one(m):
            t0 = time.perf_counter()
            pf, pn, pa = deep_packet_audit([wf_by_id[m["workflowId"]]], [m], None)  # jid=None: no step race
            return m, pf, pn, pa, round(time.perf_counter() - t0, 1)
        with ThreadPoolExecutor(max_workers=DEEP_CONCURRENCY) as ex:   # files read in parallel
            futs = [ex.submit(run_one, m) for m in master]
            for fut in as_completed(futs):
                m, pf, pn, pa, sec = fut.result()
                acc += pf; packet_notes += pn; appl_by_wf.update(pa)
                dem = m.get("demographics") or {}
                with prog_lock:
                    done[0] += 1
                    if jid:
                        JOBS[jid]["processed"] = done[0]
                        JOBS[jid].setdefault("timings", []).append({
                            "provider": f'{dem.get("firstName", "")} {dem.get("lastName", "")}'.strip() or m["workflowId"],
                            "wid": m["workflowId"], "sec": sec,
                            "errors": sum(1 for f in pf if f.get("severity") == "error")})
        # branching applicability: drop absence flags for optional elements the provider doesn't claim
        flags = [g for f in acc
                 for g in caqh_audit.suppress_by_applicability([f], appl_by_wf.get(f.get("workflowId")))]
    elif jid: JOBS[jid]["processed"] = len(wfs)
    flags = _collapse_license_flags(flags)   # drop redundant license status/expiry duplicates
    _apply_criticality(flags)
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
    return {"client": client, "summary": summary, "flags": flags, "packetNotes": packet_notes,
            "master": master if len(master) <= 30 else None, "_rows": rows}

def _audit_worker(jid, a):
    j = JOBS[jid]
    try:
        npis = [n.strip() for n in a.npis.replace("\n", ",").split(",") if n.strip()]
        res = do_audit(a.org, npis, a.assignedTo, a.limit, a.deepPacket, jid, scope=a.scope)
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

@app.get("/api/document-url")
def document_url(org: str, providerId: str, docId: str):
    """Fetch a supporting document's signed URL (ng-api) and redirect to it, so a reviewer can open
    the exact document behind an element's check. Proxied because the API needs an org header."""
    try:
        with authed_open(f"{NG_API}/v2/provider/{providerId}/supporting-documents/{docId}/signed-url",
                         org, timeout=30) as r:
            url = r.read().decode("utf-8", "replace").strip().strip('"')
        if url.startswith("http"):
            return RedirectResponse(url)
        return JSONResponse({"ok": False, "reason": "This document has no uploaded file to open."}, status_code=404)
    except Exception as e:
        return JSONResponse({"ok": False, "reason": f"{type(e).__name__}: {str(e)[:150]}"}, status_code=502)

@app.get("/api/packet-url")
def packet_url(org: str, wid: str):
    """Fetch the (short-lived) signed PSV packet URL for a workflow so a reviewer can open/download
    the actual packet. Fetched on demand because signed URLs expire quickly."""
    try:
        with authed_open(f"{NG_API}/credentialing-workflows/{wid}", org, timeout=60) as r:
            wf = json.load(r)
        url = wf.get("psvFileSignedUrl")
        if not url:
            return {"ok": False, "reason": "No PSV packet URL is available on this workflow."}
        return {"ok": True, "url": url}
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {str(e)[:150]}"}

@app.get("/api/education-insight")
def education_insight(org: str, npi: str):
    """Standalone deep E&T insight for one provider: AI reads the application/AMA profile,
    returns the education it found, backend education, findings, and a conclusion."""
    wfs = audit.resolve_workflows(org, [npi], limit=5)
    if not wfs: return {"ok": False, "reason": "No PSV-complete file for that NPI."}
    w = wfs[0]; wid = w["workflowId"]
    master = master_record.build_master([w]); m = master[0] if master else None
    path = os.path.join(PACKETS, f"{wid}.pdf")
    try:
        edu = get_extraction(wid, "education")   # reuse the audit's read (memory or BQ)
        if edu is None:
            if not os.path.exists(path): download_packet(wid, org, path)
            edu = education_audit.extract_education(path)
        flags = education_audit.education_audit(m, path, packet=edu) if m else []
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {str(e)[:200]}"}
    record_extraction(org, org, wid, npi, "education", edu)  # persist what AI read from the app
    errs = [f for f in flags if f.get("severity") == "error"]
    hierarchy = [f for f in flags if f.get("rule") in ("EDU_SOURCE_SELF_REPORTED", "EDU_SOURCE_HIERARCHY_NOT_FOLLOWED")]
    has_board = bool((m or {}).get("boardCertifications"))
    sources = education_audit._et_sources(m) if m else []
    if errs:
        conclusion = "REVIEW — " + errs[0]["message"]
    elif hierarchy:
        conclusion = "REVIEW — " + hierarchy[0]["message"]
    else:
        conclusion = "PASS — education & training requirements appear met for this provider type."
    return {"ok": True, "provider": f'{w["first"]} {w["last"]}', "npi": npi, "type": w["type"],
            "education": edu.get("education", []), "highestLevel": edu.get("highest_level"),
            "amaProfilePresent": edu.get("ama_profile_present"),
            "backendEducation": (m.get("educationTraining") if m else []),
            "boardCertified": has_board, "verificationSources": sources,
            "expectedSource": ("board certification" if has_board else "licensing agency"),
            "flags": flags, "conclusion": conclusion, "isReview": bool(errs or hierarchy)}

@app.get("/api/caqh-insight")
def caqh_insight(org: str, npi: str):
    """Standalone CAQH insight for one provider: AI reads the CAQH application, returns
    self-reported work history, disclosed gaps, disclosure answers, findings, and a conclusion."""
    wfs = audit.resolve_workflows(org, [npi], limit=5)
    if not wfs: return {"ok": False, "reason": "No PSV-complete file for that NPI."}
    w = wfs[0]; wid = w["workflowId"]
    master = master_record.build_master([w]); m = master[0] if master else None
    path = os.path.join(PACKETS, f"{wid}.pdf")
    try:
        caqh = get_extraction(wid, "caqh")   # reuse the audit's read (memory or BQ)
        if caqh is None:
            if not os.path.exists(path): download_packet(wid, org, path)
            caqh = caqh_audit.extract_caqh_full(path)   # ALL CAQH elements + supporting-doc presence
        flags = caqh_audit.caqh_audit(m, path, packet=caqh, gap_days_by_state=_gap_map(org)) if m else []
        pkt = get_extraction(wid, "packet")   # supporting-document read (reuse audit's read)
        if pkt is None:
            if not os.path.exists(path): download_packet(wid, org, path)
            pkt = packet_extract.extract(path)
            _EXTRACT_CACHE[(wid, "packet")] = pkt
        elementRows, docRows = caqh_audit.compare_caqh_elements(m, caqh, pkt)
        demoRows = caqh_audit.demographic_compare(m, caqh)
        dem = (m or {}).get("demographics") or {}
        required = reconcile.required_for(dem.get("providerType"), dem.get("credentialingCycle"),
                                          reconcile.parse_states(dem.get("assignedStates") or dem.get("states")))
        flags += caqh_audit.assertion_flags(m, caqh, required=required)
        flags += caqh_audit.demographic_flags(m, caqh)
        threeWay = caqh_audit.three_way_compare(m, pkt, caqh)
        matrix = caqh_audit.element_matrix(m, pkt, caqh, required, docRows, flags)
        _names = _resolve_user_names([d.get("verifiedBy") for row in matrix for d in row.get("docsUsed", [])])
        for row in matrix:
            for d in row.get("docsUsed", []):
                if d.get("verifiedBy"): d["verifiedBy"] = _names.get(d["verifiedBy"], d["verifiedBy"])
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {str(e)[:200]}"}
    record_extraction(org, org, wid, npi, "caqh", caqh)  # persist what AI read from the app
    errs = [f for f in flags if f.get("severity") == "error"]
    docReview = [d for d in docRows if d["status"] == "review"]
    missingDocs = [d["name"] for d in docReview]
    elemReview = [r for r in elementRows if r["status"] == "review"]
    demoReview = [r for r in demoRows if r["status"] == "review"]
    isReview = bool(errs or elemReview or docReview or demoReview)
    if errs:
        conclusion = "REVIEW — " + errs[0]["message"]
    elif elemReview or docReview or demoReview:
        bits = []
        if demoReview: bits.append(f"{len(demoReview)} identity/attestation field(s) not aligned")
        if elemReview: bits.append(f"{len(elemReview)} element(s) not aligned between CAQH and platform")
        if docReview: bits.append(f"{len(docReview)} supporting document(s) not reconciled with platform (BQ)")
        conclusion = "REVIEW — " + "; ".join(bits)
    else:
        conclusion = "PASS — CAQH elements reconcile with platform data and supporting docs are present."
    # overall quality score/signal from the element matrix
    applicable = [e for e in matrix if e.get("status") != "na"]
    mx_err = [e for e in matrix if e.get("status") == "error"]
    mx_rev = [e for e in matrix if e.get("status") == "review"]
    passed = [e for e in applicable if e.get("status") == "ok"]
    quality_pct = round(100 * len(passed) / len(applicable)) if applicable else 100
    quality_signal = "red" if mx_err else ("amber" if mx_rev else "green")
    quality = {"pct": quality_pct, "signal": quality_signal,
               "passed": len(passed), "applicable": len(applicable),
               "errors": len(mx_err), "reviews": len(mx_rev),
               "label": ("NEEDS ATTENTION" if mx_err else "REVIEW" if mx_rev else "QUALITY PASSED")}
    return {"ok": True, "provider": f'{w["first"]} {w["last"]}', "npi": npi,
            "workHistory": caqh.get("work_history", []), "gapsDisclosed": caqh.get("gaps_disclosed", []),
            "disclosureAnswers": caqh.get("disclosure_answers", []),
            "backendWorkHistory": (m.get("workHistory") if m else []),
            "demographics": demoRows, "elements": elementRows, "threeWay": threeWay,
            "matrix": matrix, "quality": quality, "supportingDocs": docRows, "missingDocs": missingDocs,
            "flags": flags, "conclusion": conclusion, "isReview": isReview}

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
    deep = True  # AI extraction (documents + applications) is always on
    try:
        client = audit.fetch_org_names({org}).get(org, org); j["client"] = client
        wfs, master, flags, conf = core_audit(org, None, "", limit)
        j["total"] = len(wfs)
        if not wfs:
            j.update(status="done", note="no PSV-complete files", finishedAt=datetime.now(timezone.utc).isoformat()); return
        if deep:
            appl_by_wf = {}; prog_lock = threading.Lock(); done = [0]
            wf_by_id = {w["workflowId"]: w for w in wfs}
            def run_one(m):
                t0 = time.perf_counter()
                pf, _, pa = deep_packet_audit([wf_by_id[m["workflowId"]]], [m], None)
                return m, pf, pa, round(time.perf_counter() - t0, 1)
            with ThreadPoolExecutor(max_workers=DEEP_CONCURRENCY) as ex:
                futs = [ex.submit(run_one, m) for m in master]
                for fut in as_completed(futs):
                    m, pf, pa, sec = fut.result()
                    flags += pf; appl_by_wf.update(pa)
                    dem = m.get("demographics") or {}
                    with prog_lock:
                        done[0] += 1; j["processed"] = done[0]
                        j.setdefault("timings", []).append({
                            "provider": f'{dem.get("firstName", "")} {dem.get("lastName", "")}'.strip() or m["workflowId"],
                            "wid": m["workflowId"], "sec": sec,
                            "errors": sum(1 for f in pf if f.get("severity") == "error")})
            flags = [g for f in flags
                     for g in caqh_audit.suppress_by_applicability([f], appl_by_wf.get(f.get("workflowId")))]
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
    cols = ["run_ts","client","provider","npi","provider_type","state","responsible","severity","category","element","rule","confidence","message","platform_link","workflow_id"]
    buf = io.StringIO(); buf.write("﻿")  # BOM for clean Excel open
    w = _csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore"); w.writeheader()
    for r in rows:
        wid = r.get("workflow_id"); o = r.get("org") or ""
        r = {**r, "platform_link": (f"https://ng.certifyos.com/credentialing/{wid}?organizationId={o}" if wid else "")}
        w.writerow({k: ("" if r.get(k) is None else str(r.get(k))) for k in cols})
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=veridian_{jid}.csv"})

@app.get("/api/history.csv")
def history_csv(org: str = None):
    """Export the full audit history (BQ) as a CSV download."""
    cols = ["run_ts","run_mode","client","org","workflow_id","provider","npi","provider_type","state","responsible",
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
