# Veridian — Credentialing PSV Audit

Confidence in every credential. Veridian audits provider credentialing files against a
client's NCQA + custom rule set, reconciles the **platform record** (BigQuery) against the
**primary-source application/packet** (read with Gemini on Vertex AI), and surfaces
findings with confidence scores, accountability, and an editable per-client rule engine.

## What it does
- **Resolve** a client's PSV-complete workflows from `credentialing_workflows` (BigQuery).
- **Assemble** a per-provider *master record* across the `edit_providers_*` element tables,
  correctly scoped to the credentialing snapshot (`edit_provider_id` matching the workflow's
  current step — this scoping is critical; pulling by `provider_id` mixes lifecycle snapshots).
- **Run rules** (rules-as-data): validity, data-entry/consistency, completeness, adverse-action
  (sanctions/NPDB/licensure), work-history gaps, attestation & time limits, Clean-vs-Non-Clean
  file type, provider demographics, and client-specific workflow-guideline params.
- **Deep audit (optional)** reads the packet PDF with Gemini and reconciles packet-vs-backend,
  CAQH self-reported-vs-verified, education/residency, and surfaces CertifyOS's own rulesEngineResults.
- **Every flag** carries *Found* (actual) + *Guideline* (what's required) + a confidence score.
- **History** of every run persists to a BigQuery table for the accountability dashboard.

## Architecture
```
Browser (static/index.html — SPA)
        │  REST
FastAPI (app.py)
   ├─ audit.py            resolve workflows (BQ) + org/analyst/records helpers
   ├─ master_record.py    build scoped master record from edit_providers_* (BQ)
   ├─ reconcile.py        rules-as-data engine (rules_catalog.json + generated + per-client)
   ├─ packet_audit.py     packet-vs-backend  (Gemini/Vertex)
   ├─ caqh_audit.py       CAQH vs verified   (Gemini/Vertex)
   ├─ education_audit.py  E&T / residency    (Gemini/Vertex)
   ├─ rules_engine_results.py  surface CertifyOS's own checks (CertifyOS API)
   └─ refresh_rules.py    guidelines Google Doc → rule overlay (Gemini)
Data: BigQuery (appdb_data.* read; psv_audit.audit_history write) · Gemini on Vertex (Vertex BAA)
```

## Setup
1. `pip install -r requirements.txt`
2. **Auth:** `gcloud auth application-default login` (BigQuery + Vertex). Gemini uses project
   `cos-sandbox-provider-data`, region `us-central1`.
3. **CertifyOS API token** (for deep audit / rules-engine): put a bearer token in `.token`.
4. **Guidelines doc access:** the client's Google Doc must be shared with the service account in
   `refresh_rules.py`; its JSON key path is set there.

## Run
```bash
python -m uvicorn app:app --port 8000     # then open http://127.0.0.1:8000
```

## UI
- **Run Audit** — records browser: filter by file type / cycle / state / provider type / analyst;
  batch-select or per-row Run; Deep (AI) toggle; results with per-provider **element checklist**.
- **Dashboard** — accountability history (from BigQuery): top errors by analyst / severity / category / rule; Run Pipeline (batch).
- **Settings** — per-client rule config (search + filters, enable/disable, add rule via screener or
  plain-English AI, delete custom rules) and the **guidelines link + AI sync**.
- **Help-Bot** — conversational Q&A over the client's guidelines with a confidence gate.

## Key API endpoints
`GET /api/clients` · `GET /api/records?org` · `POST /api/audit-async` + `GET /api/job-result/{id}` ·
`POST /api/pipeline` + `GET /api/jobs` · `GET /api/dashboard?org` · `GET /api/history.csv?org` ·
`GET /api/rules?org` · `POST /api/rules/toggle|delete` · `POST /api/add-rule` ·
`POST /api/refresh-guidelines` · `POST /api/ask` (help-bot).

## Rules system
- Base catalog: `rules_catalog.json` (hand-authored NCQA baseline).
- `generated_missing_rules.json`: auto-built per-field "missing" checks from real BQ columns
  (`python generate_missing_rules.py`).
- Per-client overlay: `clients/<client>.json` — param overrides, required elements, coverage matrix,
  disabled rules, custom rules, and `guidelinesUrl`. Auto-generatable from the guidelines doc.

## Security / HIPAA
PHI stays in GCP: BigQuery reads and Gemini (Vertex AI) inference are under the Google Cloud BAA.
Secrets (`.token`, service-account keys) and all PHI artifacts (packets, exports, history mirror)
are gitignored. See `.gitignore`.

## Deploy
Recommended: **Google Cloud Run** in the GCP project (keeps data in-boundary). Containerize with a
minimal Python image, mount ADC via the Cloud Run service account (granted BigQuery + Vertex +
the guidelines-doc access), and set the CertifyOS token as a secret. See `docs/FLOW.md`.
