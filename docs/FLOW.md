# Veridian — data flow & deploy

## Audit flow (single or batch)
1. **Select client** → `/api/clients` (orgs with PSV-complete files + names from `organizations`).
2. **Browse records** → `/api/records?org` (PSV-complete workflows; filter by file type, cycle,
   state, provider type, analyst). Pick files (checkboxes) or one row.
3. **Run** → `/api/audit-async` starts a background job (max 3 concurrent); UI polls `/api/jobs`
   then fetches `/api/job-result/{id}`.
   - `resolve_workflows` (BQ credentialing_workflows, CDC-deduped) →
   - `build_master` scopes each element to the workflow's `edit_provider_id` snapshot →
   - `reconcile.evaluate` runs the client's active rule set → flags (Found + Guideline + confidence).
   - If **Deep (AI)**: download packet (psvFileSignedUrl) → `packet_audit` + `caqh_audit` +
     `education_audit` (Gemini/Vertex) + `rules_engine_results` (CertifyOS API).
4. **Results** → per-provider summary + click a provider for the **element checklist**
   (green PASS / red-amber per element, platform vs application).
5. **History** → every run's flags are written to BigQuery `psv_audit.audit_history` (+ local mirror)
   → **Dashboard** aggregates by analyst / severity / category / rule.

## Rule authoring flow
- Edit the client's guidelines Google Doc → **Settings → Sync rules from guidelines** →
  `/api/refresh-guidelines` reads the doc (service account) → Gemini maps it to the parameter
  vocabulary → overlay regenerated (custom rules & toggles preserved).
- Or **Add rule**: screener (element/field/condition/value → deterministic) or plain-English (Gemini).

## Deploy (Google Cloud Run)
1. Add a `Dockerfile`:
   ```dockerfile
   FROM python:3.12-slim
   WORKDIR /app
   COPY requirements.txt . && RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080"]
   ```
2. `gcloud run deploy veridian --source . --region us-central1 --project <gcp-project>`
3. **Service account** for the Cloud Run service must have: `roles/bigquery.dataViewer` +
   `bigquery.jobUser` (read appdb_data, write psv_audit), `roles/aiplatform.user` (Gemini/Vertex),
   and read access to the guidelines Google Docs (share docs with it).
4. Store the CertifyOS bearer token as a **Secret Manager** secret, mount as env; read it in
   `download_packet` / `rules_engine_results` instead of `.token`.
5. Restrict access (IAP or internal-only) — this serves PHI.

## Files
`app.py` (API+SPA server) · `static/index.html` (UI) · `reconcile.py` (rule engine) ·
`master_record.py` (BQ master record) · `audit.py` (resolve/CLI) · `rules_catalog.json` +
`generated_missing_rules.json` + `clients/*.json` (rules) · `packet_audit.py` / `caqh_audit.py` /
`education_audit.py` / `rules_engine_results.py` (deep checks) · `refresh_rules.py` +
`generate_missing_rules.py` (authoring tools).
