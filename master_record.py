#!/usr/bin/env python3
"""Assemble backend 'master record' per workflow from BQ, CDC-deduped.
Backend = the record; packet = the source. This is the 'what we claim' side.
"""
import json, sys
from google.cloud import bigquery

PROJECT = "certifyos-production-platform"
DATASET = "certifyos-production-platform.appdb_data"
_client = bigquery.Client(project=PROJECT)

# element name -> table suffix. Demographics come from the workflow row itself.
ELEMENTS = {
    "specialties":        "edit_providers_specialties",
    "professionalIds":    "edit_providers_professional_ids",
    "stateLicenses":      "edit_providers_state_licenses",
    "dea":                "edit_providers_dea_data",
    "boardCertifications":"edit_providers_board_certifications",
    "licensureActions":   "edit_providers_licensure_actions",
    "sanctions":          "edit_providers_sanctions",
    "malpractice":        "edit_providers_malpractice_insurances",
    "educationTraining":  "edit_providers_education_trainings",
    "hospitalAffiliation":"edit_providers_hospital_affiliation",
    "supportingDocuments":"edit_providers_supporting_documents",
    "npdb":               "edit_providers_npdb_data",
    "workHistory":        "edit_providers_application_verifications_work_history",
    "appVerifications":   "edit_providers_application_verifications",
}

def bq_json(sql):
    return [dict(r) for r in _client.query(sql).result()]

def resolve_edit_provider_ids(provider_ids, status):
    """Map each provider to THE credentialing snapshot (edit_provider_id) whose
    credentialingStatus matches the workflow's current step. Prefer status match,
    else most recent. This scopes elements to the same view the UI shows -- NOT all
    historical/monitoring snapshots (the source of the earlier false flags)."""
    ids = ",".join("'%s'" % x for x in provider_ids)
    sql = f"""
    WITH ep AS (
      SELECT providerId, edit_provider_id,
             MAX(IF(credentialingStatus = @s, 1, 0)) is_match, MAX(timestamp) ts
      FROM `{DATASET}.edit_providers`
      WHERE providerId IN ({ids}) AND operation != 'delete' AND edit_provider_id IS NOT NULL
      GROUP BY providerId, edit_provider_id )
    SELECT providerId, edit_provider_id FROM (
      SELECT *, ROW_NUMBER() OVER (PARTITION BY providerId ORDER BY is_match DESC, ts DESC) rn FROM ep
    ) WHERE rn = 1"""
    job = _client.query(sql, job_config=bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("s", "STRING", status)]))
    return {r["providerId"]: r["edit_provider_id"] for r in job.result()}

def fetch_timeline(edit_provider_ids):
    """Workflow-level dates (attestation, decision, recred) from the parent edit_providers."""
    ids = ",".join("'%s'" % x for x in edit_provider_ids)
    P = "credentialingWorkflowTimeline_"
    F = {"attestationDate": P+"attestationDate", "decisionDate": P+"credentialingDecisionDate",
         "psvCompleteDate": P+"psvCompleteDate", "nextCredentialingDate": P+"nextCredentialingDate",
         "receivedForCredentialingDate": P+"receivedForCredentialingDate",
         "lastCredentialedDate": P+"lastCredentialedDate", "credentialingCycle": "credentialingCycle",
         "dateOfBirth": "dateOfBirth", "gender": "gender", "caqhProviderId": "caqhProviderId"}
    sel = ", ".join(f"MAX({v}) {k}" for k, v in F.items())
    sql = f"SELECT edit_provider_id, {sel} FROM `{DATASET}.edit_providers` WHERE edit_provider_id IN ({ids}) GROUP BY edit_provider_id"
    return {r["edit_provider_id"]: {k: str(r[k]) if r[k] else None for k in F} for r in bq_json(sql)}

def fetch_element(table, edit_provider_ids):
    """Fetch element rows scoped to the given credentialing snapshots, CDC-deduped."""
    ids = ",".join("'%s'" % x for x in edit_provider_ids)
    sql = (
        f"SELECT * EXCEPT(rn) FROM ("
        f"  SELECT *, ROW_NUMBER() OVER (PARTITION BY document_id ORDER BY timestamp DESC) rn"
        f"  FROM `{DATASET}.{table}`"
        f"  WHERE edit_provider_id IN ({ids}) AND operation != 'delete'"
        f") WHERE rn = 1"
    )
    return bq_json(sql)

def build_master(wfs, quiet=True, status="PSV complete by CertifyOS"):
    """Given workflow rows, assemble deduped backend master records scoped to each
    workflow's credentialing snapshot (edit_provider_id). Returns a list."""
    pid_to_wf = {w["providerId"]: w for w in wfs}
    provider_ids = list(pid_to_wf)

    # scope: resolve the correct credentialing snapshot per provider
    pid_to_epid = resolve_edit_provider_ids(provider_ids, status)
    epid_to_wf = {pid_to_epid[pid]: wf for pid, wf in pid_to_wf.items() if pid in pid_to_epid}
    epids = list(epid_to_wf)
    if not quiet:
        print(f"[scope] matched {len(epids)}/{len(provider_ids)} credentialing snapshots", file=sys.stderr)

    master = {}
    for w in wfs:
        master[w["workflowId"]] = {
            "workflowId": w["workflowId"], "providerId": w["providerId"],
            "org": w["org"], "psvFile": w.get("psvFile"),
            "editProviderId": pid_to_epid.get(w["providerId"]),
            "demographics": {"npi": w["npi"], "firstName": w["first"],
                             "lastName": w["last"], "providerType": w["type"],
                             "states": w.get("states"), "assignedStates": w.get("assignedStates"),
                             "fileType": w.get("fileType")},
            **{k: [] for k in ELEMENTS},
        }

    if not epids:
        return json.loads(json.dumps(list(master.values()), default=str))

    timeline = fetch_timeline(epids)
    for epid, wf in epid_to_wf.items():
        tl = timeline.get(epid, {})
        master[wf["workflowId"]]["timeline"] = tl
        demo = master[wf["workflowId"]]["demographics"]
        demo["credentialingCycle"] = tl.get("credentialingCycle") or wf.get("cycle")
        demo["dateOfBirth"] = tl.get("dateOfBirth")
        demo["gender"] = tl.get("gender")
        demo["caqhId"] = tl.get("caqhProviderId")
        demo["attestationDate"] = tl.get("attestationDate")

    for elem, table in ELEMENTS.items():
        try:
            rows = fetch_element(table, epids)
        except Exception as e:
            print(f"[WARN] {elem} ({table}): {e}", file=sys.stderr)
            continue
        for r in rows:
            wf = epid_to_wf.get(r.get("edit_provider_id"))
            if wf:
                master[wf["workflowId"]][elem].append(r)
        if not quiet:
            print(f"[ok] {elem:22s} rows={len(rows)}", file=sys.stderr)
    return json.loads(json.dumps(list(master.values()), default=str))

def main():
    wfs = json.load(open("workflows_10.json"))
    master = build_master(wfs, quiet=False)
    json.dump(master, open("master_records.json", "w"), indent=2)
    for m in master:
        print(m["workflowId"], m["demographics"]["lastName"], {k: len(m[k]) for k in ELEMENTS})

if __name__ == "__main__":
    main()
