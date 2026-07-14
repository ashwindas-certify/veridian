#!/usr/bin/env python3
"""Refresh a client's rule overlay from its guidelines Google Doc, using Gemini.
Reads the doc (service account) -> Gemini maps guidelines to the known parameter
vocabulary -> writes clients/<client>.generated.json for HUMAN REVIEW (never
auto-overwrites the live overlay). Execution stays deterministic: Gemini only
picks from documented params; it does not invent evaluation logic.

Usage:
  python refresh_rules.py --client headway --doc <google-doc-url-or-id> [--orgids id1,id2]
"""
import argparse, json, re, sys, os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google import genai
from google.genai import types

SA_KEY = r"C:\Users\Ashwin Das\Downloads\create-494211-147f2005e4ac.json"
PROJECT, LOCATION, MODEL = "cos-sandbox-provider-data", "us-central1", "gemini-2.5-pro"

# The vocabulary Gemini is allowed to emit -- keeps generated rules deterministic.
VOCAB = {
  "overrides (numeric day windows / months)": [
    "attestation_max_age_days", "recred_cycle_months",
    "license_verified_within_days", "dea_verified_within_days", "board_verified_within_days",
    "sanctions_verified_within_days", "npdb_verified_within_days", "workhistory_verified_within_days",
    "license_expiring_soon_days", "coi_expiring_soon_days"],
  "malpractice_coverage_matrix": "object: {STATE:{'all':[occ,agg]} , 'default':{'prescriber':[occ,agg],'nonprescriber':[occ,agg]}}",
  "workhistory_gap_days_by_state": "object: {STATE:int, 'default':int}",
  "cds_required_states": "array of 2-letter states",
  "active_license_statuses": "array of acceptable license status strings",
  "prescriber_types_client": "array of provider types treated as prescribers (e.g. MD,DO,NP)",
  "requiredElements": ("object: {'*':[elements], 'prescriber':[elements], "
    "'recredExclude':[elements not re-verified at recred], 'recredWorkHistoryStates':[states where work history IS required at recred]}. "
    "elements: stateLicenses, dea, boardCertifications, malpractice, specialties, workHistory, educationTraining, npdb, sanctions, licensureActions"),
}

def doc_id(s):
    m = re.search(r"/document/d/([A-Za-z0-9_-]+)", s)
    return m.group(1) if m else s

def read_doc(did):
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY, scopes=["https://www.googleapis.com/auth/drive.readonly"])
    return build("drive", "v3", credentials=creds).files().export(
        fileId=did, mimeType="text/plain").execute().decode("utf-8")

PROMPT = """You convert a health-plan's credentialing guidelines into a STRUCTURED rule overlay
for an automated NCQA audit engine. Output STRICT JSON only.

You may ONLY use these parameter keys (do not invent new evaluation logic):
{vocab}

Output shape:
{{
  "clientName": string,
  "overrides": {{ ...only keys from the vocab... }},
  "requiredElements": {{ ... }},
  "packetChecks": [ {{"area": string, "rule": string}} ]   // guidelines that require READING the packet PDF
                                                            // (COI type/name match, board specialty, residency, license copy) -- describe them, don't parameterize
}}
Rules:
- Map numeric windows (e.g. "verified within 90 days", "attested within 120 days") to the matching *_days key.
- Build malpractice_coverage_matrix from any state/provider-type coverage limits.
- Put anything that needs the PDF (document content, name matching, specialty=Psychiatry) into packetChecks, NOT overrides.
- Omit keys the guidelines don't mention. Do not guess values.

GUIDELINES:
{guidelines}
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", required=True)
    ap.add_argument("--doc", required=True, help="Google Doc URL or id")
    ap.add_argument("--orgids", help="comma-separated org ids (carried into overlay)")
    args = ap.parse_args()

    print(f"Reading guidelines doc ...", file=sys.stderr)
    text = read_doc(doc_id(args.doc))
    allowed = set(sum([v for v in VOCAB.values() if isinstance(v, list)], [])) | {
        "malpractice_coverage_matrix","workhistory_gap_days_by_state","cds_required_states",
        "active_license_statuses","prescriber_types_client"}

    print(f"Asking {MODEL} to map guidelines -> overlay ...", file=sys.stderr)
    client = genai.Client(vertexai=True, project=PROJECT, location=LOCATION)
    resp = client.models.generate_content(
        model=MODEL,
        contents=PROMPT.format(vocab=json.dumps(VOCAB, indent=1), guidelines=text[:60000]),
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0))
    overlay = json.loads(resp.text)
    overlay["clientName"] = overlay.get("clientName") or args.client.title()
    if args.orgids: overlay["orgIds"] = args.orgids.split(",")
    overlay["_source"] = f"auto-generated from doc {doc_id(args.doc)} via {MODEL}"

    # validate: warn on any override key outside the vocabulary
    unknown = [k for k in overlay.get("overrides", {}) if k not in allowed]
    if unknown:
        print(f"[warn] Gemini emitted unknown override keys (ignored on load): {unknown}", file=sys.stderr)

    out = os.path.join("clients", f"{args.client}.generated.json")
    json.dump(overlay, open(out, "w", encoding="utf-8"), indent=2)
    print(f"\nWrote {out} for REVIEW. Diff it against clients/{args.client}.json, then rename to activate.")
    print(f"overrides: {list(overlay.get('overrides',{}).keys())}")
    print(f"packetChecks: {len(overlay.get('packetChecks',[]))} content rules flagged for the vision layer")

if __name__ == "__main__":
    main()
