#!/usr/bin/env python3
"""Phase-2 proof: read a PSV packet PDF with Gemini on Vertex (BAA) and extract
structured data, so we can reconcile packet (source) vs backend (record)."""
import json, sys
from google import genai
from google.genai import types

PROJECT, LOCATION, MODEL = "cos-sandbox-provider-data", "us-central1", "gemini-2.5-flash"
client = genai.Client(vertexai=True, project=PROJECT, location=LOCATION)

PROMPT = """You are auditing a credentialing Primary Source Verification (PSV) packet PDF.
Extract ONLY what is actually present in the document, as JSON with this shape:
{
 "provider_name": string,
 "npi": string,
 "date_of_birth": string,
 "state_licenses": [{"state","license_number","status","expiration_date","source","holder_name"}],
 "dea": [{"number","state","expiration_date","registrant_name"}],
 "board_certifications": [{"specialty","expiration_date"}],
 "malpractice": [{"carrier","policy_number","expiration_date","occurrence_amount","aggregate_amount","insured_name"}],
 "npdb_report_present": boolean,
 "npdb": {"present": boolean, "subject_name": string, "npi": string, "date_of_birth": string, "report_count": number},
 "sanctions_screened": [ "OIG","SAM", ... ],
 "documents_present": [ {"label": string, "category": string} ]
}
Notes:
- holder_name / registrant_name / subject_name are the person the license / DEA certificate / NPDB
  report is issued to, exactly as printed on that document (so a mismatch vs the applicant can be caught).
- malpractice.insured_name is the NAMED INSURED on the certificate of insurance / COI (the person or
  the group/entity the policy covers), exactly as printed.
- npdb.report_count is the number of NPDB reports/disclosures on the report (0 if the report is clear).
- documents_present: enumerate EVERY distinct supporting document actually INCLUDED in this packet.
  Use the PDF's BOOKMARKS / outline (the table-of-contents entries usually name each document) AND
  the section divider / cover pages between documents to find them. A document counts only if an
  actual copy is present in the packet — not if it is merely mentioned or listed.
  * label: the document's name as shown in the bookmark / divider (verbatim).
  * category: map it to ONE of exactly these buckets (or "Other"):
    "State License", "DEA / CDS", "Board Certification", "Malpractice / COI", "Diploma / Education",
    "NPDB Report", "Sanctions Screening", "CV / Resume", "W-9 / Tax", "Attestation / Release", "Other".
Dates as YYYY-MM-DD when possible. Do not invent values."""

def extract(pdf_path):
    pdf = open(pdf_path, "rb").read()
    resp = client.models.generate_content(
        model=MODEL,
        contents=[types.Part.from_bytes(data=pdf, mime_type="application/pdf"), PROMPT],
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    return json.loads(resp.text)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "packets/00KDWT22z2wkm2x7PnPl.pdf"
    print(f"Extracting {path} via {MODEL} ...", file=sys.stderr)
    data = extract(path)
    print(json.dumps(data, indent=2))
