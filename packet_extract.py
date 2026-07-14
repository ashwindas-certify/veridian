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
 "state_licenses": [{"state","license_number","status","expiration_date","source"}],
 "dea": [{"number","state","expiration_date"}],
 "board_certifications": [{"specialty","expiration_date"}],
 "malpractice": [{"carrier","policy_number","expiration_date","occurrence_amount","aggregate_amount"}],
 "npdb_report_present": boolean,
 "sanctions_screened": [ "OIG","SAM", ... ],
 "documents_present": [ short labels of each distinct document/section you see ]
}
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
