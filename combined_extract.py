#!/usr/bin/env python3
"""Single-read extractor: read the PSV packet PDF ONCE with Gemini and return all three
sections (packet documents, full CAQH application, education & training) in one inference.

This replaces three separate Gemini reads (packet_extract + caqh_audit.extract_caqh_full +
education_audit.extract_education) with one PDF upload + one inference — the dominant cost —
so a run over thousands of files is ~3x cheaper/faster. The per-section JSON shapes are reused
verbatim from the individual modules, so all downstream code works unchanged.
"""
import json

from google import genai
from google.genai import types

import packet_extract, caqh_audit, education_audit

PROJECT, LOCATION, MODEL = "cos-sandbox-provider-data", "us-central1", "gemini-2.5-flash"
client = genai.Client(vertexai=True, project=PROJECT, location=LOCATION)

PROMPT = (
    "You are auditing a credentialing Primary Source Verification (PSV) packet PDF. Read the "
    "document ONCE and extract THREE sections as a SINGLE JSON object with exactly the keys "
    '"packet", "caqh", and "education". Each section follows the schema described below.\n\n'
    "======================= SECTION \"packet\" =======================\n"
    + packet_extract.PROMPT +
    "\n\n======================= SECTION \"caqh\" =======================\n"
    + caqh_audit.FULL_PROMPT +
    "\n\n======================= SECTION \"education\" =======================\n"
    + education_audit.PROMPT +
    "\n\nReturn EXACTLY one JSON object of the form "
    '{"packet": <the packet JSON>, "caqh": <the caqh JSON>, "education": <the education JSON>}. '
    "Do not invent values; use empty strings / empty lists where something is absent."
)


def combined_extract(pdf_path):
    """Read the PDF once; return (packet, caqh_full, education) dicts."""
    pdf = open(pdf_path, "rb").read()
    resp = client.models.generate_content(
        model=MODEL,
        contents=[types.Part.from_bytes(data=pdf, mime_type="application/pdf"), PROMPT],
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    d = json.loads(resp.text)
    return d.get("packet") or {}, d.get("caqh") or {}, d.get("education") or {}


if __name__ == "__main__":
    import sys
    pkt, caqh, edu = combined_extract(sys.argv[1])
    print(json.dumps({"packet": pkt, "caqh": caqh, "education": edu}, indent=2))
