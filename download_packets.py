#!/usr/bin/env python3
"""Download the PSV packet for each workflow via psvFileSignedUrl."""
import json, os, urllib.request

API = "https://ng-api-production.certifyos.com"
TOKEN = open(".token").read().strip()
os.makedirs("packets", exist_ok=True)

def get_json(url, org):
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + TOKEN, "organization-id": org})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def download(url, path):
    with urllib.request.urlopen(url, timeout=180) as r, open(path, "wb") as f:
        f.write(r.read())

wfs = json.load(open("workflows_10.json"))
for w in wfs:
    wid, org = w["workflowId"], w["org"]
    try:
        wf = get_json(f"{API}/credentialing-workflows/{wid}", org)
        signed = wf.get("psvFileSignedUrl")
        if not signed:
            print(f"[skip] {wid} {w['last']}: no psvFileSignedUrl"); continue
        path = f"packets/{wid}.pdf"
        download(signed, path)
        print(f"[ok] {wid} {w['last']:16s} {os.path.getsize(path)//1024:6d} KB")
    except Exception as e:
        print(f"[err] {wid} {w['last']}: {type(e).__name__} {str(e)[:120]}")
