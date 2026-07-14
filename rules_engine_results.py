#!/usr/bin/env python3
"""Surface CertifyOS's own rulesEngineResults (NCQA-style validations) as audit flags.

Fetches a credentialing workflow from the CertifyOS API and turns any FAILING
rules-engine check into a flag dict shaped exactly like our other audit flags.
Plain-stdlib style, mirroring download_packets.py.
"""
import argparse, json, os, urllib.request

API = "https://ng-api-production.certifyos.com"
TOKEN = open(".token").read().strip()

# CertifyOS severity -> our lowercase severity.
_SEV = {"INFO": "info", "WARNING": "warning", "ERROR": "error"}


def _sev(raw):
    """Map a CertifyOS severity (case-insensitive) to ours; default 'info'."""
    if not raw:
        return "info"
    return _SEV.get(str(raw).upper(), "info")


def get_json(url, org):
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + TOKEN, "organization-id": org})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def fetch_workflow(workflow_id, org):
    """GET one credentialing workflow as a dict."""
    return get_json(f"{API}/credentialing-workflows/{workflow_id}", org)


def _flag(workflow_id, org, rule, severity, message, element):
    return {
        "workflowId": workflow_id,
        "org": org,
        "rule": rule,
        "severity": _sev(severity),
        "message": message,
        "flagClass": "backend-rules-engine",
        "element": element,
        "confidence": 1.0,
    }


def _collect(wf, workflow_id, org):
    """Return (flags, total_checks_seen, failing_checks). A check fails if its
    valid/isValid is False, or any nested itemResults/list entry is invalid."""
    rer = wf.get("rulesEngineResults") or {}
    flags = []
    total = 0
    failing = 0

    for key, val in rer.items():
        if key == "dynamicResults":
            continue
        if not isinstance(val, dict):
            continue
        total += 1
        check_failed = False

        # Top-level checks carry 'valid' (occasionally 'isValid'); only an
        # explicit False counts as failing (None/null does not).
        top = val.get("valid", val.get("isValid"))
        if top is False:
            check_failed = True
            flags.append(_flag(
                workflow_id, org, key, val.get("severity"),
                val.get("message") or val.get("rulename") or key,
                val.get("sectionId") or key))

        # Some top-level checks nest a list of result dicts (e.g.
        # sanctionSourceMismatch -> sanctionSourceMismatchResults).
        for sub in val.values():
            if not isinstance(sub, list):
                continue
            for item in sub:
                if not isinstance(item, dict):
                    continue
                iv = item.get("isValid", item.get("isItemValid", item.get("valid")))
                if iv is False:
                    check_failed = True
                    flags.append(_flag(
                        workflow_id, org, item.get("rulename") or key,
                        item.get("severity") or val.get("severity"),
                        item.get("itemMessage") or item.get("message")
                        or val.get("message") or key,
                        item.get("sectionId") or val.get("sectionId") or key))

        if check_failed:
            failing += 1

    for rule, res in (rer.get("dynamicResults") or {}).items():
        if not isinstance(res, dict):
            continue
        total += 1
        check_failed = False
        element = res.get("sectionId") or rule

        if res.get("isValid") is False:
            check_failed = True
            flags.append(_flag(
                workflow_id, org, rule, res.get("severity"),
                res.get("message") or rule, element))

        for item in res.get("itemResults") or []:
            if not isinstance(item, dict):
                continue
            if item.get("isItemValid") is False:
                check_failed = True
                flags.append(_flag(
                    workflow_id, org, rule,
                    item.get("severity") or res.get("severity"),
                    item.get("itemMessage") or res.get("message") or rule,
                    item.get("sectionId") or element))

        if check_failed:
            failing += 1

    return flags, total, failing


def rules_engine_flags(workflow_id, org):
    """Return a list of flag dicts for every failing rules-engine check."""
    wf = fetch_workflow(workflow_id, org)
    flags, _total, _failing = _collect(wf, workflow_id, org)
    return flags


def main():
    ap = argparse.ArgumentParser(description="Surface CertifyOS rulesEngineResults as flags.")
    ap.add_argument("--workflow", required=True, help="credentialing workflow id")
    ap.add_argument("--org", required=True, help="organization-id")
    args = ap.parse_args()

    wf = fetch_workflow(args.workflow, args.org)
    flags, total, failing = _collect(wf, args.workflow, args.org)
    print(json.dumps(flags, indent=2))
    print(f"[summary] {total} checks seen, {failing} failing, {len(flags)} flag(s) emitted")


if __name__ == "__main__":
    main()
