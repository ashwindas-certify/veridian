#!/usr/bin/env python3
"""PSV Phase-1 audit tool.
Give it a client (org id) and a list of NPIs -> resolves PSV-complete workflows,
builds the backend master record, runs the NCQA rule engine, and writes an
'errors to fix' report (CSV + console). Backend data-validation only (no packet
PDF cross-check yet -- that's Phase 2, needs Vertex).

Usage:
  python audit.py --org <ORG_ID> --npis 1174411409,1114852290
  python audit.py --org <ORG_ID> --npi-file npis.txt --out report.csv
"""
import argparse, csv, sys, json
try:
    sys.stdout.reconfigure(encoding="utf-8"); sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass
import glob, os
from collections import Counter, defaultdict
from master_record import build_master, ELEMENTS, bq_json
from reconcile import evaluate, apply_client_overlay

def load_client_overlay(org):
    for p in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients", "*.json")):
        o = json.load(open(p, encoding="utf-8"))
        if org in o.get("orgIds", []):
            return o
    return None

STATUS = "PSV complete by CertifyOS"

def resolve_workflows(org, npis=None, status=STATUS, limit=500):
    """Resolve workflows for a client. If npis given, filter to them; else audit ALL
    workflows in `status` for the client (full audit). Captures the responsible analyst
    (assignment.assignedTo) since the step history doesn't record who moved to PSV complete."""
    where = [f"organization_id = '{org}'", "operation != 'delete'"]
    if npis:
        where.append("provider_npi IN (%s)" % ",".join("'%s'" % n.strip() for n in npis if n.strip()))
    if status:
        where.append(f"onStep_title = '{status}'")
    sql = f"""
    WITH latest AS (
      SELECT *, ROW_NUMBER() OVER (PARTITION BY credentialing_workflows_id ORDER BY timestamp DESC) rn
      FROM `certifyos-production-platform.appdb_data.credentialing_workflows`
      WHERE {' AND '.join(where)}
    )
    SELECT credentialing_workflows_id, provider_id, provider_npi, provider_first_name,
           provider_last_name, provider_type, provider_states, provider_file_type, credentialing_cycle,
           organization_id, psv_file, onStep_title,
           assignment_assignedToFirstName, assignment_assignedToLastName, assignment_assignedToId
    FROM latest WHERE rn = 1 LIMIT {limit}
    """
    wfs = []
    for r in bq_json(sql):
        name = " ".join(x for x in [r.get("assignment_assignedToFirstName"),
                                    r.get("assignment_assignedToLastName")] if x) or "(unassigned)"
        wfs.append({"workflowId": r["credentialing_workflows_id"], "providerId": r["provider_id"],
            "npi": r["provider_npi"], "first": r["provider_first_name"], "last": r["provider_last_name"],
            "type": r["provider_type"], "states": r.get("provider_states"), "org": r["organization_id"],
            "psvFile": r.get("psv_file"), "onStep": r.get("onStep_title"), "fileType": r.get("provider_file_type"),
            "cycle": r.get("credentialing_cycle"),
            "responsible": name, "assignedToId": r.get("assignment_assignedToId")})
    return wfs

def fetch_org_names(orgs):
    ids = ",".join("'%s'" % o for o in orgs if o)
    if not ids: return {}
    sql = (f"SELECT document_id, MAX(name) name FROM "
           f"`certifyos-production-platform.appdb_data.organizations` "
           f"WHERE document_id IN ({ids}) GROUP BY document_id")
    return {r["document_id"]: r["name"] for r in bq_json(sql)}

def write_excel(path, flags, wfs, prov_conf, org_names):
    import pandas as pd
    by_wf = defaultdict(list)
    for f in flags: by_wf[f["workflowId"]].append(f)
    # detail sheet
    det = [{"Client": org_names.get(f["org"], f["org"]), "Provider": f["provider"], "NPI": f["npi"],
            "Provider Type": f["providerType"], "State": f.get("state",""), "Element": f["element"],
            "Flag Type": f["flagClass"], "Rule": f["rule"], "Severity": f["severity"],
            "Confidence": f["confidence"], "Finding": f["message"], "Verified By": f["verified_by"],
            "Verified On": f["verified_at"], "WorkflowId": f["workflowId"]} for f in flags]
    # summary sheet (one row per provider)
    summ = []
    for w in wfs:
        fl = by_wf.get(w["workflowId"], [])
        sv = Counter(f["severity"] for f in fl)
        summ.append({"Client": org_names.get(w["org"], w["org"]), "Provider": f'{w["first"]} {w["last"]}',
            "NPI": w["npi"], "Provider Type": w["type"], "Assigned States": w.get("states"),
            "Responsible Analyst": w.get("responsible"),
            "Audit Confidence": prov_conf.get(w["workflowId"]), "Errors": sv.get("error",0),
            "Warnings": sv.get("warning",0), "Info": sv.get("info",0), "Total Flags": len(fl),
            "Status": "REVIEW" if sv.get("error",0) else ("CHECK" if fl else "CLEAN"),
            "WorkflowId": w["workflowId"]})
    with pd.ExcelWriter(path, engine="openpyxl") as xl:
        pd.DataFrame(summ).to_excel(xl, sheet_name="Provider Summary", index=False)
        pd.DataFrame(det if det else [{"Client":"","Finding":"no flags"}]).to_excel(xl, sheet_name="Flag Detail", index=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True, help="client organization id")
    ap.add_argument("--npis", help="comma-separated NPIs (omit to audit the whole client)")
    ap.add_argument("--npi-file", help="file with one NPI per line")
    ap.add_argument("--assigned-to", help="filter to files whose responsible analyst matches this name/id")
    ap.add_argument("--limit", type=int, default=500, help="max workflows for a full-client audit")
    ap.add_argument("--out", default="report.xlsx")
    ap.add_argument("--any-step", action="store_true", help="do not restrict to PSV-complete")
    args = ap.parse_args()

    npis = []
    if args.npis: npis += args.npis.split(",")
    if args.npi_file: npis += [l.strip() for l in open(args.npi_file) if l.strip()]

    scope = f"{len(npis)} NPIs" if npis else "ALL PSV-complete files"
    print(f"Resolving {scope} for client {args.org} ...", file=sys.stderr)
    wfs = resolve_workflows(args.org, npis or None, status=None if args.any_step else STATUS, limit=args.limit)
    if args.assigned_to:
        key = args.assigned_to.lower()
        wfs = [w for w in wfs if key in (w["responsible"] or "").lower() or key == (w.get("assignedToId") or "").lower()]
        print(f"  filtered to responsible analyst matching '{args.assigned_to}'", file=sys.stderr)
    found = {w["npi"] for w in wfs}
    missing = [n.strip() for n in npis if n.strip() not in found] if npis else []
    print(f"  matched {len(wfs)} workflows", file=sys.stderr)
    if not wfs:
        sys.exit("No matching workflows. Try --any-step or check the client/filters.")

    overlay = load_client_overlay(args.org)
    if overlay:
        apply_client_overlay(overlay)
        print(f"  applied client ruleset: {overlay['clientName']}", file=sys.stderr)

    print("Building backend master record ...", file=sys.stderr)
    master = build_master(wfs)
    print("Running rule engine ...", file=sys.stderr)
    flags, prov_conf = evaluate(master)

    org_names = fetch_org_names({w["org"] for w in wfs})
    client = org_names.get(args.org, args.org)

    write_excel(args.out, flags, wfs, prov_conf, org_names)
    # also a flat CSV alongside
    csv_path = args.out.rsplit(".", 1)[0] + ".csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        cols = ["workflowId","provider","npi","org","providerType","flagClass","element","state","rule",
                "severity","confidence","message","verified_by","verified_at"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(flags)

    # per-provider console report
    by_wf = defaultdict(list)
    for f in flags: by_wf[f["workflowId"]].append(f)
    order = {"error": 0, "warning": 1, "info": 2}
    print("\n" + "=" * 78)
    print(f"PSV PHASE-1 AUDIT  |  {client}  |  {len(wfs)} providers  |  {len(flags)} flags")
    print("=" * 78)
    for w in wfs:
        wid = w["workflowId"]; fl = sorted(by_wf.get(wid, []), key=lambda x: order.get(x["severity"], 3))
        errs = sum(1 for f in fl if f["severity"] == "error")
        print(f"\n* {w['first']} {w['last']}  (NPI {w['npi']}, {w['type']}, {w.get('states')})   "
              f"audit conf {prov_conf[wid]:.2f}   {errs} err / {len(fl)} flags")
        for f in fl:
            print(f"    [{f['severity']:7s} c={f['confidence']}] {f.get('state',''):3s} {f['message']}")
        if not fl: print("    (clean)")
    if missing:
        print(f"\n! {len(missing)} NPIs not in PSV-complete for this client: {', '.join(missing[:20])}")
    print(f"\nSeverity totals: {dict(Counter(f['severity'] for f in flags))}")
    print(f"Excel -> {args.out}   CSV -> {csv_path}")

if __name__ == "__main__":
    main()
