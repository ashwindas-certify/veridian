#!/usr/bin/env python3
"""Auto-generate '<ELEMENT> <field> missing' rules from the REAL element-table columns,
so field names are always correct (no false flags). Writes generated_missing_rules.json,
which reconcile.py merges into the catalog. 'X incorrect' flags are the packet-vs-backend
comparison (deep audit), not generated here.
"""
import json
from google.cloud import bigquery
from master_record import ELEMENTS  # element name -> table

DATASET = "certifyos-production-platform.appdb_data"
c = bigquery.Client(project="certifyos-production-platform")

# CDC / plumbing columns that are not data-entry fields
SKIP = {"document_id","document_name","event_id","operation","timestamp","edit_provider_id",
        "created_at","created_by","created_by_name","updated_at","updated_by","organization_id",
        "provider_id","is_current","verified_at","verified_by","data_last_acquired_date","data_acquire_date",
        "license_number_variations","license_number_variations_array","sub_collection_document_id",
        "sub_collection_name","file_url","_new_calculation_executed_","fetch_source"}
# elements that carry per-record data worth field-level completeness checks
ELIGIBLE = ["stateLicenses","dea","boardCertifications","malpractice","specialties",
            "licensureActions","sanctions","npdb","educationTraining","hospitalAffiliation","professionalIds"]
LABEL = {"stateLicenses":"State license","dea":"DEA","boardCertifications":"Board cert","malpractice":"Malpractice",
         "specialties":"Specialty","licensureActions":"Licensure action","sanctions":"Sanction","npdb":"NPDB",
         "educationTraining":"Education/training","hospitalAffiliation":"Hospital affiliation","professionalIds":"Professional ID"}

def humanfield(f): return f.replace("_"," ")

rules = []
for el in ELIGIBLE:
    table = ELEMENTS[el]
    cols = [f.name for f in c.get_table(f"{DATASET}.{table}").schema]
    for col in cols:
        if col in SKIP or col.startswith("flag"): continue
        rid = f"{el.upper()}_{col.upper()}_MISSING"
        rules.append({"id": rid, "element": el, "check": "field_present", "field": col,
                      "severity": "info",
                      "message": f"DATA ENTRY: {LABEL.get(el, el)} '{humanfield(col)}' is missing",
                      "expected": f"the '{humanfield(col)}' field must be populated in the {LABEL.get(el, el)} record"})
    print(f"{el:22s} {table:44s} -> {sum(1 for r in rules if r['element']==el)} field rules")

json.dump(rules, open("generated_missing_rules.json", "w"), indent=1)
print(f"\nTOTAL generated missing-field rules: {len(rules)} -> generated_missing_rules.json")
