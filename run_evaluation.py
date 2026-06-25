#!/usr/bin/env python3
"""Re-run SIEM query generation with improved pipeline and measure scores.

Usage:
    export ANTHROPIC_API_KEY="sk-ant-..."
    python3 run_evaluation.py
"""

import json
import sys
import os

if not os.environ.get("ANTHROPIC_API_KEY"):
    print("ERROR: Set ANTHROPIC_API_KEY environment variable first")
    sys.exit(1)

from anthropic import Anthropic
from src.prompts import build_schema_grounded_prompt, SYSTEM_PROMPT
from src.query_repair import repair_siem_query
from src.query_validator import validate_siem_query

client = Anthropic()

# Load analytics from reference_implementations.json (no raw YAML available)
with open("data/processed/reference_implementations.json") as f:
    refs = json.load(f)

# Build minimal analytic dicts from available data
sample_ids = ["CAR-2013-02-003", "CAR-2013-05-004", "CAR-2014-04-003",
              "CAR-2014-05-002", "CAR-2019-08-001", "CAR-2020-09-003"]
sample = []
for car_id in sample_ids:
    if car_id not in refs:
        continue
    impl = refs[car_id]
    sample.append({
        "id": car_id,
        "title": car_id,
        "description": impl.get("Pseudocode", ""),
        "platforms": ["Windows"],
        "techniques": ["T1059"],
        "tactics": ["TA0002"],
        "data_model_references": ["process/create/exe", "process/create/command_line"],
        "impl_types": list(impl.keys()),
    })

results = {}
repair_stats = {"attempted": 0, "fixed": 0}

for i, analytic in enumerate(sample, 1):
    print(f"[{i}/{len(sample)}] {analytic['id']} — {analytic['title'][:40]}...", end="", flush=True)
    prompt = build_schema_grounded_prompt(analytic)

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.content[0].text
        try:
            output = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}") + 1
            output = json.loads(text[start:end])

        # Validation-repair loop
        siem = output.get("siem_query", {})
        query = siem.get("query", "")
        if query and "NOT APPLICABLE" not in query:
            repaired, valid, issues = repair_siem_query(client, "claude-haiku-4-5-20251001", query)
            if repaired != query:
                repair_stats["attempted"] += 1
                if valid:
                    repair_stats["fixed"] += 1
            output["siem_query"]["query"] = repaired
            output["siem_query"]["validation_issues"] = issues

        results[analytic["id"]] = output
        print(" [OK]")
    except Exception as e:
        print(f" [ERROR: {e}]")

# Score SIEM queries
print("\n" + "=" * 60)
print("SIEM QUERY EVALUATION RESULTS")
print("=" * 60)

siem_scores = []
for car_id, output in results.items():
    siem = output.get("siem_query", {})
    query = siem.get("query", "")
    platform = siem.get("platform", "unknown")
    issues = siem.get("validation_issues", [])

    is_valid, val_issues = validate_siem_query(query)
    
    # Score: 3=valid+no issues, 2=valid with minor issues, 1=invalid
    if "NOT APPLICABLE" in query:
        score = 2.0  # Acceptable N/A
    elif is_valid and not val_issues:
        score = 3.0
    elif is_valid:
        score = 2.5
    else:
        score = 1.0

    siem_scores.append(score)
    status = "✅" if score >= 2.5 else "⚠️" if score >= 2.0 else "❌"
    print(f"  {status} {car_id}: score={score}/3 platform={platform} valid={is_valid}")
    if val_issues:
        for issue in val_issues[:2]:
            print(f"      Issue: {issue}")

avg_score = sum(siem_scores) / len(siem_scores) if siem_scores else 0
print(f"\n{'='*60}")
print(f"SIEM Query Average Score: {avg_score:.2f}/3.0")
print(f"Repair stats: {repair_stats['fixed']}/{repair_stats['attempted']} queries fixed")
print(f"{'='*60}")

# Save results
os.makedirs("outputs", exist_ok=True)
with open("outputs/siem_evaluation_results.json", "w") as f:
    json.dump({"results": results, "siem_scores": siem_scores, 
               "average": avg_score, "repair_stats": repair_stats}, f, indent=2)
print(f"\nFull results saved to: outputs/siem_evaluation_results.json")
