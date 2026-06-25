"""Validate the grammar-based transpiler against the reference corpus.

Produces a formal comparison table: for each analytic with both pseudocode
and Splunk, measures parse success and translation quality.
"""

import json
from pathlib import Path

from grammar.normalise import normalise
from grammar.parser import parse, ParseError
from grammar.translate import ast_to_splunk

CORPUS_DIR = Path(__file__).parent / "corpus"


def load_test_pairs() -> dict:
    """Load analytics that have both pseudocode and reference Splunk."""
    with open(CORPUS_DIR / "test_pairs.json") as f:
        return json.load(f)


def evaluate_translation(generated: str, reference: str) -> dict:
    """Compare generated Splunk against reference implementation.

    Returns scoring dict with:
    - exact_match: normalised strings match
    - field_match: same Sysmon fields used
    - structure_match: same query structure (EventCode, filter approach)
    - score: 0-3 scale
    """
    gen_norm = _normalise_splunk(generated)
    ref_norm = _normalise_splunk(reference)

    if gen_norm == ref_norm:
        return {"exact_match": True, "field_match": True, "structure_match": True, "score": 3}

    # Check field overlap
    gen_fields = _extract_fields(generated)
    ref_fields = _extract_fields(reference)
    field_overlap = len(gen_fields & ref_fields) / max(len(ref_fields), 1)

    # Check structural similarity (EventCode, key operators)
    gen_ec = _extract_event_code(generated)
    ref_ec = _extract_event_code(reference)
    structure_match = gen_ec == ref_ec and gen_ec is not None

    # Check if reference uses CIM tstats (different style, not comparable by fields)
    ref_is_tstats = "tstats" in reference or "datamodel=" in reference
    # Check if logic is equivalent (same exe/command_line values targeted)
    logic_overlap = _extract_logic_values(generated) & _extract_logic_values(reference)

    field_match = field_overlap >= 0.7

    if field_match and structure_match:
        score = 2  # Semantically equivalent
    elif ref_is_tstats and logic_overlap:
        score = 2  # Different style but same detection logic
    elif field_match or structure_match:
        score = 1  # Partial match
    elif logic_overlap:
        score = 1  # Different structure but targets same thing
    else:
        score = 0  # Different

    return {
        "exact_match": False,
        "field_match": field_match,
        "field_overlap": round(field_overlap, 2),
        "structure_match": structure_match,
        "score": score,
        "gen_fields": sorted(gen_fields),
        "ref_fields": sorted(ref_fields),
    }


def _normalise_splunk(query: str) -> str:
    """Normalise Splunk query for comparison (strip whitespace, index names)."""
    import re
    q = query.lower().strip()
    q = re.sub(r'index=\S+', 'index=IDX', q)
    q = re.sub(r'\s+', ' ', q)
    return q


def _extract_fields(query: str) -> set[str]:
    """Extract Sysmon field names from a Splunk query."""
    import re
    # Match known field patterns
    field_pattern = r'\b(Image|ParentImage|CommandLine|ComputerName|User|' \
                    r'TargetFilename|TargetObject|Details|ImageLoaded|Signed|' \
                    r'DestinationPort|DestinationIp|SourceIp|SourcePort|' \
                    r'OriginalFileName|Hashes|IntegrityLevel|EventCode|' \
                    r'ProcessId|ParentProcessId|CurrentDirectory|Account_Name|' \
                    r'StartFunction|SourceImage|TargetImage|GrantedAccess|CallTrace)\b'
    return set(re.findall(field_pattern, query, re.IGNORECASE))


def _extract_event_code(query: str) -> str | None:
    """Extract EventCode from query."""
    import re
    m = re.search(r'EventCode\s*=\s*(\d+)', query, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_logic_values(query: str) -> set[str]:
    """Extract key detection values (exe names, command patterns) from a query."""
    import re
    values = set()
    # Extract quoted string values that look like detection targets
    for m in re.finditer(r'"([^"]+)"', query):
        val = m.group(1).strip("*\\ ").lower()
        if val and len(val) > 3 and not val.startswith("c:\\windows"):
            values.add(val)
    # Extract exe names
    for m in re.finditer(r'\b(\w+\.exe)\b', query, re.IGNORECASE):
        values.add(m.group(1).lower())
    return values


def run_validation() -> dict:
    """Run full validation: parse + translate + compare for all test pairs.

    Returns results dict with per-analytic scores and summary stats.
    """
    pairs = load_test_pairs()
    results = {}
    summary = {"total": len(pairs), "parsed": 0, "translated": 0,
               "exact": 0, "semantic": 0, "partial": 0, "failed": 0,
               "parse_errors": []}

    for car_id, data in sorted(pairs.items()):
        pseudo = data["pseudocode"]
        ref_splunk = data["splunk"]

        result = {"car_id": car_id, "parse": None, "translate": None, "score": None}

        # Step 1: Normalise + Parse
        try:
            normalised = normalise(pseudo)
            ast = parse(normalised)
            result["parse"] = "OK"
            summary["parsed"] += 1
        except ParseError as e:
            result["parse"] = f"FAIL: {e}"
            result["score"] = {"score": 0, "reason": "parse_error"}
            summary["parse_errors"].append({"car_id": car_id, "error": str(e)})
            results[car_id] = result
            continue

        # Step 2: Translate to Splunk
        try:
            generated = ast_to_splunk(ast)
            if generated is None:
                result["translate"] = "NOT_APPLICABLE"
                result["score"] = {"score": 1, "reason": "not_translatable"}
                results[car_id] = result
                continue
            result["translate"] = generated
            summary["translated"] += 1
        except Exception as e:
            result["translate"] = f"FAIL: {e}"
            result["score"] = {"score": 0, "reason": "translate_error"}
            results[car_id] = result
            continue

        # Step 3: Compare against reference
        eval_result = evaluate_translation(generated, ref_splunk)
        result["score"] = eval_result
        result["reference"] = ref_splunk

        if eval_result["score"] == 3:
            summary["exact"] += 1
        elif eval_result["score"] == 2:
            summary["semantic"] += 1
        elif eval_result["score"] == 1:
            summary["partial"] += 1
        else:
            summary["failed"] += 1

        results[car_id] = result

    summary["parse_rate"] = round(summary["parsed"] / summary["total"] * 100, 1)
    summary["translate_rate"] = round(summary["translated"] / max(summary["parsed"], 1) * 100, 1)
    summary["accuracy"] = round(
        (summary["exact"] + summary["semantic"]) / max(summary["translated"], 1) * 100, 1)

    return {"results": results, "summary": summary}


def print_comparison_table(validation: dict):
    """Print formal comparison table for research write-up."""
    summary = validation["summary"]
    results = validation["results"]

    print("=" * 80)
    print("GRAMMAR-BASED TRANSPILER: VALIDATION RESULTS")
    print("=" * 80)

    print(f"\n{'Metric':<35} {'Value':<15} {'Notes'}")
    print("-" * 80)
    print(f"{'Total test pairs':<35} {summary['total']:<15}")
    print(f"{'Parse success rate':<35} {summary['parse_rate']}%{'':<10} ({summary['parsed']}/{summary['total']})")
    print(f"{'Translation rate':<35} {summary['translate_rate']}%{'':<10} ({summary['translated']}/{summary['parsed']} parsed)")
    print(f"{'Exact match':<35} {summary['exact']:<15} Score 3/3")
    print(f"{'Semantic equivalent':<35} {summary['semantic']:<15} Score 2/3")
    print(f"{'Partial match':<35} {summary['partial']:<15} Score 1/3")
    print(f"{'Failed':<35} {summary['failed']:<15} Score 0/3")
    print(f"{'Accuracy (exact+semantic)':<35} {summary['accuracy']}%")

    print(f"\n\n{'CAR ID':<20} {'Parse':<8} {'Score':<8} {'Notes'}")
    print("-" * 80)
    for car_id, r in sorted(results.items()):
        parse_status = "OK" if r["parse"] == "OK" else "FAIL"
        score = r["score"]["score"] if isinstance(r["score"], dict) else "?"
        reason = r["score"].get("reason", "") if isinstance(r["score"], dict) else ""
        notes = reason if score == 0 else ""
        if isinstance(r["score"], dict) and r["score"].get("field_overlap") is not None:
            notes = f"field_overlap={r['score']['field_overlap']}"
        print(f"{car_id:<20} {parse_status:<8} {score:<8} {notes}")

    # Parse errors detail
    if summary["parse_errors"]:
        print(f"\n\nPARSE ERRORS ({len(summary['parse_errors'])}):")
        print("-" * 80)
        for err in summary["parse_errors"]:
            print(f"  {err['car_id']}: {err['error'][:70]}")


if __name__ == "__main__":
    results = run_validation()
    print_comparison_table(results)

    # Save full results
    output_path = Path(__file__).parent / "validation_results.json"
    # Convert for JSON serialisation
    serialisable = {
        "summary": results["summary"],
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "ast"}
                    for k, v in results["results"].items()}
    }
    with open(output_path, "w") as f:
        json.dump(serialisable, f, indent=2, default=str)
    print(f"\n\nFull results saved to: {output_path}")
