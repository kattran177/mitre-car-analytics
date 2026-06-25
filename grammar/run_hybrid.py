#!/usr/bin/env python3
"""Run the full hybrid transpiler pipeline: deterministic parse + LLM fallback.

Usage:
    # Deterministic only (no API key needed):
    python3 -m grammar.validate

    # Full hybrid (needs API key for LLM normalisation of failures):
    export ANTHROPIC_API_KEY="sk-ant-..."
    python3 grammar/run_hybrid.py
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from grammar.normalise import normalise
from grammar.parser import parse, ParseError
from grammar.translate import ast_to_splunk
from grammar.validate import load_test_pairs, evaluate_translation

def run_deterministic():
    """Run deterministic-only pipeline. Returns (successes, failures)."""
    pairs = load_test_pairs()
    successes = {}
    failures = {}

    for car_id, data in sorted(pairs.items()):
        pseudo = data["pseudocode"]
        try:
            normalised = normalise(pseudo)
            ast = parse(normalised)
            splunk = ast_to_splunk(ast)
            successes[car_id] = {"ast": ast, "splunk": splunk, "reference": data["splunk"]}
        except ParseError as e:
            failures[car_id] = {"pseudocode": pseudo, "error": str(e)}

    return successes, failures


def run_hybrid(client, model: str):
    """Run full hybrid: deterministic + LLM fallback."""
    from grammar.llm_normalise import normalise_and_parse

    pairs = load_test_pairs()
    results = {"deterministic": {}, "llm_assisted": {}, "failed": {}}

    for car_id, data in sorted(pairs.items()):
        pseudo = data["pseudocode"]

        # Try deterministic first
        try:
            normalised = normalise(pseudo)
            ast = parse(normalised)
            splunk = ast_to_splunk(ast)
            results["deterministic"][car_id] = {"splunk": splunk, "reference": data["splunk"]}
            continue
        except ParseError:
            pass

        # LLM fallback
        ast, meta = normalise_and_parse(client, model, pseudo)
        if ast is not None:
            splunk = ast_to_splunk(ast)
            results["llm_assisted"][car_id] = {
                "splunk": splunk, "reference": data["splunk"], "meta": meta
            }
        else:
            results["failed"][car_id] = {"pseudocode": pseudo, "meta": meta}

    return results


def print_results(results: dict):
    """Print formal comparison table."""
    det = results["deterministic"]
    llm = results["llm_assisted"]
    failed = results["failed"]
    total = len(det) + len(llm) + len(failed)

    # Score translations
    det_scores = []
    for car_id, data in det.items():
        if data["splunk"]:
            score = evaluate_translation(data["splunk"], data["reference"])
            det_scores.append(score["score"])

    llm_scores = []
    for car_id, data in llm.items():
        if data["splunk"]:
            score = evaluate_translation(data["splunk"], data["reference"])
            llm_scores.append(score["score"])

    print("=" * 70)
    print("HYBRID TRANSPILER: FORMAL COMPARISON TABLE")
    print("=" * 70)
    print(f"\n{'Method':<25} {'Count':<8} {'Rate':<10} {'Avg Score'}")
    print("-" * 70)
    print(f"{'Deterministic':<25} {len(det):<8} {len(det)*100//total}%{'':>5} {sum(det_scores)/max(len(det_scores),1):.1f}/3")
    print(f"{'LLM-Assisted':<25} {len(llm):<8} {len(llm)*100//total}%{'':>5} {sum(llm_scores)/max(len(llm_scores),1):.1f}/3")
    print(f"{'Failed (unparseable)':<25} {len(failed):<8} {len(failed)*100//total}%")
    print(f"{'TOTAL':<25} {total:<8} 100%")

    combined = det_scores + llm_scores
    print(f"\n{'Overall accuracy':<25} {sum(1 for s in combined if s >= 2)}/{len(combined)} semantic match")
    print(f"{'Overall coverage':<25} {(len(det)+len(llm))*100//total}% of corpus translatable")

    print(f"\n\n{'='*70}")
    print("RESEARCH FINDING: DETERMINISTIC vs LLM CONTRIBUTION")
    print("=" * 70)
    print(f"  Deterministic parsing:  {len(det)}/{total} ({len(det)*100//total}%) — no LLM needed")
    print(f"  LLM normalisation:      {len(llm)}/{total} ({len(llm)*100//total}%) — LLM fixes syntax only")
    print(f"  Irreducible failures:   {len(failed)}/{total} ({len(failed)*100//total}%) — requires human review")
    print(f"\n  Translation step: 100% deterministic (field mapping lookup table)")
    print(f"  LLM role: syntax normalisation ONLY (not translation)")


if __name__ == "__main__":
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        print("No ANTHROPIC_API_KEY set — running deterministic-only mode.\n")
        successes, failures = run_deterministic()
        total = len(successes) + len(failures)
        print(f"Deterministic: {len(successes)}/{total} ({len(successes)*100//total}%)")
        print(f"Failures (need LLM): {len(failures)}/{total} ({len(failures)*100//total}%)")
        print(f"\nSet ANTHROPIC_API_KEY to run hybrid mode with LLM fallback.")
    else:
        from anthropic import Anthropic
        client = Anthropic()
        model = "claude-haiku-4-5-20251001"

        print(f"Running hybrid pipeline (deterministic + LLM fallback)...")
        print(f"Model: {model}\n")

        results = run_hybrid(client, model)
        print_results(results)

        # Save results
        output_path = Path(__file__).parent / "hybrid_results.json"
        serialisable = {
            "deterministic": {k: {"splunk": v["splunk"]} for k, v in results["deterministic"].items()},
            "llm_assisted": {k: {"splunk": v["splunk"]} for k, v in results["llm_assisted"].items()},
            "failed": list(results["failed"].keys()),
            "summary": {
                "deterministic_count": len(results["deterministic"]),
                "llm_count": len(results["llm_assisted"]),
                "failed_count": len(results["failed"]),
            }
        }
        with open(output_path, "w") as f:
            json.dump(serialisable, f, indent=2)
        print(f"\nResults saved to: {output_path}")
