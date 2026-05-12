"""
Phase 3 Evaluation: Assess LLM-generated threat hunting artifacts.

Score each output type (1-3 scale) and identify systematic failure patterns.
"""

import json
from typing import Any, Tuple


def validate_json_structure(output: dict) -> Tuple[bool, str]:
    """
    Validate that output has required structure for all 5 output types.

    Returns: (is_valid, error_message)
    """
    required_fields = [
        "analytic_id",
        "summary_explanation",
        "attack_mapping",
        "hunting_hypothesis",
        "siem_query",
        "false_positives"
    ]

    for field in required_fields:
        if field not in output:
            return False, f"Missing field: {field}"

    # Check summary_explanation structure
    if not isinstance(output.get("summary_explanation"), dict):
        return False, "summary_explanation must be a dict"
    if "confidence" not in output["summary_explanation"]:
        return False, "summary_explanation missing confidence"

    # Check attack_mapping structure
    if not isinstance(output.get("attack_mapping"), dict):
        return False, "attack_mapping must be a dict"
    if "techniques" not in output["attack_mapping"]:
        return False, "attack_mapping missing techniques"
    if not isinstance(output["attack_mapping"]["techniques"], list):
        return False, "attack_mapping.techniques must be a list"

    # Check hunting_hypothesis structure
    if not isinstance(output.get("hunting_hypothesis"), dict):
        return False, "hunting_hypothesis must be a dict"
    if "confidence" not in output["hunting_hypothesis"]:
        return False, "hunting_hypothesis missing confidence"
    if "question" not in output["hunting_hypothesis"]:
        return False, "hunting_hypothesis missing question"

    # Check siem_query structure
    if not isinstance(output.get("siem_query"), dict):
        return False, "siem_query must be a dict"
    if "platform" not in output["siem_query"]:
        return False, "siem_query missing platform"
    if "query" not in output["siem_query"]:
        return False, "siem_query missing query"
    if "confidence" not in output["siem_query"]:
        return False, "siem_query missing confidence"

    # Check false_positives structure
    if not isinstance(output.get("false_positives"), dict):
        return False, "false_positives must be a dict"
    if "scenarios" not in output["false_positives"]:
        return False, "false_positives missing scenarios"
    if "triage_filters" not in output["false_positives"]:
        return False, "false_positives missing triage_filters"
    if "confidence" not in output["false_positives"]:
        return False, "false_positives missing confidence"

    # Validate confidence values
    for output_type in ["summary_explanation", "hunting_hypothesis", "siem_query", "false_positives"]:
        confidence = output.get(output_type, {}).get("confidence")
        if confidence not in ["high", "medium", "low"]:
            return False, f"{output_type}.confidence must be 'high', 'medium', or 'low', got '{confidence}'"

    return True, "Valid"


class OutputEvaluator:
    """Score threat hunting artifacts on quality criteria."""

    def __init__(self):
        self.criteria = {
            "summary_explanation": {
                "1": "Generic or vague; lacks concrete detection trigger",
                "2": "Adequate; explains what is detected but lacks specificity",
                "3": "Clear and concrete; references detection logic and specific examples",
            },
            "attack_mapping": {
                "1": "Hallucinated technique IDs or weak/absent rationale",
                "2": "Correct technique IDs; rationale is inferred but reasonable",
                "3": "Explicit and well-reasoned; clear causal link between detection and technique",
            },
            "hunting_hypothesis": {
                "1": "Circular or untestable (restates detection instead of asking a question)",
                "2": "Somewhat testable but vague or indirect connection to detection",
                "3": "Clear testable question; direct connection to detection logic",
            },
            "siem_query": {
                "1": "Invalid syntax OR hallucinated/non-existent data model fields",
                "2": "Valid syntax; uses mostly correct fields but may have minor issues or caveats",
                "3": "Valid and complete; correct fields from data_model_references; appropriate caveats",
            },
            "false_positives": {
                "1": "Generic or absent (no specific scenarios)",
                "2": "Specific scenarios but incomplete or unconvincing",
                "3": "Realistic, specific scenarios grounded in detection fields",
            },
        }

    def score_explanation(self, output: dict, analytic: dict) -> int:
        """
        Score: 1=generic, 2=adequate, 3=clear/concrete.

        Check: Does it reference the detection trigger? Is it specific?
        """
        summary = output.get("summary", "")
        if not summary or len(summary) < 20:
            return 1

        # Does it reference specific detection elements from the analytic?
        description_lower = analytic.get("description", "").lower()
        if any(phrase in summary.lower() for phrase in
               ["detect", "spawn", "execute", "create", "file", "process", "command"]):
            # Check if it's more than just restating keywords
            if len(summary) > 100 and any(word in summary.lower()
                                          for word in ["unusual", "specific", "when", "from"]):
                return 3
            return 2
        return 1

    def score_attack_mapping(self, output: dict, analytic: dict) -> int:
        """
        Score: 1=hallucinated/wrong, 2=inferred correctly, 3=explicit/reasoned.

        Check: Are technique IDs real? Is rationale present and reasonable?
        """
        techniques = output.get("techniques", [])
        if not techniques:
            return 1

        # All technique IDs should be in the analytic's techniques
        valid_techniques = set(analytic.get("techniques", []))
        analytic_techniques = {t.get("technique_id") for t in techniques}

        if not analytic_techniques.issubset(valid_techniques):
            return 1  # Hallucinated technique IDs

        # Check rationale quality
        rationales = [t.get("rationale", "") for t in techniques]
        if all(len(r) > 50 for r in rationales):  # Good rationale length
            if all(t.get("confidence") in ["high", "medium"] for t in techniques):
                return 3
            return 2
        return 2 if rationales else 1

    def score_hypothesis(self, output: dict, analytic: dict) -> int:
        """
        Score: 1=circular/untestable, 2=somewhat testable, 3=clear/actionable.

        Check: Is it a question? Is it testable? Does it avoid circularity?
        """
        question = output.get("question", "")
        if not question:
            return 1

        # Must be a question
        if "?" not in question:
            return 1

        # Avoid circularity: should not just be "when does X happen" if analytic is "detect X"
        description = analytic.get("description", "").lower()
        question_lower = question.lower()

        # Look for testable keywords
        testable_words = ["when", "where", "how many", "what", "are there"]
        is_testable = any(word in question_lower for word in testable_words)

        if not is_testable:
            return 1

        # Check for circularity (weak heuristic)
        if description and question_lower == description[:len(question)].lower():
            return 1

        # Confidence field helps
        confidence = output.get("confidence")
        if confidence == "high":
            return 3
        elif confidence == "medium":
            return 2
        return 1

    def score_siem_query(self, output: dict, analytic: dict) -> int:
        """
        Score: 1=invalid/hallucinated fields, 2=partially correct, 3=valid/complete+returns results.

        Check: Valid syntax? Correct data_model_references fields? Returns results on test data?
        """
        from src.query_validator import validate_splunk_query
        from src.test_data import generate_test_events

        query = output.get("query", "")
        if not query or "NOT APPLICABLE" in query:
            return 2  # Some analytics don't support SIEM queries; not a failure

        platform = output.get("platform")
        if not platform:
            return 1

        # Check data_model_fields_used against analytic
        used_fields = output.get("data_model_fields_used", [])
        valid_fields = set(analytic.get("data_model_references", []))

        if not used_fields:
            # If no fields listed, hard to score
            if valid_fields:
                return 1  # Should have listed fields
            return 2

        # Check if used fields are subset of valid fields
        fields_valid = set(used_fields).issubset(valid_fields)
        if not fields_valid:
            if set(used_fields).intersection(valid_fields):
                return 2  # Some valid fields but not all
            else:
                return 1  # Hallucinated fields

        # Fields are valid. Now check if query returns results on synthetic test data
        if platform in ["splunk", "kql", "eql"]:
            try:
                test_events = generate_test_events(analytic)
                returns_results, reason = validate_splunk_query(query, test_events)
                if returns_results:
                    return 3  # Fields valid AND query returns results
                else:
                    return 2  # Fields valid but query doesn't match test data
            except Exception:
                # If validation fails, assume query is OK if fields are valid
                return 2

        return 3 if fields_valid else 2

    def score_false_positives(self, output: dict, analytic: dict) -> int:
        """
        Score: 1=generic, 2=specific but incomplete, 3=realistic/specific.

        Check: Are scenarios specific? Grounded in detection fields?
        """
        scenarios = output.get("scenarios", [])
        if not scenarios or len(scenarios) == 0:
            return 1

        # Check specificity: should mention specific tools, users, or processes
        specific_words = ["admin", "script", "system", "service", "task", "tool", "user"]
        specificity_count = sum(
            1 for scenario in scenarios
            if any(word in scenario.lower() for word in specific_words)
        )

        if specificity_count == len(scenarios):
            return 3
        elif specificity_count > 0:
            return 2
        return 1

    def evaluate_output(self, output: dict, analytic: dict) -> dict:
        """Score all 5 output types for a single analytic."""
        return {
            "summary_explanation": self.score_explanation(output.get("summary_explanation", {}), analytic),
            "attack_mapping": self.score_attack_mapping(output.get("attack_mapping", {}), analytic),
            "hunting_hypothesis": self.score_hypothesis(output.get("hunting_hypothesis", {}), analytic),
            "siem_query": self.score_siem_query(output.get("siem_query", {}), analytic),
            "false_positives": self.score_false_positives(output.get("false_positives", {}), analytic),
        }


def select_stratified_sample(analytics: list, n: int = 12) -> list:
    """
    Select a stratified sample of analytics spanning:
    - At least 4 ATT&CK tactics
    - Both Windows and Linux platforms
    """
    from collections import defaultdict

    # Group by tactic
    by_tactic = defaultdict(list)
    for a in analytics:
        for tactic in a.get("tactics", []):
            by_tactic[tactic].append(a)

    # Group by platform
    by_platform = defaultdict(list)
    for a in analytics:
        for platform in a.get("platforms", []):
            by_platform[platform].append(a)

    sample = []

    # Ensure we get multiple tactics
    tactics = list(by_tactic.keys())[:4]  # At least 4 tactics
    for tactic in tactics:
        # Get one from each tactic
        if by_tactic[tactic]:
            sample.append(by_tactic[tactic][0])

    # Ensure we get both Windows and Linux
    for platform in ["Windows", "Linux"]:
        if platform in by_platform:
            # Add one that we haven't selected yet
            for a in by_platform[platform]:
                if a not in sample and len(sample) < n:
                    sample.append(a)

    # Fill remaining slots with random selection
    for a in analytics:
        if a not in sample and len(sample) < n:
            sample.append(a)

    return sample[:n]


def compute_evaluation_summary(scores: dict) -> dict:
    """
    Compute mean scores and identify failure patterns.

    Input: {analytic_id: {output_type: score}}
    Output: {output_type: mean_score, failure_patterns: [...]}
    """
    output_types = ["summary_explanation", "attack_mapping", "hunting_hypothesis", "siem_query", "false_positives"]

    results = {}
    for output_type in output_types:
        scores_for_type = [scores[aid][output_type] for aid in scores if output_type in scores[aid]]
        mean_score = sum(scores_for_type) / len(scores_for_type) if scores_for_type else 0
        results[output_type] = {
            "mean_score": round(mean_score, 2),
            "count": len(scores_for_type),
            "score_distribution": {
                "1": sum(1 for s in scores_for_type if s == 1),
                "2": sum(1 for s in scores_for_type if s == 2),
                "3": sum(1 for s in scores_for_type if s == 3),
            }
        }

    return results
