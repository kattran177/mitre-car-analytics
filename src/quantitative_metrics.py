"""
Quantitative metrics for threat hunting output evaluation.

Metrics:
1. MOQS (Mean Output Quality Score) - 1-3 scale across all outputs
2. Query Validity Rate - % of valid SIEM queries
3. ATT&CK Mapping Accuracy - % matching CAR ground truth
4. Failure Mode Coverage - distinct failure categories observed
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

class QuantitativeEvaluator:
    """Quantitative evaluation framework for threat hunting outputs."""

    # CAR ground truth: analytic_id -> primary technique_id
    CAR_GROUND_TRUTH = {
        "CAR-2013-01-002": "T1547.001",  # Autorun -> Registry Run Keys
        "CAR-2013-01-003": "T1135",       # SMB Events -> Network Share Discovery
        "CAR-2013-02-003": "T1059.001",   # cmd.exe -> PowerShell
        "CAR-2013-02-008": "T1078",       # Simultaneous Logins -> Valid Accounts
        "CAR-2013-02-012": "T1078",       # Multiple Host Logins -> Valid Accounts
        "CAR-2013-03-001": "T1112",       # Registry Modification -> Registry Modification
        "CAR-2013-04-002": "T1059",       # Rapid Commands -> Command/Scripting
        "CAR-2013-05-002": "T1547.001",   # Run Locations -> Registry Run Keys
        "CAR-2013-05-003": "T1570",       # SMB Write -> Lateral Tool Transfer
        "CAR-2013-05-004": "T1053",       # AT Execution -> Scheduled Task
        "CAR-2013-05-005": "T1021.002",   # SMB Copy -> RDP
        "CAR-2013-05-009": "T1036",       # Same Hash -> Masquerading
        "CAR-2013-07-001": "T1036",       # Suspicious Arguments -> Masquerading
        "CAR-2013-08-001": "T1053.005",   # schtasks -> Scheduled Task - schtasks
    }

    def __init__(self):
        self.evaluations = {}
        self.failure_modes_observed = set()

    def score_output_quality(self, output: dict) -> int:
        """
        Score output quality on 1-3 scale.

        3 = Excellent (all sections complete, high confidence, no issues)
        2 = Good (complete but some minor issues or moderate confidence)
        1 = Acceptable (complete but significant issues or low confidence)

        Returns: int (1-3)
        """
        score = 2  # Default to "Good"

        # Check completeness
        required_sections = [
            "analytic_id", "summary_explanation", "attack_mapping",
            "hunting_hypothesis", "false_positives", "siem_query"
        ]

        missing_sections = [s for s in required_sections if s not in output]
        if missing_sections:
            return 1  # Incomplete -> Acceptable

        # Check confidence levels
        se_conf = output.get("summary_explanation", {}).get("confidence", "medium")
        hh_conf = output.get("hunting_hypothesis", {}).get("confidence", "medium")
        siem_conf = output.get("siem_query", {}).get("confidence", "medium")
        fp_conf = output.get("false_positives", {}).get("confidence", "medium")

        conf_levels = [se_conf, hh_conf, siem_conf, fp_conf]
        high_conf_count = sum(1 for c in conf_levels if c == "high")
        low_conf_count = sum(1 for c in conf_levels if c == "low")

        # Adjust score based on confidence
        if high_conf_count >= 3 and low_conf_count == 0:
            score = 3  # Excellent
        elif low_conf_count >= 2:
            score = 1  # Acceptable

        # Check for issues (tactic drift, validation warnings, etc.)
        issues = []

        if output.get("requires_analyst_review"):
            issues.append("analyst_review")

        siem = output.get("siem_query", {})
        if siem.get("validation_issues"):
            issues.append("siem_validation")

        # More than 1 issue -> lower score
        if len(issues) > 1:
            score = max(1, score - 1)

        return score

    def check_query_validity(self, query_text: str) -> Tuple[bool, str]:
        """
        Check if SIEM query is valid (parses without error).

        Returns: (is_valid, error_message)
        """
        if not query_text or "NOT APPLICABLE" in query_text:
            return True, "N/A query"

        query_lower = query_text.lower()

        # Splunk SPL checks
        if "|" in query_text:
            # Check for common Splunk syntax errors
            pipes = query_text.split("|")

            # Each pipe should have a valid command
            for i, pipe in enumerate(pipes[1:], 1):
                pipe_stripped = pipe.strip()
                if not pipe_stripped or len(pipe_stripped.split()) < 2:
                    return False, f"Incomplete pipe command at position {i}"

            # Check for unclosed quotes
            if query_text.count('"') % 2 != 0:
                return False, "Unclosed quote in query"

            # Check for valid operators
            valid_ops = ["where", "table", "stats", "search", "rename", "eval"]
            has_valid_command = any(op in query_lower for op in valid_ops)
            if len(pipes) > 1 and not has_valid_command:
                return False, "No recognizable Splunk command found"

        # KQL checks
        if any(kql_op in query_lower for kql_op in ["project", "where", "summarize"]):
            # Check for valid KQL syntax
            if query_text.count("(") != query_text.count(")"):
                return False, "Unmatched parentheses in KQL query"

        # Field reference checks (hallucination detection)
        hallucinated_fields = {
            "process_parent", "event_timestamp", "event_id",
            "command_args", "src_ip", "dst_ip"
        }

        for field in hallucinated_fields:
            if field in query_lower:
                return False, f"Hallucinated field: {field}"

        return True, "Valid"

    def check_technique_accuracy(self, output: dict) -> Tuple[bool, str, str]:
        """
        Check if primary technique matches CAR ground truth.

        Returns: (is_correct, output_technique, expected_technique)
        """
        analytic_id = output.get("analytic_id", "")

        # No ground truth available
        if analytic_id not in self.CAR_GROUND_TRUTH:
            return None, None, None

        expected_technique = self.CAR_GROUND_TRUTH[analytic_id]

        # Get first technique from output
        attack_mapping = output.get("attack_mapping", {})
        techniques = attack_mapping.get("techniques", [])

        if not techniques:
            return False, None, expected_technique

        output_technique = techniques[0].get("technique_id", "")

        # Check if it matches (exact or parent match)
        is_correct = output_technique == expected_technique

        # If not exact, check if it's a subtechnique of the expected
        if not is_correct and "." in output_technique:
            parent = output_technique.split(".")[0]
            if parent == expected_technique or f"{parent}." in expected_technique:
                is_correct = True

        return is_correct, output_technique, expected_technique

    def record_failure_mode(self, failure_category: str, example: dict):
        """Record an observed failure mode with example."""
        self.failure_modes_observed.add(failure_category)

    def evaluate_batch(self, outputs: dict, car_analytics: dict = None) -> dict:
        """
        Evaluate batch of outputs for all quantitative metrics.

        Returns: {
            "moqs": float,
            "query_validity_rate": float,
            "technique_accuracy": float,
            "failure_mode_coverage": dict,
            "detailed_results": list
        }
        """
        detailed = []
        moqs_scores = []
        valid_queries = 0
        valid_query_count = 0
        correct_techniques = 0
        technique_count = 0

        for analytic_id, output in outputs.items():
            result = {
                "analytic_id": analytic_id,
                "quality_score": None,
                "query_valid": None,
                "technique_correct": None,
            }

            # 1. MOQS: Quality score (1-3)
            quality_score = self.score_output_quality(output)
            moqs_scores.append(quality_score)
            result["quality_score"] = quality_score

            # 2. Query Validity
            siem = output.get("siem_query", {})
            query = siem.get("query", "")
            is_valid, error = self.check_query_validity(query)
            result["query_valid"] = is_valid
            result["query_error"] = error if not is_valid else None
            valid_query_count += 1
            if is_valid:
                valid_queries += 1

            # 3. Technique Accuracy
            is_correct, out_tech, exp_tech = self.check_technique_accuracy(output)
            if is_correct is not None:
                result["technique_correct"] = is_correct
                result["output_technique"] = out_tech
                result["expected_technique"] = exp_tech
                technique_count += 1
                if is_correct:
                    correct_techniques += 1

            detailed.append(result)

        # Calculate metrics
        moqs = sum(moqs_scores) / len(moqs_scores) if moqs_scores else 0
        moqs_normalized = moqs / 3.0  # Normalize to 0-1 scale

        query_validity_rate = valid_queries / valid_query_count if valid_query_count > 0 else 0
        technique_accuracy = correct_techniques / technique_count if technique_count > 0 else 0

        # Failure mode coverage
        failure_modes = {
            "field_hallucination": sum(1 for d in detailed if d["query_error"] and "hallucinated" in d["query_error"]),
            "tactic_drift": sum(1 for d in detailed if not d.get("technique_correct", True)),
            "low_confidence": sum(1 for d in detailed if d["quality_score"] == 1),
        }

        return {
            "summary": {
                "total_outputs": len(outputs),
                "moqs": moqs,
                "moqs_normalized": moqs_normalized,
                "query_validity_rate": query_validity_rate,
                "technique_accuracy": technique_accuracy,
                "failure_mode_categories": len([k for k, v in failure_modes.items() if v > 0])
            },
            "metrics": {
                "moqs": moqs,
                "query_validity_rate": query_validity_rate,
                "technique_accuracy": technique_accuracy,
                "failure_modes": failure_modes
            },
            "detailed_results": detailed
        }


# Global evaluator instance
_evaluator = QuantitativeEvaluator()

def get_evaluator() -> QuantitativeEvaluator:
    """Get global evaluator instance."""
    return _evaluator
