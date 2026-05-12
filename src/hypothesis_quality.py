"""
Hypothesis quality testing framework.
Evaluates hypotheses for testability, clarity, and adherence to requirements.
"""
import re
from typing import Tuple

class HypothesisQualityTester:
    """Test and score hypothesis quality."""

    # Required characteristics
    REQUIRED_WH_WORDS = {"who", "what", "when", "where", "why", "how", "how many", "how often"}
    CIRCULAR_PATTERNS = [
        r"does.*detect",
        r"can we.*identify.*using",
        r"will.*alert.*on",
        r"is.*triggered.*by",
        r"can we find.*same.*analytic",
        r"does.*match",
        r"is.*valid",
    ]
    TESTABLE_KEYWORDS = ["what", "where", "when", "how", "how many", "how often"]

    def __init__(self):
        self.test_results = []

    def test_hypothesis(self, hypothesis_text: str, analytic_id: str = "") -> dict:
        """
        Test a single hypothesis for quality.

        Returns: {
            "analytic_id": str,
            "hypothesis": str,
            "overall_score": float (0-1),
            "scores": {
                "ends_with_question": bool,
                "has_wh_word": bool,
                "is_testable": bool,
                "not_circular": bool,
                "reasonable_length": bool
            },
            "issues": [list of issues],
            "grade": "A|B|C|D",
            "feedback": str
        }
    """
        if not hypothesis_text:
            return {
                "analytic_id": analytic_id,
                "hypothesis": "",
                "overall_score": 0.0,
                "scores": {},
                "issues": ["Empty hypothesis"],
                "grade": "F",
                "feedback": "No hypothesis provided"
            }

        text_lower = hypothesis_text.lower().strip()
        issues = []
        scores = {}

        # Test 1: Ends with question mark
        ends_with_question = text_lower.endswith("?")
        if not ends_with_question:
            issues.append("Hypothesis must end with '?'")
        scores["ends_with_question"] = ends_with_question

        # Test 2: Contains wh-word
        has_wh = any(text_lower.startswith(w) for w in self.REQUIRED_WH_WORDS)
        if not has_wh:
            issues.append(f"Hypothesis should start with one of: {self.REQUIRED_WH_WORDS}")
        scores["has_wh_word"] = has_wh

        # Test 3: Is testable (observable, measurable)
        testable_score = self._score_testability(text_lower)
        is_testable = testable_score >= 0.7
        if not is_testable:
            issues.append("Hypothesis is not clearly testable/observable")
        scores["is_testable"] = is_testable

        # Test 4: Not circular
        circularity = self._check_circularity(text_lower)
        not_circular = circularity < 0.5
        if not not_circular:
            issues.append("Hypothesis appears to restate analytic logic (circular)")
        scores["not_circular"] = not_circular

        # Test 5: Reasonable length (20-200 characters)
        length = len(hypothesis_text)
        reasonable_length = 20 < length < 300
        if not reasonable_length:
            issues.append(f"Hypothesis length {length} characters (expected 20-300)")
        scores["reasonable_length"] = reasonable_length

        # Calculate overall score
        component_scores = [
            0.2 * float(ends_with_question),
            0.2 * float(has_wh),
            0.3 * testable_score,
            0.2 * (1.0 - circularity),
            0.1 * float(reasonable_length),
        ]
        overall_score = sum(component_scores)

        # Grade
        if overall_score >= 0.9:
            grade = "A"
        elif overall_score >= 0.75:
            grade = "B"
        elif overall_score >= 0.6:
            grade = "C"
        else:
            grade = "D"

        # Feedback
        feedback = self._generate_feedback(scores, issues)

        result = {
            "analytic_id": analytic_id,
            "hypothesis": hypothesis_text[:100],
            "overall_score": overall_score,
            "scores": scores,
            "issues": issues,
            "grade": grade,
            "feedback": feedback
        }

        self.test_results.append(result)
        return result

    def _score_testability(self, hypothesis_lower: str) -> float:
        """Score how testable a hypothesis is (0-1)."""
        score = 0.5  # Base score

        # Observable/measurable indicators
        measurable_words = ["can", "will", "is", "appear", "match", "show", "indicate"]
        if any(word in hypothesis_lower for word in measurable_words):
            score += 0.2

        # Data source references
        if any(source in hypothesis_lower for source in ["log", "event", "data", "field"]):
            score += 0.2

        # Specific indicators (not vague)
        if any(vague in hypothesis_lower for vague in ["something", "anything", "maybe", "probably"]):
            score -= 0.2

        return min(max(score, 0.0), 1.0)

    def _check_circularity(self, hypothesis_lower: str) -> float:
        """Check for circular reasoning (0-1, higher = more circular)."""
        circularity = 0.0

        for pattern in self.CIRCULAR_PATTERNS:
            if re.search(pattern, hypothesis_lower):
                circularity += 0.2

        return min(circularity, 1.0)

    def _generate_feedback(self, scores: dict, issues: list) -> str:
        """Generate human-readable feedback."""
        if not issues:
            return "Excellent hypothesis - meets all requirements"

        main_issues = issues[:2]  # Show top 2 issues
        feedback = "Issues found: " + "; ".join(main_issues)

        # Add specific guidance
        if not scores.get("has_wh_word"):
            feedback += " Rephrase to start with: what/where/when/how/why?"

        if not scores.get("is_testable"):
            feedback += " Make hypothesis observable/measurable in logs/events."

        if not scores.get("not_circular"):
            feedback += " Avoid restating analytic logic; frame as investigative question."

        return feedback

    def test_batch(self, outputs: dict) -> dict:
        """
        Test hypotheses from multiple outputs.

        Returns: {
            "total_tested": int,
            "grade_distribution": dict,
            "average_score": float,
            "issues_summary": dict,
            "recommendations": list
        }
        """
        results = []

        for analytic_id, output in outputs.items():
            hypothesis = output.get("hunting_hypothesis", {}).get("question", "")
            if hypothesis:
                result = self.test_hypothesis(hypothesis, analytic_id)
                results.append(result)

        # Aggregate
        total = len(results)
        grades = {}
        scores = []
        issues_count = {}

        for result in results:
            grade = result["grade"]
            grades[grade] = grades.get(grade, 0) + 1
            scores.append(result["overall_score"])

            for issue in result["issues"]:
                issues_count[issue] = issues_count.get(issue, 0) + 1

        average_score = sum(scores) / len(scores) if scores else 0

        # Recommendations
        recommendations = []
        if average_score < 0.75:
            recommendations.append(
                "Average hypothesis quality below target (0.75). "
                "Review prompt guidance for wh-questions and testability."
            )

        if grades.get("D", 0) > 0:
            recommendations.append(
                f"{grades.get('D', 0)} hypotheses scored D. "
                "Consider rewriting with specific measurable indicators."
            )

        most_common_issue = max(issues_count.items(), key=lambda x: x[1])[0] if issues_count else None
        if most_common_issue:
            recommendations.append(
                f"Most common issue: {most_common_issue}. "
                "Add example hypotheses to prompt addressing this."
            )

        return {
            "total_tested": total,
            "grade_distribution": grades,
            "average_score": average_score,
            "score_distribution": {
                "A (>= 0.9)": sum(1 for s in scores if s >= 0.9),
                "B (0.75-0.9)": sum(1 for s in scores if 0.75 <= s < 0.9),
                "C (0.6-0.75)": sum(1 for s in scores if 0.6 <= s < 0.75),
                "D (< 0.6)": sum(1 for s in scores if s < 0.6),
            },
            "issues_summary": issues_count,
            "recommendations": recommendations,
            "individual_results": results
        }
