"""
Failure mode detection for LLM-generated threat hunting outputs.

Detects 5 known failure modes:
1. Field Hallucination - Non-existent field names in SIEM queries
2. Tactic Drift - Incorrect ATT&CK tactic assignments
3. Hypothesis Circularity - Hypothesis restates analytic logic
4. Context Bleed - RAG context confusion (requires comparison)
5. Over-Confidence - Uncertain mappings without hedging
"""
import json
import re
from pathlib import Path

# Load CAR data model schema
CAR_DATA_MODEL = {
    # Process fields
    "process/create/exe", "process/create/parent_exe", "process/create/command_line",
    "process/create/user", "process/create/pid", "process/create/ppid",
    "process/create/integrity_level",
    # File fields
    "file/create/filename", "file/create/path", "file/create/hashes",
    # Network fields
    "network/http/url", "network/dns/query", "network/flow/source_ip", "network/flow/dest_ip",
    # Registry fields
    "registry/add/key", "registry/add/value",
    # Event fields
    "event/timestamp", "event/code", "event/computer", "event/user",
}

# Valid ATT&CK tactics (TA####)
VALID_TACTICS = {
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
    "TA0011", "TA0012", "TA0013", "TA0014",
}

# Technique-tactic mappings (subset - common ones)
TECHNIQUE_TACTIC_MAP = {
    "T1059": {"TA0002", "TA0004"},  # Command and Scripting Interpreter
    "T1053": {"TA0004", "TA0002"},  # Scheduled Task/Job
    "T1036": {"TA0005"},            # Masquerading
    "T1078": {"TA0001", "TA0003"},  # Valid Accounts
    "T1547": {"TA0003"},            # Boot or Logon Autostart Execution
    "T1547.001": {"TA0003"},        # Registry Run Keys / Startup Folder
}

def detect_field_hallucination(siem_query: dict) -> dict:
    """
    Detect if SIEM query uses non-existent field names.

    Returns: {
        "detected": bool,
        "hallucinated_fields": [list of field names],
        "evidence": str,
        "severity": "high|medium|low"
    }
    """
    if not siem_query or not isinstance(siem_query, dict):
        return {"detected": False, "hallucinated_fields": [], "evidence": "", "severity": "low"}

    query_text = siem_query.get("query", "").lower()
    if "NOT APPLICABLE" in query_text or not query_text:
        return {"detected": False, "hallucinated_fields": [], "evidence": "", "severity": "low"}

    # Extract field references from query (patterns like field_name= or field_name:)
    field_pattern = r'\b([a-z_/]+)\s*[=!<>:]'
    found_fields = re.findall(field_pattern, query_text)

    hallucinated = []
    for field in found_fields:
        # Normalize field reference
        field_normalized = field.strip('_').lower()

        # Check if it's a known CAR data model field
        is_valid = any(field_normalized in dm.lower() for dm in CAR_DATA_MODEL)

        # Common hallucinations
        hallucination_indicators = {
            "process_parent": True,  # should be parent_exe
            "event_timestamp": True,  # should be timestamp
            "event_id": True,  # should be EventCode
            "command_args": True,  # should be command_line
            "src_ip": True,  # should be source_ip
            "dst_ip": True,  # should be dest_ip
            "hostname": True,  # may be valid but context-dependent
        }

        if field_normalized in hallucination_indicators and not is_valid:
            hallucinated.append(field)

    severity = "high" if len(hallucinated) > 2 else "medium" if len(hallucinated) > 0 else "low"

    return {
        "detected": len(hallucinated) > 0,
        "hallucinated_fields": hallucinated,
        "evidence": query_text[:200],
        "severity": severity
    }


def detect_tactic_drift(attack_mapping: dict, analytic_id: str = "") -> dict:
    """
    Detect if assigned tactics don't match technique definitions.

    Returns: {
        "detected": bool,
        "drift_count": int,
        "drifts": [{"technique_id": "", "assigned_tactics": [], "expected_tactics": []}],
        "severity": "high|medium|low"
    }
    """
    if not attack_mapping or not isinstance(attack_mapping, dict):
        return {"detected": False, "drift_count": 0, "drifts": [], "severity": "low"}

    techniques = attack_mapping.get("techniques", [])
    drifts = []

    for tech in techniques:
        tech_id = tech.get("technique_id", "")
        assigned = set(tech.get("tactics", []))

        # Only check if we have mapping
        if tech_id in TECHNIQUE_TACTIC_MAP:
            expected = TECHNIQUE_TACTIC_MAP[tech_id]

            # Check for drift: assigned tactics not in expected
            invalid_tactics = assigned - expected
            if invalid_tactics:
                drifts.append({
                    "technique_id": tech_id,
                    "assigned_tactics": list(assigned),
                    "expected_tactics": list(expected),
                    "drift": list(invalid_tactics)
                })

    severity = "high" if len(drifts) > 2 else "medium" if len(drifts) > 0 else "low"

    return {
        "detected": len(drifts) > 0,
        "drift_count": len(drifts),
        "drifts": drifts,
        "severity": severity
    }


def detect_hypothesis_circularity(hypothesis: dict, analytic_summary: str = "") -> dict:
    """
    Detect if hypothesis simply restates analytic logic.

    Returns: {
        "detected": bool,
        "circularity_score": float (0-1),
        "evidence": str,
        "severity": "high|medium|low"
    }
    """
    if not hypothesis or not isinstance(hypothesis, dict):
        return {"detected": False, "circularity_score": 0.0, "evidence": "", "severity": "low"}

    question = hypothesis.get("question", "").lower()

    # Red flags for circularity
    circular_patterns = [
        r"does.*detect",
        r"can we.*identify.*using",
        r"will.*alert.*on",
        r"is.*triggered.*by",
        r"can we find.*same.*analytic",
    ]

    circularity_score = 0.0
    for pattern in circular_patterns:
        if re.search(pattern, question):
            circularity_score += 0.2

    # Check if question ends with "?" (should be testable)
    if not question.endswith("?"):
        circularity_score += 0.1

    # Check if question uses wh- words (good indicators of investigation)
    wh_words = ["who", "what", "when", "where", "why", "how"]
    has_wh = any(question.startswith(w) for w in wh_words)
    if not has_wh:
        circularity_score += 0.2

    severity = "high" if circularity_score > 0.6 else "medium" if circularity_score > 0.3 else "low"

    return {
        "detected": circularity_score > 0.3,
        "circularity_score": min(circularity_score, 1.0),
        "evidence": question[:100],
        "severity": severity
    }


def detect_over_confidence(output: dict) -> dict:
    """
    Detect over-confidence: uncertain mappings without hedging language.

    Returns: {
        "detected": bool,
        "over_confidence_indicators": [list of findings],
        "hedging_score": float (0-1, higher = more hedging),
        "severity": "high|medium|low"
    }
    """
    if not output or not isinstance(output, dict):
        return {"detected": False, "over_confidence_indicators": [], "hedging_score": 1.0, "severity": "low"}

    indicators = []
    hedging_words = ["may", "might", "could", "possible", "likely", "probably", "uncertain", "rare"]
    hedging_count = 0
    total_text = ""

    # Check summary_explanation
    se = output.get("summary_explanation", {})
    summary = se.get("summary", "")
    total_text += summary

    # Check SIEM query confidence
    siem = output.get("siem_query", {})
    if siem.get("confidence") == "high" and siem.get("platform") == "not_applicable":
        indicators.append("High confidence on N/A SIEM query")

    # Check techniques marked as high confidence but are rare (T#### with rare=true)
    attack = output.get("attack_mapping", {})
    for tech in attack.get("techniques", []):
        if tech.get("confidence") == "high" and "rare" in str(tech).lower():
            indicators.append(f"High confidence on potentially rare technique {tech.get('technique_id')}")

    # Count hedging language
    text_lower = total_text.lower()
    for word in hedging_words:
        hedging_count += text_lower.count(word)

    # Calculate hedging score (more hedging = better, but less = over-confident)
    text_length = len(text_lower.split())
    hedging_score = min(hedging_count / max(text_length / 10, 1), 1.0)

    # Over-confidence if low hedging and high confidence claims
    is_over_confident = (hedging_score < 0.3) and len(indicators) > 0

    severity = "high" if is_over_confident and len(indicators) > 2 else "medium" if is_over_confident else "low"

    return {
        "detected": is_over_confident,
        "over_confidence_indicators": indicators,
        "hedging_score": hedging_score,
        "severity": severity
    }


def detect_context_bleed(output: dict, reference_analytic: dict = None) -> dict:
    """
    Detect context bleed: confusion with other analytics from RAG.

    Returns: {
        "detected": bool,
        "bleed_indicators": [list of indicators],
        "severity": "high|medium|low"
    }
    """
    if not output or not isinstance(output, dict):
        return {"detected": False, "bleed_indicators": [], "severity": "low"}

    indicators = []

    # Check for multi-analytic references (mention of other CAR IDs)
    all_text = json.dumps(output).lower()
    car_pattern = r'car-\d{4}-\d{2}-\d{3}'
    found_cars = re.findall(car_pattern, all_text)
    output_id = output.get("analytic_id", "").lower()

    # If multiple CAR IDs found, possible context bleed
    if len(found_cars) > 1:
        indicators.append(f"Multiple CAR IDs found: {found_cars}")

    # Check for contradictory field references
    all_fields = []
    if "siem_query" in output:
        query = output["siem_query"].get("query", "")
        fields = re.findall(r'\b[a-z_/]+\s*[=:]', query.lower())
        all_fields.extend(fields)

    if "false_positives" in output:
        fp = output["false_positives"].get("explanation", "")
        fp_fields = re.findall(r'\b[a-z_/]+\s+field', fp.lower())
        all_fields.extend(fp_fields)

    # High variance in field references could indicate bleed
    unique_fields = len(set(all_fields))
    if unique_fields > 10:
        indicators.append(f"Unusual field diversity: {unique_fields} unique fields")

    severity = "high" if len(indicators) > 1 else "medium" if len(indicators) > 0 else "low"

    return {
        "detected": len(indicators) > 1,
        "bleed_indicators": indicators,
        "severity": severity
    }


def comprehensive_failure_analysis(output: dict) -> dict:
    """
    Run all failure mode detections on a single output.

    Returns dict with all detection results.
    """
    results = {
        "analytic_id": output.get("analytic_id", "unknown"),
        "field_hallucination": detect_field_hallucination(output.get("siem_query", {})),
        "tactic_drift": detect_tactic_drift(output.get("attack_mapping", {})),
        "hypothesis_circularity": detect_hypothesis_circularity(
            output.get("hunting_hypothesis", {}),
            output.get("summary_explanation", {}).get("summary", "")
        ),
        "over_confidence": detect_over_confidence(output),
        "context_bleed": detect_context_bleed(output),
    }

    # Calculate failure severity
    total_failures = sum(1 for v in results.values()
                        if isinstance(v, dict) and v.get("detected", False))

    results["total_failures"] = total_failures
    results["failure_severity"] = "critical" if total_failures >= 3 else "high" if total_failures >= 2 else "medium" if total_failures == 1 else "low"

    return results
