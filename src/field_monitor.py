"""
Field hallucination monitoring.
Tracks field references and detects new hallucinated fields.
"""
import re
from collections import defaultdict

# Known valid CAR data model fields (from ingest module)
VALID_FIELDS = {
    # Process fields
    "exe", "parent_exe", "command_line", "user", "pid", "ppid",
    "integrity_level", "process_name", "image", "parentimage",
    # File fields
    "filename", "path", "hashes", "hash",
    # Network fields
    "url", "query", "source_ip", "dest_ip", "src_ip", "dst_ip",
    # Registry fields
    "key", "value", "registry",
    # Event fields
    "timestamp", "time", "event_code", "eventcode", "computer",
    "computername", "eventid", "event_id",
    # Common Splunk fields
    "index", "sourcetype",
}

# Known hallucination patterns (field names that often appear but are wrong)
HALLUCINATION_PATTERNS = {
    "process_parent": "Should be: parent_exe",
    "event_timestamp": "Should be: timestamp or time",
    "event_id": "Should be: EventCode or event_code",
    "command_args": "Should be: command_line or CommandLine",
    "src_ip": "Should be: source_ip",
    "dst_ip": "Should be: dest_ip",
    "process_path": "Should be: exe or Image",
    "parent_process": "Should be: parent_exe or ParentImage",
    "user_name": "Should be: user or User",
}


def extract_fields_from_query(query_text: str) -> set:
    """
    Extract field references from SIEM query.

    Returns set of field names.
    """
    if not query_text or "NOT APPLICABLE" in query_text:
        return set()

    # Pattern: word followed by = or : (typical field reference)
    pattern = r'\b([a-z_]+)\s*[=:]'
    matches = re.findall(pattern, query_text.lower())

    return set(matches)


def check_field_validity(field_name: str) -> dict:
    """
    Check if a field is valid or hallucinated.

    Returns: {
        "field": str,
        "valid": bool,
        "is_known_hallucination": bool,
        "suggestion": str,
        "severity": "high|medium|low"
    }
    """
    field_lower = field_name.lower()

    # Check against known valid fields
    if field_lower in VALID_FIELDS:
        return {
            "field": field_name,
            "valid": True,
            "is_known_hallucination": False,
            "suggestion": None,
            "severity": "low"
        }

    # Check if it matches a known hallucination pattern
    if field_lower in HALLUCINATION_PATTERNS:
        return {
            "field": field_name,
            "valid": False,
            "is_known_hallucination": True,
            "suggestion": HALLUCINATION_PATTERNS[field_lower],
            "severity": "high"
        }

    # Unknown field - possibly hallucinated
    return {
        "field": field_name,
        "valid": False,
        "is_known_hallucination": False,
        "suggestion": f"Unknown field (not in CAR data model)",
        "severity": "medium"
    }


def audit_fields_in_output(output: dict) -> dict:
    """
    Audit all field references in an output for hallucinations.

    Returns: {
        "analytic_id": str,
        "total_fields": int,
        "valid_fields": int,
        "hallucinated_fields": [list of invalid fields],
        "known_hallucinations": [list of known bad patterns],
        "unknown_fields": [list of unknown fields],
        "severity_level": "critical|high|medium|low",
        "recommendation": str
    }
    """
    analytic_id = output.get("analytic_id", "unknown")
    hallucinated = []
    known_hallucinations = []
    unknown_fields = []
    all_fields = set()

    # Extract fields from SIEM query
    siem = output.get("siem_query", {})
    query_text = siem.get("query", "")
    if query_text and "NOT APPLICABLE" not in query_text:
        all_fields.update(extract_fields_from_query(query_text))

    # Extract fields from false_positives explanation
    fp = output.get("false_positives", {})
    explanation = fp.get("explanation", "")
    fp_fields = extract_fields_from_query(explanation)
    all_fields.update(fp_fields)

    # Check each field
    for field in all_fields:
        check = check_field_validity(field)

        if not check["valid"]:
            hallucinated.append(check)

            if check["is_known_hallucination"]:
                known_hallucinations.append(field)
            else:
                unknown_fields.append(field)

    # Determine severity
    if known_hallucinations:
        severity = "high"
    elif len(unknown_fields) > 2:
        severity = "medium"
    elif len(unknown_fields) > 0:
        severity = "low"
    else:
        severity = "low"

    # Recommendation
    if known_hallucinations:
        recommendation = f"Fix known hallucinations: {known_hallucinations}"
    elif unknown_fields:
        recommendation = f"Verify unknown fields: {unknown_fields}"
    else:
        recommendation = "No field issues detected"

    return {
        "analytic_id": analytic_id,
        "total_fields": len(all_fields),
        "valid_fields": len(all_fields) - len(hallucinated),
        "hallucinated_count": len(hallucinated),
        "hallucinated_fields": hallucinated,
        "known_hallucinations": known_hallucinations,
        "unknown_fields": unknown_fields,
        "severity_level": severity,
        "recommendation": recommendation
    }


def generate_field_audit_report(outputs: dict) -> dict:
    """
    Generate comprehensive field audit report for multiple outputs.

    Returns: {
        "total_analytics": int,
        "analytics_with_hallucinations": int,
        "hallucination_patterns": dict (field -> count),
        "severity_distribution": dict,
        "recommendations": [list of strings]
    }
    """
    audits = [audit_fields_in_output(output) for output in outputs.values()]

    # Aggregate results
    total = len(outputs)
    with_hallucinations = sum(1 for a in audits if a["hallucinated_count"] > 0)

    # Count hallucination patterns
    pattern_counts = defaultdict(int)
    for audit in audits:
        for field_check in audit["hallucinated_fields"]:
            pattern_counts[field_check["field"]] += 1

    # Severity distribution
    severity_dist = defaultdict(int)
    for audit in audits:
        severity_dist[audit["severity_level"]] += 1

    # Recommendations
    recommendations = []
    if with_hallucinations > total * 0.1:
        recommendations.append(
            f"High hallucination rate ({with_hallucinations}/{total}). "
            "Review SIEM query generation prompt."
        )

    if pattern_counts:
        most_common = max(pattern_counts.items(), key=lambda x: x[1])
        recommendations.append(
            f"Most common hallucination: '{most_common[0]}' ({most_common[1]} times). "
            "Add correction to prompt."
        )

    return {
        "total_analytics": total,
        "analytics_with_hallucinations": with_hallucinations,
        "hallucination_rate_pct": 100 * with_hallucinations / total if total > 0 else 0,
        "hallucination_patterns": dict(pattern_counts),
        "severity_distribution": dict(severity_dist),
        "recommendations": recommendations,
        "individual_audits": audits
    }
