"""Validate Splunk queries against synthetic test events."""

import re


def _strip_non_filters(query: str) -> str:
    """Remove Splunk clauses that don't filter (index=, | table, | stats, etc.)."""
    # Remove index=, sourcetype=, EventCode=, etc. (before first pipe)
    main = query.split("|")[0]  # Get part before pipes

    # Remove non-filter assignments
    main = re.sub(r'\b(index|sourcetype|EventCode)\s*=\s*[^|\s]+', '', main)

    return main.strip()


def _extract_filter_conditions(query_text: str) -> list[tuple[str, str, str]]:
    """Extract simple filter conditions as (field, operator, value) tuples.

    Examples:
    - field="value" → (field, ==, value)
    - field="*value*" → (field, contains, value)
    - field!="value" → (field, !=, value)
    - field="*value" → (field, endswith, value)
    """
    conditions = []

    # Pattern: field="..."
    pattern = r'(\w+)\s*=\s*"([^"]*)"'
    for match in re.finditer(pattern, query_text):
        field, value = match.groups()
        op = "=="  # exact match by default

        # Check for wildcards
        if "*" in value:
            if value.startswith("*") and value.endswith("*"):
                op = "contains"
                value = value.strip("*")
            elif value.startswith("*"):
                op = "endswith"
                value = value.lstrip("*")
            elif value.endswith("*"):
                op = "startswith"
                value = value.rstrip("*")

        conditions.append((field, op, value))

    # Pattern: field="value" (without wildcards) - plain equality
    # Already handled above

    # Pattern: field!=... (NOT EQUAL)
    pattern = r'(\w+)\s*!=\s*"?([^"\s]+)"?'
    for match in re.finditer(pattern, query_text):
        field, value = match.groups()
        conditions.append((field, "!=", value.strip('"')))

    return conditions


def _evaluate_condition(row: dict, field: str, op: str, value: str) -> bool:
    """Evaluate a single filter condition against an event row."""
    row_value = str(row.get(field, "")).lower()
    value_lower = value.lower()

    if op == "==":
        return row_value == value_lower
    elif op == "!=":
        return row_value != value_lower
    elif op == "contains":
        return value_lower in row_value
    elif op == "startswith":
        return row_value.startswith(value_lower)
    elif op == "endswith":
        return row_value.endswith(value_lower)
    return False


def validate_siem_query(query: str) -> tuple[bool, list[str]]:
    """Validate SIEM query syntax (Splunk/KQL).

    Returns (is_valid: bool, issues: list[str])
    - is_valid=True if query has no syntax errors
    - issues lists detected problems for manual review
    """
    issues = []

    if not query or len(query.strip()) == 0:
        return False, ["Empty query"]

    if "NOT APPLICABLE" in query:
        return True, []  # Explicitly marked N/A is valid

    # Check for common Splunk syntax errors
    query_lower = query.lower()

    # Missing pipe operators between commands
    if "where" in query_lower and "|" not in query:
        if not query_lower.startswith("index="):
            issues.append("Missing pipe before 'where' clause")

    # Incomplete WHERE clause (missing condition)
    if query_lower.count("where") > 0:
        # Check for valid operators after where
        valid_ops = ["=", "!=", "<", ">", "in", "like", "not", "and", "or"]
        where_pattern = r'where\s+([a-z_]+)'
        where_matches = re.findall(where_pattern, query_lower)
        if where_matches:
            for field in where_matches:
                # Check if field is followed by an operator
                field_pattern = rf'where\s+{field}\s+'
                if re.search(field_pattern, query_lower):
                    # Has field and space, check for operator
                    after_field = re.search(rf'{field}\s+(\S+)', query_lower)
                    if after_field:
                        next_token = after_field.group(1)
                        if not any(op in next_token for op in valid_ops):
                            issues.append(f"Invalid operator after WHERE {field}")

        # Check for unclosed parentheses in where clause
        where_section = query[query.lower().find("where"):]
        if where_section.count("(") != where_section.count(")"):
            issues.append("Mismatched parentheses in WHERE clause")

    # Check for undefined fields (common hallucinations)
    hallucination_patterns = {
        "process_parent": "Should be: parent_exe or process/create/parent_exe",
        "event_timestamp": "Should be: timestamp or time field",
        "event_id": "Should be: EventID or event code",
        "command_args": "Should be: command_line or CommandLine",
        "src_ip": "Should be: source_ip or src",
        "dst_ip": "Should be: dest_ip or destination",
    }

    for bad_field, suggestion in hallucination_patterns.items():
        if bad_field in query_lower:
            issues.append(f"Likely hallucinated field '{bad_field}' - {suggestion}")

    # Check for incomplete pipe chains
    pipes = [p.strip() for p in query.split("|") if p.strip()]
    for i, pipe in enumerate(pipes[1:], 1):  # Skip index= part
        if not pipe or len(pipe.split()) < 2:
            issues.append(f"Incomplete pipe command at position {i}: '{pipe}'")

    is_valid = len(issues) == 0
    return is_valid, issues


def validate_splunk_query(query: str, events: list[dict]) -> tuple[bool, str]:
    """Validate Splunk query against test events.

    Returns (returns_results: bool, reason: str)
    - returns_results=True if at least one event matches all conditions
    - reason explains the result
    """
    if not events:
        return False, "No test events provided"

    if not query or "NOT APPLICABLE" in query:
        return True, "Query is N/A for this analytic (tool-based)"

    # Clean query
    clean_query = _strip_non_filters(query)
    if not clean_query:
        return True, "No filter conditions found (may be complex query)"

    # Extract conditions
    conditions = _extract_filter_conditions(clean_query)
    if not conditions:
        return True, "Could not parse filter conditions (complex syntax)"

    # Test each event
    for i, event in enumerate(events):
        all_match = all(
            _evaluate_condition(event, field, op, value)
            for field, op, value in conditions
        )
        if all_match:
            return True, f"Matched test event {i}"

    # No events matched
    cond_str = "; ".join(f"{f}{op}{v}" for f, op, v in conditions)
    return False, f"No events matched conditions: {cond_str}"
