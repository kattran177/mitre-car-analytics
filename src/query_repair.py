"""SIEM query validation-repair loop.

When a generated SIEM query fails validation, this module feeds the error back
to the LLM for a targeted fix. This addresses the single-shot generation problem:
most LLM syntax errors are minor (missing pipe, wrong field name) and fixable
with a focused correction prompt.
"""

import json

from src.query_validator import validate_siem_query

# Compact repair prompt — gives the LLM the broken query + specific errors + field map
REPAIR_PROMPT = """Fix this SIEM query. The validator found these issues:

ISSUES:
{issues}

ORIGINAL QUERY:
```
{query}
```

VALID FIELD NAMES (Sysmon):
- Process Create (EventCode=1): Image, ParentImage, CommandLine, ComputerName, User, ProcessId, ParentProcessId, OriginalFileName, Hashes, IntegrityLevel
- Network (EventCode=3): SourceIp, SourcePort, DestinationIp, DestinationPort, Image
- File Create (EventCode=11): TargetFilename, Image
- Registry (EventCode=12/13/14): TargetObject, Details, Image
- Process Access (EventCode=10): SourceImage, TargetImage, GrantedAccess, CallTrace
- Image Load (EventCode=7): ImageLoaded, Image, Signed

Return ONLY the corrected query as plain text (no JSON, no markdown fences, no explanation).
"""


def repair_siem_query(client, model: str, query: str, max_attempts: int = 2) -> tuple[str, bool, list[str]]:
    """Attempt to repair a SIEM query by feeding validation errors back to the LLM.

    Args:
        client: Anthropic client instance
        model: Model name for repair calls
        query: The generated SIEM query to validate/repair
        max_attempts: Maximum repair iterations (default 2)

    Returns:
        (final_query, is_valid, remaining_issues)
    """
    if not query or "NOT APPLICABLE" in query:
        return query, True, []

    is_valid, issues = validate_siem_query(query)
    if is_valid:
        return query, True, []

    current_query = query
    for _ in range(max_attempts):
        prompt = REPAIR_PROMPT.format(issues="\n".join(f"- {i}" for i in issues), query=current_query)

        response = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        current_query = response.content[0].text.strip()
        # Strip markdown fences if LLM wraps the output
        if current_query.startswith("```"):
            lines = current_query.split("\n")
            current_query = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        is_valid, issues = validate_siem_query(current_query)
        if is_valid:
            return current_query, True, []

    return current_query, False, issues
