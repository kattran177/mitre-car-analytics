"""
Tactic validation and flagging system.
Detects and flags non-canonical tactic assignments.
"""

# Canonical MITRE ATT&CK technique-to-tactic mappings (common techniques)
CANONICAL_TACTIC_MAP = {
    "T1059": {"TA0002"},  # Command and Scripting Interpreter -> Execution
    "T1053": {"TA0004", "TA0002"},  # Scheduled Task -> Execution
    "T1036": {"TA0005"},  # Masquerading -> Defense Evasion
    "T1078": {"TA0001", "TA0003"},  # Valid Accounts -> Initial Access, Persistence
    "T1547": {"TA0003"},  # Boot or Logon Autostart -> Persistence
    "T1547.001": {"TA0003"},  # Registry Run Keys -> Persistence
    "T1098": {"TA0001", "TA0003"},  # Account Manipulation -> Initial Access, Persistence
    "T1197": {"TA0005"},  # BITS Jobs -> Defense Evasion
}

def validate_tactic_assignment(technique_id: str, assigned_tactics: list) -> dict:
    """
    Validate if assigned tactics match canonical MITRE mappings.

    Returns: {
        "is_canonical": bool,
        "canonical_tactics": list,
        "assigned_tactics": list,
        "non_canonical": list,
        "needs_review": bool,
        "flag_reason": str
    }
    """
    assigned_set = set(assigned_tactics) if assigned_tactics else set()

    # If technique not in our mapping, assume valid (not enough data to verify)
    if technique_id not in CANONICAL_TACTIC_MAP:
        return {
            "is_canonical": True,
            "canonical_tactics": [],
            "assigned_tactics": assigned_tactics,
            "non_canonical": [],
            "needs_review": False,
            "flag_reason": None
        }

    canonical_set = CANONICAL_TACTIC_MAP[technique_id]
    non_canonical = assigned_set - canonical_set

    is_canonical = len(non_canonical) == 0
    needs_review = len(non_canonical) > 0

    flag_reason = None
    if non_canonical:
        flag_reason = f"Non-canonical tactics assigned: {non_canonical}. Canonical: {canonical_set}"

    return {
        "is_canonical": is_canonical,
        "canonical_tactics": sorted(list(canonical_set)),
        "assigned_tactics": sorted(list(assigned_set)),
        "non_canonical": sorted(list(non_canonical)),
        "needs_review": needs_review,
        "flag_reason": flag_reason
    }


def add_tactic_validation_to_output(output: dict) -> dict:
    """
    Add tactic validation flags to attack_mapping section.

    Modifies output in-place to include validation info.
    Returns modified output.
    """
    if "attack_mapping" not in output:
        return output

    attack_mapping = output["attack_mapping"]
    techniques = attack_mapping.get("techniques", [])

    flagged_count = 0
    for tech in techniques:
        tech_id = tech.get("technique_id", "")
        assigned = tech.get("tactics", [])

        validation = validate_tactic_assignment(tech_id, assigned)

        # Add validation result to technique
        tech["tactic_validation"] = {
            "is_canonical": validation["is_canonical"],
            "canonical_tactics": validation["canonical_tactics"],
            "non_canonical": validation["non_canonical"],
            "needs_review": validation["needs_review"]
        }

        if validation["needs_review"]:
            flagged_count += 1
            # Mark technique for analyst review
            tech["analyst_review_flag"] = {
                "flag": True,
                "reason": "Non-canonical tactic assignment",
                "details": validation["flag_reason"]
            }

    # Add summary to attack_mapping
    attack_mapping["tactic_validation_summary"] = {
        "total_techniques": len(techniques),
        "techniques_requiring_review": flagged_count,
        "review_required": flagged_count > 0
    }

    # Add overall flag to output if any techniques need review
    if flagged_count > 0:
        output["requires_analyst_review"] = True
        output["review_flags"] = {
            "tactic_drift": f"{flagged_count} technique(s) with non-canonical tactics"
        }

    return output


def generate_analyst_review_summary(output: dict) -> str:
    """
    Generate human-readable summary of review flags.

    Returns markdown-formatted review summary.
    """
    if not output.get("requires_analyst_review"):
        return ""

    lines = ["## Analyst Review Required\n"]

    attack = output.get("attack_mapping", {})
    techniques = attack.get("techniques", [])

    for tech in techniques:
        if tech.get("analyst_review_flag", {}).get("flag"):
            tech_id = tech.get("technique_id", "")
            reason = tech.get("analyst_review_flag", {}).get("details", "")
            assigned = tech.get("tactics", [])
            canonical = tech.get("tactic_validation", {}).get("canonical_tactics", [])
            non_canonical = tech.get("tactic_validation", {}).get("non_canonical", [])

            lines.append(f"- **{tech_id}**: {reason}")
            lines.append(f"  - Assigned: {assigned}")
            lines.append(f"  - Canonical: {canonical}")
            lines.append(f"  - Extra: {non_canonical}\n")

    return "\n".join(lines)
