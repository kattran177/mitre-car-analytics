"""
Technique-to-tactic validation with scoring and rejection.
Used during generation to catch and flag drift early.
"""

# Canonical MITRE ATT&CK mappings (expanded set)
CANONICAL_MAPPINGS = {
    "T1059": {"TA0002"},  # Command/Scripting -> Execution
    "T1053": {"TA0004", "TA0002"},  # Scheduled Task -> Execution
    "T1036": {"TA0005"},  # Masquerading -> Defense Evasion
    "T1078": {"TA0001", "TA0003"},  # Valid Accounts -> Initial Access, Persistence
    "T1547": {"TA0003"},  # Boot/Logon Autostart -> Persistence
    "T1098": {"TA0001", "TA0003"},  # Account Manipulation -> Initial Access, Persistence
    "T1197": {"TA0005"},  # BITS Jobs -> Defense Evasion
    "T1134": {"TA0005", "TA0004"},  # Access Token Manipulation -> Defense Evasion, Execution
    "T1197": {"TA0005"},  # BITS Jobs -> Defense Evasion
    "T1110": {"TA0001"},  # Brute Force -> Initial Access
    "T1557": {"TA0006"},  # Man-in-the-Middle -> Credential Access
}

def validate_technique_tactic_pair(technique_id: str, assigned_tactics: list) -> dict:
    """
    Validate a single technique-tactic pair.

    Returns: {
        "valid": bool,
        "technique_id": str,
        "assigned_tactics": list,
        "canonical_tactics": list,
        "invalid_tactics": list,
        "validation_score": float (0-1, 1=perfect),
        "message": str
    }
    """
    assigned_set = set(assigned_tactics) if assigned_tactics else set()

    # Unknown technique - assume valid (benefit of doubt)
    if technique_id not in CANONICAL_MAPPINGS:
        return {
            "valid": True,
            "technique_id": technique_id,
            "assigned_tactics": assigned_tactics,
            "canonical_tactics": [],
            "invalid_tactics": [],
            "validation_score": 1.0,
            "message": "Technique not in validation set (assumed valid)"
        }

    canonical_set = CANONICAL_MAPPINGS[technique_id]
    invalid = assigned_set - canonical_set

    # Score: 1.0 if all canonical, 0.5 if partial, 0.0 if all invalid
    if len(assigned_set) == 0:
        score = 0.0
        is_valid = False
    elif len(invalid) == 0:
        score = 1.0
        is_valid = True
    else:
        # Partial match: valid_count / total_count
        valid_count = len(assigned_set - invalid)
        score = valid_count / len(assigned_set) if assigned_set else 0.0
        is_valid = False

    message = "Valid canonical assignment" if is_valid else f"Invalid tactics: {invalid}"

    return {
        "valid": is_valid,
        "technique_id": technique_id,
        "assigned_tactics": sorted(list(assigned_set)),
        "canonical_tactics": sorted(list(canonical_set)),
        "invalid_tactics": sorted(list(invalid)),
        "validation_score": score,
        "message": message
    }


def validate_attack_mapping(attack_mapping: dict) -> dict:
    """
    Validate entire attack_mapping section.

    Returns: {
        "overall_valid": bool,
        "overall_score": float,
        "technique_validations": [list of validations],
        "invalid_count": int,
        "partial_count": int,
        "valid_count": int,
        "recommendations": [list of strings]
    }
    """
    if not attack_mapping or not isinstance(attack_mapping, dict):
        return {
            "overall_valid": False,
            "overall_score": 0.0,
            "technique_validations": [],
            "invalid_count": 0,
            "partial_count": 0,
            "valid_count": 0,
            "recommendations": ["Invalid or missing attack_mapping"]
        }

    techniques = attack_mapping.get("techniques", [])
    validations = []
    scores = []
    invalid_count = 0
    partial_count = 0
    valid_count = 0
    recommendations = []

    for tech in techniques:
        tech_id = tech.get("technique_id", "")
        assigned = tech.get("tactics", [])

        validation = validate_technique_tactic_pair(tech_id, assigned)
        validations.append(validation)
        scores.append(validation["validation_score"])

        if validation["valid"]:
            valid_count += 1
        elif validation["validation_score"] > 0:
            partial_count += 1
            recommendations.append(
                f"{tech_id}: Remove non-canonical {validation['invalid_tactics']}, "
                f"keep {validation['canonical_tactics']}"
            )
        else:
            invalid_count += 1
            recommendations.append(
                f"{tech_id}: Replace all tactics with canonical {validation['canonical_tactics']}"
            )

    # Overall score is average of technique scores
    overall_score = sum(scores) / len(scores) if scores else 0.0
    overall_valid = invalid_count == 0 and partial_count == 0

    return {
        "overall_valid": overall_valid,
        "overall_score": overall_score,
        "technique_validations": validations,
        "invalid_count": invalid_count,
        "partial_count": partial_count,
        "valid_count": valid_count,
        "total_techniques": len(techniques),
        "recommendations": recommendations
    }


def should_reject_output(validation_result: dict, reject_threshold: float = 0.7) -> tuple:
    """
    Determine if output should be rejected based on validation score.

    Args:
        validation_result: Result from validate_attack_mapping()
        reject_threshold: Minimum score to accept (0-1)

    Returns: (should_reject, reason)
    """
    score = validation_result.get("overall_score", 0.0)

    if score < reject_threshold:
        invalid = validation_result.get("invalid_count", 0)
        partial = validation_result.get("partial_count", 0)
        reason = f"Attack mapping validation failed: score {score:.2f} < {reject_threshold} " \
                f"({invalid} invalid, {partial} partial)"
        return True, reason

    return False, None
