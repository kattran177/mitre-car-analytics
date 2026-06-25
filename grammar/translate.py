"""Translate parsed CAR pseudocode AST into Splunk SPL queries.

Uses deterministic field mapping and template-based translation.
No LLM involved — this is purely mechanical.
"""

# CAR data model field → Sysmon field name mapping
FIELD_MAP = {
    # Process:Create (EventCode=1)
    "exe": "Image",
    "parent_exe": "ParentImage",
    "command_line": "CommandLine",
    "hostname": "ComputerName",
    "image_path": "Image",
    "parent_image_path": "ParentImage",
    "parent_command_line": "ParentCommandLine",
    "ppid": "ParentProcessId",
    "pid": "ProcessId",
    "user": "User",
    "integrity_level": "IntegrityLevel",
    "current_working_directory": "CurrentDirectory",
    "parent_image": "ParentImage",
    # File:Create (EventCode=11)
    "file_path": "TargetFilename",
    "file_name": "TargetFilename",
    # Module:Load (EventCode=7)
    "module_path": "ImageLoaded",
    "signer": "Signed",
    # Registry (EventCode=12/13/14)
    "key": "TargetObject",
    # Network (EventCode=3)
    "dest_port": "DestinationPort",
    "src_port": "SourcePort",
    "dest_ip": "DestinationIp",
    "src_ip": "SourceIp",
    # Thread:RemoteCreate (EventCode=8)
    "start_function": "StartFunction",
    "src_image_path": "SourceImage",
    # Process Access (EventCode=10)
    "target_image": "TargetImage",
    "source_image": "SourceImage",
}

# Data model → Sysmon EventCode
MODEL_EVENT_CODE = {
    ("Process", "Create"): "1",
    ("Process", "Terminate"): "5",
    ("Network", "Connect"): "3",
    ("Flow", "Start"): "3",
    ("Flow", "End"): "3",
    ("Flow", "Message"): "3",
    ("File", "Create"): "11",
    ("File", "Modify"): "2",
    ("Module", "Load"): "7",
    ("Registry", "Create"): "12",
    ("Registry", "Remove"): "12",
    ("Registry", "Edit"): "13",
    ("Thread", "RemoteCreate"): "8",
    ("UserSession", "Login"): None,  # Windows Security EventCode=4624
}


def ast_to_splunk(ast: list[dict]) -> str | None:
    """Convert parsed AST to Splunk SPL query.

    Returns None if the analytic cannot be expressed as Splunk SPL
    (e.g., requires tool-based detection or unsupported operations).
    """
    # Find the search statement to determine event source
    search_stmts = [s for s in ast if s["type"] == "search"]
    filter_stmts = [s for s in ast if s["type"] == "filter"]
    output_stmts = [s for s in ast if s["type"] == "output"]

    if not search_stmts:
        return None

    # Determine EventCode from data model
    model = search_stmts[0]["models"][0]
    if isinstance(model, dict) and "actions" in model:
        # Grouped models like (Registry:Create AND Registry:Remove)
        event_codes = []
        for action in model["actions"]:
            ec = MODEL_EVENT_CODE.get((model["object"], action))
            if ec:
                event_codes.append(ec)
        event_code_clause = " OR ".join(f"EventCode={ec}" for ec in set(event_codes))
    else:
        obj = model.get("object", "")
        action = model.get("action", "")
        ec = MODEL_EVENT_CODE.get((obj, action))
        if ec:
            event_code_clause = f"EventCode={ec}"
        elif obj == "UserSession":
            # Windows Security log
            return _translate_user_session(ast)
        else:
            event_code_clause = ""

    # Build index line
    parts = [f"index=__your_sysmon_index__ {event_code_clause}".strip()]

    # Process filters into WHERE/search clauses
    for filt in filter_stmts:
        condition = filt["condition"]
        splunk_cond = _condition_to_splunk(condition)
        if splunk_cond:
            parts.append(splunk_cond)

    # Add table/output fields
    if output_stmts:
        # Default useful fields based on event type
        table_fields = _default_table_fields(search_stmts[0]["models"][0])
        parts.append(f"| table {', '.join(table_fields)}")

    return "\n".join(parts)


def _condition_to_splunk(cond: dict, negate: bool = False) -> str:
    """Recursively convert a condition AST node to Splunk search syntax."""
    op = cond.get("op")

    if op == "and":
        left = _condition_to_splunk(cond["left"])
        right = _condition_to_splunk(cond["right"])
        return f"{left} {right}" if not negate else f"NOT ({left} {right})"

    if op == "or":
        left = _condition_to_splunk(cond["left"])
        right = _condition_to_splunk(cond["right"])
        return f"({left} OR {right})"

    if op == "not":
        return _condition_to_splunk(cond["operand"], negate=True)

    if op == "==":
        field = _map_field(cond["field"])
        value = _format_value(cond["value"])
        prefix = "NOT " if negate else ""
        return f"{prefix}{field}={value}"

    if op == "!=":
        field = _map_field(cond["field"])
        value = _format_value(cond["value"])
        # != in Splunk: field!=value or NOT field=value
        if negate:
            return f"{field}={value}"
        return f"{field}!={value}"

    if op == "not_in":
        field = _map_field(cond["field"])
        values = [_format_value(v) for v in cond["values"]]
        exclusions = " ".join(f"{field}!={v}" for v in values)
        return exclusions

    if op == "in":
        field = _map_field(cond["field"])
        values = [_format_value(v) for v in cond["values"]]
        inclusions = " OR ".join(f"{field}={v}" for v in values)
        return f"({inclusions})"

    if op == "match":
        field = _map_field(cond["field"])
        pattern = cond["pattern"]
        return f'| regex {field}="{pattern}"'

    if op == "exists":
        field = _map_field(cond["field"])
        return f"{field}=*"

    if op == "ref":
        # Bare field reference (shouldn't appear at top level normally)
        return ""

    return ""


def _map_field(field: str) -> str:
    """Map a CAR pseudocode field name to Sysmon field name."""
    # Handle dotted fields: take the last part for mapping
    parts = field.split(".")
    leaf = parts[-1]
    return FIELD_MAP.get(leaf, leaf)


def _format_value(value) -> str:
    """Format a value for Splunk syntax."""
    if value is None:
        return '""'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # If contains wildcards, keep as-is
        if "*" in value or "\\" in value:
            return f'"{value}"'
        return f'"{value}"'
    return str(value)


def _default_table_fields(model: dict) -> list[str]:
    """Return sensible default table fields based on data model."""
    obj = model.get("object", "")
    if obj in ("Process",):
        return ["ComputerName", "User", "Image", "ParentImage", "CommandLine"]
    if obj == "File":
        return ["ComputerName", "Image", "TargetFilename"]
    if obj == "Registry":
        return ["ComputerName", "Image", "TargetObject", "Details"]
    if obj in ("Flow", "Network"):
        return ["ComputerName", "Image", "SourceIp", "DestinationIp", "DestinationPort"]
    if obj == "Module":
        return ["ComputerName", "Image", "ImageLoaded", "Signed"]
    return ["ComputerName", "Image"]


def _translate_user_session(ast: list[dict]) -> str:
    """Translate UserSession-based analytics to Windows Security log queries."""
    parts = ["index=__your_win_event_log_index__ EventCode=4624"]
    for filt in (s for s in ast if s["type"] == "filter"):
        cond = _condition_to_splunk(filt["condition"])
        if cond:
            parts.append(cond)
    parts.append("| table ComputerName, Account, LogonType, SourceNetworkAddress")
    return "\n".join(parts)
