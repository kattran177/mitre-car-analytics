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
    "extension": "TargetFilename",
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


# === KQL TRANSLATION ===

# CAR field → KQL (Microsoft Defender/Sentinel) field mapping
KQL_FIELD_MAP = {
    "exe": "FileName",
    "parent_exe": "InitiatingProcessFileName",
    "command_line": "ProcessCommandLine",
    "hostname": "DeviceName",
    "image_path": "FolderPath",
    "parent_image_path": "InitiatingProcessFolderPath",
    "ppid": "InitiatingProcessId",
    "pid": "ProcessId",
    "user": "AccountName",
    "file_path": "FolderPath",
    "file_name": "FileName",
    "dest_port": "RemotePort",
    "src_port": "LocalPort",
    "dest_ip": "RemoteIP",
    "src_ip": "LocalIP",
    "key": "RegistryKey",
    "module_path": "FileName",
}

KQL_MODEL_TABLE = {
    ("Process", "Create"): "DeviceProcessEvents",
    ("File", "Create"): "DeviceFileEvents",
    ("File", "Modify"): "DeviceFileEvents",
    ("Registry", "Create"): "DeviceRegistryEvents",
    ("Registry", "Edit"): "DeviceRegistryEvents",
    ("Network", "Connect"): "DeviceNetworkEvents",
    ("Flow", "Start"): "DeviceNetworkEvents",
    ("Flow", "Message"): "DeviceNetworkEvents",
    ("Module", "Load"): "DeviceImageLoadEvents",
}


def ast_to_kql(ast: list[dict]) -> str | None:
    """Convert parsed AST to KQL (Microsoft Defender/Sentinel)."""
    search_stmts = [s for s in ast if s["type"] == "search"]
    filter_stmts = [s for s in ast if s["type"] == "filter"]

    if not search_stmts:
        return None

    model = search_stmts[0]["models"][0]
    obj = model.get("object", "")
    action = model.get("action", "")
    table = KQL_MODEL_TABLE.get((obj, action))
    if not table:
        return None

    parts = [table]

    for filt in filter_stmts:
        kql_cond = _condition_to_kql(filt["condition"])
        if kql_cond:
            parts.append(f"| where {kql_cond}")

    parts.append(f"| project {', '.join(_kql_default_fields(obj))}")
    return "\n".join(parts)


def _condition_to_kql(cond: dict) -> str:
    """Convert condition AST to KQL where clause."""
    op = cond.get("op")

    if op == "and":
        return f"{_condition_to_kql(cond['left'])} and {_condition_to_kql(cond['right'])}"
    if op == "or":
        return f"({_condition_to_kql(cond['left'])} or {_condition_to_kql(cond['right'])})"
    if op == "not":
        return f"not({_condition_to_kql(cond['operand'])})"
    if op == "==":
        field = _kql_map_field(cond["field"])
        value = cond["value"]
        if isinstance(value, str) and "*" in value:
            pattern = value.replace("*", "")
            return f'{field} contains "{pattern}"'
        return f'{field} == "{value}"'
    if op == "!=":
        field = _kql_map_field(cond["field"])
        return f'{field} != "{cond["value"]}"'
    if op == "match":
        field = _kql_map_field(cond["field"])
        return f'{field} matches regex "{cond["pattern"]}"'
    return ""


def _kql_map_field(field: str) -> str:
    parts = field.split(".")
    return KQL_FIELD_MAP.get(parts[-1], parts[-1])


def _kql_default_fields(obj: str) -> list[str]:
    if obj == "Process":
        return ["DeviceName", "AccountName", "FileName", "InitiatingProcessFileName", "ProcessCommandLine"]
    if obj == "File":
        return ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName"]
    if obj == "Registry":
        return ["DeviceName", "RegistryKey", "RegistryValueName", "InitiatingProcessFileName"]
    return ["DeviceName", "FileName"]


# === SIGMA TRANSLATION ===

SIGMA_FIELD_MAP = {
    "exe": "Image",
    "parent_exe": "ParentImage",
    "command_line": "CommandLine",
    "image_path": "Image",
    "parent_image_path": "ParentImage",
    "file_path": "TargetFilename",
    "file_name": "TargetFilename",
    "key": "TargetObject",
    "module_path": "ImageLoaded",
    "dest_port": "DestinationPort",
    "user": "User",
}

SIGMA_CATEGORY = {
    ("Process", "Create"): ("windows", "process_creation"),
    ("File", "Create"): ("windows", "file_event"),
    ("Registry", "Create"): ("windows", "registry_event"),
    ("Registry", "Edit"): ("windows", "registry_event"),
    ("Module", "Load"): ("windows", "image_load"),
    ("Network", "Connect"): ("windows", "network_connection"),
}


def ast_to_sigma(ast: list[dict]) -> str | None:
    """Convert parsed AST to Sigma rule YAML format."""
    search_stmts = [s for s in ast if s["type"] == "search"]
    filter_stmts = [s for s in ast if s["type"] == "filter"]

    if not search_stmts:
        return None

    model = search_stmts[0]["models"][0]
    obj = model.get("object", "")
    action = model.get("action", "")
    cat = SIGMA_CATEGORY.get((obj, action))
    if not cat:
        return None

    product, category = cat

    # Build detection section
    selection = {}
    filters = {}
    for filt in filter_stmts:
        _sigma_extract_conditions(filt["condition"], selection, filters)

    lines = [
        "title: Auto-generated from CAR pseudocode",
        "status: experimental",
        "logsource:",
        f"    product: {product}",
        f"    category: {category}",
        "detection:",
        "    selection:",
    ]
    for field, values in selection.items():
        if len(values) == 1:
            lines.append(f"        {field}: '{values[0]}'")
        else:
            lines.append(f"        {field}:")
            for v in values:
                lines.append(f"            - '{v}'")

    if filters:
        lines.append("    filter:")
        for field, values in filters.items():
            if len(values) == 1:
                lines.append(f"        {field}: '{values[0]}'")
            else:
                lines.append(f"        {field}:")
                for v in values:
                    lines.append(f"            - '{v}'")
        lines.append("    condition: selection and not filter")
    else:
        lines.append("    condition: selection")

    return "\n".join(lines)


def _sigma_extract_conditions(cond: dict, selection: dict, filters: dict):
    """Recursively extract conditions into Sigma selection/filter dicts."""
    op = cond.get("op")
    if op == "and":
        _sigma_extract_conditions(cond["left"], selection, filters)
        _sigma_extract_conditions(cond["right"], selection, filters)
    elif op == "or":
        _sigma_extract_conditions(cond["left"], selection, filters)
        _sigma_extract_conditions(cond["right"], selection, filters)
    elif op == "==":
        field = SIGMA_FIELD_MAP.get(cond["field"].split(".")[-1], cond["field"])
        value = cond["value"] if isinstance(cond["value"], str) else str(cond["value"])
        selection.setdefault(field, []).append(value)
    elif op == "!=":
        field = SIGMA_FIELD_MAP.get(cond["field"].split(".")[-1], cond["field"])
        value = cond["value"] if isinstance(cond["value"], str) else str(cond["value"])
        filters.setdefault(field, []).append(value)
    elif op == "match":
        field = SIGMA_FIELD_MAP.get(cond["field"].split(".")[-1], cond["field"])
        selection.setdefault(field, []).append(f'*{cond["pattern"]}*')
