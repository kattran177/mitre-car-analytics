"""Generate synthetic test events that should trigger detections."""

# CAR field names → abstract test field names (used in queries)
CAR_FIELD_NAMES = {
    "process/create/exe": "exe",
    "process/create/parent_exe": "parent_exe",
    "process/create/command_line": "command_line",
    "process/create/hostname": "hostname",
    "process/create/ppid": "ppid",
    "process/create/pid": "pid",
    "process/create/md5_hash": "md5_hash",
    "process/create/image_path": "image_path",
    "process/create/user": "user",
    "network_connection/create/source_ip": "source_ip",
    "network_connection/create/destination_ip": "destination_ip",
    "network_connection/create/destination_port": "destination_port",
    "network_connection/create/hostname": "hostname",
    "file/create/file_path": "file_path",
    "file/create/file_name": "file_name",
    "registry/set/registry_key_name": "registry_key_name",
    "registry/set/registry_value_name": "registry_value_name",
}

# Suspicious values per field (for positive test cases)
SUSPICIOUS_VALUES = {
    "exe": "at.exe",
    "parent_exe": "AcroRd32.exe",
    "command_line": "at.exe 10:00 calc.exe",
    "hostname": "DESKTOP-ABC123",
    "ppid": 1234,
    "pid": 5678,
    "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "image_path": "C:\\Windows\\System32\\",
    "user": "SYSTEM",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.50",
    "destination_port": 445,
    "file_path": "C:\\Temp\\malware.exe",
    "file_name": "malware.exe",
    "registry_key_name": "HKLM\\Software\\Microsoft\\Windows\\Run",
    "registry_value_name": "Startup",
}

# Benign values per field (for negative test cases)
BENIGN_VALUES = {
    "exe": "explorer.exe",
    "parent_exe": "explorer.exe",
    "command_line": "explorer.exe /n",
    "hostname": "DESKTOP-XYZ789",
    "ppid": 9999,
    "pid": 8888,
    "md5_hash": "e41d8cd98f00b204e9800998ecf8427a",
    "image_path": "C:\\Windows\\System32\\",
    "user": "Administrator",
    "source_ip": "192.168.1.1",
    "destination_ip": "8.8.8.8",
    "destination_port": 53,
    "file_path": "C:\\Program Files\\App\\app.exe",
    "file_name": "app.exe",
    "registry_key_name": "HKLM\\Software\\App",
    "registry_value_name": "Version",
}


def generate_positive_event(analytic: dict) -> dict:
    """Generate a synthetic event that SHOULD trigger the detection."""
    event = {}

    # Use all data_model_references fields
    for dm_ref in analytic.get("data_model_references", []):
        field_name = CAR_FIELD_NAMES.get(dm_ref, dm_ref)
        value = SUSPICIOUS_VALUES.get(field_name, f"test_{field_name}")
        event[field_name] = value

    return event


def generate_benign_event(analytic: dict) -> dict:
    """Generate a synthetic event that should NOT trigger the detection."""
    event = {}

    # Use all data_model_references fields with benign values
    for dm_ref in analytic.get("data_model_references", []):
        field_name = CAR_FIELD_NAMES.get(dm_ref, dm_ref)
        value = BENIGN_VALUES.get(field_name, f"benign_{field_name}")
        event[field_name] = value

    return event


def generate_test_events(analytic: dict) -> list[dict]:
    """Generate [positive_event, benign_event] for an analytic."""
    return [
        generate_positive_event(analytic),
        generate_benign_event(analytic),
    ]
