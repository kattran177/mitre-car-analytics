import yaml
from pathlib import Path
from typing import Any

from src.config import cfg, _ROOT

_IMPL_TYPE_MAP = {
    "splunk": "Splunk",
    "eql": "EQL",
    "kql": "KQL",
    "dnif": "DNIF",
    "logpoint": "LogPoint",
    "sigma": "Sigma",
    "pseudocode": "Pseudocode",
}

def _normalize_impl_type(t: str) -> str:
    return _IMPL_TYPE_MAP.get(t.strip().lower(), t.strip().title())


def _parse_coverage(coverage: list[dict]) -> dict:
    """Flatten coverage list into deduplicated technique/tactic/subtechnique lists."""
    techniques, tactics, subtechniques = set(), set(), set()
    coverage_levels = []
    for entry in coverage or []:
        if tid := entry.get("technique"):
            techniques.add(tid)
        for st in entry.get("subtechniques", []):
            subtechniques.add(st)
        for tac in entry.get("tactics", []):
            tactics.add(tac)
        if level := entry.get("coverage"):
            coverage_levels.append(level)
    return {
        "techniques": sorted(techniques),
        "subtechniques": sorted(subtechniques),
        "tactics": sorted(tactics),
        "coverage_levels": coverage_levels,
    }


def _parse_implementations(impls: list[dict]) -> list[dict]:
    """Normalize implementations to consistent shape."""
    out = []
    for impl in impls or []:
        out.append({
            "name": impl.get("name", ""),
            "type": impl.get("type", "Unknown"),
            "description": impl.get("description", ""),
            "code": impl.get("code", "").strip(),
            "data_model": impl.get("data_model", ""),
        })
    return out


def parse_analytic(path: Path) -> dict[str, Any]:
    """Parse a single CAR analytic YAML file into a normalized dict."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    coverage = _parse_coverage(raw.get("coverage", []))
    impls = _parse_implementations(raw.get("implementations", []))

    return {
        "id": raw.get("id", path.stem),
        "title": raw.get("title", ""),
        "description": raw.get("description", "").strip(),
        "submission_date": raw.get("submission_date", ""),
        "information_domain": raw.get("information_domain", ""),
        "platforms": raw.get("platforms", []),
        "subtypes": raw.get("subtypes", []),
        "analytic_types": raw.get("analytic_types", []),
        "techniques": coverage["techniques"],
        "subtechniques": coverage["subtechniques"],
        "tactics": coverage["tactics"],
        "coverage_levels": coverage["coverage_levels"],
        "implementations": impls,
        "impl_types": list({_normalize_impl_type(i["type"]) for i in impls}),
        "data_model_references": raw.get("data_model_references", []),
        "raw_coverage": raw.get("coverage", []),
    }


def load_all_analytics(analytics_dir: str | None = None) -> list[dict[str, Any]]:
    """Load and parse all CAR analytics YAML files. Returns list sorted by ID."""
    base = Path(analytics_dir) if analytics_dir else _ROOT / cfg["data"]["raw_dir"]
    yaml_files = sorted((base / "car" / "analytics").glob("*.yaml"))

    if not yaml_files:
        raise FileNotFoundError(f"No YAML files found in {base / 'car' / 'analytics'}")

    analytics = [parse_analytic(p) for p in yaml_files]
    print(f"Loaded {len(analytics)} analytics from {base / 'car' / 'analytics'}")
    return analytics


def extract_reference_implementations(analytics_dir: str | None = None) -> dict[str, dict[str, str]]:
    """Extract reference implementations from all analytics. Returns {analytic_id: {impl_type: code}}."""
    base = Path(analytics_dir) if analytics_dir else _ROOT / cfg["data"]["raw_dir"]
    yaml_files = sorted((base / "car" / "analytics").glob("*.yaml"))

    refs = {}
    for path in yaml_files:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        analytic_id = raw.get("id")
        impls = raw.get("implementations", [])

        # Extract code by implementation type
        impl_dict = {}
        for impl in impls:
            impl_type = _normalize_impl_type(impl.get("type", "Unknown"))
            code = impl.get("code", "").strip()
            if code:
                impl_dict[impl_type] = code

        if impl_dict:
            refs[analytic_id] = impl_dict

    return refs
