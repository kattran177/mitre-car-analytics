import yaml
from pathlib import Path

_ROOT = Path(__file__).parent.parent

def load_config() -> dict:
    with open(_ROOT / "config.yaml") as f:
        return yaml.safe_load(f)

cfg = load_config()
