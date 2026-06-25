"""Extract pseudocode corpus into individual files and generate analysis."""

import json
from pathlib import Path

GRAMMAR_DIR = Path(__file__).parent
CORPUS_DIR = GRAMMAR_DIR / "corpus"
DATA_FILE = GRAMMAR_DIR.parent / "data" / "processed" / "reference_implementations.json"


def extract_corpus():
    """Extract all pseudocode blocks into individual .pseudo files."""
    CORPUS_DIR.mkdir(exist_ok=True)

    with open(DATA_FILE) as f:
        refs = json.load(f)

    pseudo = {k: v["Pseudocode"] for k, v in refs.items() if "Pseudocode" in v}
    splunk = {k: v["Splunk"] for k, v in refs.items() if "Splunk" in v}

    # Write individual files
    for car_id, code in sorted(pseudo.items()):
        (CORPUS_DIR / f"{car_id}.pseudo").write_text(code, encoding="utf-8")

    # Write test pairs (pseudocode + splunk) for validation
    pairs = {k: {"pseudocode": pseudo[k], "splunk": splunk[k]}
             for k in pseudo if k in splunk}
    (CORPUS_DIR / "test_pairs.json").write_text(
        json.dumps(pairs, indent=2), encoding="utf-8")

    print(f"Extracted {len(pseudo)} pseudocode files")
    print(f"Test pairs (pseudo + splunk): {len(pairs)}")
    return pseudo, pairs


if __name__ == "__main__":
    extract_corpus()
