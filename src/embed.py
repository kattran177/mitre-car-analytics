import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from pathlib import Path

from src.config import cfg, _ROOT

TACTIC_NAMES = {
    'TA0001': 'Initial Access',
    'TA0002': 'Execution',
    'TA0003': 'Persistence',
    'TA0004': 'Privilege Escalation',
    'TA0005': 'Defense Evasion',
    'TA0006': 'Credential Access',
    'TA0007': 'Discovery',
    'TA0008': 'Lateral Movement',
    'TA0009': 'Collection',
    'TA0010': 'Exfiltration',
    'TA0011': 'Command and Control',
    'TA0040': 'Impact',
    'TA0042': 'Resource Development',
    'TA0043': 'Reconnaissance',
}


def build_summary(analytic: dict) -> str:
    """
    Build the text string that gets embedded for one analytic.

    Design goals:
    - Include real field names  → reduces field hallucination
    - Include tactic IDs+names  → reduces tactic drift
    - Include coverage level    → gives LLM a confidence signal
    - Lead with CAR ID          → prevents context bleed across chunks
    - Separate description from
      detection fields           → reduces hypothesis circularity
    """
    tactic_labels = [
        f"{tid} ({TACTIC_NAMES.get(tid, tid)})" for tid in analytic["tactics"]
    ]
    coverage = (
        analytic["coverage_levels"][0] if analytic["coverage_levels"] else "Unknown"
    )
    fields = analytic["data_model_references"] or ["(none specified)"]
    techniques = analytic["techniques"] or ["(none specified)"]
    subtechniques = analytic["subtechniques"] or []

    parts = [
        f"ID: {analytic['id']}",
        f"Title: {analytic['title']}",
        f"Platform: {', '.join(analytic['platforms']) or 'Unknown'}",
        f"Description: {analytic['description']}",
        f"ATT&CK Techniques: {', '.join(techniques)}",
    ]
    if subtechniques:
        parts.append(f"Subtechniques: {', '.join(subtechniques)}")
    parts += [
        f"Tactics: {', '.join(tactic_labels) if tactic_labels else '(none)'}",
        f"Detection Coverage: {coverage}",
        f"Data Model Fields: {', '.join(fields)}",
    ]
    if analytic["impl_types"]:
        parts.append(f"Implementation Types: {', '.join(sorted(analytic['impl_types']))}")

    return "\n".join(parts)


def get_collection(persist_dir: str | None = None, collection_name: str | None = None):
    """Return a ChromaDB collection with the sentence-transformer embedding function attached."""
    path = str(_ROOT / (persist_dir or cfg["chromadb"]["persist_dir"]))
    name = collection_name or cfg["chromadb"]["collection_name"]
    model = cfg["embeddings"]["model"]

    client = chromadb.PersistentClient(path=path)
    ef = SentenceTransformerEmbeddingFunction(model_name=model)
    return client.get_or_create_collection(name=name, embedding_function=ef)


def ingest_analytics(analytics: list[dict], reset: bool = False) -> None:
    """
    Embed all analytics and store them in ChromaDB.

    Each document = structured summary text.
    Metadata stores filterable fields (techniques, tactics, platforms).
    ChromaDB handles embedding internally via SentenceTransformer.

    Args:
        analytics: output of load_all_analytics()
        reset: if True, delete and recreate the collection (full re-index)
    """
    persist_dir = str(_ROOT / cfg["chromadb"]["persist_dir"])
    name = cfg["chromadb"]["collection_name"]
    model = cfg["embeddings"]["model"]

    client = chromadb.PersistentClient(path=persist_dir)

    if reset:
        try:
            client.delete_collection(name)
            print(f"Deleted existing collection '{name}'")
        except Exception:
            pass  # collection didn't exist yet

    ef = SentenceTransformerEmbeddingFunction(model_name=model)
    collection = client.get_or_create_collection(name=name, embedding_function=ef)

    ids, documents, metadatas = [], [], []
    for a in analytics:
        ids.append(a["id"])
        documents.append(build_summary(a))
        # ChromaDB metadata values must be str/int/float/bool — no lists
        metadatas.append({
            "title": a["title"],
            "platforms": ", ".join(a["platforms"]),
            "techniques": ", ".join(a["techniques"]),
            "subtechniques": ", ".join(a["subtechniques"]),
            "tactics": ", ".join(a["tactics"]),
            "coverage": a["coverage_levels"][0] if a["coverage_levels"] else "Unknown",
            "impl_types": ", ".join(sorted(a["impl_types"])),
            "has_splunk": "Splunk" in a["impl_types"],
            "has_eql": "EQL" in a["impl_types"],
            "data_model_fields": ", ".join(a["data_model_references"]),
            "submission_date": a["submission_date"],
        })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    print(f"Ingested {len(ids)} analytics into collection '{name}'")
    print(f"Collection count: {collection.count()}")
