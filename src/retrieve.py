from src.embed import get_collection
from src.config import cfg

# Specific tool/technique keywords that indicate a focused query
SPECIFIC_KEYWORDS = {
    "powershell", "cmd.exe", "lsass", "mimikatz", "procdump", "psexec",
    "wmi", "scheduled task", "schtasks", "at.exe", "winrm", "wmic",
    "remote desktop", "rdp", "dcom", "winevent", "sysmon", "etw",
    "dllinject", "processinject", "dll injection", "process injection",
    "credential dump", "hash dump", "token impersonation", "runas",
    "lateral movement", "pass the hash", "silver ticket", "golden ticket",
}

def _query_specificity_score(query: str) -> float:
    """
    Score query specificity (0.0 = broad, 1.0 = very specific).

    Specific queries (like 'PowerShell execution') need fewer results (n=2)
    to stay focused. Broad queries (like 'detect lateral movement') need more
    results (n=3) to cover diverse attack paths.

    Returns: float in [0, 1]
    """
    q_lower = query.lower()

    # Count specific keywords
    specific_count = sum(1 for kw in SPECIFIC_KEYWORDS if kw in q_lower)

    # Vague keywords that suggest broad queries
    vague = ["detect", "identify", "discover", "find", "suspicious", "malicious"]
    vague_count = sum(1 for vg in vague if vg in q_lower)

    # Length heuristic: very short queries are often specific, very long are often broad
    query_len = len(q_lower.split())
    len_score = 0.2 if query_len < 4 else (0.0 if query_len > 10 else 0.5)

    # Combine signals
    specificity = (specific_count * 0.4) - (vague_count * 0.2) + len_score
    return max(0.0, min(1.0, specificity))  # clamp to [0, 1]


def retrieve(
    query: str,
    n_results: int | None = None,
    auto_n_results: bool = True,
    max_distance: float | None = None,
    filter_tactic: str | None = None,
    filter_platform: str | None = None,
    filter_has_splunk: bool | None = None,
) -> list[dict]:
    """
    Retrieve the top-k most relevant CAR analytics for a plain-English query.

    Design to reduce context bleed:
    - auto_n_results: For specific queries (PowerShell, cmd.exe), use n=2 (stay focused)
      For broad queries (detect lateral movement), use n=3 (cover diversity)
    - max_distance: Filter out tangential results (distance > threshold) that could
      contaminate the hypothesis

    Args:
        query:            Natural language hunt hypothesis or question
        n_results:        Override default. If None, uses auto_n_results or config default
        auto_n_results:   If True, adjust n_results based on query specificity
        max_distance:     Filter results above this distance. None = use config default
        filter_tactic:    Optional tactic ID to restrict results e.g. 'TA0003'
        filter_platform:  Optional platform string e.g. 'Windows'
        filter_has_splunk: If True, only return analytics with Splunk implementations

    Returns:
        List of result dicts with keys: id, title, summary, distance, metadata
    """
    collection = get_collection()

    # Determine n_results
    if n_results is None:
        if auto_n_results:
            specificity = _query_specificity_score(query)
            n_results = 2 if specificity > 0.5 else 3
        else:
            n_results = cfg["retrieval"]["n_results"]

    # Determine max_distance
    if max_distance is None:
        max_distance = cfg["retrieval"]["max_distance"]

    where = _build_where(filter_tactic, filter_platform, filter_has_splunk)
    kwargs = dict(query_texts=[query], n_results=n_results + 2, include=["documents", "metadatas", "distances"])
    # Query for n+2 to account for filtering by max_distance
    if where:
        kwargs["where"] = where

    results = collection.query(**kwargs)

    output = []
    for i in range(len(results["ids"][0])):
        distance = results["distances"][0][i]
        # Filter by max_distance threshold
        if distance > max_distance:
            continue
        output.append({
            "id":       results["ids"][0][i],
            "title":    results["metadatas"][0][i]["title"],
            "summary":  results["documents"][0][i],
            "distance": round(distance, 4),
            "metadata": results["metadatas"][0][i],
        })
        if len(output) >= n_results:
            break

    return output


def _build_where(tactic, platform, has_splunk) -> dict | None:
    """Build a ChromaDB $and/$contains filter dict from optional arguments."""
    clauses = []
    if tactic:
        clauses.append({"tactics": {"$contains": tactic}})
    if platform:
        clauses.append({"platforms": {"$contains": platform}})
    if has_splunk is True:
        clauses.append({"has_splunk": {"$eq": True}})

    if not clauses:
        return None
    return {"$and": clauses} if len(clauses) > 1 else clauses[0]


def format_results(results: list[dict], show_summary: bool = False, show_distance_flag: bool = True) -> str:
    """Pretty-print retrieval results for notebook inspection."""
    lines = []
    for i, r in enumerate(results, 1):
        distance_flag = ""
        if show_distance_flag:
            if r["distance"] < 0.4:
                distance_flag = "  [excellent]"
            elif r["distance"] < 0.5:
                distance_flag = "  [good]"
            elif r["distance"] < 0.65:
                distance_flag = "  [acceptable]"
            else:
                distance_flag = "  [FILTERED-tangential]"
        lines.append(f"[{i}] {r['id']} — {r['title']}  (distance: {r['distance']}){distance_flag}")
        lines.append(f"    Techniques: {r['metadata']['techniques']}")
        lines.append(f"    Tactics:    {r['metadata']['tactics']}")
        lines.append(f"    Coverage:   {r['metadata']['coverage']}")
        lines.append(f"    Impl types: {r['metadata']['impl_types']}")
        if show_summary:
            lines.append("")
            lines.append(r["summary"])
        lines.append("")
    return "\n".join(lines)


def analyze_query(query: str) -> dict:
    """Debug: analyze why a query got a certain specificity score."""
    specificity = _query_specificity_score(query)
    specific_hits = [kw for kw in SPECIFIC_KEYWORDS if kw in query.lower()]
    vague = ["detect", "identify", "discover", "find", "suspicious", "malicious"]
    vague_hits = [vg for vg in vague if vg in query.lower()]

    return {
        "query": query,
        "specificity_score": round(specificity, 2),
        "predicted_n_results": 2 if specificity > 0.5 else 3,
        "specific_keywords_hit": specific_hits,
        "vague_keywords_hit": vague_hits,
        "interpretation": "SPECIFIC (use n=2, stay focused)" if specificity > 0.5 else "BROAD (use n=3, cover diversity)",
    }
