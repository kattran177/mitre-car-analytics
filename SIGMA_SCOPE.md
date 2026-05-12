# Multi-Domain Expansion: SIGMA Rules (Phase 6 Roadmap)

**Date**: 2026-04-30  
**Status**: Planning (Not implemented in Phase 4-5)  
**Effort Estimate**: ~2 hours implementation + $1-2 cost

---

## Summary

The LLM-assisted threat hunting pipeline designed for MITRE CAR analytics can be adapted to work with SIGMA detection rules. This document outlines the applicability, required changes, and effort estimate for Phase 6+ expansion.

---

## What is SIGMA?

SIGMA is a community-driven open format for writing detection rules. Key characteristics:

| Aspect | Details |
|--------|---------|
| **Repository** | SigmaHQ on GitHub (~10,000 published rules) |
| **Format** | YAML (vs. CAR's JSON) |
| **Tactic Assignment** | Explicit in rule metadata (vs. CAR requiring derivation) |
| **Platform Coverage** | Windows, Linux, macOS, cloud (broader than CAR) |
| **Query Targets** | Multiple backends: Splunk, KQL, Elasticsearch, etc. |
| **Community** | Active maintenance by threat hunters and researchers |

---

## Applicability to Our Pipeline

### 1. **Corpus Characteristics** ✓ Compatible

**CAR**: 102 analytics, academic/reference quality  
**SIGMA**: 10,000+ rules, practitioner-contributed, rapidly evolving

**Impact**: SIGMA corpus is 100x larger → benefits from semantic search (RAG) to find similar rules for context

### 2. **Embedding & Retrieval** ✓ Compatible

**Current Approach**: ChromaDB + all-MiniLM-L6-v2 embeddings on CAR description text

**SIGMA Adaptation**:
- Embed rule title + detection logic (YAML syntax isn't ideal for embedding; parse to text)
- Retrieve similar SIGMA rules based on tactic and technique keywords
- Use retrieved rules as context examples

**Expected Improvement**: SIGMA rules are more specific (practical implementations) → better retrieval quality

### 3. **Tactic Mapping** ✓ Easier for SIGMA

**CAR Challenge**: Techniques listed, tactics derived from MITRE mappings → error-prone  
**SIGMA Advantage**: Tactics explicitly assigned in rule metadata (`logsource.detection.tactics`)

**Impact**: Lower tactic mapping errors (one of our failure modes)

### 4. **Prompting Changes** ⚠ Required

**CAR Task**: "Generate hunting hypothesis for this CAR analytic"  
**SIGMA Task**: "Generate testing methodology for this SIGMA rule" (rules are already operational)

**New Output Sections for SIGMA**:
1. **Rule Summary**: Plain-English explanation of what this rule detects
2. **Test Case**: Example of what triggers this rule (benign or malicious)
3. **Deployment Notes**: Platform-specific considerations
4. **Tuning Guidance**: How to adjust the rule for your environment
5. **Detection Validation**: How to verify the rule is working in your SIEM

vs. CAR which generates: summary, techniques, hypothesis, query, false positives

**Impact**: 60% new prompting work, 40% reusable (similarity search, validation patterns)

### 5. **Field Validation** ⚠ More Complex

**CAR**: Validates against CAR data model (~50 fields)  
**SIGMA**: Tool-specific field names (Splunk vs. KQL vs. ECS vs. process_creation)

**Impact**: Need field mapping layer to validate against multiple backends simultaneously

---

## Required Implementation Changes

### Phase 1: Core Ingestion (30 mins, $0)

```python
# src/sigma_ingest.py
def load_sigma_rules(repo_path: str) -> list[dict]:
    """Load SIGMA rules from SigmaHQ repo"""
    # Parse YAML files
    # Extract: id, title, tactic, technique, detection_logic, logsource
    # Normalize to match CAR structure
    
def embed_sigma_rules(rules: list[dict]) -> ChromaDB:
    """Embed rule title + detection logic"""
```

**Changes**:
- YAML parser (PyYAML)
- Flatten nested detection logic to text
- Map SIGMA logsource to platforms

---

### Phase 2: Prompt Adaptation (45 mins, $0)

```python
# src/sigma_prompts.py
SIGMA_TESTING_PROMPT = """
For this SIGMA rule, generate:
1. Testing Approach: Step-by-step how to validate this rule works
2. Tuning Guidance: How to adjust sensitivity for your environment
3. Deployment Checklist: Platform-specific installation notes
"""
```

**Changes**:
- Replace "hunting hypothesis" with "testing methodology"
- Add platform-specific output (rule works differently in Splunk vs. KQL)
- Emphasize practical deployment (SIGMA rules are ready-to-use)

---

### Phase 3: Validation (45 mins, $0)

```python
# src/sigma_validators.py
def validate_sigma_tactic(rule: dict) -> dict:
    """Validate rule tactic against MITRE"""
    # SIGMA tactic already explicit - just verify canonical
    
def validate_sigma_compatibility(rule: dict, platform: str) -> tuple[bool, str]:
    """Check if rule is compatible with target platform"""
```

**Changes**:
- Simpler tactic validation (already explicit in SIGMA)
- Platform-specific field validation (Splunk vs. EQL vs. KQL)

---

### Phase 4: Pilot Test (30 mins, ~$1)

```bash
# phase6_sigma_pilot.py
# Generate 20 SIGMA rules
# Evaluate: testing approach quality, deployment completeness
# Compare metrics to CAR baseline
```

**Expected Metrics**:
- Output quality: Similar to CAR (MOQS ~2.5)
- Tactic accuracy: Higher than CAR (tactic is explicit, fewer mappings needed)
- Cost: ~$1 for 20 rules (same model, same cost)

---

## Implementation Timeline

| Task | Effort | Cost | Prerequisites |
|------|--------|------|---|
| Ingestion (Phase 1) | 30 mins | $0 | PyYAML |
| Prompts (Phase 2) | 45 mins | $0 | Understand SIGMA output goals |
| Validation (Phase 3) | 45 mins | $0 | Platform mapping knowledge |
| Pilot (Phase 4) | 30 mins | $1 | Phases 1-3 complete |
| **Total** | **2.5 hours** | **$1** | |

---

## Why Defer to Phase 6?

1. **CAR pipeline is solid**: Current system (Grade B, 82/100) is production-ready
2. **Analyst feedback pending**: Need feedback loop (Task 3) running first
3. **Scaling unknown**: Need to validate Phase 5 scaling (20+ analytics) before expanding corpus
4. **SIGMA-specific challenges**: Platform diversity requires additional validation work
5. **Token budget**: Current project has limited budget; SIGMA expansion is nice-to-have

---

## Success Criteria for Phase 6

✓ SIGMA rule testing methodologies generate successfully (100% valid output)  
✓ Tactic accuracy >= 95% (SIGMA tactics are explicit - should be higher than CAR's 67%)  
✓ MOQS >= 2.5 (comparable to CAR quality)  
✓ Platform compatibility checking works for ≥80% of rules  
✓ Cost < $5 for 50-rule pilot test  

---

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|-----------|
| SIGMA rules vary widely in quality | Medium | Filter by star rating/maturity; start with top 100 rules |
| Platform-specific field names are confusing | Medium | Build platform mapping table upfront; validate per-platform |
| 10k corpus is too large for RAG | Low | Start with 100-rule subset; scale incrementally |
| YAML parsing breaks on malformed rules | Low | Use strict YAML parser; skip unparseable rules |

---

## Architectural Comparison

```
Current CAR Pipeline          Future SIGMA Pipeline
─────────────────             ─────────────────
Load YAML → Parse             Load YAML → Parse  
Embed descriptions            Embed YAML + logic
Retrieve similar CAR          Retrieve similar SIGMA
Generate hunting hypothesis   Generate testing methodology
Validate SIEM query           Validate rule compatibility
Output: 5 sections            Output: 5 sections (different)
```

**Key Difference**: SIGMA rules are *deployment-focused* (ready to deploy) vs. CAR analytic  are *research-focused* (theoretical). Output should reflect this.

---

## Next Steps (Phase 6)

1. **Clarify Phase 5 results**: Confirm scaling works (20+ analytics stable)
2. **Review analyst feedback**: Ensure CAR pipeline improvements are locked in
3. **Gather SIGMA corpus**: Clone SigmaHQ repo, select 100-rule pilot set
4. **Implement ingestion**: Load, parse, embed SIGMA rules
5. **Adapt prompts**: Design SIGMA-specific output sections
6. **Run pilot**: Generate 20 SIGMA rules, evaluate quality
7. **Measure impact**: Compare to CAR metrics
8. **Expand**: Roll out to full SIGMA corpus or integrate into CAR workflow

---

**Document Status**: Planning  
**Ready for Implementation**: After Phase 5 completes  
**Estimated Phase 6 Timeline**: 1 week (2.5 hours coding + testing)  
**Expected Value**: Unlock 10,000+ operational detection rules for practitioners
