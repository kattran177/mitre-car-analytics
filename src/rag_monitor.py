"""
RAG (Retrieval-Augmented Generation) context bleed detection.
Monitors for confusion between input analytic and retrieved documents.
"""
import json
from collections import defaultdict
import difflib

class RAGBleedMonitor:
    """Monitor for context bleed in RAG-augmented generation."""

    def __init__(self):
        self.retrievals = {}  # Map analytic_id -> [retrieved_docs]
        self.outputs = {}     # Map analytic_id -> output

    def record_retrieval(self, analytic_id: str, retrieved_docs: list):
        """Record which documents were retrieved for an analytic."""
        self.retrievals[analytic_id] = retrieved_docs

    def record_output(self, analytic_id: str, output: dict):
        """Record the generated output."""
        self.outputs[analytic_id] = output

    def extract_field_set(self, obj) -> set:
        """Extract all field references from an object."""
        fields = set()

        if isinstance(obj, dict):
            for k, v in obj.items():
                # Look for field-like keys
                if isinstance(k, str) and '_' in k.lower() and len(k) < 30:
                    fields.add(k.lower())
                # Recurse into values
                fields.update(self.extract_field_set(v))

        elif isinstance(obj, list):
            for item in obj:
                fields.update(self.extract_field_set(item))

        elif isinstance(obj, str):
            # Extract field patterns (camelCase or snake_case)
            import re
            snake_case = re.findall(r'\b[a-z_]+(?:_[a-z_]+)+\b', obj.lower())
            camel_case = re.findall(r'\b[a-z][a-zA-Z]+(?:[A-Z][a-zA-Z]+)+\b', obj)
            fields.update(snake_case)
            fields.update(camel_case)

        return fields

    def detect_field_contamination(self, analytic_id: str) -> dict:
        """
        Detect if output fields contaminate from retrieved documents.

        Returns: {
            "analytic_id": str,
            "has_bleed": bool,
            "contamination_score": float (0-1),
            "bleed_sources": [list of doc indices],
            "contaminating_fields": list,
            "severity": "high|medium|low"
        }
        """
        if analytic_id not in self.outputs:
            return {"analytic_id": analytic_id, "has_bleed": False, "contamination_score": 0.0}

        output = self.outputs[analytic_id]
        retrieved = self.retrievals.get(analytic_id, [])

        # Extract fields from output
        output_fields = self.extract_field_set(output)

        if not retrieved or not output_fields:
            return {
                "analytic_id": analytic_id,
                "has_bleed": False,
                "contamination_score": 0.0,
                "bleed_sources": [],
                "contaminating_fields": [],
                "severity": "low"
            }

        # Check overlap with each retrieved document
        bleed_sources = []
        contaminating_fields = []

        for doc_idx, doc in enumerate(retrieved):
            doc_fields = self.extract_field_set(doc)
            overlap = output_fields & doc_fields

            if len(overlap) > 0 and doc_idx != 0:  # Index 0 is usually the target
                bleed_sources.append(doc_idx)
                contaminating_fields.extend(list(overlap))

        # Calculate contamination score
        total_fields = len(output_fields) if output_fields else 1
        contamination_score = len(contaminating_fields) / total_fields if contaminating_fields else 0.0

        # Severity
        if contamination_score > 0.5:
            severity = "high"
        elif contamination_score > 0.2:
            severity = "medium"
        else:
            severity = "low"

        has_bleed = contamination_score > 0.1

        return {
            "analytic_id": analytic_id,
            "has_bleed": has_bleed,
            "contamination_score": contamination_score,
            "bleed_sources": bleed_sources,
            "contaminating_fields": list(set(contaminating_fields)),
            "severity": severity
        }

    def detect_technique_contamination(self, analytic_id: str) -> dict:
        """
        Detect if output techniques come from non-target retrieved docs.

        Returns: {
            "analytic_id": str,
            "has_technique_bleed": bool,
            "input_techniques": set,
            "output_techniques": set,
            "extra_techniques": set,
            "extra_sources": [doc indices with extra techniques],
            "severity": "high|medium|low"
        }
        """
        if analytic_id not in self.outputs:
            return {
                "analytic_id": analytic_id,
                "has_technique_bleed": False,
                "input_techniques": set(),
                "output_techniques": set(),
                "extra_techniques": set(),
                "extra_sources": [],
                "severity": "low"
            }

        output = self.outputs[analytic_id]
        retrieved = self.retrievals.get(analytic_id, [])

        # Input techniques (target document, usually index 0)
        input_techniques = set()
        if retrieved and len(retrieved) > 0:
            if isinstance(retrieved[0], dict):
                input_techniques = set(retrieved[0].get("techniques", []))
            elif isinstance(retrieved[0], str):
                import re
                input_techniques = set(re.findall(r'T\d{4}', retrieved[0]))

        # Output techniques
        output_techniques = set()
        attack_mapping = output.get("attack_mapping", {})
        if isinstance(attack_mapping, dict):
            for tech in attack_mapping.get("techniques", []):
                if isinstance(tech, dict):
                    output_techniques.add(tech.get("technique_id", ""))

        # Extra techniques (not in input)
        extra_techniques = output_techniques - input_techniques

        # Find sources of extra techniques
        extra_sources = []
        if extra_techniques and retrieved:
            for doc_idx, doc in enumerate(retrieved[1:], 1):  # Skip target (index 0)
                doc_techniques = set()
                if isinstance(doc, dict):
                    doc_techniques = set(doc.get("techniques", []))
                elif isinstance(doc, str):
                    import re
                    doc_techniques = set(re.findall(r'T\d{4}', doc))

                if extra_techniques & doc_techniques:
                    extra_sources.append(doc_idx)

        # Severity
        extra_ratio = len(extra_techniques) / len(output_techniques) if output_techniques else 0
        if extra_ratio > 0.5:
            severity = "high"
        elif extra_ratio > 0.2:
            severity = "medium"
        else:
            severity = "low"

        has_bleed = len(extra_techniques) > 0

        return {
            "analytic_id": analytic_id,
            "has_technique_bleed": has_bleed,
            "input_techniques": input_techniques,
            "output_techniques": output_techniques,
            "extra_techniques": extra_techniques,
            "extra_ratio": extra_ratio,
            "extra_sources": extra_sources,
            "severity": severity
        }

    def generate_report(self) -> dict:
        """Generate comprehensive RAG bleed report."""
        field_bleeds = []
        technique_bleeds = []

        for analytic_id in self.outputs.keys():
            field_bleed = self.detect_field_contamination(analytic_id)
            technique_bleed = self.detect_technique_contamination(analytic_id)

            if field_bleed["has_bleed"]:
                field_bleeds.append(field_bleed)

            if technique_bleed["has_technique_bleed"]:
                technique_bleeds.append(technique_bleed)

        # Summary
        total_outputs = len(self.outputs)
        field_bleed_count = len(field_bleeds)
        technique_bleed_count = len(technique_bleeds)

        severity_distribution = defaultdict(int)
        for bleed in field_bleeds + technique_bleeds:
            severity_distribution[bleed["severity"]] += 1

        return {
            "total_outputs": total_outputs,
            "field_bleed_incidents": field_bleed_count,
            "technique_bleed_incidents": technique_bleed_count,
            "total_bleed_incidents": field_bleed_count + technique_bleed_count,
            "bleed_rate_pct": 100 * (field_bleed_count + technique_bleed_count) / total_outputs if total_outputs > 0 else 0,
            "field_bleeds": field_bleeds,
            "technique_bleeds": technique_bleeds,
            "severity_distribution": dict(severity_distribution),
            "recommendations": self._generate_recommendations(field_bleeds, technique_bleeds)
        }

    def _generate_recommendations(self, field_bleeds, technique_bleeds) -> list:
        """Generate recommendations based on detected bleeds."""
        recommendations = []

        if len(field_bleeds) > 0:
            recommendations.append(
                f"Field contamination detected in {len(field_bleeds)} outputs. "
                "Consider: (1) Single-document retrieval, (2) Document isolation, "
                "(3) Enhanced prompt guidance to ignore retrieved context"
            )

        if len(technique_bleeds) > 0:
            recommendations.append(
                f"Technique contamination detected in {len(technique_bleeds)} outputs. "
                "Ensure input analytic techniques are clearly marked and distinct from retrieved docs."
            )

        if not recommendations:
            recommendations.append("No RAG bleed detected - system performing well")

        return recommendations
