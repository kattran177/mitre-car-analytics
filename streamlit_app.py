#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Streamlit UI for CAR Analytics Threat Hunting Artifact Generator.

Interactive interface to query CAR IDs and display all 5 structured outputs:
1. summary_explanation
2. attack_mapping
3. hunting_hypothesis
4. siem_query
5. false_positives
"""

import streamlit as st
import json
from pathlib import Path
from typing import Optional

st.set_page_config(
    page_title="CAR Threat Hunting Artifacts",
    page_icon=":mag:",
    layout="wide",
    initial_sidebar_state="expanded"
)

OUTPUTS_FILE = Path(__file__).parent / "outputs" / "phase4_enhanced" / "phase4_enhanced_outputs.json"

@st.cache_resource
def load_outputs():
    """Load the pre-generated artifacts from JSON."""
    if not OUTPUTS_FILE.exists():
        return {}
    with open(OUTPUTS_FILE, encoding="utf-8") as f:
        return json.load(f)

def get_car_ids():
    """Get list of available CAR IDs."""
    outputs = load_outputs()
    return sorted(outputs.keys())

def get_artifact(car_id: str) -> Optional[dict]:
    """Get artifacts for a specific CAR ID."""
    outputs = load_outputs()
    return outputs.get(car_id)

def render_summary_explanation(summary_data: dict):
    """Render summary explanation section."""
    with st.expander("Summary Explanation", expanded=True):
        st.markdown(summary_data.get("summary", ""))

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Confidence", summary_data.get("confidence", "").upper())
        with col2:
            st.caption("Reasoning")
            st.markdown(summary_data.get("reasoning", ""))
        with col3:
            st.info("Plain-English explanation of what the analytic detects and why it matters.")

def render_attack_mapping(attack_data: dict):
    """Render ATT&CK technique mapping section."""
    with st.expander("ATT&CK Technique Mapping", expanded=False):
        techniques = attack_data.get("techniques", [])

        for i, technique in enumerate(techniques, 1):
            st.subheader(f"{technique.get('technique_id')} - {technique.get('technique_name')}")

            col1, col2 = st.columns([1, 3])
            with col1:
                st.metric("Confidence", technique.get("confidence", "").upper())
                tactics = technique.get("tactic_names", [])
                if tactics:
                    st.caption(f"Tactic(s): {', '.join(tactics)}")
            with col2:
                if technique.get("subtechnique_id"):
                    st.caption(f"Subtechnique: {technique.get('subtechnique_id')} - {technique.get('subtechnique_name')}")
                st.markdown("**Rationale**:")
                st.markdown(technique.get("rationale", ""))

            if i < len(techniques):
                st.divider()

def render_hunting_hypothesis(hypothesis_data: dict):
    """Render threat hunting hypothesis section."""
    with st.expander("Threat Hunting Hypothesis", expanded=False):
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown("**Hypothesis Question**:")
            st.info(hypothesis_data.get("question", ""))
        with col2:
            st.metric("Confidence", hypothesis_data.get("confidence", "").upper())
            testable = hypothesis_data.get("testable")
            status = "Yes" if testable else "No"
            st.metric("Testable", status)

        st.markdown("**Rationale**:")
        st.markdown(hypothesis_data.get("rationale", ""))

        st.info("Structured testable question framed as an if-then statement to guide threat hunting investigations.")

def render_siem_query(query_data: dict):
    """Render SIEM query section."""
    with st.expander("SIEM Query", expanded=False):
        col1, col2 = st.columns([1, 3])
        with col1:
            st.metric("Platform", query_data.get("platform", "unknown").title())
            st.metric("Confidence", query_data.get("confidence", "").upper())
        with col2:
            if query_data.get("platform") != "not_applicable":
                st.markdown("**Query**:")
                st.code(query_data.get("query", ""), language="sql")

        fields = query_data.get("data_model_fields_used", [])
        if fields:
            st.markdown("**Data Model Fields**:")
            for field in fields:
                st.caption(f"* {field}")

        if query_data.get("caveats"):
            st.warning("**Caveats & Notes**:")
            st.markdown(query_data.get("caveats", ""))

        if query_data.get("validation_issues"):
            st.error("**Validation Issues**:")
            for issue in query_data.get("validation_issues", []):
                st.markdown(f"* {issue}")

        st.info("SIEM-ready query (Splunk SPL or KQL) that operationalizes the detection logic.")

def render_false_positives(fp_data: dict):
    """Render false positives analysis section."""
    with st.expander("False Positive Analysis", expanded=False):
        col1, col2 = st.columns([3, 1])
        with col1:
            risk = fp_data.get("risk_level", "").upper()
            st.markdown(f"**Risk Level**: {risk}")
        with col2:
            st.metric("Confidence", fp_data.get("confidence", "").upper())

        scenarios = fp_data.get("scenarios", [])
        st.markdown("**False Positive Scenarios**:")
        for scenario in scenarios:
            st.markdown(f"* {scenario}")

        if fp_data.get("explanation"):
            st.markdown("**Explanation**:")
            st.markdown(fp_data.get("explanation", ""))

        if fp_data.get("triage_filters"):
            st.markdown("**Recommended Triage Filters**:")
            for filter_str in fp_data.get("triage_filters", []):
                st.code(filter_str, language="sql")

        st.info("Identify legitimate scenarios that could trigger this analytic and recommend filtering strategies.")

def main():
    """Main Streamlit app."""
    st.title("CAR Threat Hunting Artifacts Generator")
    st.markdown("Transform MITRE CAR analytics into actionable threat hunting outputs")

    with st.sidebar:
        st.header("Input")
        car_ids = get_car_ids()

        if not car_ids:
            st.error("No CAR analytics found. Please ensure phase4_enhanced_outputs.json exists.")
            st.stop()

        input_method = st.radio("Input Method:", ["Select from list", "Search by ID"])

        if input_method == "Select from list":
            selected_car_id = st.selectbox("Select CAR ID:", car_ids)
        else:
            search_term = st.text_input("Search CAR ID (e.g., CAR-2013-02-003):")
            matching_ids = [id for id in car_ids if search_term.upper() in id]
            if matching_ids:
                selected_car_id = st.selectbox("Matching CAR IDs:", matching_ids)
            else:
                st.warning("No matching CAR IDs found")
                selected_car_id = None

        st.divider()
        st.markdown("### About This Tool")
        st.markdown("""
        This interface displays **5 structured outputs** for each MITRE CAR analytic:

        1. **Summary** - Plain-English explanation
        2. **ATT&CK Mapping** - Technique classification
        3. **Hypothesis** - Testable hunting question
        4. **SIEM Query** - Splunk/KQL queries
        5. **False Positives** - Tuning guidance

        Data Source: phase4_enhanced outputs (Phase 4 completion)
        """)

    if selected_car_id:
        artifact = get_artifact(selected_car_id)

        if artifact:
            st.header(selected_car_id)
            st.divider()

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Analytic ID", selected_car_id)
            with col2:
                st.caption("5 Structured Outputs")
            with col3:
                st.caption("Phase 4 Artifacts")

            st.divider()

            if "summary_explanation" in artifact:
                render_summary_explanation(artifact["summary_explanation"])

            if "attack_mapping" in artifact:
                render_attack_mapping(artifact["attack_mapping"])

            if "hunting_hypothesis" in artifact:
                render_hunting_hypothesis(artifact["hunting_hypothesis"])

            if "siem_query" in artifact:
                render_siem_query(artifact["siem_query"])

            if "false_positives" in artifact:
                render_false_positives(artifact["false_positives"])

            st.divider()
            st.markdown("### Export & Share")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Copy as JSON"):
                    st.code(json.dumps(artifact, indent=2), language="json")
            with col2:
                json_str = json.dumps(artifact, indent=2)
                st.download_button(
                    label="Download JSON",
                    data=json_str,
                    file_name=f"{selected_car_id}_artifacts.json",
                    mime="application/json"
                )
        else:
            st.error(f"Artifact not found for CAR ID: {selected_car_id}")
    else:
        st.info("Select a CAR ID from the sidebar to view threat hunting artifacts")

if __name__ == "__main__":
    main()
