# CAR Threat Hunting Artifacts UI

Interactive Streamlit interface for exploring all 5 structured threat hunting outputs for MITRE CAR analytics.

## Quick Start

### 1. Install (if needed)
Streamlit is already installed in your venv. To verify:
```bash
pip list | grep streamlit
```

### 2. Run the App
From the project root directory:
```bash
streamlit run streamlit_app.py
```

This opens the app at `http://localhost:8501` in your default browser.

### 3. Usage
- **Sidebar**: Select a CAR ID from dropdown or search by ID
- **Main View**: Displays all 5 structured outputs for the selected analytic
- **Expandable Sections**: Click to expand/collapse each output type
- **Export**: Copy as JSON or download the artifact file

## Features

### Input Options
- **Select from list**: Browse all available CAR IDs
- **Search by ID**: Type/paste a CAR ID (e.g., CAR-2013-02-003)

### 5 Structured Outputs

1. **Summary Explanation**
   - Plain-English description of what the analytic detects
   - Why it matters for threat hunting
   - Adversary behavior patterns
   - Confidence level

2. **ATT&CK Technique Mapping**
   - Technique ID and name
   - Tactic(s) and subtechniques
   - Rationale explaining the link between detection and technique
   - Per-technique confidence

3. **Threat Hunting Hypothesis**
   - Testable "if-then" question format
   - Explanation avoiding circularity
   - Clear data sources and indicators
   - Confidence and testability status

4. **SIEM Query**
   - Splunk SPL or KQL syntax
   - Platform and query type
   - Data model fields used
   - Caveats and validation issues
   - Confidence level

5. **False Positive Analysis**
   - Realistic scenarios that could trigger the analytic
   - Risk level assessment
   - Detailed explanation
   - Recommended triage filters
   - Confidence in false positive prediction

## Data Source

The app loads pre-generated artifacts from:
```
outputs/phase4_enhanced/phase4_enhanced_outputs.json
```

Currently includes 10 CAR analytics with quality scores documented in PHASE5_COMPLETION_REPORT.md

## Customization

### Change Output Source
Edit the `OUTPUTS_FILE` path in `streamlit_app.py`:
```python
OUTPUTS_FILE = Path(__file__).parent / "outputs" / "YOUR_FOLDER" / "outputs.json"
```

### Modify UI Layout
- Change `layout="wide"` to `layout="centered"` in `st.set_page_config()`
- Adjust column distributions in `st.columns()` calls
- Modify colors/styling via Streamlit theming

## Troubleshooting

### Port Already in Use
Run on a different port:
```bash
streamlit run streamlit_app.py --server.port 8502
```

### Data Not Loading
1. Verify JSON file exists at the configured path
2. Check JSON is valid:
   ```bash
   python -c "import json; json.load(open('outputs/phase4_enhanced/phase4_enhanced_outputs.json'))"
   ```

### Slow Loading
The app caches outputs in memory via `@st.cache_resource`. Clear cache if needed:
```bash
streamlit cache clear
```

## Next Steps

### To Generate New Outputs
Run the Phase 4 query generation pipeline:
```bash
# See notebooks/04_phase4_generation.ipynb
jupyter notebook notebooks/04_phase4_generation.ipynb
```

### To Integrate Real-Time Generation
Modify the app to call the LLM pipeline instead of loading pre-generated outputs:
```python
from src.query_generator import generate_artifacts

artifact = generate_artifacts(car_id)
```

This would require:
- Configuring Anthropic API credentials
- Adding LLM calls to generate outputs on-demand
- Caching results to avoid repeated API calls
