"""
Confidence monitoring system.
Tracks confidence levels across outputs and detects over-confidence.
"""
from collections import defaultdict, Counter
import json
from datetime import datetime

class ConfidenceMonitor:
    """Monitor confidence levels in threat hunting outputs."""

    def __init__(self):
        self.sessions = []  # List of monitoring sessions
        self.current_session = None

    def start_session(self, session_name: str = None):
        """Start a new monitoring session."""
        session_id = session_name or datetime.now().isoformat()
        self.current_session = {
            "session_id": session_id,
            "start_time": datetime.now().isoformat(),
            "analytics": {},
            "summary": {}
        }
        self.sessions.append(self.current_session)

    def record_output(self, analytic_id: str, output: dict):
        """Record confidence levels from a single output."""
        if not self.current_session:
            self.start_session()

        confidence_data = {
            "analytic_id": analytic_id,
            "summary_explanation": None,
            "hunting_hypothesis": None,
            "siem_query": None,
            "false_positives": None,
            "attack_mapping": None
        }

        # Extract confidence from each section
        se = output.get("summary_explanation", {})
        if se:
            confidence_data["summary_explanation"] = se.get("confidence", "unknown")

        hh = output.get("hunting_hypothesis", {})
        if hh:
            confidence_data["hunting_hypothesis"] = hh.get("confidence", "unknown")

        sq = output.get("siem_query", {})
        if sq:
            confidence_data["siem_query"] = sq.get("confidence", "unknown")

        fp = output.get("false_positives", {})
        if fp:
            confidence_data["false_positives"] = fp.get("confidence", "unknown")

        am = output.get("attack_mapping", {})
        if am:
            # For attack_mapping, take average of technique confidences
            techniques = am.get("techniques", [])
            if techniques:
                confs = [t.get("confidence", "medium") for t in techniques]
                # Map to numeric for averaging
                conf_map = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
                avg_conf = sum(conf_map.get(c, 0) for c in confs) / len(confs)
                # Map back to level
                if avg_conf >= 2.5:
                    confidence_data["attack_mapping"] = "high"
                elif avg_conf >= 1.5:
                    confidence_data["attack_mapping"] = "medium"
                else:
                    confidence_data["attack_mapping"] = "low"

        self.current_session["analytics"][analytic_id] = confidence_data

    def end_session(self) -> dict:
        """End current session and generate summary."""
        if not self.current_session:
            return {}

        analytics = self.current_session["analytics"]
        sections = ["summary_explanation", "hunting_hypothesis", "siem_query", "false_positives", "attack_mapping"]

        summary = {}
        for section in sections:
            confs = [a[section] for a in analytics.values() if a[section]]
            if not confs:
                continue

            distribution = Counter(confs)
            summary[section] = {
                "distribution": dict(distribution),
                "total": len(confs),
                "high_confidence_pct": 100 * distribution.get("high", 0) / len(confs),
                "low_confidence_pct": 100 * distribution.get("low", 0) / len(confs),
            }

        self.current_session["summary"] = summary
        self.current_session["end_time"] = datetime.now().isoformat()

        return self.current_session

    def get_trends(self) -> dict:
        """Analyze confidence trends across all sessions."""
        if not self.sessions:
            return {"message": "No sessions recorded"}

        trends = defaultdict(list)

        for session in self.sessions:
            summary = session.get("summary", {})
            for section, data in summary.items():
                trends[section].append({
                    "session": session["session_id"],
                    "high_pct": data.get("high_confidence_pct", 0),
                    "timestamp": session.get("start_time")
                })

        return {
            "total_sessions": len(self.sessions),
            "trends": dict(trends),
            "alerts": self._generate_alerts(trends)
        }

    def _generate_alerts(self, trends: dict) -> list:
        """Generate alerts for concerning trends."""
        alerts = []

        for section, history in trends.items():
            if len(history) >= 2:
                # Check if >80% high confidence across multiple sessions
                high_pcts = [h["high_pct"] for h in history]
                avg_high = sum(high_pcts) / len(high_pcts)

                if avg_high > 80:
                    alerts.append({
                        "severity": "warning",
                        "section": section,
                        "message": f"Average {section} high confidence: {avg_high:.0f}% (may indicate over-confidence)",
                        "recommendation": "Review confidence calibration and add hedging language"
                    })

                # Check for decreasing confidence (quality regression)
                if len(history) >= 3:
                    trend = high_pcts[-1] - high_pcts[0]
                    if trend < -15:
                        alerts.append({
                            "severity": "info",
                            "section": section,
                            "message": f"{section} confidence declining: {high_pcts[0]:.0f}% -> {high_pcts[-1]:.0f}%",
                            "recommendation": "Monitor cause (model drift, prompt changes, etc.)"
                        })

        return alerts

    def save_report(self, filepath: str):
        """Save monitoring report to file."""
        data = {
            "sessions": self.sessions,
            "trends": self.get_trends()
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


# Global monitor instance
_monitor = ConfidenceMonitor()

def get_monitor() -> ConfidenceMonitor:
    """Get global monitor instance."""
    return _monitor
