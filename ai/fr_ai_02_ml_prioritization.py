"""
FR-AI-02: ML-Based Alert Prioritization
Uses trained severity classifier to re-rank incoming alerts.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "voc"))
sys.path.insert(0, os.path.dirname(__file__))

def prioritize_alerts(alerts: list) -> list:
    """
    FR-AI-02: Re-rank alerts using ML severity classifier.
    Falls back to CVSS-based ranking if model not trained.
    """
    model_path = os.path.join(os.path.dirname(__file__), "models", "saved", "severity_classifier.pkl")
    if os.path.exists(model_path):
        try:
            from models.severity_classifier import predict_batch
            classified = predict_batch(alerts)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
            for alert, cls in zip(alerts, classified):
                alert["ml_severity"] = cls["predicted_severity"]
                alert["ml_confidence"] = cls["confidence"]
            return sorted(alerts, key=lambda a: (
                severity_order.get(a.get("ml_severity", "Medium"), 2),
                -a.get("cvss_score", 0)
            ))
        except Exception as e:
            print(f"[FR-AI-02] ML classify failed: {e} — using CVSS fallback")

    # Fallback: sort by CVSS score
    return sorted(alerts, key=lambda a: a.get("cvss_score", 0), reverse=True)
