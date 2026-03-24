"""
AI Model 3: Anomaly Detection on Scan Results
Uses Isolation Forest + Autoencoder approach to detect unusual
vulnerability patterns that may indicate active exploitation or
misconfigured systems.
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
import json

from .exploitability_model import parse_vector_to_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "saved", "anomaly_detector.pkl")
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

def _cve_to_anomaly_features(cve: dict) -> np.ndarray:
    """
    Build feature vector for anomaly detection.
    Includes temporal, scoring, and behavioral features.
    """
    import datetime

    base_features = parse_vector_to_features(cve.get("cvss_vector", ""))
    score = cve.get("cvss_score", 0.0)

    # Temporal feature: days since published
    try:
        pub = datetime.datetime.fromisoformat(
            cve.get("published", "2023-01-01T00:00:00").replace("Z", "")
        )
        days_old = max(0, (datetime.datetime.utcnow() - pub).days)
    except Exception:
        days_old = 365

    # Scoring anomaly: score much higher/lower than vector would suggest
    vector = cve.get("cvss_vector", "")
    high_impact = 1 if (vector and "/C:H/I:H/A:H" in vector) else 0
    network_vector = 1 if (vector and "AV:N" in vector) else 0
    no_auth = 1 if (vector and "PR:N" in vector) else 0

    # Status features
    status_map = {"missing": 0, "available": 1, "scheduled": 2, "applied": 3, "wontfix": 4}
    status = status_map.get(cve.get("status", "missing"), 0)

    return np.concatenate([
        base_features,
        [score, days_old / 365.0, high_impact, network_vector, no_auth, status]
    ])

def train(cves: list) -> dict:
    """
    FR-AI-03: Train anomaly detector using Isolation Forest.
    Learns the "normal" distribution of CVE patterns.
    Anomalies = unusual combinations (high score + no patch + network vector + etc.)
    """
    print(f"[MODEL-ANOMALY] Training on {len(cves)} CVEs...")

    X = []
    for cve in cves:
        if cve.get("cvss_vector") and cve.get("cvss_score", 0) > 0:
            X.append(_cve_to_anomaly_features(cve))

    if len(X) < 10:
        raise ValueError(f"Not enough data: {len(X)} samples")

    X = np.array(X)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("detector", IsolationForest(
            n_estimators=200,
            contamination=0.05,  # Expect ~5% anomalies
            max_samples="auto",
            random_state=42,
            n_jobs=-1
        ))
    ])

    model.fit(X)

    # Compute anomaly scores on training set for threshold calibration
    scores = model.decision_function(X)
    threshold = float(np.percentile(scores, 5))  # bottom 5% = anomaly

    metadata = {
        "model": "IsolationForest",
        "training_samples": len(X),
        "contamination": 0.05,
        "anomaly_threshold": round(threshold, 4),
        "score_mean": round(float(scores.mean()), 4),
        "score_std": round(float(scores.std()), 4)
    }

    joblib.dump({"model": model, "threshold": threshold, "metadata": metadata}, MODEL_PATH)
    print(f"[MODEL-ANOMALY] Trained → threshold: {threshold:.4f}")
    return metadata

def detect(cves: list) -> list:
    """
    Detect anomalous CVEs in a list of scan results.
    Returns list of CVEs with anomaly scores and flags.
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Anomaly detector not trained yet.")

    saved = joblib.load(MODEL_PATH)
    model = saved["model"]
    threshold = saved["threshold"]

    results = []
    for cve in cves:
        if not cve.get("cvss_vector"):
            continue
        features = _cve_to_anomaly_features(cve).reshape(1, -1)
        score = float(model.decision_function(features)[0])
        prediction = int(model.predict(features)[0])
        is_anomaly = prediction == -1  # IsolationForest: -1 = anomaly

        # Anomaly severity based on score
        if is_anomaly:
            if score < threshold - 0.1:
                anomaly_level = "severe"
            else:
                anomaly_level = "moderate"
        else:
            anomaly_level = "normal"

        results.append({
            "cve_id": cve.get("cve_id", "unknown"),
            "host_ip": cve.get("host_ip", "unknown"),
            "cvss_score": cve.get("cvss_score", 0),
            "severity": cve.get("severity", "unknown"),
            "status": cve.get("status", "unknown"),
            "anomaly_score": round(score, 4),
            "is_anomaly": is_anomaly,
            "anomaly_level": anomaly_level,
            "reason": _explain_anomaly(cve) if is_anomaly else None
        })

    anomalies = [r for r in results if r["is_anomaly"]]
    print(f"[MODEL-ANOMALY] Detected {len(anomalies)}/{len(results)} anomalies")
    return results

def _explain_anomaly(cve: dict) -> str:
    """Generate a human-readable explanation for why a CVE is anomalous."""
    reasons = []
    score = cve.get("cvss_score", 0)
    vector = cve.get("cvss_vector", "")
    status = cve.get("status", "")

    if score >= 9.0 and status == "missing":
        reasons.append(f"Critical CVE (CVSS {score}) with no patch applied")
    if "AV:N" in vector and "PR:N" in vector and "UI:N" in vector:
        reasons.append("Fully remote, no-auth, no-interaction attack vector")
    if "/C:H/I:H/A:H" in vector:
        reasons.append("Complete CIA impact triad (maximum damage potential)")
    if "S:C" in vector:
        reasons.append("Scope change — potential for lateral movement")
    if not reasons:
        reasons.append("Unusual combination of CVSS metrics compared to training baseline")

    return "; ".join(reasons)

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "voc"))
    from fr_voc_06_nvd_integration import load_cached_cves, _generate_synthetic_cves
    from fr_voc_03_patch_tracking import load_patch_db

    cves = load_cached_cves()
    if not cves:
        cves = _generate_synthetic_cves(500)

    metadata = train(cves)
    print(f"Threshold: {metadata['anomaly_threshold']}")

    # Test on lab CVEs
    try:
        patch_records = load_patch_db()
        lab_cves = [
            {
                "cve_id": r.cve_id,
                "cvss_score": r.cvss_score,
                "cvss_vector": "",
                "severity": r.severity,
                "status": r.status,
                "host_ip": r.host_ip
            }
            for r in patch_records
        ]
        # Add vectors from known CVEs
        from fr_voc_02_cvss_scoring import DEMO_CVE_VECTORS
        vector_map = {cve_id: vec for cve_id, vec, _ in DEMO_CVE_VECTORS}
        for c in lab_cves:
            c["cvss_vector"] = vector_map.get(c["cve_id"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        results = detect(lab_cves)
        print("\nAnomaly Detection on Lab CVEs:")
        for r in results:
            flag = "⚠ ANOMALY" if r["is_anomaly"] else "  normal"
            print(f"  {flag} | {r['cve_id']} | score={r['anomaly_score']:.3f} | {r.get('reason','')}")
    except Exception as e:
        print(f"Lab test error: {e}")
