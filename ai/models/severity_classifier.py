"""
AI Model 2: Alert Severity Classifier (Multi-class)
Classifies CVEs/alerts into Critical/High/Medium/Low/None.
Uses Random Forest with probability calibration.
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline

from .exploitability_model import parse_vector_to_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "saved", "severity_classifier.pkl")
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

SEVERITY_LABELS = ["None", "Low", "Medium", "High", "Critical"]

def _encode_severity(sev_str: str) -> int:
    mapping = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4, "Unknown": 2}
    return mapping.get(sev_str, 2)

def build_dataset(cves: list) -> tuple:
    X, y = [], []
    for cve in cves:
        vector = cve.get("cvss_vector", "")
        severity = cve.get("severity", "")
        if vector and severity in SEVERITY_LABELS:
            features = parse_vector_to_features(vector)
            features = np.append(features, [cve.get("cvss_score", 0.0)])
            X.append(features)
            y.append(_encode_severity(severity))
    return np.array(X), np.array(y)

def train(cves: list) -> dict:
    """
    FR-AI-02: Train severity classifier on NVD CVE data.
    Returns performance metrics.
    """
    print(f"[MODEL-CLASSIFIER] Training on {len(cves)} CVEs...")
    X, y = build_dataset(cves)

    if len(X) < 20:
        raise ValueError(f"Not enough training data: {len(X)} samples")

    # Get the actual classes present in the data
    present_classes = sorted(set(y))
    present_labels = [SEVERITY_LABELS[i] for i in present_classes]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", CalibratedClassifierCV(rf, cv=3, method="sigmoid"))
    ])

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    # Use labels= to only report on classes actually present
    report = classification_report(y_test, y_pred,
                                   labels=present_classes,
                                   target_names=present_labels,
                                   output_dict=True,
                                   zero_division=0)
    cv = cross_val_score(model, X, y, cv=5, scoring="accuracy")

    metrics = {
        "model": "RandomForest+Calibration",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(float(acc), 4),
        "cv_accuracy_mean": round(float(cv.mean()), 4),
        "cv_accuracy_std": round(float(cv.std()), 4),
        "classes_present": present_labels,
        "per_class": {
            cls: {
                "precision": round(report[cls]["precision"], 3),
                "recall": round(report[cls]["recall"], 3),
                "f1": round(report[cls]["f1-score"], 3)
            }
            for cls in present_labels if cls in report
        }
    }

    joblib.dump(model, MODEL_PATH)
    print(f"[MODEL-CLASSIFIER] Trained -> Accuracy: {metrics['accuracy']}")
    print(f"[MODEL-CLASSIFIER] CV Accuracy: {metrics['cv_accuracy_mean']} +/- {metrics['cv_accuracy_std']}")
    return metrics

def predict(vector_str: str, cvss_score: float = 0.0) -> dict:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Classifier not trained yet. Run train() first.")
    model = joblib.load(MODEL_PATH)
    features = parse_vector_to_features(vector_str)
    features = np.append(features, [cvss_score]).reshape(1, -1)
    predicted_class = int(model.predict(features)[0])
    probabilities = model.predict_proba(features)[0]
    return {
        "vector": vector_str,
        "cvss_score": cvss_score,
        "predicted_severity": SEVERITY_LABELS[predicted_class],
        "confidence": round(float(max(probabilities)), 3),
        "class_probabilities": {
            SEVERITY_LABELS[i]: round(float(p), 3)
            for i, p in enumerate(probabilities)
        },
        "model": "severity_classifier"
    }

def predict_batch(records: list) -> list:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Classifier not trained yet.")
    model = joblib.load(MODEL_PATH)
    features_list = []
    for r in records:
        f = parse_vector_to_features(r.get("cvss_vector", ""))
        f = np.append(f, [r.get("cvss_score", 0.0)])
        features_list.append(f)
    X = np.array(features_list)
    predicted = model.predict(X)
    probas = model.predict_proba(X)
    results = []
    for i, r in enumerate(records):
        results.append({
            "cve_id": r.get("cve_id"),
            "predicted_severity": SEVERITY_LABELS[int(predicted[i])],
            "confidence": round(float(max(probas[i])), 3),
            "original_severity": r.get("severity", "unknown")
        })
    return results

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "voc"))
    from fr_voc_06_nvd_integration import load_cached_cves, _generate_synthetic_cves
    cves = load_cached_cves()
    if not cves:
        cves = _generate_synthetic_cves(1000)
    metrics = train(cves)
    print("\nTest predictions:")
    tests = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ]
    for v, score in tests:
        r = predict(v, score)
        print(f"  Score {score} → {r['predicted_severity']} (conf={r['confidence']})")