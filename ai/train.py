"""
AI Training Pipeline — trains all 3 models on real NVD CVE data.
Run this before starting the API server.

Usage:
    python train.py                        # Use cached NVD data (recommended)
    python train.py --download             # Force fresh NVD download first
    python train.py --synthetic            # Use synthetic data (no internet, for testing only)
    python train.py --years 2022 2024      # Specify year range for --download

IMPORTANT: The cache at voc/data/nvd_cache/cve_database.json must exist
and contain real NVD data before running without --synthetic. If it doesn't,
run fr_voc_06_nvd_integration.py --download from a machine with internet access.
"""

import sys
import os
import json
import argparse
import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VOC_DIR    = os.path.join(SCRIPT_DIR, "..", "voc")
sys.path.insert(0, VOC_DIR)
sys.path.insert(0, SCRIPT_DIR)


def train_all(cves: list) -> dict:
    """Train all three ML models sequentially."""
    from models.exploitability_model import train as train_exploit
    from models.severity_classifier  import train as train_classifier
    from models.anomaly_detector     import train as train_anomaly

    print(f"\n{'='*60}")
    print(f"ICOC-LITE AI Training Pipeline")
    print(f"Dataset size: {len(cves)} CVEs")
    print(f"Started: {datetime.datetime.utcnow().isoformat()}Z")
    print(f"{'='*60}\n")

    valid_cves = [c for c in cves
                  if c.get("cvss_vector") and c.get("cvss_score", 0) > 0]
    print(f"Valid CVEs with CVSS data: {len(valid_cves)}\n")

    if len(valid_cves) < 50:
        print("[!] Warning: small dataset — model accuracy may be limited.")
        print("  Run: python voc/fr_voc_06_nvd_integration.py --download")
        print("  Then re-run train.py\n")

    results = {}

    print(f"[1/3] Training Exploitability Regression Model...")
    try:
        results["exploitability"] = train_exploit(valid_cves)
        print(f"  [OK] RMSE: {results['exploitability']['rmse']} "
              f"| R2: {results['exploitability']['r2_score']}\n")
    except Exception as exc:
        print(f"  [FAILED] Failed: {exc}\n")
        results["exploitability"] = {"error": str(exc)}

    print("[2/3] Training Severity Classifier...")
    try:
        results["severity_classifier"] = train_classifier(valid_cves)
        print(f"  [OK] Accuracy: {results['severity_classifier']['accuracy']} "
              f"| CV: {results['severity_classifier']['cv_accuracy_mean']}\n")
    except Exception as exc:
        print(f"  [FAILED] Failed: {exc}\n")
        results["severity_classifier"] = {"error": str(exc)}

    print("[3/3] Training Anomaly Detector...")
    try:
        results["anomaly_detector"] = train_anomaly(valid_cves)
        print(f"  [OK] Threshold: {results['anomaly_detector']['anomaly_threshold']}\n")
    except Exception as exc:
        print(f"  [FAILED] Failed: {exc}\n")
        results["anomaly_detector"] = {"error": str(exc)}

    report = {
        "trained_at":     datetime.datetime.utcnow().isoformat() + "Z",
        "dataset_size":   len(cves),
        "valid_samples":  len(valid_cves),
        "data_source":    cves[0].get("source", "unknown") if cves else "empty",
        "models":         results,
    }
    report_path = os.path.join(SCRIPT_DIR, "models", "saved", "training_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"{'='*60}")
    print(f"Training complete! Report: {report_path}")
    print(f"{'='*60}\n")
    return results


def main():
    parser = argparse.ArgumentParser(description="ICOC-Lite AI Training Pipeline")
    parser.add_argument("--download", action="store_true",
                        help="Download fresh NVD data before training")
    parser.add_argument("--synthetic", action="store_true",
                        help="Use synthetic data (testing only — not for final evaluation)")
    parser.add_argument("--years", nargs=2, type=int, default=[2021, 2024],
                        metavar=("START", "END"))
    parser.add_argument("--max-per-year", type=int, default=500)
    args = parser.parse_args()

    from fr_voc_06_nvd_integration import (
        load_cached_cves, fetch_bulk_for_training, _generate_synthetic_cves
    )

    if args.synthetic:
        print("[TRAIN] --synthetic: generating synthetic CVE dataset (testing only)")
        print("[TRAIN] WARNING: models trained on synthetic data will NOT be used in production")
        cves = _generate_synthetic_cves(2000)

    elif args.download:
        print(f"[TRAIN] --download: fetching CVEs from NVD "
              f"({args.years[0]}–{args.years[1]})...")
        nvd_key = os.getenv("NVD_API_KEY", "").strip()
        if nvd_key:
            print(f"[TRAIN] NVD API key found: {nvd_key[:8]}...")
        else:
            print("[TRAIN] WARNING: NVD_API_KEY not set in .env — using unauthenticated access (slow)")
        cves = fetch_bulk_for_training(
            start_year=args.years[0],
            end_year=args.years[1],
            max_per_year=args.max_per_year
        )
        if not cves:
            print("[TRAIN] ✗ NVD download returned no data.")
            print("[TRAIN]   Possible causes:")
            print("[TRAIN]     1. NVD API key invalid/expired — check NVD_API_KEY in .env")
            print("[TRAIN]     2. No internet access from Docker container")
            print("[TRAIN]     3. NVD API temporarily unavailable")
            print("[TRAIN]   Falling back to synthetic dataset for this run...")
            print("[TRAIN]   To fix NVD: get a free key at https://nvd.nist.gov/developers/request-an-api-key")
            cves = _generate_synthetic_cves(2000)
            print(f"[TRAIN] Generated {len(cves)} synthetic CVEs (statistically realistic)")
            print("[TRAIN] WARNING: Models trained on synthetic data — retrain with real NVD data later")

    else:
        print("[TRAIN] Loading cached NVD CVEs...")
        cves = load_cached_cves()
        if not cves:
            print("\n[TRAIN] ✗ No NVD cache found and no --download flag specified.")
            print("[TRAIN]   Options:")
            print("[TRAIN]     1. python train.py --download          (requires internet)")
            print("[TRAIN]     2. python train.py --synthetic          (testing only)")
            print("[TRAIN]   Populate the cache first from a machine with internet:")
            print("[TRAIN]     python voc/fr_voc_06_nvd_integration.py --download")
            sys.exit(1)

        source = cves[0].get("source", "unknown") if cves else "unknown"
        if source == "synthetic":
            print("\n[TRAIN] [!] WARNING: cached data is synthetic (generated, not real NVD).")
            print("[TRAIN]   Run 'python train.py --download' to replace with real data.")
            print("[TRAIN]   Continuing with synthetic data...\n")

    results = train_all(cves)

    print("\nTraining Summary:")
    for name, metrics in results.items():
        if "error" in metrics:
            print(f"  [X] {name}: {metrics['error']}")
        elif name == "exploitability":
            print(f"  [OK] Exploitability: R2={metrics.get('r2_score')} RMSE={metrics.get('rmse')}")
        elif name == "severity_classifier":
            print(f"  [OK] Severity Classifier: Accuracy={metrics.get('accuracy')}")
        elif name == "anomaly_detector":
            print(f"  [OK] Anomaly Detector: {metrics.get('training_samples')} samples")


if __name__ == "__main__":
    main()