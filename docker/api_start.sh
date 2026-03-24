#!/bin/bash
set -e

echo "[API] ICOC-Lite API starting..."
echo "[API] Waiting for PostgreSQL..."

# Wait for DB to be ready
for i in $(seq 1 30); do
    python3 -c "
import psycopg2, os
try:
    conn = psycopg2.connect(os.getenv('POSTGRES_URL','postgresql://icoc:icoc2026@db:5432/icoc'))
    conn.close()
    print('DB ready')
    exit(0)
except Exception as e:
    exit(1)
" && break || true
    echo "[API] DB not ready yet ($i/30)..."
    sleep 2
done

echo "[API] Creating database schema..."
python3 -c "
import sys
sys.path.insert(0, '/app')
from database import create_schema, seed_lab_data
create_schema()
seed_lab_data()
print('[API] Schema ready')
"

echo "[API] Checking ML models..."
python3 -c "
import os, sys
sys.path.insert(0, '/app')
sys.path.insert(0, '/app/ai')
sys.path.insert(0, '/app/voc')

model_path = '/app/ai/models/saved/severity_classifier.pkl'
if os.path.exists(model_path):
    print('[API] ML models already trained — skipping')
else:
    print('[API] ML models not found — training now...')
    # Try real NVD cache first
    from fr_voc_06_nvd_integration import load_cached_cves, _generate_synthetic_cves
    cves = load_cached_cves()
    if len(cves) >= 50:
        print(f'[API] Training on {len(cves)} cached NVD CVEs')
    else:
        print('[API] No NVD cache or too few CVEs — using synthetic dataset (2000 samples)')
        cves = _generate_synthetic_cves(2000)

    import sys as _sys
    # Add ai dir to path so model imports work
    _sys.path.insert(0, '/app/ai')
    from models.exploitability_model import train as train_exploit
    from models.severity_classifier  import train as train_classifier
    from models.anomaly_detector     import train as train_anomaly

    valid = [c for c in cves if c.get('cvss_vector') and c.get('cvss_score', 0) > 0]
    print(f'[API] Valid CVEs for training: {len(valid)}')
    try:
        m = train_exploit(valid)
        print(f'[API] Exploitability model trained — R²={m[\"r2_score\"]}')
    except Exception as e:
        print(f'[API] Exploitability model failed: {e}')
    try:
        m = train_classifier(valid)
        print(f'[API] Severity classifier trained — accuracy={m[\"accuracy\"]}')
    except Exception as e:
        print(f'[API] Severity classifier failed: {e}')
    try:
        m = train_anomaly(valid)
        print(f'[API] Anomaly detector trained — {m[\"training_samples\"]} samples')
    except Exception as e:
        print(f'[API] Anomaly detector failed: {e}')
    print('[API] ML training complete')
"

echo "[API] Running startup background tasks (inventory + compliance)..."
python3 -c "
import sys, time
sys.path.insert(0, '/app')
sys.path.insert(0, '/app/voc')
sys.path.insert(0, '/app/ai')

# Run inventory scan
try:
    from fr_voc_01_inventory import run_inventory_scan
    from database import upsert_inventory
    result = run_inventory_scan()
    if result.total_packages > 0:
        rows = [{'host_ip': e.host_ip, 'hostname': e.hostname, 'os': e.os,
                 'package': e.package, 'version': e.version, 'scanned_at': e.scanned_at}
                for e in result.entries]
        upsert_inventory(rows)
        print('[STARTUP] Inventory: {} packages saved'.format(len(rows)))
    else:
        print('[STARTUP] Inventory: SSH scan returned 0 packages - check connectivity to victim')
except Exception as e:
    print('[STARTUP] Inventory scan failed (non-critical): {}'.format(e))

# Save initial compliance snapshot
try:
    from fr_voc_07_compliance import generate_compliance_report
    report = generate_compliance_report()
    print('[STARTUP] Compliance snapshot saved')
except Exception as e:
    print('[STARTUP] Compliance snapshot failed (non-critical): {}'.format(e))
" &

echo "[API] Starting uvicorn..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
