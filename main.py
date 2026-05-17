"""
ICOC-Lite API Server — Member 3 (VOC + AI + NOC)
FastAPI backend serving all VOC, AI, and NOC module endpoints.
Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
import json
import asyncio
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VOC_DIR  = os.path.join(BASE_DIR, "voc")
AI_DIR   = os.path.join(BASE_DIR, "ai")
NOC_DIR  = os.path.join(BASE_DIR, "noc")
sys.path.insert(0, VOC_DIR)
sys.path.insert(0, AI_DIR)
sys.path.insert(0, NOC_DIR)

app = FastAPI(
    title="ICOC-Lite Integrated API",
    description="Vulnerability Operations Center (VOC) + Network Operations Center (NOC) + AI Risk Engine — Members 2 & 3",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic Models ───────────────────────────────────────────────────────────

class PatchUpdate(BaseModel):
    cve_id: str
    host_ip: str
    notes: Optional[str] = ""

class VTHashCheck(BaseModel):
    hash: str

class VTIPCheck(BaseModel):
    ip: str

class VTURLCheck(BaseModel):
    url: str

class ScanRequest(BaseModel):
    network: Optional[str] = None
    enrich_vt: bool = True

class SOCAlert(BaseModel):
    id: str
    type: str
    src_ip: str
    dst_ip: str
    cvss_score: Optional[float] = 0.0
    cvss_vector: Optional[str] = ""
    severity: Optional[str] = "Medium"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _live_soc_stats() -> dict:
    """
    Pull real-time SOC stats from event_store.
    Returns alert count, incident count, and threat intel hit count
    so the AI risk score reflects actual lab activity, not hardcoded values.
    Falls back to zeros if event_store is not yet populated.
    """
    # Get threat intel count dynamically from DB (falls back to len(STATIC_INTEL))
    try:
        from ai.fr_ai_05_07 import STATIC_INTEL
        _static_ti_count = len(STATIC_INTEL)
    except Exception:
        _static_ti_count = 11  # last-resort fallback if import fails

    try:
        from database import get_threat_intel_count
        ti_hits = get_threat_intel_count()
        if ti_hits == 0:
            ti_hits = _static_ti_count
    except Exception:
        ti_hits = _static_ti_count

    try:
        from event_store import get_live_stats
        stats = get_live_stats()
        return {
            "soc_alerts":        stats.get("alert_count_5min", 0),
            "active_incidents":  stats.get("incidents", 0),
            "threat_intel_hits": ti_hits,
        }
    except Exception:
        return {"soc_alerts": 0, "active_incidents": 0, "threat_intel_hits": ti_hits}

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {"service": "ICOC-Lite VOC/AI/NOC API", "status": "running", "version": "1.0.0"}

@app.get("/health", tags=["Health"])
def health():
    db_ok = False
    try:
        from database import test_connection
        db_ok = test_connection()
    except Exception:
        pass
    return {"status": "ok", "db_connected": db_ok}

# ── VOC Endpoints ─────────────────────────────────────────────────────────────

@app.get("/voc/inventory", tags=["VOC"])
def get_inventory():
    """FR-VOC-01: Get software inventory across all hosts."""
    from fr_voc_01_inventory import run_inventory_scan
    result = run_inventory_scan()
    return {
        "total_hosts":    result.total_hosts,
        "total_packages": result.total_packages,
        "scanned_at":     result.scanned_at,
        "source":         result.source,
        "entries": [
            {"host_ip": e.host_ip, "hostname": e.hostname, "os": e.os,
             "package": e.package, "version": e.version, "source": e.source}
            for e in result.entries
        ]
    }

@app.get("/voc/cvss/{cve_id}", tags=["VOC"])
def get_cvss_score(cve_id: str):
    """FR-VOC-02: Calculate CVSS v3.1 score for a CVE."""
    from fr_voc_02_cvss_scoring import LAB_CVE_VECTORS, parse_cvss_vector_string, calculate_cvss_v31
    # Check lab CVE list first (fast, no network)
    for cid, vec, desc in LAB_CVE_VECTORS:
        if cid == cve_id:
            v = parse_cvss_vector_string(vec, cid, desc)
            return calculate_cvss_v31(v)
    # Try NVD cache / live
    from fr_voc_06_nvd_integration import fetch_cve_by_id
    cve_data = fetch_cve_by_id(cve_id)
    if cve_data and cve_data.get("cvss_vector"):
        try:
            v = parse_cvss_vector_string(cve_data["cvss_vector"], cve_id,
                                          cve_data.get("description"))
            return calculate_cvss_v31(v)
        except Exception:
            pass
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

@app.get("/voc/cvss", tags=["VOC"])
def get_all_cvss():
    """FR-VOC-02: Score all lab CVEs — returns DB-backed CVEs with CVSS details."""
    from fr_voc_02_cvss_scoring import LAB_CVE_VECTORS, parse_cvss_vector_string, calculate_cvss_v31
    from database import get_cursor
    import os

    victim_ip = os.getenv("VICTIM_IP", "192.168.237.129")
    vector_map = {cve_id: (vec, desc) for cve_id, vec, desc in LAB_CVE_VECTORS}

    try:
        with get_cursor() as cur:
            # Only show CVEs for victim host, top 20 by score
            cur.execute("""
                SELECT DISTINCT ON (cve_id) cve_id, cvss_score, severity, source
                FROM cve_database
                WHERE cvss_score >= 7.0
                ORDER BY cve_id, cvss_score DESC
                LIMIT 20
            """)
            rows = cur.fetchall()
    except Exception as e:
        rows = []

    results = []
    for row in sorted(rows, key=lambda r: r["cvss_score"], reverse=True):
        cve_id = row["cve_id"]
        if cve_id in vector_map:
            vec, desc = vector_map[cve_id]
            v = parse_cvss_vector_string(vec, cve_id, desc)
            result = calculate_cvss_v31(v)
            result["source"] = row["source"]
            results.append(result)
        else:
            results.append({
                "cve_id": cve_id,
                "base_score": float(row["cvss_score"]),
                "severity": row["severity"],
                "vector_string": "N/A",
                "description": cve_id,
                "source": row["source"]
            })

    if not results:
        # No scan data yet
        return {"cves": [], "total": 0, "source": "empty", "message": "Run a scan first"}

    return {"cves": results, "total": len(results), "source": "db"}

@app.get("/voc/patches", tags=["VOC"])
def get_patches():
    """FR-VOC-03: Get patch status for all vulnerabilities."""
    from fr_voc_03_patch_tracking import get_patch_summary
    return get_patch_summary()

@app.post("/voc/patches/apply", tags=["VOC"])
def apply_patch(req: PatchUpdate):
    """FR-VOC-03: Mark a patch as applied."""
    from fr_voc_03_patch_tracking import mark_patch_applied
    return mark_patch_applied(req.cve_id, req.host_ip, req.notes or "")

@app.get("/voc/patches/overdue", tags=["VOC"])
def get_overdue(days: int = Query(7)):
    """FR-VOC-03: Get patches overdue by N days."""
    from fr_voc_03_patch_tracking import get_overdue_patches
    return {"overdue": get_overdue_patches(days)}

@app.get("/voc/report", tags=["VOC"])
def get_report(
    severity: Optional[str] = None,
    status:   Optional[str] = None,
    include_applied: bool = False
):
    """FR-VOC-04: Generate vulnerability report with filters."""
    from fr_voc_04_reports import generate_report
    sevs  = [s.strip() for s in severity.split(",")] if severity else None
    stats = [s.strip() for s in status.split(",")]   if status   else None
    return generate_report(sevs, stats, include_applied=include_applied)

@app.get("/voc/report/csv", tags=["VOC"])
def get_report_csv():
    """FR-VOC-04: Export vulnerability report as CSV."""
    from fr_voc_04_reports import generate_report, export_csv
    report = generate_report()
    csv = export_csv(report)
    return StreamingResponse(
        iter([csv]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={report['report_id']}.csv"}
    )

@app.post("/voc/scan", tags=["VOC"])
def trigger_scan(req: ScanRequest, background: BackgroundTasks):
    """FR-VOC-05: Trigger on-demand vulnerability scan (runs in background)."""
    from fr_voc_05_scanner import get_scan_state, _run_scan_tracked
    state = get_scan_state()
    if state["running"]:
        return {"message": "Scan already running", "scan_id": state["scan_id"],
                "pct": state["pct"], "stage": state["stage"]}
    background.add_task(_run_scan_tracked, req.network, req.enrich_vt)
    return {"message": "Scan started", "note": "Poll /voc/scan/status for progress"}

@app.get("/voc/scan/status", tags=["VOC"])
def get_scan_status():
    """FR-VOC-05: Get current scan progress and last result."""
    from fr_voc_05_scanner import get_scan_state
    return get_scan_state()

@app.get("/voc/scan/results", tags=["VOC"])
def get_scan_results():
    """FR-VOC-05: Get latest scan results from disk."""
    import glob
    scan_dir = os.path.join(VOC_DIR, "data", "scans")
    files = sorted(glob.glob(os.path.join(scan_dir, "SCAN-*.json")), reverse=True)
    if not files:
        raise HTTPException(status_code=404,
                            detail="No scan results yet. POST /voc/scan to trigger one.")
    with open(files[0]) as f:
        return json.load(f)

@app.get("/voc/nvd/recent", tags=["VOC"])
def get_recent_cves(days: int = Query(7), limit: int = Query(20)):
    """FR-VOC-06: Get recently published CVEs from NVD (or cache)."""
    from fr_voc_06_nvd_integration import fetch_recent_cves
    cves = fetch_recent_cves(days_back=days, max_results=limit)
    return {"total": len(cves), "cves": cves}

@app.get("/voc/nvd/{cve_id}", tags=["VOC"])
def get_cve(cve_id: str):
    """FR-VOC-06: Get specific CVE from NVD cache or live."""
    from fr_voc_06_nvd_integration import fetch_cve_by_id
    result = fetch_cve_by_id(cve_id)
    if result:
        return result
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD")

@app.get("/voc/compliance", tags=["VOC"])
def get_compliance():
    """FR-VOC-07: Get compliance assessment (PCI-DSS, ISO 27001, NIST CSF)."""
    from fr_voc_07_compliance import generate_compliance_report
    return generate_compliance_report()

# ── VirusTotal Endpoints ──────────────────────────────────────────────────────

@app.post("/vt/hash", tags=["VirusTotal"])
def vt_hash(req: VTHashCheck):
    """Check a file hash against VirusTotal."""
    from virustotal_client import check_file_hash
    return check_file_hash(req.hash)

@app.post("/vt/ip", tags=["VirusTotal"])
def vt_ip(req: VTIPCheck):
    """Check an IP reputation on VirusTotal."""
    from virustotal_client import check_ip
    return check_ip(req.ip)

@app.post("/vt/url", tags=["VirusTotal"])
def vt_url(req: VTURLCheck):
    """Check a URL against VirusTotal."""
    from virustotal_client import check_url
    return check_url(req.url)

# ── AI Endpoints ──────────────────────────────────────────────────────────────

@app.get("/ai/risk-score", tags=["AI"])
def get_risk_score(soc_alerts: int = None, incidents: int = None, ti_hits: int = None):
    """
    FR-AI-01: Get global risk score (0-100).
    If params not supplied, pulls live values from event_store automatically.
    """
    from fr_ai_01_risk_score import calculate_global_risk_score
    live = _live_soc_stats()
    score = calculate_global_risk_score(
        soc_alerts=soc_alerts        if soc_alerts is not None else live["soc_alerts"],
        active_incidents=incidents   if incidents  is not None else live["active_incidents"],
        threat_intel_hits=ti_hits    if ti_hits    is not None else live["threat_intel_hits"],
    )
    # Persist to DB for time-series
    try:
        from database import insert_risk_score
        insert_risk_score(score)
    except Exception:
        pass
    return score

@app.post("/ai/prioritize", tags=["AI"])
def prioritize(alerts: List[SOCAlert]):
    """FR-AI-02: ML-based alert prioritization."""
    from fr_ai_02_ml_prioritization import prioritize_alerts
    return {"prioritized": prioritize_alerts([a.dict() for a in alerts])}

@app.post("/ai/correlate", tags=["AI"])
def correlate(alerts: List[SOCAlert]):
    """FR-AI-03: Cross-domain SOC × VOC correlation."""
    from fr_ai_03_correlation import correlate_soc_voc
    return correlate_soc_voc([a.dict() for a in alerts])

@app.get("/ai/risk-stream", tags=["AI"])
async def risk_stream():
    """
    FR-AI-04: Real-time risk score stream (SSE, updates every 15s).
    Uses live event_store stats — no hardcoded values.
    """
    from fr_ai_01_risk_score import calculate_global_risk_score

    async def event_generator():
        while True:
            live  = _live_soc_stats()
            score = calculate_global_risk_score(
                soc_alerts=live["soc_alerts"],
                active_incidents=live["active_incidents"],
                threat_intel_hits=live["threat_intel_hits"],
            )
            # Persist each broadcast
            try:
                from database import insert_risk_score
                insert_risk_score(score)
            except Exception:
                pass
            yield f"data: {json.dumps(score)}\n\n"
            await asyncio.sleep(15)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/ai/threat-intel", tags=["AI"])
def get_threat_intel(limit: int = 20):
    """FR-AI-05: Get threat intelligence feed."""
    from fr_ai_05_07 import get_threat_intel_feed
    return {"feed": get_threat_intel_feed(limit)}

@app.get("/ai/predict-incident", tags=["AI"])
def predict_incident(soc_alerts: int = None):
    """FR-AI-06: Predict incident probability in next 24 hours."""
    from fr_ai_05_07 import predict_incident_probability
    if soc_alerts is None:
        soc_alerts = _live_soc_stats()["soc_alerts"]
    return predict_incident_probability(soc_alerts=soc_alerts)

@app.get("/ai/recommendations", tags=["AI"])
def get_recommendations(soc_alerts: int = None):
    """FR-AI-07: Get automated response recommendations."""
    from fr_ai_05_07 import generate_recommendations
    if soc_alerts is None:
        soc_alerts = _live_soc_stats()["soc_alerts"]
    return {"recommendations": generate_recommendations(soc_alerts=soc_alerts)}

@app.get("/ai/anomalies", tags=["AI"])
def detect_anomalies():
    """Detect anomalous CVE patterns using trained Isolation Forest model."""
    try:
        from fr_voc_03_patch_tracking import load_patch_db
        from fr_voc_02_cvss_scoring import LAB_CVE_VECTORS
        from models.anomaly_detector import detect

        records    = load_patch_db()
        vector_map = {cve_id: vec for cve_id, vec, _ in LAB_CVE_VECTORS}
        cves = [{
            "cve_id":      r.cve_id,
            "cvss_score":  r.cvss_score,
            "cvss_vector": vector_map.get(r.cve_id,
                           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "severity":    r.severity,
            "status":      r.status,
            "host_ip":     r.host_ip,
        } for r in records]
        return {"anomalies": detect(cves)}
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Anomaly model not trained. Run: python ai/train.py"
        )

@app.get("/ai/train-status", tags=["AI"])
def get_train_status():
    """Check if ML models are trained and ready."""
    model_dir = os.path.join(AI_DIR, "models", "saved")
    models = {
        "exploitability_model": os.path.exists(os.path.join(model_dir, "exploitability_model.pkl")),
        "severity_classifier":  os.path.exists(os.path.join(model_dir, "severity_classifier.pkl")),
        "anomaly_detector":     os.path.exists(os.path.join(model_dir, "anomaly_detector.pkl")),
    }
    report_path = os.path.join(model_dir, "training_report.json")
    report = None
    if os.path.exists(report_path):
        with open(report_path) as f:
            report = json.load(f)
    return {"models": models, "all_ready": all(models.values()), "training_report": report}

# ── Dashboard Aggregation Endpoint ────────────────────────────────────────────

@app.get("/dashboard", tags=["Dashboard"])
def get_dashboard():
    """
    Single endpoint returning all data needed by the React dashboard.
    Integrates VOC (vulnerabilities), NOC (performance), and AI (risk intelligence).
    All AI inputs pulled from live event_store — no hardcoded values.
    """
    from fr_ai_01_risk_score import calculate_global_risk_score
    from fr_voc_03_patch_tracking import get_patch_summary
    from fr_ai_05_07 import get_threat_intel_feed, generate_recommendations, predict_incident_probability
    from fr_voc_07_compliance import generate_compliance_report
    from fr_voc_02_cvss_scoring import parse_cvss_vector_string, calculate_cvss_v31, LAB_CVE_VECTORS
    from database import get_cves

    live = _live_soc_stats()
    risk = calculate_global_risk_score(
        soc_alerts=live["soc_alerts"],
        active_incidents=live["active_incidents"],
        threat_intel_hits=live["threat_intel_hits"],
    )
    # Persist risk score for history chart
    try:
        from database import insert_risk_score
        insert_risk_score(risk)
    except Exception:
        pass

    noc_data = {}
    try:
        from noc.noc_api import get_noc_summary
        from noc.noc_alerts import fetch_active_alerts
        noc_data["summary"] = get_noc_summary()
        # Call the async function from a sync context if needed, or just import logic
        # For simplicity in this aggregation, we can try to call it
        import asyncio
        loop = asyncio.new_event_loop()
        alerts_res = loop.run_until_complete(fetch_active_alerts())
        noc_data["alerts"] = alerts_res.get("alerts", [])
        loop.close()
    except Exception as e:
        noc_data = {"summary": {}, "alerts": [], "error": f"NOC unavailable: {e}"}

    return {
        "risk_score":          risk,
        "patch_summary":       get_patch_summary(),
        "threat_intel":        get_threat_intel_feed(5),
        "recommendations":     generate_recommendations(soc_alerts=live["soc_alerts"]),
        "incident_prediction": predict_incident_probability(soc_alerts=live["soc_alerts"]),
        "compliance":          generate_compliance_report(),
        "cve_scores":          get_all_cvss()["cves"],
        "noc":                 noc_data,
        "live_stats":          live,
    }


# ── Event Ingestion (Victim Agent + Attacker) ─────────────────────────────────
from event_routes import events_router
app.include_router(events_router)

from event_store import load_persisted
load_persisted()


# ── Database Routes ────────────────────────────────────────────────────────────

@app.get("/db/stats", tags=["Database"])
def db_stats():
    """Return row counts for all tables and DB size."""
    try:
        from database import get_db_stats
        return get_db_stats()
    except Exception as e:
        return {"error": str(e), "note": "DB may not be running"}

@app.get("/db/events", tags=["Database"])
def db_events(limit: int = 100, severity: str = None, event_type: str = None):
    """Query security_events table."""
    from database import get_events
    return {"events": get_events(limit=limit, severity=severity, event_type=event_type)}

@app.get("/db/cves", tags=["Database"])
def db_cves(severity: str = None, min_score: float = 0.0,
            limit: int = 50, search: str = None):
    """Query cve_database table."""
    from database import get_cves
    return {"cves": get_cves(severity=severity, min_score=min_score,
                              limit=limit, search=search)}

@app.get("/db/risk-history", tags=["Database"])
def db_risk_history(hours: int = 24):
    """Get risk score time-series from DB."""
    from database import get_risk_history
    return {"history": get_risk_history(hours=hours)}

@app.get("/db/scan-reports", tags=["Database"])
def db_scan_reports(limit: int = 20):
    """List all scan reports stored in DB."""
    from database import get_scan_reports
    return {"reports": get_scan_reports(limit=limit)}

@app.get("/db/inventory", tags=["Database"])
def db_inventory():
    """Get host inventory summary from DB."""
    from database import get_inventory_summary
    return get_inventory_summary()

@app.get("/db/attacks", tags=["Database"])
def db_attacks(limit: int = 50):
    """Get attack log from DB."""
    from database import get_attack_log
    return {"attacks": get_attack_log(limit=limit)}

@app.get("/db/compliance-trend/{framework}", tags=["Database"])
def db_compliance_trend(framework: str, days: int = 30):
    """Get compliance score trend from DB."""
    from database import get_compliance_trend
    return {"trend": get_compliance_trend(framework, days)}

@app.post("/db/init", tags=["Database"])
def db_init():
    """Initialize DB schema and seed initial lab data."""
    try:
        from database import create_schema, seed_lab_data
        create_schema()
        seed_lab_data()
        return {"status": "ok", "message": "Schema created and lab data seeded"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/db/purge-scan", tags=["Database"])
def db_purge_scan():
    """Wipe all scan-generated patch records and CVEs, keeping only victim host data."""
    from database import get_conn
    victim_ip = os.getenv("VICTIM_IP", "192.168.237.129")
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Delete patch records not belonging to victim
            cur.execute("DELETE FROM patch_records WHERE host_ip != %s", (victim_ip,))
            deleted_patches = cur.rowcount
            # Delete all CVEs (they'll be repopulated by next scan against victim only)
            cur.execute("TRUNCATE TABLE cve_database")
    return {"status": "ok", "deleted_patch_records": deleted_patches, "cve_database": "cleared"}

@app.post("/db/reseed", tags=["Database"])
def db_reseed():
    """Force wipe and reseed CVEs, patch records, and threat intel with current lab data."""
    try:
        from database import get_conn, upsert_cves, upsert_patch_records, get_cursor
        from voc.fr_voc_03_patch_tracking import load_patch_db
        from voc.fr_voc_02_cvss_scoring import LAB_CVE_VECTORS, parse_cvss_vector_string, calculate_cvss_v31
        from ai.fr_ai_05_07 import STATIC_INTEL
        import json

        # Wipe old seeded data
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE cve_database, patch_records, threat_intel RESTART IDENTITY CASCADE")

        # Reseed patch records
        patch_records = load_patch_db()
        records = [{
            "cve_id": r.cve_id, "host_ip": r.host_ip, "hostname": r.hostname,
            "package": r.package, "current_version": r.current_version,
            "fixed_version": r.fixed_version, "status": r.status,
            "cvss_score": r.cvss_score, "severity": r.severity,
            "last_checked": r.last_checked, "notes": r.notes
        } for r in patch_records]
        upsert_patch_records(records)

        # Reseed CVEs with correct source label
        cves = []
        for cve_id, vec, desc in LAB_CVE_VECTORS:
            try:
                v = parse_cvss_vector_string(vec, cve_id, desc)
                result = calculate_cvss_v31(v)
                cves.append({
                    "cve_id": cve_id, "description": desc,
                    "cvss_score": result["base_score"],
                    "cvss_vector": vec, "cvss_version": "cvssMetricV31",
                    "severity": result["severity"],
                    "published": "2024-01-01T00:00:00",
                    "modified": "2024-01-01T00:00:00",
                    "source": "lab_seed"
                })
            except Exception:
                pass
        upsert_cves(cves)

        # Reseed threat intel
        sql = """
            INSERT INTO threat_intel
                (intel_id, source, indicator_type, indicator, severity, description, tags, published)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (intel_id) DO UPDATE SET
                description=EXCLUDED.description,
                tags=EXCLUDED.tags
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                for ti in STATIC_INTEL:
                    cur.execute(sql, (
                        ti["id"], ti["source"], ti["type"], ti["indicator"],
                        ti["severity"], ti["description"],
                        json.dumps(ti.get("tags", [])),
                        ti.get("published")
                    ))

        return {
            "status": "ok",
            "patch_records": len(records),
            "cves": len(cves),
            "threat_intel": len(STATIC_INTEL)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/db/table/{table_name}", tags=["Database"])
def db_table_browse(
    table_name: str,
    limit: int = 50,
    offset: int = 0,
    order_col: str = None,
):
    """Browse any PostgreSQL table — returns columns, rows, and total count. Read-only."""
    ALLOWED_TABLES = [
        "security_events", "cve_database", "patch_records", "scan_reports",
        "risk_score_history", "host_inventory", "attack_log",
        "compliance_snapshots", "threat_intel", "noc_audit_trail",
        "noc_incidents", "soc_alert_archives",
    ]
    if table_name not in ALLOWED_TABLES:
        raise HTTPException(
            status_code=400,
            detail=f"Table '{table_name}' not in allowed list: {ALLOWED_TABLES}"
        )
    try:
        from database import get_cursor
        with get_cursor() as cur:
            cur.execute(f"SELECT COUNT(*) as n FROM {table_name}")
            total = cur.fetchone()["n"]
            cur.execute(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_name = %s ORDER BY ordinal_position",
                (table_name,)
            )
            columns = [{"name": r["column_name"], "type": r["data_type"]} for r in cur.fetchall()]
            safe_order = (
                order_col
                if order_col and any(c["name"] == order_col for c in columns)
                else "id"
            )
            cur.execute(
                f"SELECT * FROM {table_name} ORDER BY {safe_order} DESC LIMIT %s OFFSET %s",
                (limit, offset)
            )
            rows = []
            for row in cur.fetchall():
                clean = {}
                for k, v in row.items():
                    if hasattr(v, "isoformat"):
                        clean[k] = v.isoformat()
                    elif isinstance(v, (dict, list)):
                        clean[k] = v
                    else:
                        clean[k] = str(v) if v is not None else None
                rows.append(clean)
        return {
            "table": table_name, "total": total,
            "limit": limit, "offset": offset,
            "columns": columns, "rows": rows,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Attack Console Proxy ──────────────────────────────────────────────────────

ATTACKER_URL = os.getenv("ATTACKER_SERVER_URL", "http://192.168.237.131:5000")

class AttackRequest(BaseModel):
    attack_id: str

@app.post("/attacks/run", tags=["Attacks"])
def run_attack(req: AttackRequest):
    """Proxy attack launch to the attacker container HTTP server."""
    try:
        import requests as rlib
        r = rlib.post(f"{ATTACKER_URL}/run",
                      json={"attack_id": req.attack_id}, timeout=5)
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=503,
                            detail=f"Attacker server unreachable: {e}")

@app.get("/attacks/status", tags=["Attacks"])
def attack_status():
    """Get currently running attacks."""
    try:
        import requests as rlib
        r = rlib.get(f"{ATTACKER_URL}/status", timeout=3)
        return r.json()
    except Exception as e:
        return {"running": {}, "error": str(e)}


# ── NOC Routes (Zabbix Performance Monitoring) ─────────────────────
try:
    from noc.noc_api import noc_router
    app.include_router(noc_router)
    print("✅ NOC module loaded successfully")
except Exception as e:
    print(f"⚠️  NOC module not available: {e}")

# ── SOC Routes (Wazuh SIEM Integration) ────────────────────────────
try:
    from soc.soc_api import soc_router
    app.include_router(soc_router)
    print("✅ SOC module loaded successfully")
except Exception as e:
    print(f"⚠️  SOC module not available: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
