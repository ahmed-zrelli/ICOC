import json
import asyncio
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List

# These imports assume the project root is in sys.path, which main.py handles
from fr_ai_01_risk_score import calculate_global_risk_score
from fr_ai_02_ml_prioritization import prioritize_alerts
from fr_ai_03_correlation import correlate_soc_voc
from fr_ai_05_07 import get_threat_intel_feed, predict_incident_probability, generate_recommendations, STATIC_INTEL
from database import insert_risk_score, get_threat_intel_count

router = APIRouter(prefix="/ai", tags=["AI"])

class SOCAlert(BaseModel):
    id: str
    type: str
    src_ip: str
    dst_ip: str
    cvss_score: Optional[float] = 0.0
    cvss_vector: Optional[str] = ""
    severity: Optional[str] = "Medium"

def _live_soc_stats() -> dict:
    """Pull real-time SOC stats from event_store."""
    try:
        _static_ti_count = len(STATIC_INTEL)
    except Exception:
        _static_ti_count = 11

    try:
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

@router.get("/risk-score")
def get_risk_score(soc_alerts: int = None, incidents: int = None, ti_hits: int = None):
    """FR-AI-01: Get global risk score (0-100)."""
    live = _live_soc_stats()
    score = calculate_global_risk_score(
        soc_alerts=soc_alerts        if soc_alerts is not None else live["soc_alerts"],
        active_incidents=incidents   if incidents  is not None else live["active_incidents"],
        threat_intel_hits=ti_hits    if ti_hits    is not None else live["threat_intel_hits"],
    )
    try:
        insert_risk_score(score)
    except Exception:
        pass
    return score

@router.post("/prioritize")
def prioritize(alerts: List[SOCAlert]):
    """FR-AI-02: ML-based alert prioritization."""
    return {"prioritized": prioritize_alerts([a.dict() for a in alerts])}

@router.post("/correlate")
def correlate(alerts: List[SOCAlert]):
    """FR-AI-03: Cross-domain SOC × VOC correlation."""
    return correlate_soc_voc([a.dict() for a in alerts])

@router.get("/risk-stream")
async def risk_stream():
    """FR-AI-04: Real-time risk score stream (SSE, updates every 15s)."""
    async def event_generator():
        while True:
            live  = _live_soc_stats()
            score = calculate_global_risk_score(
                soc_alerts=live["soc_alerts"],
                active_incidents=live["active_incidents"],
                threat_intel_hits=live["threat_intel_hits"],
            )
            try:
                insert_risk_score(score)
            except Exception:
                pass
            yield f"data: {json.dumps(score)}\n\n"
            await asyncio.sleep(15)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/threat-intel")
async def get_threat_intel(limit: int = 20):
    """FR-AI-05: Get threat intelligence feed."""
    return {"feed": await get_threat_intel_feed(limit)}

@router.get("/predict-incident")
def predict_incident(soc_alerts: int = None):
    """FR-AI-06: Predict incident probability in next 24 hours."""
    if soc_alerts is None:
        soc_alerts = _live_soc_stats()["soc_alerts"]
    return predict_incident_probability(soc_alerts=soc_alerts)

@router.get("/recommendations")
def get_recommendations(soc_alerts: int = None):
    """FR-AI-07: Get automated response recommendations."""
    if soc_alerts is None:
        soc_alerts = _live_soc_stats()["soc_alerts"]
    return {"recommendations": generate_recommendations(soc_alerts=soc_alerts)}

@router.get("/anomalies")
def detect_anomalies():
    """Detect anomalous CVE patterns using trained Isolation Forest model."""
    try:
        from voc.fr_voc_03_patch_tracking import load_patch_db
        from voc.fr_voc_02_cvss_scoring import LAB_CVE_VECTORS
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
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Anomaly detection unavailable: {e}"
        )

@router.get("/train-status")
def get_train_status():
    """Check if ML models are trained and ready."""
    import os
    AI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/ai"
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
