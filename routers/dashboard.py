import asyncio
from fastapi import APIRouter
from fr_ai_01_risk_score import calculate_global_risk_score
from fr_voc_03_patch_tracking import get_patch_summary
from fr_ai_05_07 import get_threat_intel_feed, generate_recommendations, predict_incident_probability
from fr_voc_07_compliance import generate_compliance_report
from database import insert_risk_score
from routers.ai import _live_soc_stats
from routers.voc import get_all_cvss

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("")
async def get_dashboard():
    """
    Single endpoint returning all data needed by the React dashboard.
    Integrates VOC (vulnerabilities), NOC (performance), and AI (risk intelligence).
    """
    live = _live_soc_stats()
    risk = calculate_global_risk_score(
        soc_alerts=live["soc_alerts"],
        active_incidents=live["active_incidents"],
        threat_intel_hits=live["threat_intel_hits"],
    )
    # Persist risk score for history chart
    try:
        insert_risk_score(risk)
    except Exception:
        pass

    noc_data = {}
    try:
        from noc.noc_api import get_noc_summary
        from noc.noc_alerts import fetch_active_alerts
        noc_data["summary"] = await get_noc_summary()
        # Non-blocking call for alerts
        alerts_res = await fetch_active_alerts()
        noc_data["alerts"] = alerts_res.get("alerts", [])
    except Exception as e:
        noc_data = {"summary": {}, "alerts": [], "error": f"NOC unavailable: {e}"}

    return {
        "risk_score":          risk,
        "patch_summary":       get_patch_summary(),
        "threat_intel":        await get_threat_intel_feed(5),
        "recommendations":     generate_recommendations(soc_alerts=live["soc_alerts"]),
        "incident_prediction": predict_incident_probability(soc_alerts=live["soc_alerts"]),
        "compliance":          generate_compliance_report(),
        "cve_scores":          get_all_cvss()["cves"],
        "noc":                 noc_data,
        "live_stats":          live,
    }
