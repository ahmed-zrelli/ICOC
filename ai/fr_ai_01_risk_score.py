"""
FR-AI-01: Global Risk Score Calculation (0-100 scale)
Aggregates VOC, SOC signals into a single actionable risk score.
"""

import os
import sys
import json
import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "voc"))

from fr_voc_03_patch_tracking import load_patch_db

def calculate_global_risk_score(
    patch_records=None,
    soc_alerts: int = 0,
    active_incidents: int = 0,
    threat_intel_hits: int = 0
) -> dict:
    """
    FR-AI-01: Compute global risk score (0-100).

    Formula:
        VOC component (60%): weighted CVSS scores of unpatched critical/high CVEs
        SOC component (25%): active alerts and incidents
        TI component (15%):  threat intel feed hits

    Returns score + breakdown + trend.
    """
    if patch_records is None:
        # Prefer DB records (live), fall back to disk file
        try:
            import sys as _sys, os as _os
            _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..'))
            from database import get_cursor
            with get_cursor() as cur:
                cur.execute("SELECT cve_id, host_ip, status, cvss_score, severity FROM patch_records")
                rows = cur.fetchall()
            if rows:
                from voc.fr_voc_03_patch_tracking import PatchRecord
                import datetime as _dt
                patch_records = [PatchRecord(
                    cve_id=r['cve_id'], host_ip=r['host_ip'], hostname='',
                    package='', current_version='', fixed_version='',
                    status=r['status'], cvss_score=float(r['cvss_score'] or 0),
                    severity=r['severity'],
                    last_checked=_dt.datetime.utcnow().isoformat()+'Z'
                ) for r in rows]
            else:
                patch_records = load_patch_db()
        except Exception:
            patch_records = load_patch_db()

    now = datetime.datetime.utcnow().isoformat() + "Z"

    # ── VOC Component (0-60) ─────────────────────────────────────────────────
    voc_score = 0.0
    unpatched = [r for r in patch_records if r.status in ("missing", "available")]

    severity_weights = {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.1}
    for r in unpatched:
        w = severity_weights.get(r.severity, 0.2)
        normalized_cvss = r.cvss_score / 10.0  # normalize to 0-1
        voc_score += w * normalized_cvss * 10  # scale contribution

    # Cap at 60
    voc_score = min(60.0, voc_score)

    # ── SOC Component (0-25) ─────────────────────────────────────────────────
    soc_score = min(25.0, soc_alerts * 1.5 + active_incidents * 5.0)

    # ── Threat Intel Component (0-15) ─────────────────────────────────────────
    ti_score = min(15.0, threat_intel_hits * 3.0)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    total = round(voc_score + soc_score + ti_score, 1)

    # Risk level classification
    if total >= 80:
        level = "Critical"
        color = "#ff1a4b"
    elif total >= 60:
        level = "High"
        color = "#ff6b35"
    elif total >= 40:
        level = "Medium"
        color = "#ffd600"
    elif total >= 20:
        level = "Low"
        color = "#00e5ff"
    else:
        level = "Minimal"
        color = "#00e676"

    result = {
        "score": total,
        "level": level,
        "color": color,
        "computed_at": now,
        "breakdown": {
            "voc_component": round(voc_score, 2),
            "soc_component": round(soc_score, 2),
            "ti_component": round(ti_score, 2),
            "max_possible": 100.0
        },
        "inputs": {
            "unpatched_cves": len(unpatched),
            "critical_unpatched": len([r for r in unpatched if r.severity == "Critical"]),
            "soc_alerts": soc_alerts,
            "active_incidents": active_incidents,
            "threat_intel_hits": threat_intel_hits
        }
    }

    print(f"[FR-AI-01] Global Risk Score: {total}/100 ({level})")
    return result


if __name__ == "__main__":
    score = calculate_global_risk_score(
        soc_alerts=5,
        active_incidents=1,
        threat_intel_hits=3
    )
    print(json.dumps(score, indent=2))
