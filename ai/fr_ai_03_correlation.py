"""
FR-AI-03: Cross-Domain Correlation (SOC × VOC)
Correlates active security alerts with known unpatched CVEs.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "voc"))

def correlate_soc_voc(soc_alerts: list, patch_records=None) -> dict:
    """
    FR-AI-03: Cross-reference SOC alerts with unpatched CVEs.
    If a SOC alert targets a host with critical unpatched CVEs → high correlation.
    """
    from fr_voc_03_patch_tracking import load_patch_db
    if patch_records is None:
        patch_records = load_patch_db()

    # Build host → CVE map
    host_cve_map = {}
    for r in patch_records:
        if r.status in ("missing", "available"):
            host_cve_map.setdefault(r.host_ip, []).append({
                "cve_id": r.cve_id, "cvss_score": r.cvss_score, "severity": r.severity
            })

    correlations = []
    for alert in soc_alerts:
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")
        matched_cves = host_cve_map.get(dst_ip, []) or host_cve_map.get(src_ip, [])

        correlation_score = 0.0
        if matched_cves:
            max_cvss = max(c["cvss_score"] for c in matched_cves)
            correlation_score = min(1.0, max_cvss / 10.0 * 1.2)

        correlations.append({
            "alert_id": alert.get("id", "unknown"),
            "alert_type": alert.get("type", "unknown"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "matched_cves": matched_cves[:3],
            "correlation_score": round(correlation_score, 3),
            "risk_amplified": correlation_score > 0.7
        })

    high_risk = [c for c in correlations if c["risk_amplified"]]
    return {
        "total_alerts": len(soc_alerts),
        "correlated": len([c for c in correlations if c["matched_cves"]]),
        "high_risk_correlations": len(high_risk),
        "correlations": sorted(correlations, key=lambda x: x["correlation_score"], reverse=True)
    }
