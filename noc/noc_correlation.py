from fastapi import APIRouter, HTTPException
import os
import requests
from database import get_cves, get_events
from noc.noc_utils import get_cpu_usage

router = APIRouter()

@router.get("/correlation")
async def get_noc_voc_correlation():
    """FR-NOC-06: Link NOC metrics with VOC/SOC security data."""
    try:
        # 1. Get Security Events (SOC Data) from the last 15 minutes
        recent_security_events = get_events(limit=10, since_seconds=900)
        critical_alerts = [e for e in recent_security_events if e.get('severity') in ('Critical', 'High')]
        
        # 2. Get CPU Usage (NOC Data)
        cpu_data = get_cpu_usage()
        high_cpu_hosts = [h for h in cpu_data.get('cpu_usage', []) if h.get('cpu_percent', 0) > 70]
        
        # 3. Get Active Vulnerabilities (VOC Data)
        vulns = get_cves(limit=50)
        high_risk_vulns = [v for v in vulns if float(v.get('cvss_score', 0)) > 8.0]
        
        # 4. Perform Correlation Logic
        correlations = []
        impact_assessment = "No critical security-performance correlation detected."
        
        # Check if high CPU hosts have recent critical security alerts
        for host in high_cpu_hosts:
            hostname = host.get('hostname')
            host_alerts = [e for e in critical_alerts if e.get('hostname') == hostname or e.get('host_ip') == host.get('host')]
            
            if host_alerts:
                correlations.append({
                    "host": host.get('host'),
                    "cpu": f"{host.get('cpu_percent')}%",
                    "security_event": host_alerts[0].get('event_type'),
                    "severity": host_alerts[0].get('severity')
                })
                impact_assessment = f"CRITICAL: Performance spike on {host.get('host')} correlates with active {host_alerts[0].get('event_type')} attack!"

        return {
            "summary": "NOC + VOC/SOC Correlation Analysis",
            "active_security_events": len(recent_security_events),
            "high_cpu_incidents": len(high_cpu_hosts),
            "active_vulnerabilities": len(vulns),
            "detected_correlations": correlations,
            "correlation_status": "Alert" if correlations else "Monitoring",
            "impact_assessment": impact_assessment,
            "module": "ICOC NOC Module"
        }
    except Exception as e:
        print(f"[NOC-CORRELATION] Error: {e}")
        return {"error": str(e), "module": "ICOC NOC Module"}
