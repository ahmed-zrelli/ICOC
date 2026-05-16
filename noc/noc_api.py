import os
import requests
from fastapi import APIRouter, HTTPException

from noc.noc_alerts import router as alerts_router
from noc.noc_incidents import router as incidents_router
from noc.noc_sla import router as sla_router
from noc.noc_trending import router as trending_router
from noc.noc_correlation import router as correlation_router
from noc.noc_forecasting import router as forecasting_router
from noc.noc_metrics import router as metrics_router
from noc.noc_audit import router as audit_router
from noc.noc_remediation import router as remediation_router
from noc.noc_utils import get_zabbix_auth, get_cpu_usage, ZABBIX_API

noc_router = APIRouter(prefix="/noc", tags=["NOC"])
noc_router.include_router(alerts_router)
noc_router.include_router(incidents_router)
noc_router.include_router(sla_router)
noc_router.include_router(trending_router)
noc_router.include_router(correlation_router)
noc_router.include_router(forecasting_router)
noc_router.include_router(metrics_router)
noc_router.include_router(audit_router)
noc_router.include_router(remediation_router)

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

@noc_router.get("/status")
def get_noc_status():
    """NOC system health check"""
    try:
        auth = get_zabbix_auth()
        if not auth and DEMO_MODE:
            return {
                "status": "operational",
                "zabbix_reachable": True,
                "auth_ok": True,
                "demo": True,
                "module": "ICOC NOC Module"
            }
        return {
            "status": "operational" if auth else "degraded",
            "zabbix_reachable": True if auth else False,
            "auth_ok": bool(auth),
            "module": "ICOC NOC Module"
        }
    except:
        return {
            "status": "down",
            "zabbix_reachable": False,
            "module": "ICOC NOC Module"
        }

def get_noc_summary():
    """Get NOC summary for dashboard"""
    try:
        auth = get_zabbix_auth()
        if not auth and DEMO_MODE:
             return {
                "monitored_hosts": 12, 
                "active_alerts": 3, 
                "noc_status": "operational",
                "demo": True,
                "module": "ICOC NOC Module"
             }
        
        if not auth:
             return {"monitored_hosts": 0, "active_alerts": 0, "noc_status": "offline"}
        
        # Get host count
        hosts_response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {"output": ["hostid"]},
            "auth": auth,
            "id": 2
        }, timeout=5)
        
        hosts_data = hosts_response.json()
        host_count = len(hosts_data.get('result', []))
        
        # Get active triggers (alerts)
        triggers_response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "trigger.get",
            "params": {"only_true": 1, "output": ["triggerid"]},
            "auth": auth,
            "id": 3
        }, timeout=5)
        
        alert_count = len(triggers_response.json().get('result', []))
        
        # Include Virtual Alerts in summary count
        from noc.noc_utils import get_virtual_alerts
        v_alerts = get_virtual_alerts()
        alert_count += len(v_alerts)
        
        return {
            "monitored_hosts": host_count,
            "active_alerts": alert_count,
            "noc_status": "operational",
            "module": "ICOC NOC Module"
        }
    except Exception as e:
        return {
            "monitored_hosts": 0,
            "active_alerts": 0,
            "noc_status": "error",
            "error": str(e),
            "module": "ICOC NOC Module"
        }

@noc_router.get("/summary")
def _get_noc_summary_endpoint():
    return get_noc_summary()

@noc_router.get("/metrics/{hostname}")
def get_host_metrics(hostname: str):
    """Get performance metrics for a specific host"""
    try:
        auth = get_zabbix_auth()
        if not auth:
            raise HTTPException(status_code=503, detail="Zabbix auth failed")
        
        # Get items for host
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "host": hostname,
                "output": ["name", "lastvalue"],
                "monitored": True
            },
            "auth": auth,
            "id": 4
        }, timeout=10)
        
        items = response.json().get('result', [])
        
        metrics = {"cpu": None, "memory": None, "disk": None}
        
        for item in items:
            name = item.get('name', '').lower()
            try:
                value = float(item.get('lastvalue', 0))
            except:
                continue
            
            if 'cpu' in name and 'utilization' in name:
                metrics['cpu'] = round(value, 2)
            elif 'memory' in name and 'utilization' in name:
                metrics['memory'] = round(value, 2)
            elif 'disk' in name and 'space' in name:
                metrics['disk'] = round(value, 2)
        
        return {
            "host": hostname,
            "metrics": metrics,
            "status": "ok",
            "module": "ICOC NOC Module"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@noc_router.get("/cpu-usage")
def _get_cpu_usage_endpoint():
    return get_cpu_usage()
