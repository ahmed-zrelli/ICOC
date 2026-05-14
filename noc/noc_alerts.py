from fastapi import APIRouter, HTTPException
import os
import aiohttp
from config import config
from noc.noc_utils import get_zabbix_auth, ZABBIX_API, get_virtual_alerts, zabbix_rpc_call

router = APIRouter()

@router.get("/alerts/active")
async def fetch_active_alerts():
    """FR-NOC-02: Retrieve active Zabbix triggers/alerts (Async)."""
    auth = await get_zabbix_auth()
    if not auth:
        # If Zabbix is down, we still want Virtual Alerts
        v_alerts = await get_virtual_alerts()
        return {"alerts": v_alerts, "count": len(v_alerts), "module": "ICOC NOC Module (Zabbix Offline)"}
        
    try:
        res = await zabbix_rpc_call("trigger.get", {
            "only_true": 1,
            "output": ["triggerid", "description", "priority", "lastchange"],
            "selectHosts": ["host", "name"],
            "sortfield": "priority",
            "sortorder": "DESC"
        }, auth=auth, req_id=4)
        
        triggers = res.get('result', [])
        
        # Merge with Virtual Alerts from Dynamic Baselines
        v_alerts = await get_virtual_alerts()
        
        # Auto-create incidents for high priority alerts
        from database import create_noc_incident, get_noc_incidents, log_noc_action
        existing_incidents = get_noc_incidents(status="Open")
        existing_desc = [inc['description'] for inc in existing_incidents]

        alerts = []
        for t in triggers:
            desc = t.get('description')
            priority = int(t.get('priority', 0))
            host_name = t['hosts'][0]['name'] if t['hosts'] else "Unknown"

            if priority >= 4 and f"AUTO-ALERT: {desc}" not in existing_desc:
                try:
                    incident_id = create_noc_incident(
                        host=host_name,
                        description=f"AUTO-ALERT: {desc}",
                        severity="Critical" if priority >= 5 else "High"
                    )
                    log_noc_action(
                        action="AUTO_INCIDENT_CREATION",
                        module="ALERTS",
                        details={"trigger_id": t['triggerid'], "description": desc, "host": host_name, "incident_id": incident_id},
                        status="Success"
                    )
                except Exception as e:
                    print(f"[NOC-ALERTS] Auto-incident failed: {e}")

            alerts.append({
                "id": t['triggerid'],
                "host": host_name,
                "description": desc,
                "severity": priority,
                "time": t['lastchange'],
                "type": "performance"
            })
            
        alerts.extend(v_alerts)
            
        return {
            "alerts": alerts,
            "count": len(alerts),
            "module": "ICOC NOC Module"
        }
    except Exception as e:
        print(f"[NOC-ALERTS] Error: {e}")
        # Return what we have (virtual alerts) instead of 500
        v_alerts = await get_virtual_alerts()
        return {"alerts": v_alerts, "count": len(v_alerts), "error": str(e)}
