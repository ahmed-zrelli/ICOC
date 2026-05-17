from fastapi import APIRouter, HTTPException
import os
import requests

router = APIRouter()

from noc.noc_utils import get_zabbix_auth, ZABBIX_API

@router.get("/alerts/active")
async def fetch_active_alerts():
    """FR-NOC-02: Retrieve active Zabbix triggers/alerts."""
    auth = get_zabbix_auth()
    if not auth:
        raise HTTPException(status_code=503, detail="Zabbix API unreachable")
        
    try:
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "trigger.get",
            "params": {
                "only_true": 1,
                "output": ["triggerid", "description", "priority", "lastchange"],
                "selectHosts": ["host", "name"],
                "sortfield": "priority",
                "sortorder": "DESC"
            },
            "auth": auth,
            "id": 4
        }, timeout=5)
        
        triggers = response.json().get('result', [])
        
        # Merge with Virtual Alerts from Dynamic Baselines
        from noc.noc_utils import get_virtual_alerts
        v_alerts = get_virtual_alerts()
        
        # Auto-create incidents for high priority alerts
        from database import create_noc_incident, get_noc_incidents, log_noc_action
        existing_incidents = get_noc_incidents(status="Open")
        existing_desc = [inc['description'] for inc in existing_incidents]

        alerts = []
        # Process Zabbix Triggers
        for t in triggers:
            desc = t.get('description')
            priority = int(t.get('priority', 0))
            host_name = t['hosts'][0]['name'] if t['hosts'] else "Unknown"

            if priority >= 4 and f"AUTO-ALERT: {desc}" not in existing_desc:
                incident_id = create_noc_incident(
                    host=host_name,
                    description=f"AUTO-ALERT: {desc}",
                    severity="Critical" if priority >= 5 else "High"
                )
                # Log the auto-creation to audit trail
                log_noc_action(
                    action="AUTO_INCIDENT_CREATION",
                    module="ALERTS",
                    details={
                        "trigger_id": t['triggerid'],
                        "description": desc,
                        "host": host_name,
                        "incident_id": incident_id
                    },
                    status="Success"
                )

            alerts.append({
                "id": t['triggerid'],
                "host": host_name,
                "description": desc,
                "severity": priority,
                "time": t['lastchange'],
                "type": "performance"
            })
            
        # Add Virtual Alerts
        for va in v_alerts:
            alerts.append(va)
            
        return {
            "alerts": alerts,
            "count": len(alerts),
            "module": "ICOC NOC Module"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
