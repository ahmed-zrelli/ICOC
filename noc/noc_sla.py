from fastapi import APIRouter, HTTPException
import requests
import os
from database import log_noc_action

router = APIRouter()

from noc.noc_utils import get_zabbix_auth, ZABBIX_API, ZABBIX_USER, ZABBIX_PASS

@router.get("/sla")
async def get_sla_metrics():
    """FR-NOC-07: Track system uptime and SLA compliance."""
    auth = get_zabbix_auth()
    if not auth:
        return []

    try:
        # Get hosts with availability status from interfaces
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["name"],
                "selectInterfaces": ["available", "type", "main"],
                "monitored_hosts": True
            },
            "auth": auth,
            "id": 2
        }, timeout=5)
        
        hosts = response.json().get('result', [])
        
        sla_data = []
        for h in hosts:
            # Find the main Zabbix agent interface (type 1, main 1)
            interfaces = h.get('interfaces', [])
            availability = 0 # Default to Unknown
            
            for iface in interfaces:
                if iface.get('main') == '1' and iface.get('type') == '1':
                    availability = int(iface.get('available', 0))
                    break
            
            # If no main agent interface, check any available interface
            if availability == 0 and interfaces:
                for iface in interfaces:
                    if int(iface.get('available', 0)) == 1:
                        availability = 1
                        break
            
            status = "Compliant" if availability == 1 else "Critical" if availability == 2 else "Unknown"
            uptime = "100.00%" if availability == 1 else "0.00%"
            
            if status == "Critical":
                log_noc_action(
                    action="SLA_BREACH_DETECTED",
                    module="SLA",
                    details={"host": h.get('name'), "uptime": uptime, "status": status},
                    status="Critical"
                )

            sla_data.append({
                "service": h.get('name'),
                "uptime": uptime,
                "status": status
            })
            
        return sla_data
    except Exception as e:
        print(f"[NOC-SLA] Error: {e}")
        return []
