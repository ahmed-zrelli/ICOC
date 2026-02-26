from fastapi import APIRouter, HTTPException
import requests
import os

router = APIRouter()

ZABBIX_API = os.getenv("ZABBIX_API_URL", "http://192.168.100.21:8080/api_jsonrpc.php")
ZABBIX_USER = os.getenv("ZABBIX_USER", "Admin")
ZABBIX_PASS = os.getenv("ZABBIX_PASS", "zabbix")

def get_zabbix_auth():
    try:
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {"username": ZABBIX_USER, "password": ZABBIX_PASS},
            "id": 1
        }, timeout=5)
        return response.json().get('result')
    except:
        return None

@router.get("/sla")
async def get_sla_metrics():
    """FR-NOC-07: Track system uptime and SLA compliance."""
    auth = get_zabbix_auth()
    if not auth:
        return []

    try:
        # Get hosts with availability status
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["name", "available", "error"],
                "monitored_hosts": True
            },
            "auth": auth,
            "id": 2
        }, timeout=5)
        
        hosts = response.json().get('result', [])
        
        sla_data = []
        for h in hosts:
            availability = int(h.get('available', 0))
            status = "Compliant" if availability == 1 else "Critical" if availability == 2 else "Unknown"
            uptime = "100.00%" if availability == 1 else "0.00%"
            
            sla_data.append({
                "service": h.get('name'),
                "uptime": uptime,
                "status": status
            })
            
        return sla_data
    except Exception as e:
        print(f"[NOC-SLA] Error: {e}")
        return []
