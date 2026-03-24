from fastapi import APIRouter, HTTPException
import os
import requests

router = APIRouter()

ZABBIX_API = os.getenv("ZABBIX_API_URL", "http://192.168.100.21:8080/api_jsonrpc.php")
ZABBIX_USER = os.getenv("ZABBIX_USER", "Admin")
ZABBIX_PASS = os.getenv("ZABBIX_PASS", "zabbix")

def get_zabbix_auth():
    """Get Zabbix API authentication token"""
    try:
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "username": ZABBIX_USER,
                "password": ZABBIX_PASS
            },
            "id": 1
        }, timeout=5)
        result = response.json()
        return result.get('result')
    except Exception as e:
        return None

@router.get("/metrics/summary")
async def fetch_metrics_summary():
    """FR-NOC-01: Get high-level infrastructure metrics."""
    auth = get_zabbix_auth()
    if not auth:
        raise HTTPException(status_code=503, detail="Zabbix API unreachable")
        
    try:
        # Get host count
        hosts_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0", "method": "host.get", "params": {"output": ["hostid"]}, "auth": auth, "id": 2
        }, timeout=5)
        total_hosts = len(hosts_res.json().get('result', []))
        
        # Get item data for health status
        items_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0", "method": "item.get", "params": {"output": ["name", "lastvalue"], "monitored": True}, "auth": auth, "id": 3
        }, timeout=5)
        
        # Get problems to determine "healthy" hosts
        problems_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0", 
            "method": "trigger.get", 
            "params": {
                "only_true": 1, 
                "filter": {"value": 1},
                "selectHosts": ["hostid"]
            }, 
            "auth": auth, 
            "id": 4
        }, timeout=5)
        
        problem_hosts = set()
        for t in problems_res.json().get('result', []):
            for h in t.get('hosts', []):
                problem_hosts.add(h['hostid'])
        
        healthy_count = max(0, total_hosts - len(problem_hosts))
        status = "Healthy" if healthy_count == total_hosts else "Degraded" if healthy_count > 0 else "Critical"

        # Fetch real-time network data from utils
        from noc.noc_utils import get_network_latency_and_throughput
        net_data = get_network_latency_and_throughput()
        avg_latency = net_data.get('latency', '0ms')
        net_throughput = net_data.get('throughput', '0 Mbps')

        return {
            "total_hosts": total_hosts,
            "healthy_hosts": healthy_count,
            "metrics_collected": len(items_res.json().get('result', [])),
            "status": status,
            "avg_latency": avg_latency,
            "net_throughput": net_throughput
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
