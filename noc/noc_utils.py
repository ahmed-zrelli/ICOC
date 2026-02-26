import os
import requests
import time
from fastapi import HTTPException

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
        auth_token = result.get('result')
        return auth_token
    except Exception as e:
        return None

def get_cpu_usage():
    """Get CPU utilization across all monitored hosts"""
    auth = get_zabbix_auth()
    if not auth:
        return {"cpu_usage": [], "count": 0, "error": "Zabbix auth failed"}

    try:
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "search": {"name": "CPU utilization"},
                "output": ["itemid", "name", "lastvalue"],
                "selectHosts": ["host", "name"]
            },
            "auth": auth,
            "id": 6
        }, timeout=10)
        
        result = response.json()
        items = result.get('result', [])
        
        cpu_data = []
        for item in items:
            try:
                cpu_value = float(item.get('lastvalue', 0))
                hosts = item.get('hosts', [])
                itemid = item.get('itemid')
                if hosts:
                    host_info = hosts[0]
                    host_name = host_info.get('name', 'Unknown')
                    
                    # For performance, only get baseline for active hosts
                    baseline = None
                    if cpu_value > 0:
                        baseline = get_historical_baseline(itemid, hours=6)
                    
                    status = "low"
                    if baseline:
                        if cpu_value > baseline * 1.8: status = "high"
                        elif cpu_value > baseline * 1.3: status = "normal"
                    else:
                        status = "high" if cpu_value > 80 else "normal" if cpu_value > 50 else "low"

                    cpu_data.append({
                        "host": host_name,
                        "hostname": host_info.get('host', 'Unknown'),
                        "cpu_percent": round(cpu_value, 2),
                        "baseline": round(baseline, 2) if baseline else None,
                        "status": status
                    })
            except Exception:
                continue
        
        return {"cpu_usage": cpu_data, "count": len(cpu_data), "module": "ICOC NOC Module"}
    except Exception as e:
        return {"cpu_usage": [], "count": 0, "error": str(e), "module": "ICOC NOC Module"}

def get_network_latency_and_throughput():
    """Fetch real-time network latency and throughput from Zabbix."""
    auth = get_zabbix_auth()
    if not auth:
        return {"latency": "0ms", "throughput": "0 Mbps"}

    try:
        # Fetch ICMP response time (latency)
        latency_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "search": {"key_": "icmppingsec"},
                "output": ["lastvalue"],
                "limit": 1
            },
            "auth": auth,
            "id": 8
        }, timeout=5)
        
        latency_data = latency_res.json().get('result', [])
        latency = "0ms"
        if latency_data:
            val = float(latency_data[0].get('lastvalue', 0)) * 1000 # Convert to ms
            latency = f"{val:.2f}ms"

        # Fetch Interface In/Out throughput
        throughput_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "search": {"name": "Network interface"},
                "output": ["lastvalue", "name"],
                "monitored": True
            },
            "auth": auth,
            "id": 9
        }, timeout=5)
        
        items = throughput_res.json().get('result', [])
        total_bits = 0
        for item in items:
            try:
                # Summing up last values of all network interfaces
                total_bits += float(item.get('lastvalue', 0))
            except:
                continue
        
        throughput = f"{total_bits / 1000000:.1f} Mbps" if total_bits > 0 else "0.0 Mbps"
        
        return {"latency": latency, "throughput": throughput}
    except Exception:
        return {"latency": "Error", "throughput": "Error"}

def get_virtual_alerts():
    """Generate virtual alerts based on dynamic baselines and forecasting logic."""
    auth = get_zabbix_auth()
    if not auth:
        return []

    virtual_alerts = []
    try:
        # Fetch items for common monitors
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "search": {"name": "CPU utilization"},
                "output": ["itemid", "name", "lastvalue"],
                "selectHosts": ["name"],
                "monitored": True
            },
            "auth": auth,
            "id": 11
        }, timeout=5)
        
        items = response.json().get('result', [])
        
        for item in items:
            try:
                val = float(item.get('lastvalue', 0))
                itemid = item.get('itemid')
                host_name = item.get('hosts', [{}])[0].get('name', 'Unknown')
                
                # Check CPU Anomaly
                baseline = get_historical_baseline(itemid, hours=6)
                if baseline and val > baseline * 2.0: # 100% above baseline = Critical
                    virtual_alerts.append({
                        "id": f"v-cpu-{itemid}",
                        "host": host_name,
                        "description": f"Dynamic Anomaly: CPU usage ({val}%) is 2x above baseline ({round(baseline,2)}%)",
                        "severity": 5, # Critical
                        "time": int(time.time()),
                        "type": "virtual"
                    })
                elif baseline and val > baseline * 1.5: # 50% above baseline = Warning
                    virtual_alerts.append({
                        "id": f"v-cpu-{itemid}",
                        "host": host_name,
                        "description": f"Dynamic Anomaly: CPU usage ({val}%) is 50% above baseline ({round(baseline,2)}%)",
                        "severity": 3, # Warning
                        "time": int(time.time()),
                        "type": "virtual"
                    })
            except:
                continue
    except Exception as e:
        print(f"[VIRTUAL-ALERTS] Error: {e}")
        
    return virtual_alerts

def get_historical_baseline(itemid: str, hours: int = 24):
    """Calculate average value over the last X hours to establish a baseline"""
    auth = get_zabbix_auth()
    if not auth:
        return None
    
    time_from = int(time.time()) - (hours * 3600)
    
    try:
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "history.get",
            "params": {
                "itemids": [itemid],
                "time_from": time_from,
                "history": 0, # Float
                "output": ["value"],
                "limit": 500
            },
            "auth": auth,
            "id": 7
        }, timeout=5)
        
        history = response.json().get('result', [])
        if not history:
            return None
        
        values = [float(h['value']) for h in history]
        return sum(values) / len(values)
    except:
        return None
