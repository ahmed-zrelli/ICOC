import os
import aiohttp
import asyncio
import time
from datetime import datetime
from config import config

ZABBIX_API = config.ZABBIX_API_URL
ZABBIX_USER = config.ZABBIX_USER
ZABBIX_PASS = config.ZABBIX_PASS

async def get_zabbix_auth():
    """Get Zabbix API authentication token (Async)"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(ZABBIX_API, json={
                "jsonrpc": "2.0",
                "method": "user.login",
                "params": {
                    "username": ZABBIX_USER,
                    "password": ZABBIX_PASS
                },
                "id": 1
            }, timeout=5) as resp:
                result = await resp.json()
                return result.get('result')
    except Exception as e:
        print(f"[ZABBIX-AUTH] Error: {e}")
        return None

async def zabbix_rpc_call(method, params, auth=None, req_id=1):
    """Generic async Zabbix RPC call helper"""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": req_id
    }
    if auth:
        payload["auth"] = auth
        
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(ZABBIX_API, json=payload, timeout=10) as resp:
                return await resp.json()
    except Exception as e:
        print(f"[ZABBIX-RPC] Error calling {method}: {e}")
        return {"error": str(e)}

async def get_cpu_usage():
    """Get CPU utilization across all monitored hosts (Async)"""
    auth = await get_zabbix_auth()
    if not auth:
        return {"cpu_usage": [], "count": 0, "error": "Zabbix auth failed"}

    res = await zabbix_rpc_call("item.get", {
        "search": {"name": "CPU utilization"},
        "output": ["itemid", "name", "lastvalue"],
        "selectHosts": ["host", "name"]
    }, auth=auth, req_id=6)
    
    items = res.get('result', [])
    cpu_data = []
    
    # We can fetch baselines in parallel
    async def process_item(item):
        try:
            cpu_value = float(item.get('lastvalue', 0))
            hosts = item.get('hosts', [])
            itemid = item.get('itemid')
            if hosts:
                host_info = hosts[0]
                host_name = host_info.get('name', 'Unknown')
                
                baseline = None
                if cpu_value > 0:
                    baseline = await get_historical_baseline(itemid, hours=6, auth=auth)
                
                status = "low"
                if baseline:
                    if cpu_value > baseline * 1.8: status = "high"
                    elif cpu_value > baseline * 1.3: status = "normal"
                else:
                    status = "high" if cpu_value > 80 else "normal" if cpu_value > 50 else "low"

                return {
                    "host": host_name,
                    "hostname": host_info.get('host', 'Unknown'),
                    "cpu_percent": round(cpu_value, 2),
                    "baseline": round(baseline, 2) if baseline else None,
                    "status": status
                }
        except Exception:
            return None

    tasks = [process_item(item) for item in items]
    results = await asyncio.gather(*tasks)
    cpu_data = [r for r in results if r]
    
    return {"cpu_usage": cpu_data, "count": len(cpu_data), "module": "ICOC NOC Module"}

async def get_network_latency_and_throughput():
    """Fetch real-time network latency and throughput from Zabbix (Async)."""
    auth = await get_zabbix_auth()
    if not auth:
        return {"latency": "0ms", "throughput": "0 Mbps"}

    try:
        # Run both requests in parallel
        lat_task = zabbix_rpc_call("item.get", {
            "search": {"key_": "icmppingsec"},
            "output": ["lastvalue"],
            "limit": 1
        }, auth=auth, req_id=8)
        
        tp_task = zabbix_rpc_call("item.get", {
            "search": {"name": "Network interface"},
            "output": ["lastvalue", "name"],
            "monitored": True
        }, auth=auth, req_id=9)
        
        latency_res, throughput_res = await asyncio.gather(lat_task, tp_task)
        
        latency_data = latency_res.get('result', [])
        latency = "0ms"
        if latency_data:
            val = float(latency_data[0].get('lastvalue', 0)) * 1000
            latency = f"{val:.2f}ms"

        items = throughput_res.get('result', [])
        total_bits = 0
        for item in items:
            try:
                total_bits += float(item.get('lastvalue', 0))
            except:
                continue
        
        throughput = f"{total_bits / 1000000:.1f} Mbps" if total_bits > 0 else "0.0 Mbps"
        return {"latency": latency, "throughput": throughput}
    except Exception:
        return {"latency": "Error", "throughput": "Error"}

async def get_virtual_alerts():
    """Generate virtual alerts based on dynamic baselines and forecasting logic (Async)."""
    auth = await get_zabbix_auth()
    virtual_alerts = []
    
    # Check simulation and security events
    from database import get_noc_audit_trail, get_events
    
    async def check_sim():
        try:
            # get_noc_audit_trail is sync but we'll call it for now
            recent_audit = get_noc_audit_trail(limit=5)
            now = datetime.utcnow()
            for a in recent_audit:
                if a['action'] == "SIMULATE_ATTACK":
                    ts = a['timestamp']
                    if not isinstance(ts, datetime):
                        try: ts = datetime.fromisoformat(str(ts).replace('Z', ''))
                        except: continue
                    if ts.tzinfo: ts = ts.replace(tzinfo=None)
                    if (now - ts).total_seconds() < 120:
                        return True
            return False
        except Exception: return False

    async def check_sec():
        sec_alerts = []
        try:
            recent_security = get_events(limit=10, severity="Critical") + get_events(limit=10, severity="High")
            now = datetime.utcnow()
            for evt in recent_security:
                evt_ts = evt['timestamp']
                if not isinstance(evt_ts, datetime):
                    evt_ts = datetime.fromisoformat(str(evt_ts).replace('Z', ''))
                if evt_ts.tzinfo: evt_ts = evt_ts.replace(tzinfo=None)
                if (now - evt_ts).total_seconds() < 600:
                    sec_alerts.append({
                        "id": f"sec-{evt['id']}",
                        "host": evt.get('hostname', 'Unknown'),
                        "description": f"SECURITY: {evt['data'].get('summary', evt['event_type'])}",
                        "severity": 5 if evt['severity'] == "Critical" else 4,
                        "time": int(evt_ts.timestamp()),
                        "type": "security"
                    })
            return sec_alerts
        except Exception: return []

    sim_active, sec_alerts = await asyncio.gather(check_sim(), check_sec())
    
    if sim_active:
        virtual_alerts.extend([
            {"id": "v-sim-01", "host": "Global Load Balancer", "description": "CRITICAL: Unexpected traffic surge (Simulation)", "severity": 5, "time": int(time.time()), "type": "virtual"},
            {"id": "v-sim-02", "host": "Victim Host", "description": "HIGH: Connection queue full", "severity": 4, "time": int(time.time()), "type": "virtual"}
        ])
    virtual_alerts.extend(sec_alerts)

    if not auth:
        return virtual_alerts

    try:
        res = await zabbix_rpc_call("item.get", {
            "search": {"name": "CPU utilization"},
            "output": ["itemid", "name", "lastvalue"],
            "selectHosts": ["name"],
            "monitored": True
        }, auth=auth, req_id=11)
        
        items = res.get('result', [])
        
        async def check_anomaly(item):
            try:
                val = float(item.get('lastvalue', 0))
                itemid = item.get('itemid')
                host_name = item.get('hosts', [{}])[0].get('name', 'Unknown')
                baseline = await get_historical_baseline(itemid, hours=6, auth=auth)
                if baseline and val > baseline * 2.0:
                    return {"id": f"v-cpu-{itemid}", "host": host_name, "description": f"Dynamic Anomaly: CPU ({round(val,2)}%) is 2x above baseline", "severity": 5, "time": int(time.time()), "type": "virtual"}
                elif baseline and val > baseline * 1.5:
                    return {"id": f"v-cpu-{itemid}", "host": host_name, "description": f"Dynamic Anomaly: CPU ({round(val,2)}%) is 50% above baseline", "severity": 3, "time": int(time.time()), "type": "virtual"}
            except: pass
            return None

        anomalies = await asyncio.gather(*[check_anomaly(i) for i in items])
        virtual_alerts.extend([a for a in anomalies if a])
    except Exception as e:
        print(f"[VIRTUAL-ALERTS] Error: {e}")
        
    return virtual_alerts

async def get_historical_baseline(itemid: str, hours: int = 24, auth=None):
    """Calculate average value over the last X hours (Async)"""
    if not auth:
        auth = await get_zabbix_auth()
    if not auth:
        return None
    
    time_from = int(time.time()) - (hours * 3600)
    res = await zabbix_rpc_call("history.get", {
        "itemids": [itemid],
        "time_from": time_from,
        "history": 0,
        "output": ["value"],
        "limit": 500
    }, auth=auth, req_id=7)
    
    history = res.get('result', [])
    if not history:
        return None
    
    values = [float(h['value']) for h in history]
    return sum(values) / len(values)
