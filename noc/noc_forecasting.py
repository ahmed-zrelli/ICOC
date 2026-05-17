from fastapi import APIRouter, HTTPException
import os
import requests

router = APIRouter()

from noc.noc_utils import get_zabbix_auth, get_historical_baseline, ZABBIX_API, ZABBIX_USER, ZABBIX_PASS

@router.get("/forecasting")
async def get_capacity_forecasting():
    """FR-NOC-05: Capacity prediction with dynamic baselines."""
    auth = get_zabbix_auth()
    if not auth:
        return {"error": "Zabbix API unreachable"}

    try:
        # Fetch CPU and Disk items specifically
        response = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "search": {"name": ["CPU utilization", "disk space"]},
                "searchByAny": True,
                "output": ["itemid", "name", "lastvalue", "key_"],
                "selectHosts": ["name"],
                "monitored": True
            },
            "auth": auth,
            "id": 2
        }, timeout=5)
        
        items = response.json().get('result', [])
        
        high_cpu_hosts = []
        low_disk_hosts = []
        baselines = {}
        
        for item in items:
            name = item.get('name', '').lower()
            try:
                val = float(item.get('lastvalue', 0))
            except (ValueError, TypeError):
                continue
            
            host_name = item.get('hosts', [{}])[0].get('name', 'Unknown')
            itemid = item.get('itemid')
            
            # Use dynamic threshold if it's the Victim Host CPU
            if 'cpu' in name and 'utilization' in name:
                baseline = get_historical_baseline(itemid, hours=12)
                if baseline:
                    baselines[host_name] = round(baseline, 2)
                    threshold = baseline * 1.5 # Alert if 50% above baseline
                    if val > threshold:
                        high_cpu_hosts.append(f"{host_name} (Current: {val}%, Baseline: {round(baseline,2)}%)")
                elif val > 70: # Fallback to static
                    high_cpu_hosts.append(host_name)
                    
            elif 'disk' in name and 'space' in name and 'percentage' in name and val > 85:
                low_disk_hosts.append(host_name)

        recs = []
        if high_cpu_hosts:
            recs.append(f"Performance Anomaly detected: {', '.join(set(high_cpu_hosts))}. Consider scaling resources.")
        else:
            recs.append("Infrastructure performance within normal seasonal baselines.")
            
        if low_disk_hosts:
            recs.append(f"Storage alert: {', '.join(set(low_disk_hosts))} exceeding 85% capacity.")
        else:
            recs.append("Disk space usage remains stable.")

        return {
            "storage_exhaustion": "Safe" if not low_disk_hosts else "Warning",
            "cpu_headroom": "Anomalous" if high_cpu_hosts else f"Stable (Avg Baseline: {sum(baselines.values())/len(baselines) if baselines else 0:.1f}%)",
            "recommendations": recs,
            "baselines": baselines
        }
    except Exception as e:
        print(f"[NOC-FORECAST] Error: {e}")
        return {"error": str(e)}
