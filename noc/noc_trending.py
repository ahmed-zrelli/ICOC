from fastapi import APIRouter, HTTPException
import os
import requests
import time
from datetime import datetime, timedelta

router = APIRouter()

from noc.noc_utils import get_zabbix_auth, ZABBIX_API

@router.get("/trending")
async def get_performance_trends():
    """FR-NOC-04: Analyze historical performance trends."""
    auth = get_zabbix_auth()
    if not auth:
        # Fallback to empty/mock if Zabbix is down
        return {"cpu_trend": [], "alert_frequency": {"critical": 0, "warning": 0, "info": 0}}

    try:
        # Find Victim Host CPU itemid dynamically
        victim_hostname = os.getenv("VICTIM_HOSTNAME", "victim")
        items_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "host": victim_hostname,
                "search": {"name": "CPU utilization"},
                "output": ["itemid"]
            },
            "auth": auth,
            "id": 10
        }, timeout=5)
        
        items = items_res.json().get('result', [])
        itemid = items[0]['itemid'] if items else None
        
        if not itemid:
            # Fallback to hardcoded or common one if dynamic fails
            itemid = "47231"

        # Get history for Victim Host CPU
        time_from = int(time.time()) - (6 * 3600)
        
        history_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "history.get",
            "params": {
                "itemids": [itemid],
                "history": 0, # Float
                "time_from": time_from,
                "output": ["value", "clock"],
                "sortfield": "clock",
                "sortorder": "ASC",
                "limit": 100
            },
            "auth": auth,
            "id": 2
        }, timeout=10)
        
        history_data = history_res.json().get('result', [])
        
        cpu_trend = []
        for point in history_data:
            dt = datetime.fromtimestamp(int(point['clock']))
            cpu_trend.append({
                "time": dt.strftime("%H:%M"),
                "value": round(float(point['value']), 2)
            })

        # If no history yet, return some defaults to avoid empty graph
        if not cpu_trend:
             cpu_trend = [{"time": datetime.now().strftime("%H:%M"), "value": 0}]

        # Get alert frequency (counts by priority)
        triggers_res = requests.post(ZABBIX_API, json={
            "jsonrpc": "2.0",
            "method": "trigger.get",
            "params": {
                "only_true": 1,
                "output": ["priority"]
            },
            "auth": auth,
            "id": 3
        }, timeout=5)
        
        triggers = triggers_res.json().get('result', [])
        
        # Include Virtual Alerts in distribution
        from noc.noc_utils import get_virtual_alerts
        v_alerts = get_virtual_alerts()
        
        freq = {"critical": 0, "warning": 0, "info": 0}
        for t in triggers:
            p = int(t['priority'])
            if p >= 4: freq["critical"] += 1
            elif p >= 2: freq["warning"] += 1
            else: freq["info"] += 1

        for va in v_alerts:
            p = va['severity']
            if p >= 4: freq["critical"] += 1
            elif p >= 2: freq["warning"] += 1
            else: freq["info"] += 1

        return {
            "cpu_trend": cpu_trend,
            "alert_frequency": freq
        }
    except Exception as e:
        print(f"[NOC-TRENDING] Error: {e}")
        return {"cpu_trend": [], "alert_frequency": {"critical": 0, "warning": 0, "info": 0}, "error": str(e)}
