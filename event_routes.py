"""
Event Ingestion Routes — appended to main.py
Handles victim agent reports and attack notifications.
Provides live event feed for dashboard.

FIX: attack_launched now also calls ingest_event() so Critical/High/Alerts/Incidents
     counters actually increment in the stats panel.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Any
import datetime

events_router = APIRouter(prefix="/events", tags=["Events"])

class AgentEvent(BaseModel):
    agent_id: str
    host_ip: str
    hostname: str
    timestamp: str
    event_type: str
    severity: str
    data: dict

class AttackEvent(BaseModel):
    attacker_ip: str
    victim_ip: str
    attack_type: str
    timestamp: str
    details: dict

# Map attack_type → (event_type, severity, summary)
# These match the event_type strings used in attacks.py notify_api() calls
_ATTACK_EVENT_MAP = {
    # attack_type from notify_api()           event_type for ingest     severity   summary
    "ssh_brute_force":          ("ssh_brute_force",           "High",     "SSH Brute-Force attack initiated"),
    "ssh_brute_success":        ("ssh_login_success",          "Critical", "SSH Brute-Force SUCCESS — credentials found"),
    "port_scan":                ("port_scan_detected",         "Medium",   "Port scan initiated against victim"),
    "port_scan_complete":       ("port_scan_detected",         "Medium",   "Port scan completed — open ports enumerated"),
    "cve_exploit_attempt":      ("cve_exploit_attempt",        "Critical", "CVE exploit probe launched"),
    "cve_exploit_sent":         ("cve_exploit_attempt",        "Critical", "CVE exploit payload delivered"),
    "cve_exploit_blocked":      ("cve_exploit_attempt",        "High",     "CVE exploit attempt blocked/failed"),
    "sqli_attack":              ("sqli_attack",                "High",     "SQL Injection attack against web app"),
    "sqli_complete":            ("sqli_attack",                "High",     "SQL Injection sequence completed"),
    "lfi_attack":               ("lfi_attack",                 "High",     "LFI / Path Traversal attack"),
    "lfi_success":              ("lfi_attack",                 "Critical", "LFI SUCCESS — sensitive file accessed"),
    "reverse_shell_attempt":    ("reverse_shell_detected",     "Critical", "Reverse shell attempt — C2 connection"),
    "reverse_shell_connected":  ("reverse_shell_detected",     "Critical", "Reverse shell CONNECTED — system compromised"),
    "malware_dropped":          ("malware_dropped",            "Critical", "Malware / persistence script dropped on disk"),
    "malware_drop_attempt":     ("malware_dropped",            "High",     "Malware drop attempt (blocked)"),
    "dos_started":              ("dos_attack",                 "High",     "DoS / connection flood started"),
    "dos_complete":             ("dos_attack",                 "High",     "DoS flood complete"),
}

def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"

@events_router.post("/ingest")
def ingest(event: AgentEvent):
    """Receive event from victim agent."""
    from event_store import ingest_event
    return ingest_event(event.dict())

@events_router.post("/attack_launched")
def attack_launched(attack: AttackEvent):
    """
    Receive notification of attacker action.
    FIX: now also ingests a proper security event so severity counters
    (Critical, High, Alerts, Incidents) update in the dashboard stats bar.
    """
    from event_store import ingest_attack, ingest_event

    # 1. Store in attack log (original behaviour)
    ingest_attack(attack.dict())

    # 2. Also ingest as a real security event so stats counters update
    mapping = _ATTACK_EVENT_MAP.get(attack.attack_type)
    if mapping:
        event_type, severity, summary = mapping
    else:
        # Unknown attack type — still ingest as High
        event_type = attack.attack_type
        severity   = "High"
        summary    = f"Attack: {attack.attack_type}"

    # 3. Log to NOC Audit Trail for visibility in NOC Center
    try:
        from database import log_noc_action
        log_noc_action(
            action="SECURITY_ALERT",
            module="ATTACKER",
            details={
                "attack_type": attack.attack_type,
                "summary": summary,
                "target": attack.victim_ip,
                "severity": severity
            },
            status="Critical" if severity == "Critical" else "Warning"
        )
    except Exception:
        pass

    security_event = {
        "agent_id":   "attacker-module",
        "host_ip":    attack.attacker_ip,
        "hostname":   "attacker",
        "timestamp":  attack.timestamp or _now(),
        "event_type": event_type,
        "severity":   severity,
        "data": {
            "summary":      summary,
            "src_ip":       attack.attacker_ip,
            "dst_ip":       attack.victim_ip,
            "attack_type":  attack.attack_type,
            **attack.details
        }
    }
    ingest_event(security_event)

    return {"status": "ok", "event_type": event_type, "severity": severity}

@events_router.get("/live")
def get_live(limit: int = 50, severity: Optional[str] = None,
             event_type: Optional[str] = None, since: Optional[int] = None):
    """Get live event feed from victim agent."""
    from event_store import get_events
    return {"events": get_events(limit, severity, event_type, since)}

@events_router.get("/attacks")
def get_attacks(limit: int = 50):
    """Get log of attacks launched by attacker."""
    from event_store import get_attack_log
    return {"attacks": get_attack_log(limit)}

@events_router.get("/stats")
def get_stats():
    """Live stats: event counts, severity breakdown, active brute-force, risk score."""
    from event_store import get_live_stats
    return get_live_stats()

@events_router.get("/stream")
async def event_stream():
    """SSE stream of live events (updates every 2s)."""
    import asyncio, json
    from fastapi.responses import StreamingResponse
    from event_store import get_events, get_live_stats

    async def generator():
        last_count = 0
        while True:
            events = get_events(10)
            stats = get_live_stats()
            if len(events) != last_count:
                last_count = len(events)
                payload = {"events": events[:5], "stats": stats}
                yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(generator(), media_type="text/event-stream")