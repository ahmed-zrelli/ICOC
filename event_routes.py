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

@events_router.get("/remediation/{event_id}")
def get_remediation(event_id: str):
    """Return remediation advice for a specific security event."""
    import database as db

    events = db.get_events(limit=1000)
    event = next((e for e in events if str(e.get("id")) == event_id or e.get("event_id") == event_id), None)
    if not event:
        return {"error": "Event not found"}

    evt_type = event.get("event_type", "")
    severity = event.get("severity", "")
    summary  = event.get("summary", "")
    src_ip   = event.get("src_ip") or "unknown"
    host_ip  = event.get("host_ip") or "unknown"
    raw      = event.get("raw_data") or {}

    REMEDIATION = {
        "suspicious_file_drop": {
            "what": "A new file was created in /tmp, a common staging area for attackers. This indicates post-exploitation, web shell drops, or malware staging.",
            "why":  "Attackers use /tmp because it is world-writable and often excluded from integrity monitoring.",
            "fix":  [
                "Inspect the file: ssh into host and run `ls -la /tmp` and `file /tmp/<filename>`",
                "If sess_* PHP session file, check Apache logs for suspicious GET/POST requests",
                "If script or binary, isolate the host and perform forensic analysis",
                "Harden /tmp: mount with `noexec,nosuid` in /etc/fstab",
                "Install AIDE or auditd to alert on /tmp changes in real-time",
            ],
            "ioc": f"File dropped on {host_ip}. Summary: {summary}",
        },
        "ssh_brute_force": {
            "what": "Multiple failed SSH login attempts from a single source — brute-force or password-spraying attack.",
            "why":  "Weak SSH passwords are a top entry vector. Attackers use tools like Hydra or Medusa.",
            "fix":  [
                f"Block attacker IP immediately: `sudo ufw deny from {src_ip}`",
                "Install fail2ban to auto-ban IPs: `sudo apt install fail2ban`",
                "Disable SSH password auth — use key-based auth only (`PasswordAuthentication no` in sshd_config)",
                "Change SSH port from 22 to reduce automated scans",
                "Review `/var/log/auth.log` for any successful logins after the brute-force window",
            ],
            "ioc": f"Source: {src_ip} → Target: {host_ip}",
        },
        "ssh_login_success": {
            "what": "SSH login succeeded — possibly after brute-force. The attacker has a shell on your system.",
            "why":  "Successful auth gives attacker interactive access to run commands, escalate privileges, and pivot.",
            "fix":  [
                "URGENT: Check who is logged in: `who` and `w`",
                "Kill active sessions: `pkill -u <username>` or `kill -9 <PID>`",
                "Check for new accounts: `cat /etc/passwd | tail -10`",
                "Review bash history: `cat ~/.bash_history` and `/root/.bash_history`",
                "Rotate ALL SSH keys and passwords immediately",
                "Check cron jobs for persistence: `crontab -l` and `ls /etc/cron*`",
            ],
            "ioc": f"Successful login to {host_ip} from {src_ip}",
        },
        "unusual_outbound_connection": {
            "what": "Outbound connection to an unexpected destination — possible C2 beaconing or data exfiltration.",
            "why":  "After compromising a host, attackers establish outbound connections to receive commands or exfiltrate data.",
            "fix":  [
                f"Investigate connection: `netstat -antp | grep {src_ip}`",
                "Check which process owns the connection: `lsof -i :<port>`",
                "Block unexpected outbound traffic with firewall rules",
                "Capture traffic: `tcpdump -i any host <dst_ip> -w capture.pcap`",
                "Check for reverse shells or malware running as services",
            ],
            "ioc": f"Outbound from {host_ip}: {summary}",
        },
        "port_scan_detected": {
            "what": "A port scan was detected — attacker is enumerating open services to find attack vectors.",
            "why":  "Port scanning is reconnaissance phase before an actual attack.",
            "fix":  [
                f"Block the scanning IP: `sudo ufw deny from {src_ip}`",
                "Enable port scan detection with portsentry or fail2ban",
                "Close unnecessary open ports: review `sudo ufw status`",
                "Expect follow-up exploitation on discovered open ports",
            ],
            "ioc": f"Scan from {src_ip} against {host_ip}",
        },
        "reverse_shell_detected": {
            "what": "A reverse shell was detected. The host is actively being controlled by an attacker.",
            "why":  "Reverse shells give attackers a remote terminal bypassing firewall rules.",
            "fix":  [
                "CRITICAL: Isolate the host from network immediately",
                "Identify and kill the shell: `ps aux | grep -E 'bash|sh|nc|python'`",
                "Check active connections: `netstat -antp`",
                "Preserve forensic evidence before killing processes",
                "Rebuild the host from a clean image after forensic analysis",
            ],
            "ioc": f"Reverse shell on {host_ip} connecting to {src_ip}",
        },
        "cve_exploit_attempt": {
            "what": "An attempt to exploit a known CVE was detected against this host.",
            "why":  "Unpatched vulnerabilities are the #1 attack vector. Tools like Metasploit automate this.",
            "fix":  [
                "Identify which CVE was targeted from the raw data below",
                "Apply the patch or mitigation for that CVE immediately",
                "Check if the exploit succeeded by reviewing service logs",
                "Run a full vulnerability scan to identify all unpatched CVEs",
            ],
            "ioc": f"Exploit attempt against {host_ip} from {src_ip}",
        },
        "malware_dropped": {
            "what": "Malware or a persistence script was dropped on disk. Attacker is establishing long-term access.",
            "why":  "Persistence mechanisms survive reboots and allow re-entry even after passwords are changed.",
            "fix":  [
                "Scan with ClamAV: `sudo clamscan -r /`",
                "Check cron jobs and services: `systemctl list-units --type=service`",
                "Find recently modified files: `find / -newer /tmp -type f 2>/dev/null`",
                "Check /tmp, /var/tmp, /dev/shm for dropped binaries",
                "Consider full re-imaging if persistence is confirmed",
            ],
            "ioc": f"Malware on {host_ip}: {summary}",
        },
        "sqli_attack": {
            "what": "SQL injection attack detected against the web application.",
            "why":  "SQLi can allow attackers to dump the entire database, bypass authentication, or execute OS commands.",
            "fix":  [
                "Review web application logs for injected payloads",
                "Use parameterized queries / prepared statements in all DB calls",
                "Deploy a Web Application Firewall (WAF)",
                "Audit the database for unauthorized data access or modifications",
            ],
            "ioc": f"SQLi against {host_ip}: {summary}",
        },
        "lfi_attack": {
            "what": "Local File Inclusion attack detected — attacker is trying to read sensitive files via the web app.",
            "why":  "LFI can expose /etc/passwd, SSH keys, config files with credentials.",
            "fix":  [
                "Sanitize all user-supplied file path inputs in the web application",
                "Disable PHP allow_url_include and allow_url_fopen if using PHP",
                "Check web logs for accessed sensitive files",
                "Apply least-privilege to web server file permissions",
            ],
            "ioc": f"LFI against {host_ip}: {summary}",
        },
        "dos_attack": {
            "what": "Denial of Service attack detected — attacker is flooding the host with connections.",
            "why":  "DoS can make services unavailable to legitimate users and mask other attack activity.",
            "fix":  [
                f"Rate-limit connections from {src_ip}: `sudo ufw limit from {src_ip}`",
                "Enable SYN cookies: `sudo sysctl -w net.ipv4.tcp_syncookies=1`",
                "Use fail2ban to auto-block flood sources",
                "Monitor service availability and restart if needed",
            ],
            "ioc": f"DoS from {src_ip} against {host_ip}",
        },
    }

    advice = REMEDIATION.get(evt_type) or {
        "what": f"Security event of type '{evt_type}' detected with {severity} severity.",
        "why":  "This event type requires manual investigation to determine root cause.",
        "fix":  [
            "Review the raw event data below for indicators of compromise",
            "Check system logs on the affected host for related activity",
            "Correlate with other events from the same source IP or time window",
            "Consult MITRE ATT&CK for this technique",
        ],
        "ioc": summary,
    }

    return {
        "event_id":   event_id,
        "event_type": evt_type,
        "severity":   severity,
        "host_ip":    host_ip,
        "src_ip":     src_ip,
        "summary":    summary,
        "ai_enabled": False,
        "remediation": advice,
        "raw_data":   raw,
    }


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