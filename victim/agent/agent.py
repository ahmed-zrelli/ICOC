"""
Victim Agent — runs inside the victim container.
Monitors: SSH auth logs, open ports, file integrity, process list, network connections.
Reports events to VOC/AI API in real-time via HTTP POST.
This is the "Wazuh-like" agent simplified for the lab.
"""

import os
import time
import json
import socket
import hashlib
import datetime
import threading
import subprocess
import requests
import psutil
from pathlib import Path

API_URL    = os.getenv("ICOC_API_URL", "http://api:8000")
VICTIM_IP  = os.getenv("VICTIM_IP", "192.168.100.102")
HOSTNAME   = socket.gethostname()
AGENT_ID   = f"victim-agent-{HOSTNAME}"
LOG_PATH   = "/var/log/auth.log"
REPORT_INT = 5   # seconds between heartbeats

# ── Files to monitor for integrity ─────────────────────────────────────────
WATCHED_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/etc/ssh/sshd_config", "/tmp"
]

_file_hashes = {}

# ── Helpers ─────────────────────────────────────────────────────────────────

def now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def post_event(event_type: str, severity: str, data: dict):
    """Send event to VOC/AI API."""
    payload = {
        "agent_id":   AGENT_ID,
        "host_ip":    VICTIM_IP,
        "hostname":   HOSTNAME,
        "timestamp":  now(),
        "event_type": event_type,
        "severity":   severity,
        "data":       data
    }
    try:
        requests.post(f"{API_URL}/events/ingest", json=payload, timeout=3)
        print(f"[AGENT] {severity:8s} | {event_type} | {data.get('summary','')}")
    except Exception as e:
        print(f"[AGENT] Failed to post event: {e}")

# ── Monitor: Auth Log (SSH brute-force, login success/fail) ─────────────────

class AuthLogMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._pos = 0
        self._fail_counts = {}  # ip -> count

    def run(self):
        # Seed position at end of existing log
        try:
            self._pos = os.path.getsize(LOG_PATH)
        except FileNotFoundError:
            pass

        while True:
            try:
                self._check()
            except Exception as e:
                pass
            time.sleep(1)

    def _check(self):
        try:
            with open(LOG_PATH, "r") as f:
                f.seek(self._pos)
                new = f.read()
                self._pos = f.tell()
        except FileNotFoundError:
            return

        for line in new.splitlines():
            line = line.strip()
            if not line:
                continue

            # SSH failed password
            if "Failed password" in line or "Invalid user" in line:
                ip = self._extract_ip(line)
                self._fail_counts[ip] = self._fail_counts.get(ip, 0) + 1
                count = self._fail_counts[ip]
                sev = "Critical" if count >= 5 else "High" if count >= 3 else "Medium"
                post_event("ssh_brute_force" if count >= 3 else "ssh_failed_auth",
                           sev, {
                    "summary": f"SSH failed login from {ip} (attempt #{count})",
                    "src_ip": ip, "attempts": count,
                    "rule": "FR-SOC-02 — brute-force threshold",
                    "raw_log": line[-100:]
                })

            # Successful login
            elif "Accepted password" in line or "Accepted publickey" in line:
                ip = self._extract_ip(line)
                user = self._extract_user(line)
                self._fail_counts.pop(ip, None)  # reset counter
                post_event("ssh_login_success", "High", {
                    "summary": f"SSH login SUCCESS from {ip} user={user}",
                    "src_ip": ip, "user": user,
                    "rule": "Post-brute-force login detected",
                    "raw_log": line[-100:]
                })

            # Port scan detection (via kernel log)
            elif "SYN_RECV" in line or "POSSIBLE PORT SCAN" in line:
                ip = self._extract_ip(line)
                post_event("port_scan_detected", "High", {
                    "summary": f"Port scan detected from {ip}",
                    "src_ip": ip, "raw_log": line[-100:]
                })

    def _extract_ip(self, line):
        import re
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        return m.group(1) if m else "unknown"

    def _extract_user(self, line):
        import re
        m = re.search(r'for (\S+) from', line)
        return m.group(1) if m else "unknown"


# ── Monitor: Open Ports ─────────────────────────────────────────────────────

class PortMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._prev_ports = set()

    def run(self):
        while True:
            try:
                self._check()
            except Exception:
                pass
            time.sleep(10)

    def _check(self):
        conns = psutil.net_connections(kind="inet")
        listening = {c.laddr.port for c in conns if c.status == "LISTEN"}
        new = listening - self._prev_ports
        closed = self._prev_ports - listening
        if new:
            post_event("new_port_opened", "Medium", {
                "summary": f"New listening port(s): {sorted(new)}",
                "ports": sorted(new)
            })
        if closed:
            post_event("port_closed", "Low", {
                "summary": f"Port(s) closed: {sorted(closed)}",
                "ports": sorted(closed)
            })
        self._prev_ports = listening


# ── Monitor: File Integrity ─────────────────────────────────────────────────

class FIMMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)

    def run(self):
        self._baseline()
        while True:
            time.sleep(15)
            try:
                self._check()
            except Exception:
                pass

    def _hash(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _baseline(self):
        for path in WATCHED_FILES:
            p = Path(path)
            if p.is_file():
                _file_hashes[path] = self._hash(path)
            elif p.is_dir():
                for f in p.iterdir():
                    if f.is_file():
                        _file_hashes[str(f)] = self._hash(str(f))

    def _check(self):
        for path, old_hash in list(_file_hashes.items()):
            new_hash = self._hash(path)
            if new_hash and new_hash != old_hash:
                _file_hashes[path] = new_hash
                post_event("file_integrity_violation", "Critical", {
                    "summary": f"File modified: {path}",
                    "path": path,
                    "old_hash": old_hash[:16] + "...",
                    "new_hash": new_hash[:16] + "...",
                    "rule": "FR-SOC-06 — FIM alert"
                })
        # Check for new files in /tmp (common malware drop)
        try:
            tmp_files = set(str(f) for f in Path("/tmp").iterdir() if f.is_file())
            known = set(k for k in _file_hashes if k.startswith("/tmp"))
            for new_file in tmp_files - known:
                h = self._hash(new_file)
                _file_hashes[new_file] = h
                post_event("suspicious_file_drop", "Critical", {
                    "summary": f"New file in /tmp: {new_file}",
                    "path": new_file,
                    "hash": h[:32] + "..." if h else "unknown",
                    "rule": "FR-SOC-07 — malware drop detection"
                })
        except Exception:
            pass


# ── Monitor: Process Anomalies ───────────────────────────────────────────────

class ProcessMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._prev_pids = set()
        SUSPICIOUS = {"nmap", "masscan", "hydra", "medusa", "john", "hashcat",
                      "msfconsole", "meterpreter", "netcat", "nc", "reverse_shell",
                      "python3 -c", "bash -i", "sh -i"}
        self._suspicious = SUSPICIOUS

    def run(self):
        self._prev_pids = {p.pid for p in psutil.process_iter()}
        while True:
            time.sleep(5)
            try:
                self._check()
            except Exception:
                pass

    def _check(self):
        current = {}
        for p in psutil.process_iter(["pid", "name", "cmdline", "username", "cpu_percent"]):
            try:
                current[p.pid] = p.info
            except Exception:
                pass

        new_pids = set(current) - self._prev_pids
        for pid in new_pids:
            proc = current.get(pid, {})
            name = proc.get("name", "")
            cmd  = " ".join(proc.get("cmdline") or [])[:100]
            user = proc.get("username", "unknown")

            # Check if suspicious
            is_suspicious = any(s in cmd.lower() or s in name.lower()
                                 for s in self._suspicious)
            if is_suspicious:
                post_event("suspicious_process", "Critical", {
                    "summary": f"Suspicious process: {name} (user={user})",
                    "pid": pid, "name": name, "cmdline": cmd, "user": user,
                    "rule": "FR-SOC-08 — UBA anomaly"
                })

        self._prev_pids = set(current)


# ── Monitor: Network Connections ─────────────────────────────────────────────

class NetMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._prev = set()

    def run(self):
        while True:
            time.sleep(8)
            try:
                self._check()
            except Exception:
                pass

    def _check(self):
        conns = set()
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                conns.add((c.laddr.port, c.raddr.ip, c.raddr.port))

        new = conns - self._prev
        for lport, rip, rport in new:
            # Flag suspicious outbound (potential reverse shell / C2)
            if lport > 1024 and rport in (4444, 5555, 6666, 7777, 8888, 9001, 9999, 1337):
                post_event("reverse_shell_detected", "Critical", {
                    "summary": f"Reverse shell connection: {VICTIM_IP}:{lport} → {rip}:{rport}",
                    "src_ip": rip, "dst_port": rport, "local_port": lport,
                    "rule": "FR-SOC-01 — reverse shell C2 pattern"
                })
            elif rport not in (80, 443, 53, 8000, 3000, 22, 5432, 6379):
                post_event("unusual_outbound_connection", "Medium", {
                    "summary": f"Unusual outbound: {VICTIM_IP}:{lport} → {rip}:{rport}",
                    "src_ip": rip, "dst_port": rport
                })
        self._prev = conns


# ── Heartbeat ────────────────────────────────────────────────────────────────

def heartbeat_loop():
    while True:
        try:
            cpu  = psutil.cpu_percent(interval=1)
            mem  = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent
            net  = psutil.net_io_counters()

            post_event("heartbeat", "Info", {
                "summary": f"CPU={cpu}% MEM={mem}% DISK={disk}%",
                "cpu_pct": cpu, "mem_pct": mem, "disk_pct": disk,
                "net_bytes_sent": net.bytes_sent,
                "net_bytes_recv": net.bytes_recv,
                "open_ports": [c.laddr.port for c in psutil.net_connections()
                               if c.status == "LISTEN"]
            })
        except Exception as e:
            print(f"[AGENT] Heartbeat error: {e}")
        time.sleep(REPORT_INT)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[AGENT] ICOC-Lite Victim Agent starting on {HOSTNAME} ({VICTIM_IP})")
    print(f"[AGENT] Reporting to: {API_URL}")

    # Start all monitors
    AuthLogMonitor().start()
    PortMonitor().start()
    FIMMonitor().start()
    ProcessMonitor().start()
    NetMonitor().start()

    # Announce
    post_event("agent_started", "Info", {
        "summary": f"Victim agent online — monitoring {len(WATCHED_FILES)} paths",
        "monitored_paths": WATCHED_FILES,
        "capabilities": ["auth_log", "port_monitor", "fim", "process_monitor", "net_monitor"]
    })

    # Heartbeat in main thread
    heartbeat_loop()
