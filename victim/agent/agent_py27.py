"""
Victim Agent — Python 2.7 compatible
Monitors: SSH auth logs, open ports, file integrity, process list, network connections.
Reports events to VOC/AI API in real-time via HTTP POST.
"""

import os
import re
import time
import json
import socket
import hashlib
import datetime
import threading
import subprocess

# Python 2.7 compatible imports
try:
    import urllib2 as urllib_request
    def post_json(url, data):
        req = urllib_request.Request(url, json.dumps(data).encode('utf-8'))
        req.add_header('Content-Type', 'application/json')
        try:
            urllib_request.urlopen(req, timeout=3)
        except Exception as e:
            raise e
except ImportError:
    import urllib.request as urllib_request
    def post_json(url, data):
        req = urllib_request.Request(url, json.dumps(data).encode('utf-8'),
                                     {'Content-Type': 'application/json'})
        try:
            urllib_request.urlopen(req, timeout=3)
        except Exception as e:
            raise e

# Try psutil, fall back to subprocess-based monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

API_URL   = os.environ.get("ICOC_API_URL", "http://192.168.237.1:8000")
VICTIM_IP = os.environ.get("VICTIM_IP",   "192.168.237.129")
HOSTNAME  = socket.gethostname()
AGENT_ID  = "victim-agent-" + HOSTNAME
LOG_PATH  = "/var/log/auth.log"
REPORT_INT = 5

WATCHED_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/etc/ssh/sshd_config", "/tmp"
]

_file_hashes = {}

def now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def post_event(event_type, severity, data):
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
        post_json(API_URL + "/events/ingest", payload)
        print("[AGENT] {} | {} | {}".format(severity, event_type, data.get("summary", "")))
    except Exception as e:
        print("[AGENT] Failed to post event: {}".format(e))


# ── Monitor: Auth Log ────────────────────────────────────────────────────────

class AuthLogMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._pos = 0
        self._fail_counts = {}

    def run(self):
        try:
            self._pos = os.path.getsize(LOG_PATH)
        except OSError:
            pass
        while True:
            try:
                self._check()
            except Exception:
                pass
            time.sleep(1)

    def _check(self):
        try:
            with open(LOG_PATH, "r") as f:
                f.seek(self._pos)
                new = f.read()
                self._pos = f.tell()
        except IOError:
            return

        for line in new.splitlines():
            line = line.strip()
            if not line:
                continue
            if "Failed password" in line or "Invalid user" in line:
                ip = self._extract_ip(line)
                self._fail_counts[ip] = self._fail_counts.get(ip, 0) + 1
                count = self._fail_counts[ip]
                sev = "Critical" if count >= 5 else "High" if count >= 3 else "Medium"
                post_event(
                    "ssh_brute_force" if count >= 3 else "ssh_failed_auth",
                    sev, {
                        "summary": "SSH failed login from {} (attempt #{})".format(ip, count),
                        "src_ip": ip, "attempts": count,
                        "rule": "FR-SOC-02 - brute-force threshold",
                        "raw_log": line[-100:]
                    })
            elif "Accepted password" in line or "Accepted publickey" in line:
                ip = self._extract_ip(line)
                user = self._extract_user(line)
                self._fail_counts.pop(ip, None)
                post_event("ssh_login_success", "High", {
                    "summary": "SSH login SUCCESS from {} user={}".format(ip, user),
                    "src_ip": ip, "user": user,
                    "rule": "Post-brute-force login detected",
                    "raw_log": line[-100:]
                })

    def _extract_ip(self, line):
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        return m.group(1) if m else "unknown"

    def _extract_user(self, line):
        m = re.search(r'for (\S+) from', line)
        return m.group(1) if m else "unknown"


# ── Monitor: Open Ports ──────────────────────────────────────────────────────

class PortMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._prev_ports = set()

    def run(self):
        while True:
            try:
                self._check()
            except Exception:
                pass
            time.sleep(10)

    def _get_listening_ports(self):
        ports = set()
        if HAS_PSUTIL:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN":
                    ports.add(c.laddr.port)
        else:
            try:
                out = subprocess.check_output(["ss", "-tlnp"], stderr=subprocess.STDOUT)
                for line in out.decode().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[3]
                        port = int(addr.rsplit(":", 1)[-1])
                        ports.add(port)
            except Exception:
                try:
                    out = subprocess.check_output(["netstat", "-tlnp"], stderr=subprocess.STDOUT)
                    for line in out.decode().splitlines()[2:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            addr = parts[3]
                            port = int(addr.rsplit(":", 1)[-1])
                            ports.add(port)
                except Exception:
                    pass
        return ports

    def _check(self):
        listening = self._get_listening_ports()
        new = listening - self._prev_ports
        closed = self._prev_ports - listening
        if new:
            post_event("new_port_opened", "Medium", {
                "summary": "New listening port(s): {}".format(sorted(new)),
                "ports": sorted(new)
            })
        if closed:
            post_event("port_closed", "Low", {
                "summary": "Port(s) closed: {}".format(sorted(closed)),
                "ports": sorted(closed)
            })
        self._prev_ports = listening


# ── Monitor: File Integrity ──────────────────────────────────────────────────

class FIMMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True

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
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _baseline(self):
        for path in WATCHED_FILES:
            if os.path.isfile(path):
                _file_hashes[path] = self._hash(path)
            elif os.path.isdir(path):
                for fname in os.listdir(path):
                    fpath = os.path.join(path, fname)
                    if os.path.isfile(fpath):
                        _file_hashes[fpath] = self._hash(fpath)

    def _check(self):
        for path, old_hash in list(_file_hashes.items()):
            new_hash = self._hash(path)
            if new_hash and new_hash != old_hash:
                _file_hashes[path] = new_hash
                post_event("file_integrity_violation", "Critical", {
                    "summary": "File modified: {}".format(path),
                    "path": path,
                    "old_hash": old_hash[:16] + "...",
                    "new_hash": new_hash[:16] + "...",
                    "rule": "FR-SOC-06 - FIM alert"
                })
        # Check for new files in /tmp
        try:
            known = set(k for k in _file_hashes if k.startswith("/tmp"))
            for fname in os.listdir("/tmp"):
                fpath = os.path.join("/tmp", fname)
                if os.path.isfile(fpath) and fpath not in known:
                    h = self._hash(fpath)
                    _file_hashes[fpath] = h
                    post_event("suspicious_file_drop", "Critical", {
                        "summary": "New file in /tmp: {}".format(fpath),
                        "path": fpath,
                        "hash": (h[:32] + "...") if h else "unknown",
                        "rule": "FR-SOC-07 - malware drop detection"
                    })
        except Exception:
            pass


# ── Monitor: Process Anomalies ───────────────────────────────────────────────

class ProcessMonitor(threading.Thread):
    SUSPICIOUS = {"nmap", "masscan", "hydra", "medusa", "john", "hashcat",
                  "msfconsole", "meterpreter", "netcat", "nc", "python -c",
                  "bash -i", "sh -i"}

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._prev_pids = set()

    def run(self):
        self._prev_pids = self._get_pids()
        while True:
            time.sleep(5)
            try:
                self._check()
            except Exception:
                pass

    def _get_pids(self):
        try:
            out = subprocess.check_output(["ps", "aux"], stderr=subprocess.STDOUT)
            pids = set()
            for line in out.decode().splitlines()[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 2:
                    try:
                        pids.add(int(parts[1]))
                    except ValueError:
                        pass
            return pids
        except Exception:
            return set()

    def _get_processes(self):
        procs = {}
        try:
            out = subprocess.check_output(["ps", "aux"], stderr=subprocess.STDOUT)
            for line in out.decode().splitlines()[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    try:
                        pid = int(parts[1])
                        procs[pid] = {"user": parts[0], "cmd": parts[10]}
                    except ValueError:
                        pass
        except Exception:
            pass
        return procs

    def _check(self):
        current = self._get_processes()
        new_pids = set(current.keys()) - self._prev_pids
        for pid in new_pids:
            proc = current.get(pid, {})
            cmd = proc.get("cmd", "")
            user = proc.get("user", "unknown")
            is_suspicious = any(s in cmd.lower() for s in self.SUSPICIOUS)
            if is_suspicious:
                post_event("suspicious_process", "Critical", {
                    "summary": "Suspicious process: {} (user={})".format(cmd[:50], user),
                    "pid": pid, "cmdline": cmd[:100], "user": user,
                    "rule": "FR-SOC-08 - UBA anomaly"
                })
        self._prev_pids = set(current.keys())


# ── Monitor: Network Connections ─────────────────────────────────────────────

class NetMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._prev = set()

    def run(self):
        while True:
            time.sleep(8)
            try:
                self._check()
            except Exception:
                pass

    def _get_connections(self):
        conns = set()
        if HAS_PSUTIL:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr:
                    conns.add((c.laddr.port, c.raddr.ip, c.raddr.port))
        else:
            try:
                out = subprocess.check_output(["ss", "-tnp"], stderr=subprocess.STDOUT)
                for line in out.decode().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] == "ESTAB":
                        local = parts[3].rsplit(":", 1)
                        remote = parts[4].rsplit(":", 1)
                        if len(local) == 2 and len(remote) == 2:
                            try:
                                conns.add((int(local[1]), remote[0], int(remote[1])))
                            except ValueError:
                                pass
            except Exception:
                pass
        return conns

    def _check(self):
        conns = self._get_connections()
        new = conns - self._prev
        for lport, rip, rport in new:
            if lport > 1024 and rport in (4444, 5555, 6666, 7777, 8888, 9001, 9999, 1337):
                post_event("reverse_shell_detected", "Critical", {
                    "summary": "Reverse shell: {}:{} -> {}:{}".format(VICTIM_IP, lport, rip, rport),
                    "src_ip": rip, "dst_port": rport, "local_port": lport,
                    "rule": "FR-SOC-01 - reverse shell C2 pattern"
                })
            elif rport not in (80, 443, 53, 8000, 3000, 22, 5432, 8080, 8443, 123, 111, 631, 49152, 49153, 49154, 49155, 49160):
                post_event("unusual_outbound_connection", "Medium", {
                    "summary": "Unusual outbound: {}:{} -> {}:{}".format(VICTIM_IP, lport, rip, rport),
                    "src_ip": rip, "dst_port": rport
                })
        self._prev = conns


# ── Heartbeat ────────────────────────────────────────────────────────────────

def heartbeat_loop():
    while True:
        try:
            if HAS_PSUTIL:
                cpu  = psutil.cpu_percent(interval=1)
                mem  = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent
                net  = psutil.net_io_counters()
                ports = [c.laddr.port for c in psutil.net_connections() if c.status == "LISTEN"]
                extra = {"net_bytes_sent": net.bytes_sent, "net_bytes_recv": net.bytes_recv}
            else:
                cpu = 0
                mem = 0
                disk = 0
                ports = []
                extra = {}

            data = {
                "summary": "CPU={}% MEM={}% DISK={}%".format(cpu, mem, disk),
                "cpu_pct": cpu, "mem_pct": mem, "disk_pct": disk,
                "open_ports": ports
            }
            data.update(extra)
            post_event("heartbeat", "Info", data)
        except Exception as e:
            print("[AGENT] Heartbeat error: {}".format(e))
        time.sleep(REPORT_INT)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[AGENT] ICOC-Lite Victim Agent starting on {} ({})".format(HOSTNAME, VICTIM_IP))
    print("[AGENT] Reporting to: {}".format(API_URL))
    print("[AGENT] psutil available: {}".format(HAS_PSUTIL))

    AuthLogMonitor().start()
    PortMonitor().start()
    FIMMonitor().start()
    ProcessMonitor().start()
    NetMonitor().start()

    post_event("agent_started", "Info", {
        "summary": "Victim agent online - monitoring {} paths".format(len(WATCHED_FILES)),
        "monitored_paths": WATCHED_FILES,
        "capabilities": ["auth_log", "port_monitor", "fim", "process_monitor", "net_monitor"],
        "python_version": "2.7",
        "psutil": HAS_PSUTIL
    })

    heartbeat_loop()
