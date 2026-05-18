#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ICOC-Lite Victim Agent - Legacy Edition
Compatible with Python 2.7 AND Python 3.x
Zero external dependencies - uses only Python stdlib + /proc + system commands

Works on Metasploitable3 (Ubuntu 14.04) out of the box.
No pip, no internet, no installation of packages needed.

Usage:
    python agent_legacy.py
    # or as root for full access:
    sudo python agent_legacy.py
"""

from __future__ import print_function

import os
import re
import sys
import time
import json
import socket
import hashlib
import datetime
import threading
import subprocess

# -- Python 2/3 compat --------------------------------------------------------
PY2 = sys.version_info[0] == 2

if PY2:
    from urllib2 import urlopen, Request, URLError
    from urllib import urlencode
else:
    from urllib.request import urlopen, Request
    from urllib.error import URLError

# -- Config --------------------------------------------------------------------
API_URL     = os.environ.get("ICOC_API_URL", "http://192.168.237.1:8000")
VICTIM_IP   = os.environ.get("VICTIM_IP",    "192.168.237.129")
HOSTNAME    = socket.gethostname()
AGENT_ID    = "victim-agent-" + HOSTNAME

AUTH_LOG    = "/var/log/auth.log"
WATCHED     = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/ssh/sshd_config"]
HEARTBEAT_S = 10
AUTH_POLL_S = 2
FIM_POLL_S  = 20
PROC_POLL_S = 8
NET_POLL_S  = 10

SUSPICIOUS_NAMES = {
    "nmap", "masscan", "hydra", "medusa", "john", "hashcat",
    "msfconsole", "netcat", "nc", "socat", "meterpreter",
}
SUSPICIOUS_CMDS = [
    "bash -i", "sh -i", "/bin/sh -i", "python -c", "perl -e",
    "ruby -e", "nc -e", "ncat", "reverse", "exploit",
]
REVERSE_PORTS = {4444, 5555, 6666, 7777, 8888, 9001, 9999, 1337, 31337}
NORMAL_PORTS  = {22, 53, 80, 443, 8000, 3000, 5432, 3306, 6379, 8080}

# -- Helpers -------------------------------------------------------------------

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def post_event(event_type, severity, data):
    payload = {
        "agent_id":   AGENT_ID,
        "host_ip":    VICTIM_IP,
        "hostname":   HOSTNAME,
        "timestamp":  now(),
        "event_type": event_type,
        "severity":   severity,
        "data":       data,
    }
    try:
        body = json.dumps(payload)
        if PY2:
            body = body.encode("utf-8")
        else:
            body = body.encode("utf-8")
        req = Request(
            API_URL + "/events/ingest",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        urlopen(req, timeout=3)
        print("[AGENT] {:<8s} | {:<30s} | {}".format(
            severity, event_type, data.get("summary", "")))
    except Exception as e:
        print("[AGENT] Post failed: {}".format(e))


def run_cmd(cmd):
    """Run shell command, return stdout string. Never raises."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, _ = proc.communicate()
        if PY2:
            return out
        return out.decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_ip(line):
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    return m.group(1) if m else "unknown"


def extract_user(line):
    m = re.search(r'for (\S+) from', line)
    return m.group(1) if m else "unknown"


def read_file(path):
    """Read a file, return content string or ''."""
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return ""


def md5_file(path):
    """Return MD5 hex of a file, or None on error."""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# -- Monitor: Auth Log ---------------------------------------------------------

class AuthLogMonitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._pos = 0
        self._fail_counts = {}

    def run(self):
        try:
            self._pos = os.path.getsize(AUTH_LOG)
        except OSError:
            self._pos = 0
        print("[AGENT] AuthLogMonitor started (offset={})".format(self._pos))
        while True:
            try:
                self._poll()
            except Exception as e:
                print("[AGENT] AuthLog error: {}".format(e))
            time.sleep(AUTH_POLL_S)

    def _poll(self):
        try:
            new_size = os.path.getsize(AUTH_LOG)
        except OSError:
            return
        if new_size <= self._pos:
            return
        try:
            with open(AUTH_LOG, "r") as f:
                f.seek(self._pos)
                new_text = f.read()
                self._pos = f.tell()
        except Exception:
            return

        for line in new_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if "Failed password" in line or "Invalid user" in line:
                ip    = extract_ip(line)
                self._fail_counts[ip] = self._fail_counts.get(ip, 0) + 1
                count = self._fail_counts[ip]
                sev   = "Critical" if count >= 5 else "High" if count >= 3 else "Medium"
                etype = "ssh_brute_force" if count >= 3 else "ssh_failed_auth"
                post_event(etype, sev, {
                    "summary":  "SSH failed login from {} (attempt #{})".format(ip, count),
                    "src_ip":   ip,
                    "attempts": count,
                    "rule":     "FR-SOC-02 - brute-force threshold",
                    "raw_log":  line[-120:],
                })
            elif "Accepted password" in line or "Accepted publickey" in line:
                ip   = extract_ip(line)
                user = extract_user(line)
                self._fail_counts.pop(ip, None)
                post_event("ssh_login_success", "High", {
                    "summary": "SSH login SUCCESS from {} user={}".format(ip, user),
                    "src_ip":  ip,
                    "user":    user,
                    "rule":    "Post-brute-force login detected",
                    "raw_log": line[-120:],
                })

# -- Monitor: File Integrity ---------------------------------------------------

class FIMMonitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._hashes = {}

    def run(self):
        self._baseline()
        print("[AGENT] FIMMonitor started ({} files)".format(len(self._hashes)))
        while True:
            time.sleep(FIM_POLL_S)
            try:
                self._check()
            except Exception as e:
                print("[AGENT] FIM error: {}".format(e))

    def _baseline(self):
        for path in WATCHED:
            h = md5_file(path)
            if h:
                self._hashes[path] = h
        # Baseline /tmp
        try:
            for fname in os.listdir("/tmp"):
                full = "/tmp/" + fname
                if os.path.isfile(full):
                    self._hashes[full] = md5_file(full) or "listed"
        except Exception:
            pass

    def _check(self):
        # Check watched files
        for path in WATCHED:
            old = self._hashes.get(path)
            new = md5_file(path)
            if old and new and old != new:
                self._hashes[path] = new
                post_event("file_integrity_violation", "Critical", {
                    "summary":  "File modified: {}".format(path),
                    "path":     path,
                    "old_hash": old[:16] + "...",
                    "new_hash": new[:16] + "...",
                    "rule":     "FR-SOC-06 - FIM alert",
                })
        # Check /tmp for new files
        try:
            for fname in os.listdir("/tmp"):
                full = "/tmp/" + fname
                if os.path.isfile(full) and full not in self._hashes:
                    h = md5_file(full) or "unknown"
                    self._hashes[full] = h
                    post_event("suspicious_file_drop", "Critical", {
                        "summary": "New file in /tmp: {}".format(full),
                        "path":    full,
                        "hash":    h[:32] + "..." if len(h) > 32 else h,
                        "rule":    "FR-SOC-07 - malware drop detection",
                    })
        except Exception:
            pass

# -- Monitor: Process List -----------------------------------------------------

class ProcessMonitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._seen = set()

    def run(self):
        self._seen = self._get_procs()
        print("[AGENT] ProcessMonitor started ({} procs)".format(len(self._seen)))
        while True:
            time.sleep(PROC_POLL_S)
            try:
                self._check()
            except Exception as e:
                print("[AGENT] Process error: {}".format(e))

    def _get_procs(self):
        out = run_cmd("ps aux 2>/dev/null")
        procs = set()
        for line in out.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.add(parts[10][:80])
        return procs

    def _check(self):
        current = self._get_procs()
        for cmd in current - self._seen:
            cmd_lower = cmd.lower()
            parts = cmd_lower.split()
            name = parts[0].split("/")[-1] if parts else ""
            is_sus = (
                name in SUSPICIOUS_NAMES or
                any(s in cmd_lower for s in SUSPICIOUS_CMDS)
            )
            if is_sus:
                post_event("suspicious_process", "Critical", {
                    "summary": "Suspicious process: {}".format(cmd[:80]),
                    "cmdline": cmd[:120],
                    "rule":    "FR-SOC-08 - UBA anomaly",
                })
        self._seen = current

# -- Monitor: Network Connections ---------------------------------------------

class NetMonitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._prev = set()

    def run(self):
        self._prev = self._get_established()
        print("[AGENT] NetMonitor started")
        while True:
            time.sleep(NET_POLL_S)
            try:
                self._check()
            except Exception as e:
                print("[AGENT] Net error: {}".format(e))

    def _hex_to_ip_port(self, hex_addr):
        try:
            addr, port_hex = hex_addr.split(":")
            ip_int = int(addr, 16)
            ip = "{}.{}.{}.{}".format(
                ip_int & 0xFF,
                (ip_int >> 8) & 0xFF,
                (ip_int >> 16) & 0xFF,
                (ip_int >> 24) & 0xFF,
            )
            return ip, int(port_hex, 16)
        except Exception:
            return "unknown", 0

    def _get_established(self):
        conns = set()
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            content = read_file(path)
            for line in content.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[3] != "01":
                    continue
                try:
                    _, lport = self._hex_to_ip_port(parts[1])
                    rip, rport = self._hex_to_ip_port(parts[2])
                    # Skip loopback, unrouted, and same-host connections
                    if rip in ("0.0.0.0", "127.0.0.1", "::1", VICTIM_IP):
                        continue
                    # Skip IPv6-mapped loopback (::ffff:127.x.x.x)
                    if "127.0.0.1" in rip or rip.startswith("::ffff:127."):
                        continue
                    conns.add((lport, rip, rport))
                except Exception:
                    pass
        return conns

    def _check(self):
        current = self._get_established()
        for lport, rip, rport in current - self._prev:
            if rport in REVERSE_PORTS:
                post_event("reverse_shell_detected", "Critical", {
                    "summary":    "Reverse shell: {}:{} -> {}:{}".format(
                        VICTIM_IP, lport, rip, rport),
                    "src_ip":     rip,
                    "dst_port":   rport,
                    "local_port": lport,
                    "rule":       "FR-SOC-01 - reverse shell C2 pattern",
                })
            elif rport not in NORMAL_PORTS and rip != VICTIM_IP:
                post_event("unusual_outbound_connection", "Medium", {
                    "summary":  "Unusual outbound: {}:{} -> {}:{}".format(
                        VICTIM_IP, lport, rip, rport),
                    "src_ip":   rip,
                    "dst_port": rport,
                })
        self._prev = current

# -- Heartbeat -----------------------------------------------------------------

class HeartbeatMonitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self._prev_cpu = None
        self._prev_net = None

    def run(self):
        print("[AGENT] HeartbeatMonitor started")
        while True:
            try:
                self._beat()
            except Exception as e:
                print("[AGENT] Heartbeat error: {}".format(e))
            time.sleep(HEARTBEAT_S)

    def _cpu(self):
        content = read_file("/proc/stat")
        for line in content.splitlines():
            if line.startswith("cpu "):
                parts = line.split()
                try:
                    vals  = [int(x) for x in parts[1:8]]
                    total = sum(vals)
                    idle  = vals[3]
                    if self._prev_cpu:
                        pt, pi = self._prev_cpu
                        dt = total - pt
                        di = idle  - pi
                        pct = round(100.0 * (1.0 - float(di) / max(dt, 1)), 1)
                    else:
                        pct = 0.0
                    self._prev_cpu = (total, idle)
                    return pct
                except Exception:
                    pass
        return 0.0

    def _mem(self):
        content = read_file("/proc/meminfo")
        total = avail = 0
        for line in content.splitlines():
            if line.startswith("MemTotal:"):
                try:
                    total = int(line.split()[1])
                except Exception:
                    pass
            elif line.startswith("MemAvailable:"):
                try:
                    avail = int(line.split()[1])
                except Exception:
                    pass
        if total:
            return round(100.0 * (total - avail) / total, 1)
        return 0.0

    def _disk(self):
        out = run_cmd("df / 2>/dev/null | tail -1")
        parts = out.split()
        if len(parts) >= 5:
            try:
                return float(parts[4].replace("%", ""))
            except Exception:
                pass
        return 0.0

    def _net(self):
        content = read_file("/proc/net/dev")
        rx = tx = 0
        for line in content.splitlines():
            if ":" in line and "lo" not in line and "Receive" not in line:
                parts = line.replace(":", " ").split()
                if len(parts) >= 10:
                    try:
                        rx += int(parts[1])
                        tx += int(parts[9])
                    except Exception:
                        pass
        if self._prev_net:
            prx, ptx = self._prev_net
            drx = max(rx - prx, 0)
            dtx = max(tx - ptx, 0)
        else:
            drx = dtx = 0
        self._prev_net = (rx, tx)
        return drx, dtx

    def _ports(self):
        out = run_cmd("netstat -ltn 2>/dev/null || ss -ltn 2>/dev/null")
        ports = []
        for line in out.splitlines():
            m = re.search(r':(\d+)\s', line)
            if m and "LISTEN" in line:
                try:
                    p = int(m.group(1))
                    if p not in ports:
                        ports.append(p)
                except Exception:
                    pass
        return sorted(ports)

    def _beat(self):
        cpu  = self._cpu()
        mem  = self._mem()
        disk = self._disk()
        rx, tx = self._net()
        ports  = self._ports()
        post_event("heartbeat", "Info", {
            "summary":        "CPU={}% MEM={}% DISK={}%".format(cpu, mem, disk),
            "cpu_pct":        cpu,
            "mem_pct":        mem,
            "disk_pct":       disk,
            "net_bytes_recv": rx,
            "net_bytes_sent": tx,
            "open_ports":     ports,
        })

# -- Main ---------------------------------------------------------------------

if __name__ == "__main__":
    print("[AGENT] ICOC-Lite Legacy Agent starting on {} ({})".format(HOSTNAME, VICTIM_IP))
    print("[AGENT] Python version: {}".format(sys.version))
    print("[AGENT] Reporting to: {}".format(API_URL))

    AuthLogMonitor().start()
    FIMMonitor().start()
    ProcessMonitor().start()
    NetMonitor().start()
    HeartbeatMonitor().start()

    post_event("agent_started", "Info", {
        "summary":      "Legacy agent online - no external deps",
        "python":       sys.version.split()[0],
        "capabilities": ["auth_log", "fim", "process_monitor",
                         "net_monitor", "heartbeat"],
    })

    # Keep main thread alive
    while True:
        time.sleep(60)
