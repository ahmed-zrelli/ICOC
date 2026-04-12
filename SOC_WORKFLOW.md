# ICOC-Lite — SOC Branch Workflow
**Branch Owner:** SOC Lead | **Covers:** FR-SOC-01 → FR-SOC-08  
**Stack:** Wazuh 4.8.0 (Docker) · Metasploitable3 · Kali · Windows Server 2012

---

## 🔑 Credentials

| Machine | Username | Password |
|---|---|---|
| Windows Server 2012 | `admin` | `P@ssw0rd123` |
| Metasploitable3 (Ubuntu 14.04) | `vagrant` | `vagrant` |
| Wazuh Manager | `taher` | `taher` |

---

## 🌐 Network Map

| Role | IP |
|---|---|
| Wazuh Manager | `192.168.100.10` |
| Windows Endpoint (Server 2012) | `192.168.100.101` |
| Linux Endpoint (Metasploitable3) | `192.168.100.102` |
| Kali Attacker | `192.168.100.200` |

> **Host requirements:** VMware/VirtualBox · 24 GB RAM · 8 Cores  
> Wazuh Manager container needs **≥ 4096 MB RAM**.

---

## ⚡ Manager — Start / Stop / Recovery

### Normal Start
```bash
# On Wazuh Manager VM (Ubuntu)
sudo systemctl start docker
cd wazuh-docker/single-node
docker compose up -d
```

### Check Running Containers
```bash
docker compose ps -a
```

### Normal Stop (clean, saves RAM)
```bash
cd ~/wazuh-docker/single-node
sudo docker compose down
sudo systemctl stop docker.service
sudo systemctl stop docker.socket
```

### Pause Only (resume exactly where you left off)
```bash
sudo docker compose stop
```

> **`stop` vs `down`:**  
> - `stop` → freezes containers in place, no CPU used, instant resume.  
> - `down` → removes containers entirely. Cleaner RAM, prevents Wazuh startup bugs on next boot.

---

### 🚨 Crash Recovery (containers stuck in "starting/exiting" loop)

```bash
# Step 1 — full teardown
cd ~/wazuh-docker/single-node
docker compose down

# Step 2 — start the indexer FIRST (database must be healthy before manager)
docker compose up -d wazuh.indexer

# Wait 30 seconds, verify it's Up
docker compose ps

# If wazuh.indexer is NOT "Up" — do NOT proceed, check logs:
docker compose logs wazuh.indexer

# Step 3 — once indexer is stable, bring up the rest
docker compose up -d
```

---

## 🛠️ Agent Installation

### Linux — Metasploitable3 (Ubuntu 14.04)

```bash
# 1. Download the agent package
curl -L https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb -o wazuh-agent.deb

# 2. Install
sudo dpkg -i wazuh-agent.deb

# 3. Point agent to Manager
sudo sed -i 's/<address>MANAGER_IP<\/address>/<address>192.168.100.10<\/address>/' /var/ossec/etc/ossec.conf

# 4. Start and verify
sudo service wazuh-agent restart
sudo service wazuh-agent status
```

---

### Linux — Kali

```bash
# 1. Download the agent package
curl -L https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb -o wazuh-agent.deb

# 2. Install
sudo dpkg -i wazuh-agent.deb

# 3. Point agent to Manager
sudo sed -i 's/<address>MANAGER_IP<\/address>/<address>192.168.100.10<\/address>/' /var/ossec/etc/ossec.conf

# 4. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent
```

---

### Windows Server 2012

**Step 1 — Set static IP**

1. Right-click network icon → **Open Network and Sharing Center**
2. Click **Change adapter settings**
3. Right-click Ethernet adapter → **Properties**
4. Select **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**
5. Choose **Use the following IP address** and fill:
   - IP address: `192.168.100.101`
   - Subnet mask: `255.255.255.0`
   - Default gateway: `192.168.100.1` (or leave blank)
   - Preferred DNS: `8.8.8.8`
6. Click OK → OK → Close
7. Verify in Command Prompt (as Administrator):
   ```cmd
   ipconfig
   ```
   Must show **IPv4 Address: 192.168.100.101**
8. Test from Manager:
   ```bash
   ping 192.168.100.101
   ```

**Step 2 — Install Wazuh Agent (PowerShell as Administrator)**

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile ${env:tmp}\wazuh-agent; msiexec.exe /i ${env:tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.100.101' WAZUH_AGENT_NAME='Windows_Server_2012'
```

> Agent name used: `Windows_Server_2012`  
> Manager address used in installer: `192.168.100.101`

**Step 3 — Start the agent**

```powershell
NET START WazuhSvc
```

**Step 4 — Verify in Dashboard**

Go to `https://192.168.100.10` → **Agents** tab.  
You should see **4 agents** all showing **Active** (green):
- wazuh-manager
- metasploitable3
- kali-attacker
- Windows_Server_2012

---

## 🚀 Agent Start / Stop / Status

### Start Agents

| Machine | Command |
|---|---|
| Metasploitable3 | `sudo service wazuh-agent start` |
| Kali | `sudo systemctl start wazuh-agent` |
| Windows (PowerShell) | `NET START WazuhSvc` |

### Stop Agents

| Machine | Command |
|---|---|
| Kali + Metasploitable3 | `sudo service wazuh-agent stop` |
| Windows (PowerShell) | `Stop-Service -Name Wazuh` |

### Status / Restart

```bash
# Kali
sudo systemctl status wazuh-agent
sudo systemctl restart wazuh-agent

# Metasploitable3
sudo service wazuh-agent status
sudo service wazuh-agent restart
```

```powershell
# Windows
Get-Service -Name Wazuh
Restart-Service wazuh
# or
Stop-Service -Name Wazuh
NET START WazuhSvc
```

---

## FR-SOC-01 — Centralized Log Collection

**Status:** Covered automatically once all 4 agents are Active and sending heartbeats to the Manager.

Verify in Dashboard → **Agents** → all agents show green / Active.

---

## FR-SOC-06 — FIM (File Integrity Monitoring)

### Linux (Metasploitable3 AND Kali)

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Find the `<syscheck>` block and add inside it:

```xml
<directories check_all="yes" realtime="yes" report_changes="yes">/etc,/boot,/usr/bin,/tmp</directories>
```

Save (Ctrl+O → Enter → Ctrl+X), then restart:

```bash
# Metasploitable3
sudo service wazuh-agent restart

# Kali
sudo systemctl restart wazuh-agent
```

**Test (on Metasploitable3 or Kali):**
```bash
sudo touch /etc/hacked-by-taher
```
→ Dashboard → **Security Events** → High severity FIM alert within ~30 seconds.

---

### Windows

1. Open `C:\Program Files (x86)\ossec-agent\ossec.conf` with Notepad **as Administrator**
2. Find `<syscheck>` section and add inside it:

```xml
<ignore>C:\Windows\System32\certlog</ignore>
<ignore type="sregex">.jrs$</ignore>
<ignore type="sregex">.log$</ignore>
<ignore type="sregex">.tmp$</ignore>
<ignore>C:\Windows\System32\LogFiles</ignore>
<directories check_all="yes" realtime="yes" report_changes="yes">C:\Windows\System32,C:\Windows\SysWOW64</directories>
```

> The `<ignore>` entries suppress false positive logs from certlog, journal files, log files, and temp files.

3. Save the file.
4. Restart the agent:
   - `Win + R` → `services.msc` → find **Wazuh Agent** → right-click → **Restart**
   - or PowerShell:
     ```powershell
     Stop-Service -Name Wazuh
     NET START WazuhSvc
     ```

**Test FIM on Windows:**
```cmd
echo test > C:\Windows\System32\test-hacked.txt
```
→ Dashboard → Security Events → FIM alert appears.

---

## FR-SOC-02 + FR-SOC-04 — Brute-Force Detection + Auto IP Block

### Linux Target (Metasploitable3)

**Manager config — add Active Response block:**

```bash
cd ~/wazuh-docker/single-node
sudo nano config/wazuh_cluster/wazuh_manager.conf
```

Paste the following just before the closing `</ossec_config>` tag:

```xml
</cluster>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>600</timeout>
  </active-response>

</ossec_config>

<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>
```

> **Rule 5763** = "SSHD brute force trying to get access (based on past history)" — triggers when a previously flagged IP keeps hammering SSH over an extended period.

Restart the Manager to load the new config:

```bash
sudo docker compose restart wazuh.manager
```

Wait 30 seconds, then **from Kali:**

```bash
hydra -l vagrant -P /usr/share/wordlists/rockyou.txt 192.168.100.102 ssh
```

**Expected in Dashboard:**
- Multiple SSH brute-force alerts (FR-SOC-02 + FR-SOC-03)
- After ~5 failures → IP automatically blocked on Metasploitable3 for 10 minutes (FR-SOC-04)

**Verify the block on Metasploitable3:**
```bash
sudo iptables -L -n -v | grep 192.168.100.200
```

---

### Windows Target (Windows Server 2012)

**Manager config — add Active Response for WinRM brute force:**

```bash
cd ~/wazuh-docker/single-node
sudo nano config/wazuh_cluster/wazuh_manager.conf
```

Add inside the config (before closing `</ossec_config>`):

```xml
<active-response>
  <command>netsh-win</command>
  <location>local</location>
  <rules_id>60122</rules_id>
  <timeout>120</timeout>
</active-response>
```

> **Rule 60122** = WinRM brute force rule. Triggers Windows Firewall block via `netsh`.

**From Kali:**
```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt 192.168.100.101 rdp
```

Wait ~30–60 seconds.

**Expected in Dashboard:**
- "WinRM brute force" / "Windows logon failure" alerts (rule 60122)
- After ~5–6 failed attempts → Active Response alert
- Windows Firewall block is added automatically

**Verify the block on Windows:**
```cmd
netsh advfirewall firewall show rule name=all | find "Wazuh"
```

---

## FR-SOC-07 — Malware Detection

### Linux (Metasploitable3) — EICAR Signature Test

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
```

→ Wazuh detects via **rootcheck + FIM** → "Potential malware / suspicious file" alert in Dashboard.

---

### Windows — VirusTotal Integration (Pro Method, FR-SOC-07 High Level)

1. Get a free API key from [virustotal.com](https://www.virustotal.com/)
2. Add to Manager's `ossec.conf`:

```xml
<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

3. Drop the EICAR test file on Windows (Command Prompt as Administrator):

```cmd
echo X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > C:\Windows\System32\eicar.com
```

**How it works:** FIM detects the new file → computes hash → sends to VirusTotal API → triggers **Level 12** alert.

**Confirmed result (lab output):**
```
Apr 11, 2026 @ 23:28:07.434 | VirusTotal: Alert - c:\windows\system32\virus.exe - 5 engines detected this file | Level 12 | Rule 87105
Apr 11, 2026 @ 23:28:05.717 | File added to the system.
```

---

## FR-SOC-08 — User Behavior Analytics / Anomaly Detection

### Linux (Metasploitable3)

```bash
ssh wronguser@127.0.0.1   # enter wrong password 4 times
sudo -u dirmngr whoami    # executes command as user dirmngr (privilege use)
```

**Expected alerts:**
```
syslog: User missed the password more than one time
Privilege Escalation, Defense Evasion | Successful sudo executed.
```

---

### Windows

```cmd
net user testuser p@ssw0rd123 /add
net localgroup Administrators testuser /add
```

Then from **Kali**, attempt a few failed logons against Windows.

**Expected alerts:**
- "User created"
- "Privilege escalation"
- "Multiple failed logons"

---

## FR-SOC-05 — Incident Reporting

In the Wazuh Dashboard:

1. Go to **Security Events**
2. Filter by Agent (Kali, Metasploitable3, or Windows)
3. Click the three dots → **Export** → choose **PDF** or **CSV**

You get a full timeline with IoCs (Who, What, When, Where) ready for documentation.

---

## FR-SOC-03 — Severity Classification

Covered automatically by Wazuh rules. Color coding in Dashboard:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🔵 Low / Info

No manual config needed — validated by observing alert colors during attack tests.

---

## ✅ Final Verification Checklist

Go to **Dashboard → Security Events** and filter by each agent.

| Requirement | Test Method | Expected Alert |
|---|---|---|
| **FR-SOC-01** | Agents send logs | All 4 agents Active |
| **FR-SOC-02** | `hydra` SSH + RDP brute force | SSH/WinRM brute force alerts |
| **FR-SOC-03** | All tests above | Color-coded severity tags |
| **FR-SOC-04** | Auto-block after brute force | Active Response alert + iptables/netsh rule |
| **FR-SOC-05** | Export from Dashboard | PDF/CSV with timeline + IoCs |
| **FR-SOC-06** | `touch /etc/hacked-by-taher` + `test-hacked.txt` | FIM High alert |
| **FR-SOC-07** | EICAR drop + VirusTotal | Level 12 malware alert |
| **FR-SOC-08** | Wrong SSH logins + `net user` + `sudo -u` | Anomaly / privilege escalation alert |

Take **one screenshot per row** for your documentation.

---

## 📚 Concept Reference

**FIM (File Integrity Monitoring)**  
Watches `/etc`, `/boot`, `/usr/bin`, `System32` for any modification. `realtime="yes"` fires the alert the instant a file is saved. `report_changes="yes"` shows the exact diff (which line was added/deleted).

**Active Response**  
Turns Wazuh from passive observer into active defender. Links an alert (rule 5763 SSH brute / rule 60122 WinRM brute) to a script (`firewall-drop` on Linux / `netsh-win` on Windows) that blocks the attacker's IP automatically.

**EICAR Test**  
A universal harmless string that every security tool is programmed to flag. If Wazuh FIM + VirusTotal sees it → Level 12 alert proves FR-SOC-07 is working.

**User Behavior Anomaly**  
Failed logins + privilege escalation commands = FR-SOC-08 proof. The 96 failed logins were the anomaly test.

**Reports**  
Dashboard → Security Events → Export PDF/CSV = formal evidence with Who/What/When/Where for FR-SOC-05.


## 📁 Repository Structure

```

soc/

├── config/
│ └── wazuh_cluster/
│    └── wazuh_manager.conf
├── ossec-agent-configs/
│ ├── linux_ossec.conf (/var/ossec/etc/ossec.conf)
│ └── windows_ossec.conf (C:\Program Files (x86)\ossec-agent\ossec.conf)
├── WORKFLOW.md
└── README.md

```


### `config/wazuh_cluster/wazuh_manager.conf`
The Wazuh Manager configuration file. Contains all SOC-specific additions:
- **Active Response** block for SSH brute-force (rule 5763) — automatically drops the attacker IP via `iptables` on the Linux endpoint for 10 minutes
- **Active Response** block for WinRM/RDP brute-force (rule 60122) — automatically blocks via `netsh` on the Windows endpoint for 2 minutes
- **VirusTotal integration** — FIM triggers a hash lookup on every new file dropped in monitored directories, generating a Level 12 alert if detected
- **Active response log** localfile block for audit trail

### `ossec-agent-configs/linux_ossec.conf`
The agent-side configuration deployed on both **Metasploitable3** and **Kali**. Key addition inside `<syscheck>`:
- Realtime FIM watching `/etc`, `/boot`, `/usr/bin`, `/tmp` with full diff reporting

### `ossec-agent-configs/windows_ossec.conf`
The agent-side configuration deployed on **Windows Server 2012**. Key additions inside `<syscheck>`:
- Realtime FIM watching `C:\Windows\System32` and `C:\Windows\SysWOW64`
- Ignore rules for `.log`, `.tmp`, `.jrs` extensions and `certlog`/`LogFiles` directories to suppress false positives

### `WORKFLOW.md`
Full operational runbook covering: credentials, network map, manager start/stop/crash recovery, agent installation for all 3 endpoints, and step-by-step proof of every requirement FR-SOC-01 through FR-SOC-08.

