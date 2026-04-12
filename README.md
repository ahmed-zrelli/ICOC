# 🛡️ SOC Module

**Security Operations Center | Wazuh SIEM 4.8.0**

> Part of the [ICOC-Lite](../README.md) — Integrated Cyber Operations Center Project.  
> This branch covers the SOC domain exclusively, implementing all 8 SOC functional requirements defined in the project specification.

---

## Operational Runbook

All commands for starting, stopping, installing agents, running attack simulations, and validating each FR are documented in **[WorkflowW.md](./Workflow.md)**.

---

## What is This Branch?

This branch contains the full implementation of the **Security Operations Center (SOC)** component of ICOC-Lite. The SOC module is built on top of **Wazuh 4.8.0** deployed via Docker and is responsible for:

- Collecting and centralizing security logs from all lab endpoints
- Detecting attacks in real time and classifying them by severity
- Automatically blocking attacker IPs without human intervention
- Monitoring critical system files for unauthorized changes
- Detecting malware using both local analysis and VirusTotal
- Identifying abnormal user behavior and privilege abuse
- Generating exportable incident reports with full IoC timelines

---

## Lab Environment

| Machine          | OS                  | IP                | Role              |
| ---------------- | ------------------- | ----------------- | ----------------- |
| Wazuh Manager    | Ubuntu + Docker     | `192.168.100.10`  | SIEM core         |
| Windows Endpoint | Windows Server 2012 | `192.168.100.101` | Monitored target  |
| Linux Endpoint   | Metasploitable3     | `192.168.100.102` | Monitored target  |
| Attacker         | Kali Linux          | `192.168.100.200` | Attack simulation |

---

## Requirements Coverage

| ID        | Requirement                | How It's Met                                                       |
| --------- | -------------------------- | ------------------------------------------------------------------ |
| FR-SOC-01 | Centralized log collection | Wazuh agents deployed on all 4 endpoints, streaming to Manager     |
| FR-SOC-02 | Brute-force detection      | Rules 5763 (SSH) and 60122 (WinRM/RDP) fire after 5 failures       |
| FR-SOC-03 | Severity classification    | Native Wazuh rule levels mapped to Critical / High / Medium / Low  |
| FR-SOC-04 | Automated IP blocking      | Active Response: `firewall-drop` on Linux, `netsh-win` on Windows  |
| FR-SOC-05 | Incident reporting         | Dashboard PDF/CSV export with timeline and IoCs                    |
| FR-SOC-06 | File Integrity Monitoring  | Realtime FIM on `/etc`, `/boot`, `System32`, `SysWOW64`            |
| FR-SOC-07 | Malware detection          | EICAR test + VirusTotal API integration (Level 12 alert confirmed) |
| FR-SOC-08 | User behavior analytics    | Failed login anomaly and privilege escalation detection            |

---

## 📁 Branch Structure

```
soc/
├── config/
│   └── wazuh_cluster/
│       └── wazuh_manager.conf   ← Active Response + VirusTotal config
├── ossec-agent-configs/
│   ├── linux_ossec.conf         ← Agent config file for Kali & Metasploitable3
│   └── windows_ossec.conf       ← Agent config file for Windows Server 2012
├── Workflow.md                  ← Full operational runbook
└── README.md                    ← This file
```

---

## Stack

| Component       | Purpose                                 | Version      |
| --------------- | --------------------------------------- | ------------ |
| Wazuh Manager   | SIEM core, rule engine, Active Response | 4.8.0        |
| Wazuh Indexer   | Elasticsearch backend, event storage    | 4.8.0        |
| Wazuh Dashboard | Web UI, alerting, reporting             | 4.8.0        |
| Docker Compose  | Container runtime on Manager VM         | —            |
| VirusTotal API  | External malware hash lookup            | v3 free tier |

---

## Key Configurations

### Active Response (Manager)

Two auto-blocking rules configured in `wazuh_manager.conf`:

- **Rule 5763** → SSH brute force → `firewall-drop` → blocks attacker on Metasploitable3 for 10 min
- **Rule 60122** → WinRM/RDP brute force → `netsh-win` → blocks attacker on Windows for 2 min

### File Integrity Monitoring

- **Linux:** realtime monitoring of `/etc`, `/boot`, `/usr/bin`, `/tmp` with diff reporting
- **Windows:** realtime monitoring of `System32` and `SysWOW64` with noise filters for `.log`, `.tmp`, `.jrs` files

### VirusTotal Integration

FIM detects a new file → computes hash → sends to VirusTotal API → fires **Level 12** alert if flagged.

---

> Crafted with ❤️ by Med Taher Borgi

---

---
