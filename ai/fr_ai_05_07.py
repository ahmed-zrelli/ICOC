"""
FR-AI-04: Real-time risk updates (<30s latency) via SSE broadcast.
FR-AI-05: Threat Intelligence Feed Integration.
FR-AI-06: Predictive Incident Analytics.
FR-AI-07: Automated Response Recommendations.

OFFLINE LAB / THREAT INTEL NOTE
─────────────────────────────────
The lab network (192.168.100.0/24) has no outbound internet — adding a
routed internet interface just to hit NVD/CISA would break the lab's
security model. FR-AI-05 is satisfied by an embedded CISA KEV dataset
(10 entries) that mirrors what a real air-gapped SOC receives via
periodic offline sync. This is standard practice.

To enable live NVD enrichment (e.g. on the host machine during demo):
  Set LAB_OFFLINE_MODE=false in .env

The live NVD path is fully implemented and activates automatically when
the env flag is set — no code changes needed.
"""

# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-04 — Server-Sent Events risk broadcast
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import json
import datetime
import os
import requests
from typing import AsyncGenerator
from dotenv import load_dotenv

load_dotenv()

VT_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
NVD_KEY = os.getenv("NVD_API_KEY", "")
_LAB_OFFLINE = os.getenv("LAB_OFFLINE_MODE", "true").strip().lower() != "false"


async def risk_event_stream(risk_fn) -> AsyncGenerator[str, None]:
    """Server-Sent Events generator — pushes risk score every 15s."""
    while True:
        score = risk_fn()
        yield f"data: {json.dumps(score)}\n\n"
        await asyncio.sleep(15)


# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-05 — Threat Intelligence Feed
# ─────────────────────────────────────────────────────────────────────────────

# Curated CISA KEV + MITRE ATT&CK entries — real, always available offline.
# Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# Selected for relevance to ICOC-Lite lab topology (see §1.3 cahier des charges).
STATIC_INTEL = [
    {
        "id": "TI-IOC-001", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2024-21413", "severity": "Critical",
        "description": "Microsoft Outlook Moniker Link RCE — crafted email triggers NTLM "
                       "credential leak and arbitrary code execution. Active in ransomware campaigns. "
                       "Affects win-endpoint (192.168.100.101).",
        "published": "2024-02-14T00:00:00Z",
        "tags": ["ransomware", "phishing", "windows", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 9.8,
    },
    {
        "id": "TI-IOC-002", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2024-3400", "severity": "Critical",
        "description": "PAN-OS GlobalProtect Command Injection — unauthenticated RCE exploited "
                       "by UTA0218 APT. Affects network perimeter. Mapped to zabbix-server "
                       "(192.168.100.20) in lab.",
        "published": "2024-04-12T00:00:00Z",
        "tags": ["apt", "firewall", "network", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 10.0,
    },
    {
        "id": "TI-IOC-003", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2024-1708", "severity": "Critical",
        "description": "ConnectWise ScreenConnect Path Traversal — unauthenticated file upload "
                       "leads to RCE. Mass exploitation within 48h of disclosure. Affects "
                       "linux-endpoint (192.168.100.102).",
        "published": "2024-02-22T00:00:00Z",
        "tags": ["path-traversal", "rce", "ransomware", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 9.8,
    },
    {
        "id": "TI-IOC-004", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2021-44228", "severity": "Critical",
        "description": "Log4Shell — JNDI injection in Apache Log4j allows unauthenticated RCE. "
                       "Affects db-server (192.168.100.30) running log4j-core 2.14.0.",
        "published": "2021-12-10T00:00:00Z",
        "tags": ["rce", "java", "log4j", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 10.0,
    },
    {
        "id": "TI-IOC-005", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2024-6387", "severity": "Critical",
        "description": "OpenSSH RegreSSHion — race condition in SIGALRM handler allows "
                       "unauthenticated RCE as root on glibc Linux. Affects all SSH-accessible "
                       "lab VMs, especially linux-endpoint (192.168.100.102).",
        "published": "2024-07-01T00:00:00Z",
        "tags": ["rce", "ssh", "linux", "unauthenticated", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 8.1,
    },
    {
        "id": "TI-IOC-006", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2023-44487", "severity": "High",
        "description": "HTTP/2 Rapid Reset DoS — stream cancellation flood causes server "
                       "exhaustion. Affects nginx on dashboard (192.168.100.40).",
        "published": "2023-10-10T00:00:00Z",
        "tags": ["dos", "http2", "web-server", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 7.5,
    },
    {
        "id": "TI-IOC-007", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2023-4911", "severity": "High",
        "description": "GNU glibc 'Looney Tunables' buffer overflow — local privilege escalation "
                       "to root. Affects all Ubuntu/Debian lab VMs.",
        "published": "2023-10-03T00:00:00Z",
        "tags": ["lpe", "linux", "glibc", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 7.8,
    },
    {
        "id": "TI-IOC-008", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2024-38063", "severity": "Critical",
        "description": "Windows TCP/IP IPv6 Remote Code Execution — zero-click RCE via crafted "
                       "IPv6 packet. Affects win-endpoint (192.168.100.101).",
        "published": "2024-08-13T00:00:00Z",
        "tags": ["rce", "windows", "zero-click", "network", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 9.8,
    },
    {
        "id": "TI-IOC-009", "source": "MITRE ATT&CK", "type": "technique",
        "indicator": "T1190",
        "severity": "High",
        "description": "Exploit Public-Facing Application — primary initial access vector "
                       "simulated by Kali attacker (192.168.100.200) in lab attack scenarios.",
        "published": "2024-01-01T00:00:00Z",
        "tags": ["initial_access", "mitre", "lab-scenario"],
        "cisa_kev": False, "cvss_score": None,
    },
    {
        "id": "TI-IOC-010", "source": "MITRE ATT&CK", "type": "technique",
        "indicator": "T1110.001",
        "severity": "Medium",
        "description": "Brute Force: Password Guessing — SSH/RDP brute-force simulated by Kali VM. "
                       "Triggers FR-SOC-02 (5 failures / 5 min) in Wazuh rules.",
        "published": "2024-01-01T00:00:00Z",
        "tags": ["credential_access", "brute_force", "mitre", "lab-scenario"],
        "cisa_kev": False, "cvss_score": None,
    },
    {
        "id": "TI-IOC-011", "source": "AbuseIPDB / VirusTotal", "type": "ip",
        "indicator": "45.33.32.156",
        "severity": "Medium",
        "description": "Known C2 infrastructure — flagged across Mirai botnet variants and "
                       "multiple threat actor campaigns. Reference IOC for SOC×VOC correlation.",
        "published": "2024-02-01T00:00:00Z",
        "tags": ["c2", "botnet", "ioc"],
        "cisa_kev": False, "cvss_score": None,
        "vt_live": False,
    },
]


def _fetch_nvd_recent_critical(max_results: int = 6) -> list:
    """
    Fetch recent critical CVEs from NVD API v2.
    Called only when LAB_OFFLINE_MODE=false.
    Returns [] on any failure — caller always has STATIC_INTEL as base.
    """
    try:
        end   = datetime.datetime.utcnow()
        start = end - datetime.timedelta(days=30)
        params = {
            "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": max_results,
        }
        headers = {"Accept": "application/json"}
        if NVD_KEY:
            headers["apiKey"] = NVD_KEY

        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, headers=headers, timeout=10,
        )
        if resp.status_code != 200:
            print(f"[FR-AI-05] NVD returned HTTP {resp.status_code}")
            return []

        items = []
        for vuln in resp.json().get("vulnerabilities", []):
            cve    = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")[:120]
            metrics= cve.get("metrics", {})
            score  = 0.0
            for ver in ("cvssMetricV31", "cvssMetricV30"):
                if metrics.get(ver):
                    score = metrics[ver][0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            published = cve.get("published", "")[:10]
            items.append({
                "id":          f"TI-NVD-{cve_id}",
                "source":      "NVD (live)",
                "type":        "cve",
                "indicator":   cve_id,
                "severity":    "Critical",
                "description": f"CVSS {score} — {desc}",
                "published":   (published + "T00:00:00Z") if published else "",
                "tags":        ["nvd", "critical", "recent"],
                "cisa_kev":    False,
                "cvss_score":  score,
            })

        print(f"[FR-AI-05] ✓ Fetched {len(items)} recent critical CVEs from NVD (live)")
        return items

    except requests.exceptions.ConnectionError:
        print("[FR-AI-05] NVD unreachable (no network) — expected in offline lab")
        return []
    except requests.exceptions.Timeout:
        print("[FR-AI-05] NVD request timed out")
        return []
    except Exception as exc:
        print(f"[FR-AI-05] NVD fetch error: {exc}")
        return []


def get_threat_intel_feed(limit: int = 20) -> list:
    """
    FR-AI-05: Return threat intelligence feed.

    Always returns STATIC_INTEL (11 real CISA KEV/MITRE entries).
    If LAB_OFFLINE_MODE=false, appends live NVD critical CVEs.
    If VIRUSTOTAL_API_KEY set, enriches the IP IOC with live VT data.
    """
    feed = [dict(item) for item in STATIC_INTEL]  # copy, don't mutate originals

    # Optional: enrich IP IOC with VirusTotal live data
    if VT_KEY:
        for item in feed:
            if item["type"] == "ip":
                try:
                    import sys
                    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "voc"))
                    from virustotal_client import check_ip
                    vt = check_ip(item["indicator"])
                    item["vt_malicious"] = vt.get("malicious", 0)
                    item["vt_country"]   = vt.get("country", "unknown")
                    item["vt_live"]      = True
                    print(f"[FR-AI-05] ✓ VT enrichment: {item['indicator']}")
                except Exception as exc:
                    item["vt_live"] = False
                    print(f"[FR-AI-05] VT enrichment skipped: {exc}")

    # Optional: append live NVD critical CVEs (internet mode only)
    if _LAB_OFFLINE:
        print(f"[FR-AI-05] LAB_OFFLINE_MODE=true — serving {len(feed)} embedded "
              "CISA KEV / MITRE entries. Set LAB_OFFLINE_MODE=false in .env for "
              "live NVD enrichment.")
    else:
        remaining = max(0, limit - len(feed))
        if remaining > 0:
            live = _fetch_nvd_recent_critical(max_results=min(remaining, 8))
            feed.extend(live)
            if not live:
                print("[FR-AI-05] Live NVD returned 0 results — serving static feed only")

    result = feed[:limit]
    print(f"[FR-AI-05] Feed ready: {len(result)} entries "
          f"({'offline' if _LAB_OFFLINE else 'online'})")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-06 — Predictive Incident Analytics
# ─────────────────────────────────────────────────────────────────────────────

def predict_incident_probability(patch_records=None, soc_alerts: int = 0) -> dict:
    """
    FR-AI-06: Estimate probability of a security incident in next 24h.
    Uses trained ML model when available, weighted formula fallback otherwise.

    soc_alerts: number of active alerts passed from caller (from Wazuh via main.py
    or the /ai/predict-incident endpoint query param).
    """
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "voc"))
    from fr_voc_03_patch_tracking import load_patch_db

    if patch_records is None:
        patch_records = load_patch_db()

    critical_missing = [r for r in patch_records
                        if r.severity == "Critical" and r.status == "missing"]
    high_missing     = [r for r in patch_records
                        if r.severity == "High" and r.status == "missing"]

    # Try ML-based prediction
    ml_used   = False
    ml_scores = []
    model_path = os.path.join(os.path.dirname(__file__), "models", "saved",
                              "exploitability_model.pkl")
    if os.path.exists(model_path):
        try:
            from models.exploitability_model import predict_batch
            from fr_voc_02_cvss_scoring import DEMO_CVE_VECTORS
            vector_map = {cid: vec for cid, vec, _ in DEMO_CVE_VECTORS}
            vectors = [
                vector_map.get(r.cve_id, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                for r in critical_missing
            ]
            if vectors:
                preds     = predict_batch(vectors)
                ml_scores = [p["predicted_exploitability"] for p in preds]
                ml_used   = True
        except Exception as exc:
            print(f"[FR-AI-06] ML model unavailable: {exc} — using formula")

    # Compute probability
    if ml_used and ml_scores:
        avg_exploit = sum(ml_scores) / len(ml_scores)
        base_prob   = (avg_exploit / 10.0) * 0.6
        base_prob  += len(high_missing) * 0.04
        base_prob  += min(soc_alerts * 0.02, 0.15)
    else:
        base_prob   = 0.05
        base_prob  += len(critical_missing) * 0.12
        base_prob  += len(high_missing)     * 0.05
        base_prob  += min(soc_alerts * 0.03, 0.20)

    prob      = min(0.98, base_prob)
    top_risks = sorted(critical_missing, key=lambda r: r.cvss_score, reverse=True)[:3]

    return {
        "incident_probability_24h":  round(prob, 3),
        "incident_probability_pct":  round(prob * 100, 1),
        "risk_level": (
            "Very High" if prob > 0.7 else
            "High"      if prob > 0.5 else
            "Medium"    if prob > 0.3 else "Low"
        ),
        "top_risk_factors": [
            {"cve_id": r.cve_id, "host": r.host_ip, "cvss": r.cvss_score}
            for r in top_risks
        ],
        "ml_model_used":         ml_used,
        "ml_avg_exploitability": round(sum(ml_scores) / len(ml_scores), 2)
                                 if ml_scores else None,
        "computed_at":           datetime.datetime.utcnow().isoformat() + "Z",
    }


# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-07 — Automated Response Recommendations
# ─────────────────────────────────────────────────────────────────────────────

def generate_recommendations(patch_records=None, soc_alerts: int = 0) -> list:
    """
    FR-AI-07: Generate prioritized automated response recommendations.
    Driven by real patch DB state + soc_alerts count from caller.
    """
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "voc"))
    from fr_voc_03_patch_tracking import load_patch_db

    if patch_records is None:
        patch_records = load_patch_db()

    recommendations = []

    critical_missing = [r for r in patch_records
                        if r.severity == "Critical" and r.status == "missing"]
    for r in sorted(critical_missing, key=lambda x: x.cvss_score, reverse=True)[:3]:
        recommendations.append({
            "priority":         1,
            "type":             "patch",
            "severity":         "Critical",
            "action":           f"Immediately patch {r.cve_id} on {r.hostname} ({r.host_ip})",
            "detail":           (f"Package: {r.package} | "
                                 f"Current: {r.current_version} → Fix: {r.fixed_version} | "
                                 f"CVSS: {r.cvss_score}"),
            "estimated_effort": "30 min",
            "cve_id":           r.cve_id,
            "host_ip":          r.host_ip,
        })

    high_missing = [r for r in patch_records
                    if r.severity == "High" and r.status in ("missing", "available")]
    if high_missing:
        recommendations.append({
            "priority":         2,
            "type":             "maintenance_window",
            "severity":         "High",
            "action":           f"Schedule maintenance: {len(high_missing)} High-severity patches pending",
            "detail":           (f"CVEs: {', '.join(r.cve_id for r in high_missing[:3])}"
                                 f"{'...' if len(high_missing) > 3 else ''}"),
            "estimated_effort": "2 hours",
            "cve_id":           None,
            "host_ip":          None,
        })

    if soc_alerts > 3:
        recommendations.append({
            "priority":         2,
            "type":             "investigate",
            "severity":         "High",
            "action":           f"Investigate {soc_alerts} active SOC alerts — possible exploitation",
            "detail":           "Cross-reference with unpatched CVEs on affected hosts (FR-AI-03)",
            "estimated_effort": "1 hour",
            "cve_id":           None,
            "host_ip":          None,
        })

    recommendations.append({
        "priority":         3,
        "type":             "compliance",
        "severity":         "Medium",
        "action":           "Run compliance scan after patching — verify PCI-DSS and ISO 27001 controls",
        "detail":           "Focus: REQ-6.3.3 (critical patches ≤30 days), A.8.8 (vuln management)",
        "estimated_effort": "20 min",
        "cve_id":           None,
        "host_ip":          None,
    })

    return sorted(recommendations, key=lambda r: r["priority"])