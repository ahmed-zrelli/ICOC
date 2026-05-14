"""
FR-AI-04: Real-time risk updates (<30s latency) via SSE broadcast.
FR-AI-05: Threat Intelligence Feed Integration.
FR-AI-06: Predictive Incident Analytics.
FR-AI-07: Automated Response Recommendations.
"""

import asyncio
import json
import datetime
import os
import aiohttp
from typing import AsyncGenerator, List, Optional
from config import config

VT_KEY  = config.VIRUSTOTAL_API_KEY
NVD_KEY = config.NVD_API_KEY
_LAB_OFFLINE = config.LAB_OFFLINE_MODE


async def risk_event_stream(risk_fn) -> AsyncGenerator[str, None]:
    """Server-Sent Events generator — pushes risk score every 15s."""
    while True:
        # Assuming risk_fn is async or wrapped properly
        if asyncio.iscoroutinefunction(risk_fn):
            score = await risk_fn()
        else:
            score = risk_fn()
        yield f"data: {json.dumps(score)}\n\n"
        await asyncio.sleep(15)


# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-05 — Threat Intelligence Feed
# ─────────────────────────────────────────────────────────────────────────────

STATIC_INTEL = [
    {
        "id": "TI-IOC-001", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2024-6387", "severity": "Critical",
        "description": "OpenSSH RegreSSHion — race condition in SIGALRM handler allows "
                       "unauthenticated RCE as root on glibc Linux.",
        "published": "2024-07-01T00:00:00Z",
        "tags": ["rce", "ssh", "linux", "unauthenticated", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 8.1,
    },
    {
        "id": "TI-IOC-002", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2023-38408", "severity": "Critical",
        "description": "OpenSSH ssh-agent remote code execution — malicious agent forwarding allows RCE.",
        "published": "2023-07-19T00:00:00Z",
        "tags": ["rce", "ssh", "agent-forwarding", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 9.8,
    },
    {
        "id": "TI-IOC-003", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2014-6271", "severity": "Critical",
        "description": "Shellshock — bash environment variable injection allows unauthenticated RCE.",
        "published": "2014-09-24T00:00:00Z",
        "tags": ["rce", "bash", "cgi", "unauthenticated", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 9.8,
    },
    {
        "id": "TI-IOC-004", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2016-5195", "severity": "High",
        "description": "Dirty COW — race condition in Linux kernel copy-on-write allows local privilege escalation.",
        "published": "2016-10-19T00:00:00Z",
        "tags": ["lpe", "kernel", "linux", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 7.8,
    },
    {
        "id": "TI-IOC-005", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2022-2068", "severity": "Critical",
        "description": "OpenSSL c_rehash command injection — allows RCE.",
        "published": "2022-06-21T00:00:00Z",
        "tags": ["rce", "openssl", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 9.8,
    },
    {
        "id": "TI-IOC-006", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2023-4911", "severity": "High",
        "description": "Looney Tunables — glibc dynamic linker buffer overflow allows local privilege escalation.",
        "published": "2023-10-03T00:00:00Z",
        "tags": ["lpe", "linux", "glibc", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 7.8,
    },
    {
        "id": "TI-IOC-007", "source": "CISA KEV", "type": "cve",
        "indicator": "CVE-2021-3156", "severity": "High",
        "description": "sudo Heap Overflow (Baron Samedit) — allows any local user to gain root.",
        "published": "2021-01-26T00:00:00Z",
        "tags": ["lpe", "sudo", "linux", "actively-exploited"],
        "cisa_kev": True, "cvss_score": 7.8,
    },
    {
        "id": "TI-IOC-011", "source": "AbuseIPDB / VirusTotal", "type": "ip",
        "indicator": "45.33.32.156",
        "severity": "Medium",
        "description": "Known C2 infrastructure — flagged across Mirai botnet variants.",
        "published": "2024-02-01T00:00:00Z",
        "tags": ["c2", "botnet", "ioc"],
        "cisa_kev": False, "cvss_score": None,
    },
]

async def _fetch_nvd_recent_critical(max_results: int = 6) -> list:
    """Fetch recent critical CVEs from NVD API v2."""
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

        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, headers=headers, timeout=10,
            ) as resp:
                if resp.status != 200:
                    return []
                
                data = await resp.json()
                items = []
                for vuln in data.get("vulnerabilities", []):
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
                return items
    except Exception as exc:
        print(f"[FR-AI-05] NVD fetch error: {exc}")
        return []


async def _fetch_cisa_kev_live(max_results: int = 10) -> list:
    """Fetch latest entries from CISA KEV catalog."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=10, headers={"Accept": "application/json"}
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                vulns = data.get("vulnerabilities", [])
                vulns = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)
                items = []
                known_ids = {item["indicator"] for item in STATIC_INTEL if item["type"] == "cve"}
                for v in vulns:
                    cve_id = v.get("cveID", "")
                    if not cve_id or cve_id in known_ids:
                        continue
                    items.append({
                        "id":          f"TI-KEV-{cve_id}",
                        "source":      "CISA KEV (live)",
                        "type":        "cve",
                        "indicator":   cve_id,
                        "severity":    "Critical",
                        "description": f"{cve_id} — {v.get('vulnerabilityName', '')}. Vendor: {v.get('vendorProject', '')}.",
                        "published":   v.get("dateAdded", "") + "T00:00:00Z",
                        "tags":        ["cisa-kev", "actively-exploited"],
                        "cisa_kev":    True,
                    })
                    if len(items) >= max_results:
                        break
                return items
    except Exception as exc:
        print(f"[FR-AI-05] CISA KEV fetch error: {exc}")
        return []


async def get_threat_intel_feed(limit: int = 20) -> list:
    """FR-AI-05: Return threat intelligence feed."""
    feed = [dict(item) for item in STATIC_INTEL]

    if VT_KEY:
        from voc.virustotal_client import check_ip
        for item in feed:
            if item["type"] == "ip":
                try:
                    vt = await check_ip(item["indicator"])
                    item["vt_malicious"] = vt.get("malicious", 0)
                    item["vt_country"]   = vt.get("country", "unknown")
                    item["vt_live"]      = True
                except Exception:
                    item["vt_live"] = False

    if _LAB_OFFLINE:
        return feed[:limit]
    
    cisa_live = await _fetch_cisa_kev_live(max_results=12)
    nvd_live = await _fetch_nvd_recent_critical(max_results=8)
    live_combined = cisa_live + nvd_live

    if live_combined:
        return live_combined[:limit]
    
    return feed[:limit]


# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-06 — Predictive Incident Analytics
# ─────────────────────────────────────────────────────────────────────────────

def predict_incident_probability(patch_records=None, soc_alerts: int = 0) -> dict:
    """FR-AI-06: Estimate probability of a security incident in next 24h."""
    from voc.fr_voc_03_patch_tracking import load_patch_db

    if patch_records is None:
        patch_records = load_patch_db()

    critical_missing = [r for r in patch_records
                        if r.severity == "Critical" and r.status == "missing"]
    high_missing     = [r for r in patch_records
                        if r.severity == "High" and r.status == "missing"]

    # Weighted formula (0-100%)
    # Base: Each critical unpatched CVE adds 15%, High adds 5%
    # SOC: Each alert in last 5min adds 10%
    prob = (len(critical_missing) * 15) + (len(high_missing) * 5) + (soc_alerts * 10)
    prob = min(prob, 99.0) # never 100% until it happens
    prob = max(prob, 1.0)  # always at least 1% base risk

    level = "Critical" if prob > 80 else "High" if prob > 50 else "Medium" if prob > 20 else "Low"
    
    return {
        "probability": round(prob, 1),
        "level": level,
        "factors": {
            "critical_vulnerabilities": len(critical_missing),
            "high_vulnerabilities": len(high_missing),
            "active_soc_alerts": soc_alerts
        },
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }


# ─────────────────────────────────────────────────────────────────────────────
# FR-AI-07 — Response Recommendations
# ─────────────────────────────────────────────────────────────────────────────

def generate_recommendations(soc_alerts: int = 0) -> List[dict]:
    """FR-AI-07: Get automated response recommendations."""
    recs = []
    
    if soc_alerts > 10:
        recs.append({
            "id": "REC-001",
            "priority": "Critical",
            "action": "Enable Aggressive Rate Limiting",
            "description": "High alert volume detected. Enable temporary WAF shielding."
        })
    
    from voc.fr_voc_03_patch_tracking import load_patch_db
    patches = load_patch_db()
    critical_missing = [p for p in patches if p.severity == "Critical" and p.status == "missing"]
    
    if critical_missing:
        recs.append({
            "id": "REC-002",
            "priority": "High",
            "action": f"Apply {len(critical_missing)} Critical Patches",
            "description": "Immediate patching required for critical CVEs."
        })
        
    if not recs:
        recs.append({
            "id": "REC-000",
            "priority": "Low",
            "action": "Routine Monitoring",
            "description": "System state stable. No urgent actions required."
        })
        
    return recs
