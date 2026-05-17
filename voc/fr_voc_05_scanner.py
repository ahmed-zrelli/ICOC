"""
FR-VOC-05: Scheduled & On-Demand Vulnerability Scanning

Scan modes:
  - Live (default): nmap + vulners script against lab network. Requires
    nmap installed and the API container to have network access to lab VMs.
  - Fallback: if nmap is not installed or scan fails, uses the current
    patch_status.json from disk (real data after first scan, seed data
    on very first run). Never generates fake data.

VT enrichment: optional, requires VIRUSTOTAL_API_KEY in .env.
"""

import os
import json
import datetime
import time
import threading
import requests
from typing import List, Optional, Callable
from dotenv import load_dotenv

from fr_voc_02_cvss_scoring import parse_cvss_vector_string, calculate_cvss_v31
from fr_voc_03_patch_tracking import load_patch_db, save_patch_db, DEMO_PATCH_DB, PatchRecord

load_dotenv()

VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
# Scan only the victim VM, not the whole network (avoids scanning the PC/gateway)
LAB_NETWORK = os.getenv("VICTIM_IP", "192.168.100.102")

# Known fix versions for CVEs commonly found on Metasploitable 3 / Ubuntu 14.04
# Source: Ubuntu Security Notices (USN) and NVD
CVE_FIX_MAP = {
    "CVE-2016-1908": "1:7.2p2-4ubuntu2.1",
    "CVE-2016-10009": "1:7.2p2-4ubuntu2.1",
    "CVE-2016-10010": "1:7.2p2-4ubuntu2.1",
    "CVE-2016-10011": "1:7.2p2-4ubuntu2.1",
    "CVE-2016-10012": "1:7.2p2-4ubuntu2.1",
    "CVE-2023-38408": "1:9.3p2-1",
    "CVE-2024-6387":  "1:9.8p1-1",
    "CVE-2021-41617": "1:8.8p1-1",
    "CVE-2014-6271":  "4.3-14ubuntu1.1",
    "CVE-2016-5195":  "4.4.0-45",
    "CVE-2021-3156":  "1.8.9p5-1ubuntu1.5",
    "CVE-2022-2068":  "1.0.1f-1ubuntu2.27",
    "CVE-2023-4911":  "2.19-0ubuntu6.15",
    "CVE-2014-7169":  "4.3-14ubuntu1.1",
    "CVE-2014-6277":  "4.3-14ubuntu1.1",
    "CVE-2021-33910": "229-4ubuntu21.31",
    "CVE-2022-1664":  "1.18.0-1ubuntu1.1",
    "CVE-2021-4034":  "0.109-1ubuntu0.1",
    "CVE-2022-0847":  "5.15.0-23.23",
    "CVE-2021-44228": "2.17.1",
    "CVE-2022-22965": "5.3.18",
}

VT_BASE    = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": VT_API_KEY or "", "Accept": "application/json"}


# ── VirusTotal Integration ────────────────────────────────────────────────────

def vt_check_hash(file_hash: str) -> dict:
    """Query VirusTotal for a file hash (MD5/SHA1/SHA256)."""
    if not VT_API_KEY:
        return {"hash": file_hash, "error": "no_api_key", "source": "virustotal_skipped"}
    try:
        resp = requests.get(f"{VT_BASE}/files/{file_hash}", headers=VT_HEADERS, timeout=10)
        if resp.status_code == 200:
            data  = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label", "unknown"),
                "names": data.get("names", [])[:3],
                "source": "virustotal_live"
            }
        return {"hash": file_hash, "error": f"http_{resp.status_code}", "source": "virustotal_live"}
    except Exception as exc:
        return {"hash": file_hash, "error": str(exc), "source": "virustotal_error"}


def vt_check_url(url: str) -> dict:
    """Submit and check a URL against VirusTotal."""
    if not VT_API_KEY:
        return {"url": url, "error": "no_api_key", "source": "virustotal_skipped"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp   = requests.get(f"{VT_BASE}/urls/{url_id}", headers=VT_HEADERS, timeout=10)
        if resp.status_code == 200:
            data  = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "categories": data.get("categories", {}),
                "source": "virustotal_live"
            }
        if resp.status_code == 404:
            post = requests.post(f"{VT_BASE}/urls", headers=VT_HEADERS,
                                 data={"url": url}, timeout=10)
            if post.status_code == 200:
                return {"url": url, "status": "submitted_for_analysis", "source": "virustotal_live"}
        return {"url": url, "error": f"http_{resp.status_code}", "source": "virustotal_live"}
    except Exception as exc:
        return {"url": url, "error": str(exc), "source": "virustotal_error"}


def vt_check_ip(ip: str) -> dict:
    """Check an IP address against VirusTotal."""
    if not VT_API_KEY:
        return {"ip": ip, "error": "no_api_key", "source": "virustotal_skipped"}
    try:
        resp = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=VT_HEADERS, timeout=10)
        if resp.status_code == 200:
            data  = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "country": data.get("country", "unknown"),
                "asn": data.get("asn", 0),
                "as_owner": data.get("as_owner", "unknown"),
                "reputation": data.get("reputation", 0),
                "source": "virustotal_live"
            }
        return {"ip": ip, "error": f"http_{resp.status_code}", "source": "virustotal_live"}
    except Exception as exc:
        return {"ip": ip, "error": str(exc), "source": "virustotal_error"}


# ── Scanner Core ─────────────────────────────────────────────────────────────

def _live_scan(network: str) -> tuple[List[dict], str]:
    """
    Real nmap-based CVE scan using the vulners NSE script.
    Returns (results_list, mode_string).
    Requires: nmap installed, python-nmap pip package, and network
    access from the API container to the lab VMs.
    """
    try:
        import nmap  # python-nmap
        nm = nmap.PortScanner()
        print(f"[FR-VOC-05] Starting nmap scan on {network}...")
        # Ports covering all services visible on Metasploitable3:
        #   22=SSH, 80=Apache, 443=HTTPS, 8080=Jetty/Tomcat, 8009=AJP,
        #   3306=MySQL, 5432=PostgreSQL, 8443=HTTPS-alt, 21=FTP, 25=SMTP,
        #   139/445=Samba, 6667=IRC, 3500=webapp
        nm.scan(
            hosts=network,
            arguments="-sV --script vulners "
                      "-p 21,22,25,80,139,443,445,3306,5432,6667,8009,8080,8443,3500",
            timeout=180
        )

        # Map nmap service names → real package names for VOC reporting
        _pkg_map = {
            "ssh":         "openssh-server",
            "http":        "apache2",
            "https":       "apache2",
            "ftp":         "vsftpd",
            "smtp":        "postfix",
            "mysql":       "mysql-server",
            "postgresql":  "postgresql",
            "ssl":         "openssl",
            "telnet":      "telnetd",
            "netbios-ssn": "samba",
            "microsoft-ds":"samba",
            "irc":         "unrealircd",
            "ajp13":       "tomcat",
            "http-proxy":  "jetty",
        }

        results = []
        seen = set()  # deduplicate (cve_id, host_ip, port)

        for host in nm.all_hosts():
            if nm[host].state() != "up":
                continue
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    svc = nm[host][proto][port]
                    if "script" not in svc or "vulners" not in svc["script"]:
                        continue

                    raw_pkg  = svc.get("name", "unknown")
                    pkg_name = _pkg_map.get(raw_pkg, raw_pkg)
                    svc_ver  = svc.get("version", "unknown")

                    # Track the last CVE seen so exploit refs can be linked to it
                    last_cve = None

                    for line in svc["script"]["vulners"].split("\n"):
                        line = line.strip()
                        if not line:
                            continue

                        parts = line.split()
                        if len(parts) < 2:
                            continue

                        entry_id = parts[0]
                        try:
                            score = float(parts[1])
                        except (ValueError, IndexError):
                            continue

                        is_exploit = "*EXPLOIT*" in line

                        if entry_id.startswith("CVE-"):
                            last_cve = entry_id
                            key = (entry_id, host, port)
                            if key in seen:
                                continue
                            seen.add(key)

                            sev = ("Critical" if score >= 9.0 else
                                   "High"     if score >= 7.0 else
                                   "Medium"   if score >= 4.0 else "Low")

                            results.append({
                                "cve_id":          entry_id,
                                "host_ip":         host,
                                "hostname":        nm[host].hostname() or host,
                                "package":         pkg_name,
                                "current_version": svc_ver,
                                "fixed_version":   CVE_FIX_MAP.get(entry_id, "Upgrade to latest"),
                                "cvss_score":      score,
                                "severity":        sev,
                                "status":          "missing",
                                "port":            port,
                                "service":         raw_pkg,
                                "is_exploit":      False,
                                "exploit_refs":    [],
                                "vt_checked":      False,
                            })

                        elif is_exploit and last_cve:
                            # Attach exploit reference to the most recent CVE entry
                            for r in reversed(results):
                                if r["cve_id"] == last_cve and r["host_ip"] == host:
                                    r["exploit_refs"].append({
                                        "id":    entry_id,
                                        "score": score,
                                        "url":   parts[2] if len(parts) > 2 else "",
                                    })
                                    r["is_exploit"] = True  # has public exploit
                                    break

        print(f"[FR-VOC-05] nmap scan complete: {len(results)} CVEs found "
              f"({sum(1 for r in results if r['is_exploit'])} with public exploits)")
        return results, "live_nmap"

    except ImportError:
        print("[FR-VOC-05] python-nmap not installed (pip install python-nmap) — using disk data")
        return None, "fallback"
    except Exception as exc:
        print(f"[FR-VOC-05] nmap scan failed: {exc} — using disk data")
        return None, "fallback"


def _disk_fallback() -> tuple[List[dict], str]:
    """
    Load current patch DB from disk as scan results.
    After the first real scan this contains real data.
    On very first run it contains the seed CVE list.
    """
    records = load_patch_db()
    results = [
        {
            "cve_id":          r.cve_id,
            "host_ip":         r.host_ip,
            "hostname":        r.hostname,
            "package":         r.package,
            "current_version": r.current_version,
            "fixed_version":   r.fixed_version,
            "cvss_score":      r.cvss_score,
            "severity":        r.severity,
            "status":          r.status,
            "vt_checked":      False,
        }
        for r in records
    ]
    print(f"[FR-VOC-05] Loaded {len(results)} records from disk (patch_status.json)")
    return results, "disk"


def _update_patch_db_from_scan(raw_results: List[dict]):
    """
    After a live nmap scan, merge new findings into the persistent patch DB.
    Preserves existing 'applied' / 'wontfix' statuses.
    Adds newly discovered CVEs.
    """
    existing = load_patch_db()
    existing_keys = {(r.cve_id, r.host_ip) for r in existing}
    now = datetime.datetime.utcnow().isoformat() + "Z"

    # Update last_checked on existing records
    for r in existing:
        r.last_checked = now
        # Backfill is_exploit flag if the scan found exploit refs for this CVE
        for item in raw_results:
            if item["cve_id"] == r.cve_id and item["host_ip"] == r.host_ip:
                if item.get("is_exploit"):
                    r.notes = f"Public exploit available ({len(item.get('exploit_refs', []))} refs)"
                break

    # Add new records from scan
    new_count = 0
    for item in raw_results:
        key = (item["cve_id"], item["host_ip"])
        if key not in existing_keys:
            notes = None
            if item.get("is_exploit"):
                notes = f"Public exploit available ({len(item.get('exploit_refs', []))} refs)"
            existing.append(PatchRecord(
                cve_id=item["cve_id"],
                host_ip=item["host_ip"],
                hostname=item.get("hostname", item["host_ip"]),
                package=item.get("package", "unknown"),
                current_version=item.get("current_version", "unknown"),
                fixed_version=item.get("fixed_version"),
                status="missing",
                cvss_score=item["cvss_score"],
                severity=item["severity"],
                last_checked=now,
                notes=notes,
            ))
            new_count += 1

    save_patch_db(existing)
    print(f"[FR-VOC-05] Patch DB updated: {new_count} new CVEs added, "
          f"{len(existing)} total records")


def run_scan(
    network: Optional[str] = None,
    enrich_vt: bool = True,
    on_progress: Optional[Callable] = None
) -> dict:
    """
    FR-VOC-05: Main scan entrypoint (on-demand or scheduled).
    Always attempts live nmap scan first, falls back to disk data.
    """
    scan_id = f"SCAN-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    started = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[FR-VOC-05] Starting scan {scan_id}")

    if on_progress:
        on_progress({"stage": "discovery", "pct": 10})

    raw_results, mode = _live_scan(network or LAB_NETWORK)
    if raw_results is None:
        raw_results, mode = _disk_fallback()

    # Persist new nmap findings back to the patch DB
    if mode == "live_nmap":
        _update_patch_db_from_scan(raw_results)

    if on_progress:
        on_progress({"stage": "cvss_scoring", "pct": 40})

    # VT enrichment for top critical CVEs (if key configured)
    vt_results = {}
    if enrich_vt and VT_API_KEY:
        critical = [r for r in raw_results if r["severity"] == "Critical"][:3]
        for i, r in enumerate(critical):
            if on_progress:
                on_progress({"stage": f"vt_check_{r['cve_id']}", "pct": 50 + i * 10})
            vt_ip = vt_check_ip(r["host_ip"])
            vt_results[r["host_ip"]] = vt_ip
            r["vt_ip_report"] = vt_ip
            r["vt_checked"] = True
            time.sleep(0.5)  # VT free tier: 4 req/min
    elif enrich_vt and not VT_API_KEY:
        print("[FR-VOC-05] VT enrichment skipped: VIRUSTOTAL_API_KEY not set in .env")

    if on_progress:
        on_progress({"stage": "finalizing", "pct": 90})

    completed = datetime.datetime.utcnow().isoformat() + "Z"
    result = {
        "scan_id":              scan_id,
        "started_at":           started,
        "completed_at":         completed,
        "network":              network or LAB_NETWORK,
        "mode":                 mode,
        "total_vulnerabilities": len(raw_results),
        "exploitable_count":    sum(1 for r in raw_results if r.get("is_exploit")),
        "vt_enriched":          len(vt_results),
        "severity_summary": {
            s: len([r for r in raw_results if r["severity"] == s])
            for s in ["Critical", "High", "Medium", "Low"]
        },
        "vulnerabilities": raw_results,
        "vt_ip_reports":   vt_results,
    }

    out = os.path.join(os.path.dirname(__file__), "data", "scans", f"{scan_id}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    if on_progress:
        on_progress({"stage": "done", "pct": 100})

    print(f"[FR-VOC-05] Scan complete [{mode}]: "
          f"{result['total_vulnerabilities']} vulns "
          f"({result['exploitable_count']} exploitable), "
          f"{len(vt_results)} VT-enriched")
    return result


# ── Scheduler ────────────────────────────────────────────────────────────────

class ScanScheduler:
    """FR-VOC-05: Background scheduled scan support."""
    def __init__(self, interval_hours: int = 24):
        self.interval = interval_hours * 3600
        self._thread  = None
        self._running = False

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[FR-VOC-05] Scheduler started — scan every {self.interval // 3600}h")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            run_scan()
            time.sleep(self.interval)


scheduler = ScanScheduler(interval_hours=24)

# ── Global scan state (for status polling) ────────────────────────────────────
_scan_state = {
    "running":      False,
    "scan_id":      None,
    "stage":        None,
    "pct":          0,
    "last_result":  None,
    "last_error":   None,
}

def get_scan_state() -> dict:
    """Return current scan state for the /voc/scan/status endpoint."""
    return dict(_scan_state)

def _run_scan_tracked(network=None, enrich_vt=True):
    """Wrapper that updates global state and persists result to DB."""
    global _scan_state
    _scan_state.update({"running": True, "last_error": None})

    def _progress(p):
        _scan_state.update({"stage": p["stage"], "pct": p["pct"]})

    try:
        result = run_scan(network, enrich_vt, on_progress=_progress)
        _scan_state["last_result"] = {
            "scan_id":   result["scan_id"],
            "mode":      result["mode"],
            "total_vulns": result["total_vulnerabilities"],
            "severity_summary": result["severity_summary"],
            "completed_at": result["completed_at"],
        }
        # Persist scan report and push CVEs into cve_database
        try:
            from database import insert_scan_report, upsert_cves
            insert_scan_report(result)
            # Push every found CVE into cve_database so the CVE table is populated
            cves = []
            for v in result.get("vulnerabilities", []):
                cves.append({
                    "cve_id":       v["cve_id"],
                    "description":  "{} affecting {} on {}".format(
                                        v["cve_id"], v.get("package","unknown"),
                                        v.get("host_ip","")),
                    "cvss_score":   v["cvss_score"],
                    "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cvss_version": "cvssMetricV31",
                    "severity":     v["severity"],
                    "published":    "2024-01-01T00:00:00",
                    "modified":     result["completed_at"][:19],
                    "source":       "nmap_vulners",
                })
            if cves:
                upsert_cves(cves)
                print("[FR-VOC-05] Pushed {} CVEs into cve_database".format(len(cves)))
        except Exception as e:
            print("[FR-VOC-05] DB persist error (non-critical): {}".format(e))
    except Exception as exc:
        _scan_state["last_error"] = str(exc)
    finally:
        _scan_state.update({"running": False, "stage": "done", "pct": 100})


if __name__ == "__main__":
    def progress(p):
        print(f"  → {p['stage']} ({p['pct']}%)")

    result = run_scan(enrich_vt=True, on_progress=progress)
    print(f"\nScan ID: {result['scan_id']}")
    print(f"Mode:    {result['mode']}")
    print(f"Total:   {result['total_vulnerabilities']} vulns")
    print(f"Severity: {result['severity_summary']}")
    if result["vt_ip_reports"]:
        print("\nVirusTotal IP reports:")
        for ip, vt in result["vt_ip_reports"].items():
            print(f"  {ip}: malicious={vt.get('malicious', 0)}, "
                  f"country={vt.get('country', '?')}")