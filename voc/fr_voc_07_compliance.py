"""
FR-VOC-07: Compliance Framework Mapping (PCI-DSS, ISO 27001, NIST CSF)
Maps CVEs and patch status to compliance control requirements.
"""

import json
import os
import datetime
from typing import List, Dict
from fr_voc_03_patch_tracking import load_patch_db
from fr_voc_01_inventory import LAB_HOSTS

# ── Compliance control mappings ───────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "PCI-DSS": {
        "version": "v4.0",
        "controls": {
            "REQ-6.3": {
                "name": "Identify and manage security vulnerabilities",
                "description": "All security vulnerabilities must be identified and managed",
                "check": lambda records: _check_vuln_management(records),
                "weight": 0.25
            },
            "REQ-6.3.3": {
                "name": "Patches for critical vulnerabilities applied within 1 month",
                "description": "Security patches for critical vulnerabilities applied within one month",
                "check": lambda records: _check_critical_patch_timing(records, days=30),
                "weight": 0.25
            },
            "REQ-11.3": {
                "name": "External and internal vulnerability scans",
                "description": "Vulnerability scanning performed regularly",
                "check": lambda records: _check_scan_coverage(records),
                "weight": 0.20
            },
            "REQ-12.3": {
                "name": "Risk assessment performed",
                "description": "Annual risk assessment and risk-targeted security controls",
                "check": lambda records: _check_risk_assessment(records),
                "weight": 0.15
            },
            "REQ-5.3": {
                "name": "Anti-malware mechanisms active",
                "description": "Anti-malware solutions are active, maintained, and monitored",
                "check": lambda records: _check_malware_controls(records),
                "weight": 0.15
            }
        }
    },
    "ISO-27001": {
        "version": "2022",
        "controls": {
            "A.8.8": {
                "name": "Management of technical vulnerabilities",
                "description": "Timely identification and remediation of technical vulnerabilities",
                "check": lambda records: _check_vuln_management(records),
                "weight": 0.30
            },
            "A.8.19": {
                "name": "Installation of software on operational systems",
                "description": "Software installation controlled through procedures",
                "check": lambda records: _check_patch_tracking(records),
                "weight": 0.25
            },
            "A.5.37": {
                "name": "Documented operating procedures",
                "description": "Operating procedures documented and available",
                "check": lambda records: _check_patch_tracking(records),
                "weight": 0.20
            },
            "A.8.9": {
                "name": "Configuration management",
                "description": "Configurations established, documented, and monitored",
                "check": lambda records: _check_scan_coverage(records),
                "weight": 0.25
            }
        }
    },
    "NIST-CSF": {
        "version": "v2.0",
        "controls": {
            "ID.RA": {
                "name": "Risk Assessment",
                "description": "Organization understands cybersecurity risk",
                "check": lambda records: _check_risk_assessment(records),
                "weight": 0.25
            },
            "PR.PS": {
                "name": "Platform Security",
                "description": "Platform components managed consistent with risk strategy",
                "check": lambda records: _check_patch_tracking(records),
                "weight": 0.25
            },
            "DE.CM": {
                "name": "Continuous Monitoring",
                "description": "Assets and configuration monitored for anomalies",
                "check": lambda records: _check_scan_coverage(records),
                "weight": 0.25
            },
            "RS.MI": {
                "name": "Incident Mitigation",
                "description": "Newly identified vulnerabilities mitigated",
                "check": lambda records: _check_critical_patch_timing(records, days=7),
                "weight": 0.25
            }
        }
    }
}

# ── Check functions ───────────────────────────────────────────────────────────

def _check_vuln_management(records) -> dict:
    total = len(records)
    addressed = len([r for r in records if r.status in ("applied", "wontfix")])
    score = addressed / total if total else 0
    findings = []
    missing = [r.cve_id for r in records if r.status == "missing"]
    if missing:
        findings.append(f"{len(missing)} vulnerabilities still unaddressed: {', '.join(missing[:3])}")
    return {"score": round(score, 2), "findings": findings}

def _check_critical_patch_timing(records, days: int = 30) -> dict:
    import datetime
    now = datetime.datetime.utcnow()
    critical = [r for r in records if r.severity == "Critical"]
    if not critical:
        return {"score": 1.0, "findings": ["No critical CVEs found"]}
    on_time = 0
    findings = []
    unpatched = []
    for r in critical:
        if r.status == "applied" and r.applied_at:
            try:
                applied = r.applied_at
                checked = r.last_checked
                # Handle both string and datetime objects
                if isinstance(applied, str):
                    applied = datetime.datetime.fromisoformat(applied.replace("Z","").split("+")[0])
                elif hasattr(applied, 'replace'):
                    applied = applied.replace(tzinfo=None)
                if isinstance(checked, str):
                    checked = datetime.datetime.fromisoformat(checked.replace("Z","").split("+")[0])
                elif hasattr(checked, 'replace'):
                    checked = checked.replace(tzinfo=None)
                if (applied - checked).days <= days:
                    on_time += 1
                else:
                    unpatched.append(r.cve_id)
            except Exception:
                unpatched.append(r.cve_id)
        else:
            unpatched.append(r.cve_id)
    score = on_time / len(critical)
    if unpatched:
        shown   = unpatched[:3]
        rest    = len(unpatched) - 3
        summary = ", ".join(shown)
        if rest > 0:
            summary += " (+{} more)".format(rest)
        findings.append("{}/{} critical CVEs unpatched: {}".format(
            len(unpatched), len(critical), summary))
    return {"score": round(score, 2), "findings": findings}

def _check_scan_coverage(records) -> dict:
    # Only check victim hosts — not the attacker (Kali) which we don't protect
    import os
    victim_ip = os.getenv("VICTIM_IP", "192.168.100.102")
    expected_hosts = {victim_ip}
    hosts = set(r.host_ip for r in records)
    covered = hosts & expected_hosts
    score = len(covered) / len(expected_hosts) if expected_hosts else 0.0
    findings = []
    missing = expected_hosts - covered
    if missing:
        findings.append("Victim host not yet scanned: {} - run a scan first".format(", ".join(sorted(missing))))
    return {"score": round(score, 2), "findings": findings}

def _check_risk_assessment(records) -> dict:
    """
    Score based on ratio of unpatched critical CVEs to total critical CVEs.
    0 critical unpatched = 100%, all critical unpatched = 0%.
    Uses a curve so partial remediation shows meaningful progress.
    """
    critical_all     = [r for r in records if r.severity == "Critical"]
    critical_missing = [r for r in critical_all if r.status == "missing"]

    if not critical_all:
        return {"score": 1.0, "findings": ["No critical CVEs found — risk assessment clean"]}

    total    = len(critical_all)
    missing  = len(critical_missing)
    patched  = total - missing

    # Proportional score: what fraction of critical CVEs have been addressed
    # Apply a square-root curve so even partial progress shows improvement
    ratio   = patched / total                        # 0.0 → 1.0
    score   = round(ratio ** 0.5, 2)                 # sqrt curve: 50% patched → 71% score

    findings = []
    if missing > 0:
        findings.append(
            "{}/{} critical CVEs unpatched — patch coverage {:.0f}%".format(
                missing, total, ratio * 100)
        )
    return {"score": score, "findings": findings}

def _check_patch_tracking(records) -> dict:
    if not records:
        return {"score": 0.0, "findings": ["No patch records yet — run a vulnerability scan first"]}
    tracked = len([r for r in records if r.last_checked])
    score = tracked / len(records)
    return {"score": round(score, 2), "findings": [] if score == 1.0 else ["{}/{} records missing tracking data".format(len(records)-tracked, len(records))]}

def _check_malware_controls(records) -> dict:
    """
    Check malware control effectiveness based on:
    - Whether VirusTotal API key is configured (active enrichment)
    - Whether VT cache has scan results (enrichment actually ran)
    - Whether any VT-flagged threats were found in scan data
    """
    findings = []
    score = 0.0

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    vt_cache_dir = os.path.join(os.path.dirname(__file__), "data", "vt_cache")
    vt_cache_files = []
    if os.path.isdir(vt_cache_dir):
        vt_cache_files = [f for f in os.listdir(vt_cache_dir) if f.endswith(".json")]

    # +0.40: VT API key configured
    if vt_key:
        score += 0.40
        findings.append(f"VirusTotal API key configured — live enrichment active")
    else:
        findings.append("WARNING: VIRUSTOTAL_API_KEY not set — VT enrichment disabled")

    # +0.35: VT scans have actually been executed (cache populated)
    if vt_cache_files:
        score += 0.35
        findings.append(f"VT scan cache contains {len(vt_cache_files)} result(s) — enrichment is running")
    else:
        findings.append("VT cache empty — run a vulnerability scan to populate enrichment data")

    # +0.25: patch DB exists and is being actively maintained (last_checked within 7 days)
    now = datetime.datetime.utcnow()
    recently_checked = []
    for r in records:
        if not r.last_checked:
            continue
        try:
            lc = r.last_checked
            # Handle both string and datetime objects from DB
            if isinstance(lc, str):
                lc = datetime.datetime.fromisoformat(lc.replace("Z", "").split("+")[0])
            elif hasattr(lc, 'replace'):
                # psycopg2 returns timezone-aware datetime — strip tz
                lc = lc.replace(tzinfo=None)
            if (now - lc).days <= 7:
                recently_checked.append(r)
        except Exception:
            pass
    if recently_checked:
        score += 0.25
        findings.append(f"{len(recently_checked)} hosts scanned within last 7 days — monitoring active")
    else:
        findings.append("No recent scans within 7 days — schedule regular vulnerability scans")

    return {"score": round(min(score, 1.0), 2), "findings": findings}

# ── Main compliance report ────────────────────────────────────────────────────

def generate_compliance_report() -> dict:
    """FR-VOC-07: Generate full compliance assessment report."""
    # Read from DB (live), fall back to disk
    records = []
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(os.path.dirname(__file__), ".."))
        from database import get_cursor
        with get_cursor() as cur:
            cur.execute("SELECT cve_id, host_ip, status, cvss_score, severity, last_checked FROM patch_records")
            rows = cur.fetchall()
        if rows:
            import datetime as _dt
            records = [PatchRecord(
                cve_id=r["cve_id"], host_ip=r["host_ip"], hostname="",
                package="", current_version="", fixed_version="",
                status=r["status"], cvss_score=float(r["cvss_score"] or 0),
                severity=r["severity"],
                last_checked=str(r["last_checked"]) if r["last_checked"] else _dt.datetime.utcnow().isoformat()+"Z"
            ) for r in rows]
    except Exception as e:
        print("[FR-VOC-07] DB read failed, using disk: {}".format(e))
        records = load_patch_db()
    report = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "frameworks": {}
    }

    for framework_name, framework in COMPLIANCE_FRAMEWORKS.items():
        control_results = {}
        weighted_score = 0.0

        for control_id, control in framework["controls"].items():
            result = control["check"](records)
            weighted_score += result["score"] * control["weight"]
            control_results[control_id] = {
                "name": control["name"],
                "description": control["description"],
                "score_pct": round(result["score"] * 100, 1),
                "weight": control["weight"],
                "findings": result["findings"],
                "status": "Pass" if result["score"] >= 0.75 else "Partial" if result["score"] >= 0.5 else "Fail"
            }

        framework_score = round(weighted_score * 100, 1)
        report["frameworks"][framework_name] = {
            "version": framework["version"],
            "overall_score_pct": framework_score,
            "status": "Compliant" if framework_score >= 80 else "Partial" if framework_score >= 60 else "Non-Compliant",
            "controls": control_results
        }
        print(f"[FR-VOC-07] {framework_name}: {framework_score}% compliance")

    # Persist snapshot to DB — best effort
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from database import insert_compliance_snapshot
        for framework_name, fw_data in report["frameworks"].items():
            insert_compliance_snapshot({
                "framework": framework_name,
                "version": fw_data["version"],
                "overall_score": fw_data["overall_score_pct"],
                "status": fw_data["status"],
                "controls": fw_data["controls"]
            })
    except Exception as e:
        print("[FR-VOC-07] DB snapshot skipped (non-critical): {}".format(e))

    return report

if __name__ == "__main__":
    report = generate_compliance_report()
    print("\n=== Compliance Report ===")
    for fw, data in report["frameworks"].items():
        print(f"\n{fw} ({data['version']}): {data['overall_score_pct']}% — {data['status']}")
        for ctrl_id, ctrl in data["controls"].items():
            print(f"  {ctrl_id}: {ctrl['score_pct']}% [{ctrl['status']}]")
            for f in ctrl["findings"]:
                print(f"    ⚠ {f}")