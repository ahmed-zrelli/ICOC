"""
FR-VOC-03: Patch Status Tracking and Deployment Verification
Tracks patch status per CVE per host, with history and verification.

SEED DATA NOTE
──────────────
DEMO_PATCH_DB is the initial seed loaded on first run when no
patch_status.json exists on disk. Once the scanner runs a real scan
(fr_voc_05), it calls save_patch_db() and the JSON file takes over.
The name is kept for import compatibility with fr_voc_05_scanner.py.
The CVEs listed here are real CVEs mapped to real lab hosts per the
ICOC-Lite network topology (192.168.100.0/24).
"""

import json
import os
import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional
from enum import Enum


class PatchStatus(Enum):
    MISSING   = "missing"
    AVAILABLE = "available"
    SCHEDULED = "scheduled"
    APPLIED   = "applied"
    WONTFIX   = "wontfix"


@dataclass
class PatchRecord:
    cve_id: str
    host_ip: str
    hostname: str
    package: str
    current_version: str
    fixed_version: Optional[str]
    status: str
    cvss_score: float
    severity: str
    last_checked: str
    applied_at: Optional[str] = None
    notes: Optional[str] = None


DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "patch_status.json")

# ── Initial seed — real CVEs mapped to lab topology ──────────────────────────
# Loaded only on first run. Overwritten by fr_voc_05 scanner on first real scan.
# CVE → host mapping follows ICOC-Lite network topology from the cahier des charges.
# Seed data — only real lab hosts (Metasploitable 3 at 192.168.100.102)
# These are REAL CVEs affecting packages actually present on Metasploitable 3 (Ubuntu 14.04).
# Replaced automatically after first real nmap scan.
DEMO_PATCH_DB = [
    PatchRecord("CVE-2024-6387",  "192.168.100.102", "metasploitable3",
                "openssh-server", "1:6.6p1-2ubuntu2", "1:9.8p1-1",
                "missing", 8.1, "High",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
    PatchRecord("CVE-2023-38408", "192.168.100.102", "metasploitable3",
                "openssh-client", "1:6.6p1-2ubuntu2", "1:9.3p2-1",
                "missing", 9.8, "Critical",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
    PatchRecord("CVE-2021-41617", "192.168.100.102", "metasploitable3",
                "openssh-server", "1:6.6p1-2ubuntu2", "1:8.8p1-1",
                "missing", 7.0, "High",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
    PatchRecord("CVE-2023-4911",  "192.168.100.102", "metasploitable3",
                "libc6", "2.19-0ubuntu6", "2.19-0ubuntu6.15",
                "missing", 7.8, "High",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
    PatchRecord("CVE-2021-3156",  "192.168.100.102", "metasploitable3",
                "sudo", "1.8.9p5-1ubuntu1", "1.8.9p5-1ubuntu1.5",
                "missing", 7.8, "High",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
    PatchRecord("CVE-2022-2068",  "192.168.100.102", "metasploitable3",
                "openssl", "1.0.1f-1ubuntu2", "1.0.1f-1ubuntu2.27",
                "missing", 9.8, "Critical",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
    PatchRecord("CVE-2014-6271",  "192.168.100.102", "metasploitable3",
                "bash", "4.3-7ubuntu1", "4.3-14ubuntu1.1",
                "missing", 9.8, "Critical",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                notes="Shellshock — affects Metasploitable 3 bash 4.3"),
    PatchRecord("CVE-2016-5195",  "192.168.100.102", "metasploitable3",
                "linux-image", "3.13.0-24", "3.13.0-100",
                "missing", 7.8, "High",
                datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                notes="Dirty COW — kernel privilege escalation"),
]


def load_patch_db() -> List[PatchRecord]:
    """Load patch database from disk. Returns empty list on first run — populated by nmap scan."""
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH) as f:
            raw = json.load(f)
        return [PatchRecord(**r) for r in raw]
    # First run — no seed, wait for real nmap scan
    print("[FR-VOC-03] No patch_status.json yet — run a scan first (Scanner tab -> RUN SCAN)")
    return []


def save_patch_db(records: List[PatchRecord]):
    """Save all patch records to JSON and sync to PostgreSQL."""
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w") as f:
        json.dump([asdict(r) for r in records], f, indent=2)
    # Sync to PostgreSQL — best-effort, non-blocking
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from database import upsert_patch_records
        upsert_patch_records([{
            "cve_id":           r.cve_id,
            "host_ip":          r.host_ip,
            "hostname":         r.hostname,
            "package":          r.package,
            "current_version":  r.current_version,
            "fixed_version":    r.fixed_version,
            "status":           r.status,
            "cvss_score":       r.cvss_score,
            "severity":         r.severity,
            "last_checked":     r.last_checked,
            "notes":            r.notes,
        } for r in records])
    except Exception as e:
        print(f"[FR-VOC-03] DB sync skipped (non-critical): {e}")


def get_patch_summary(records: Optional[List[PatchRecord]] = None) -> dict:
    """FR-VOC-03: Return patch status summary."""
    if records is None:
        records = load_patch_db()

    counts = {s.value: 0 for s in PatchStatus}
    for r in records:
        counts[r.status] = counts.get(r.status, 0) + 1

    critical_missing = [r for r in records if r.status == "missing" and r.severity == "Critical"]
    coverage_pct = round(counts["applied"] / len(records) * 100, 1) if records else 0

    return {
        "total_vulnerabilities": len(records),
        "patch_coverage_pct": coverage_pct,
        "by_status": counts,
        "critical_missing": len(critical_missing),
        "critical_missing_cves": [r.cve_id for r in critical_missing],
        "records": [asdict(r) for r in records]
    }


def mark_patch_applied(cve_id: str, host_ip: str, notes: str = "") -> dict:
    """FR-VOC-03: Mark a patch as applied and record timestamp.
    Writes to both patch_status.json (fast read path) and PostgreSQL (persistent record).
    """
    records = load_patch_db()
    updated_record = None
    for r in records:
        if r.cve_id == cve_id and r.host_ip == host_ip:
            r.status = PatchStatus.APPLIED.value
            r.applied_at = datetime.datetime.utcnow().isoformat() + "Z"
            r.notes = notes
            updated_record = r
            break
    if updated_record:
        # 1. Persist to JSON (fast read path for all other endpoints)
        save_patch_db(records)
        # 2. Sync the updated record to PostgreSQL patch_records table
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
            from database import upsert_patch_records
            upsert_patch_records([{
                "cve_id":           updated_record.cve_id,
                "host_ip":          updated_record.host_ip,
                "hostname":         updated_record.hostname,
                "package":          updated_record.package,
                "current_version":  updated_record.current_version,
                "fixed_version":    updated_record.fixed_version,
                "status":           updated_record.status,
                "cvss_score":       updated_record.cvss_score,
                "severity":         updated_record.severity,
                "last_checked":     updated_record.last_checked,
                "notes":            updated_record.notes,
            }])
            print(f"[FR-VOC-03] Patch applied + DB synced: {cve_id} on {host_ip}")
        except Exception as e:
            # DB sync is best-effort — JSON is the source of truth
            print(f"[FR-VOC-03] Patch applied (DB sync failed — non-critical): {e}")
        return {"success": True, "cve_id": cve_id, "host_ip": host_ip}
    return {"success": False, "error": "CVE/host not found"}


def get_overdue_patches(days_threshold: int = 7) -> List[dict]:
    """Return patches that have been available for > N days without being applied."""
    records = load_patch_db()
    overdue = []
    now = datetime.datetime.utcnow()
    for r in records:
        if r.status in ("missing", "available"):
            checked = datetime.datetime.fromisoformat(r.last_checked.replace("Z", ""))
            if (now - checked).days >= days_threshold:
                d = asdict(r)
                d["days_overdue"] = (now - checked).days
                overdue.append(d)
    return sorted(overdue, key=lambda x: x["cvss_score"], reverse=True)


if __name__ == "__main__":
    summary = get_patch_summary()
    print(f"[FR-VOC-03] Patch Coverage: {summary['patch_coverage_pct']}%")
    print(f"[FR-VOC-03] Missing Critical: {summary['critical_missing']} → {summary['critical_missing_cves']}")
    print(f"[FR-VOC-03] Status breakdown: {summary['by_status']}")