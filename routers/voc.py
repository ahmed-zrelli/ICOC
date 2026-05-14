import os
import json
import glob
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
from config import config

# These imports assume the project root is in sys.path, which main.py handles
from fr_voc_01_inventory import run_inventory_scan
from fr_voc_02_cvss_scoring import LAB_CVE_VECTORS, parse_cvss_vector_string, calculate_cvss_v31
from fr_voc_03_patch_tracking import get_patch_summary, mark_patch_applied, get_overdue_patches
from fr_voc_04_reports import generate_report, export_csv
from fr_voc_05_scanner import get_scan_state, _run_scan_tracked
from fr_voc_06_nvd_integration import fetch_cve_by_id, fetch_recent_cves
from fr_voc_07_compliance import generate_compliance_report
from database import get_cursor

router = APIRouter(prefix="/voc", tags=["VOC"])

class PatchUpdate(BaseModel):
    cve_id: str
    host_ip: str
    notes: Optional[str] = ""

class ScanRequest(BaseModel):
    network: Optional[str] = None
    enrich_vt: bool = True

@router.get("/inventory")
def get_inventory():
    """FR-VOC-01: Get software inventory across all hosts."""
    result = run_inventory_scan()
    return {
        "total_hosts":    result.total_hosts,
        "total_packages": result.total_packages,
        "scanned_at":     result.scanned_at,
        "source":         result.source,
        "entries": [
            {"host_ip": e.host_ip, "hostname": e.hostname, "os": e.os,
             "package": e.package, "version": e.version, "source": e.source}
            for e in result.entries
        ]
    }

@router.get("/cvss/{cve_id}")
async def get_cvss_score(cve_id: str):
    """FR-VOC-02: Calculate CVSS v3.1 score for a CVE."""
    # Check lab CVE list first (fast, no network)
    for cid, vec, desc in LAB_CVE_VECTORS:
        if cid == cve_id:
            v = parse_cvss_vector_string(vec, cid, desc)
            return calculate_cvss_v31(v)
    # Try NVD cache / live
    cve_data = await fetch_cve_by_id(cve_id)
    if cve_data and cve_data.get("cvss_vector"):
        try:
            v = parse_cvss_vector_string(cve_data["cvss_vector"], cve_id,
                                          cve_data.get("description"))
            return calculate_cvss_v31(v)
        except Exception:
            pass
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

@router.get("/cvss")
def get_all_cvss():
    """FR-VOC-02: Score all lab CVEs — returns DB-backed CVEs with CVSS details."""
    victim_ip = config.VICTIM_IP
    vector_map = {cve_id: (vec, desc) for cve_id, vec, desc in LAB_CVE_VECTORS}

    try:
        with get_cursor() as cur:
            # Only show CVEs for victim host, top 20 by score
            cur.execute("""
                SELECT DISTINCT ON (cve_id) cve_id, cvss_score, severity, source
                FROM cve_database
                WHERE cvss_score >= 7.0
                ORDER BY cve_id, cvss_score DESC
                LIMIT 20
            """)
            rows = cur.fetchall()
    except Exception as e:
        rows = []

    results = []
    for row in sorted(rows, key=lambda r: r["cvss_score"], reverse=True):
        cve_id = row["cve_id"]
        if cve_id in vector_map:
            vec, desc = vector_map[cve_id]
            v = parse_cvss_vector_string(vec, cve_id, desc)
            result = calculate_cvss_v31(v)
            result["source"] = row["source"]
            results.append(result)
        else:
            results.append({
                "cve_id": cve_id,
                "base_score": float(row["cvss_score"]),
                "severity": row["severity"],
                "vector_string": "N/A",
                "description": cve_id,
                "source": row["source"]
            })

    if not results:
        # No scan data yet
        return {"cves": [], "total": 0, "source": "empty", "message": "Run a scan first"}

    return {"cves": results, "total": len(results), "source": "db"}

@router.get("/patches")
def get_patches():
    """FR-VOC-03: Get patch status for all vulnerabilities."""
    return get_patch_summary()

@router.post("/patches/apply")
def apply_patch(req: PatchUpdate):
    """FR-VOC-03: Mark a patch as applied."""
    return mark_patch_applied(req.cve_id, req.host_ip, req.notes or "")

@router.get("/patches/overdue")
def get_overdue(days: int = Query(7)):
    """FR-VOC-03: Get patches overdue by N days."""
    return {"overdue": get_overdue_patches(days)}

@router.get("/report")
def get_report(
    severity: Optional[str] = None,
    status:   Optional[str] = None,
    include_applied: bool = False
):
    """FR-VOC-04: Generate vulnerability report with filters."""
    sevs  = [s.strip() for s in severity.split(",")] if severity else None
    stats = [s.strip() for s in status.split(",")]   if status   else None
    return generate_report(sevs, stats, include_applied=include_applied)

@router.get("/report/csv")
def get_report_csv():
    """FR-VOC-04: Export vulnerability report as CSV."""
    report = generate_report()
    csv = export_csv(report)
    return StreamingResponse(
        iter([csv]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={report['report_id']}.csv"}
    )

@router.post("/scan")
def trigger_scan(req: ScanRequest, background: BackgroundTasks):
    """FR-VOC-05: Trigger on-demand vulnerability scan (runs in background)."""
    state = get_scan_state()
    if state["running"]:
        return {"message": "Scan already running", "scan_id": state["scan_id"],
                "pct": state["pct"], "stage": state["stage"]}
    background.add_task(_run_scan_tracked, req.network, req.enrich_vt)
    return {"message": "Scan started", "note": "Poll /voc/scan/status for progress"}

@router.get("/scan/status")
def get_scan_status():
    """FR-VOC-05: Get current scan progress and last result."""
    return get_scan_state()

@router.get("/scan/results")
def get_scan_results():
    """FR-VOC-05: Get latest scan results from disk."""
    VOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/voc"
    scan_dir = os.path.join(VOC_DIR, "data", "scans")
    files = sorted(glob.glob(os.path.join(scan_dir, "SCAN-*.json")), reverse=True)
    if not files:
        raise HTTPException(status_code=404,
                            detail="No scan results yet. POST /voc/scan to trigger one.")
    with open(files[0]) as f:
        return json.load(f)

@router.get("/nvd/recent")
async def get_recent_cves(days: int = Query(7), limit: int = Query(20)):
    """FR-VOC-06: Get recently published CVEs from NVD (or cache)."""
    cves = await fetch_recent_cves(days_back=days, max_results=limit)
    return {"total": len(cves), "cves": cves}

@router.get("/nvd/{cve_id}")
async def get_cve(cve_id: str):
    """FR-VOC-06: Get specific CVE from NVD cache or live."""
    result = await fetch_cve_by_id(cve_id)
    if result:
        return result
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD")

@router.get("/compliance")
def get_compliance():
    """FR-VOC-07: Get compliance assessment (PCI-DSS, ISO 27001, NIST CSF)."""
    return generate_compliance_report()
