import json
from fastapi import APIRouter, HTTPException
from config import config
from database import (
    get_db_stats, get_events, get_cves, get_risk_history,
    get_scan_reports, get_inventory_summary, get_attack_log,
    get_compliance_trend, create_schema, seed_lab_data,
    get_conn, upsert_cves, upsert_patch_records
)

router = APIRouter(prefix="/db", tags=["Database"])

@router.get("/stats")
def db_stats():
    """Return row counts for all tables and DB size."""
    try:
        return get_db_stats()
    except Exception as e:
        return {"error": str(e), "note": "DB may not be running"}

@router.get("/events")
def db_events(limit: int = 100, severity: str = None, event_type: str = None):
    """Query security_events table."""
    return {"events": get_events(limit=limit, severity=severity, event_type=event_type)}

@router.get("/cves")
def db_cves(severity: str = None, min_score: float = 0.0,
            limit: int = 50, search: str = None):
    """Query cve_database table."""
    return {"cves": get_cves(severity=severity, min_score=min_score,
                              limit=limit, search=search)}

@router.get("/risk-history")
def db_risk_history(hours: int = 24):
    """Get risk score time-series from DB."""
    return {"history": get_risk_history(hours=hours)}

@router.get("/scan-reports")
def db_scan_reports(limit: int = 20):
    """List all scan reports stored in DB."""
    return {"reports": get_scan_reports(limit=limit)}

@router.get("/inventory")
def db_inventory():
    """Get host inventory summary from DB."""
    return get_inventory_summary()

@router.get("/attacks")
def db_attacks(limit: int = 50):
    """Get attack log from DB."""
    return {"attacks": get_attack_log(limit=limit)}

@router.get("/compliance-trend/{framework}")
def db_compliance_trend(framework: str, days: int = 30):
    """Get compliance score trend from DB."""
    return {"trend": get_compliance_trend(framework, days)}

@router.post("/init")
def db_init():
    """Initialize DB schema and seed initial lab data."""
    try:
        create_schema()
        seed_lab_data()
        return {"status": "ok", "message": "Schema created and lab data seeded"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/purge-scan")
def db_purge_scan():
    """Wipe all scan-generated patch records and CVEs, keeping only victim host data."""
    victim_ip = config.VICTIM_IP
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Delete patch records not belonging to victim
            cur.execute("DELETE FROM patch_records WHERE host_ip != %s", (victim_ip,))
            deleted_patches = cur.rowcount
            # Delete all CVEs (they'll be repopulated by next scan against victim only)
            cur.execute("TRUNCATE TABLE cve_database")
    return {"status": "ok", "deleted_patch_records": deleted_patches, "cve_database": "cleared"}

@router.post("/reseed")
def db_reseed():
    """Force wipe and reseed CVEs, patch records, and threat intel with current lab data."""
    try:
        from voc.fr_voc_03_patch_tracking import load_patch_db
        from voc.fr_voc_02_cvss_scoring import LAB_CVE_VECTORS, parse_cvss_vector_string, calculate_cvss_v31
        from ai.fr_ai_05_07 import STATIC_INTEL

        # Wipe old seeded data
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE cve_database, patch_records, threat_intel RESTART IDENTITY CASCADE")

        # Reseed patch records
        patch_records = load_patch_db()
        records = [{
            "cve_id": r.cve_id, "host_ip": r.host_ip, "hostname": r.hostname,
            "package": r.package, "current_version": r.current_version,
            "fixed_version": r.fixed_version, "status": r.status,
            "cvss_score": r.cvss_score, "severity": r.severity,
            "last_checked": r.last_checked, "notes": r.notes
        } for r in patch_records]
        upsert_patch_records(records)

        # Reseed CVEs with correct source label
        cves = []
        for cve_id, vec, desc in LAB_CVE_VECTORS:
            try:
                v = parse_cvss_vector_string(vec, cve_id, desc)
                result = calculate_cvss_v31(v)
                cves.append({
                    "cve_id": cve_id, "description": desc,
                    "cvss_score": result["base_score"],
                    "cvss_vector": vec, "cvss_version": "cvssMetricV31",
                    "severity": result["severity"],
                    "published": "2024-01-01T00:00:00",
                    "modified": "2024-01-01T00:00:00",
                    "source": "lab_seed"
                })
            except Exception:
                pass
        upsert_cves(cves)

        # Reseed threat intel
        sql = """
            INSERT INTO threat_intel
                (intel_id, source, indicator_type, indicator, severity, description, tags, published)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (intel_id) DO UPDATE SET
                description=EXCLUDED.description,
                tags=EXCLUDED.tags
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                for ti in STATIC_INTEL:
                    cur.execute(sql, (
                        ti["id"], ti["source"], ti["type"], ti["indicator"],
                        ti["severity"], ti["description"],
                        json.dumps(ti.get("tags", [])),
                        ti.get("published")
                    ))

        return {
            "status": "ok",
            "patch_records": len(records),
            "cves": len(cves),
            "threat_intel": len(STATIC_INTEL)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
