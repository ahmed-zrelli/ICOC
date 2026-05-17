"""
database.py — PostgreSQL data layer for ICOC-Lite
Single source of truth for all persistent data.
Replaces all JSON file storage.

Tables:
  - security_events      : live events from victim agent (FR-SOC-*)
  - vulnerabilities      : CVE records from NVD (FR-VOC-06)
  - patch_records        : patch status per CVE per host (FR-VOC-03)
  - scan_reports         : vulnerability scan results (FR-VOC-04/05)
  - risk_score_history   : AI risk score over time (FR-AI-01)
  - host_inventory       : software inventory per host (FR-VOC-01)
  - threat_intel         : threat intelligence feed (FR-AI-05)
  - attack_log           : attacker actions (lab only)
"""

import os
import json
import datetime
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "POSTGRES_URL",
    "postgresql://icoc:icoc2026@db:5432/icoc"
)

# ── Connection pool ────────────────────────────────────────────────────────────

@contextmanager
def get_conn():
    """Context manager: get a connection, auto-commit, auto-close."""
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def get_cursor(conn=None):
    """Context manager: get a RealDictCursor (returns dicts not tuples)."""
    if conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cur
        finally:
            cur.close()
    else:
        with get_conn() as c:
            cur = c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                yield cur
            finally:
                cur.close()

def test_connection() -> bool:
    """Return True if DB is reachable."""
    try:
        with get_conn() as conn:
            with get_cursor(conn) as cur:
                cur.execute("SELECT 1")
        return True
    except Exception as e:
        print(f"[DB] Connection failed: {e}")
        return False

# ── Schema creation ────────────────────────────────────────────────────────────

SCHEMA_SQL = """
-- Security events from victim agent
CREATE TABLE IF NOT EXISTS security_events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        VARCHAR(50) UNIQUE,
    agent_id        VARCHAR(100),
    host_ip         INET,
    hostname        VARCHAR(100),
    event_type      VARCHAR(80) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    summary         TEXT,
    raw_data        JSONB,
    src_ip          INET,
    rule_triggered  VARCHAR(200),
    auto_blocked    BOOLEAN DEFAULT FALSE,
    fail_count      INTEGER DEFAULT 0,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_type       ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_host       ON security_events(host_ip);
CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON security_events(src_ip);

-- NOC Incidents tracking
CREATE TABLE IF NOT EXISTS noc_incidents (
    id              BIGSERIAL PRIMARY KEY,
    incident_id     VARCHAR(50) UNIQUE,
    host            VARCHAR(100),
    description     TEXT,
    severity        VARCHAR(20),
    status          VARCHAR(20) DEFAULT 'Open',
    assigned_to     VARCHAR(100),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- CVE database from NVD
CREATE TABLE IF NOT EXISTS cve_database (
    id              BIGSERIAL PRIMARY KEY,
    cve_id          VARCHAR(30) UNIQUE NOT NULL,
    description     TEXT,
    cvss_score      NUMERIC(4,1),
    cvss_vector     VARCHAR(200),
    cvss_version    VARCHAR(20),
    severity        VARCHAR(20),
    published       TIMESTAMPTZ,
    modified        TIMESTAMPTZ,
    cve_references  JSONB DEFAULT '[]',
    affected_products JSONB DEFAULT '[]',
    source          VARCHAR(30) DEFAULT 'nvd',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cve_severity  ON cve_database(severity);
CREATE INDEX IF NOT EXISTS idx_cve_score     ON cve_database(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_database(published DESC);

-- Patch status per CVE per host
CREATE TABLE IF NOT EXISTS patch_records (
    id              BIGSERIAL PRIMARY KEY,
    cve_id          VARCHAR(30) NOT NULL,
    host_ip         INET NOT NULL,
    hostname        VARCHAR(100),
    package         VARCHAR(200),
    current_version VARCHAR(100),
    fixed_version   VARCHAR(100),
    status          VARCHAR(20) NOT NULL DEFAULT 'missing',
    cvss_score      NUMERIC(4,1),
    severity        VARCHAR(20),
    last_checked    TIMESTAMPTZ DEFAULT NOW(),
    applied_at      TIMESTAMPTZ,
    notes           TEXT,
    UNIQUE(cve_id, host_ip)
);
CREATE INDEX IF NOT EXISTS idx_patch_status   ON patch_records(status);
CREATE INDEX IF NOT EXISTS idx_patch_severity ON patch_records(severity);
CREATE INDEX IF NOT EXISTS idx_patch_host     ON patch_records(host_ip);

-- Vulnerability scan results
CREATE TABLE IF NOT EXISTS scan_reports (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         VARCHAR(50) UNIQUE NOT NULL,
    network         VARCHAR(50),
    mode            VARCHAR(20) DEFAULT 'unknown',
    total_vulns     INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    vt_enriched     INTEGER DEFAULT 0,
    results         JSONB DEFAULT '[]',
    vt_reports      JSONB DEFAULT '{}',
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scan_reports(started_at DESC);

-- AI risk score history (time-series)
CREATE TABLE IF NOT EXISTS risk_score_history (
    id              BIGSERIAL PRIMARY KEY,
    score           NUMERIC(5,1) NOT NULL,
    level           VARCHAR(20),
    color           VARCHAR(10),
    voc_component   NUMERIC(5,2),
    soc_component   NUMERIC(5,2),
    ti_component    NUMERIC(5,2),
    unpatched_cves  INTEGER,
    critical_unpatched INTEGER,
    soc_alerts      INTEGER,
    active_incidents INTEGER,
    threat_intel_hits INTEGER,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risk_time ON risk_score_history(computed_at DESC);

-- Host software inventory
CREATE TABLE IF NOT EXISTS host_inventory (
    id              BIGSERIAL PRIMARY KEY,
    host_ip         INET NOT NULL,
    hostname        VARCHAR(100),
    os              VARCHAR(100),
    package         VARCHAR(200),
    version         VARCHAR(100),
    scanned_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(host_ip, package)
);
CREATE INDEX IF NOT EXISTS idx_inventory_host ON host_inventory(host_ip);

-- Threat intelligence feed
CREATE TABLE IF NOT EXISTS threat_intel (
    id              BIGSERIAL PRIMARY KEY,
    intel_id        VARCHAR(30) UNIQUE NOT NULL,
    source          VARCHAR(50),
    indicator_type  VARCHAR(30),
    indicator       VARCHAR(200),
    severity        VARCHAR(20),
    description     TEXT,
    tags            JSONB DEFAULT '[]',
    vt_malicious    INTEGER DEFAULT 0,
    vt_country      VARCHAR(10),
    vt_live         BOOLEAN DEFAULT FALSE,
    published       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Attack log (attacker actions in lab)
CREATE TABLE IF NOT EXISTS attack_log (
    id              BIGSERIAL PRIMARY KEY,
    attack_id       VARCHAR(50) UNIQUE,
    attacker_ip     INET,
    victim_ip       INET,
    attack_type     VARCHAR(80),
    details         JSONB DEFAULT '{}',
    launched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attacks_time ON attack_log(launched_at DESC);
CREATE INDEX IF NOT EXISTS idx_attacks_type ON attack_log(attack_type);

-- Compliance snapshots
CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    framework       VARCHAR(30) NOT NULL,
    version         VARCHAR(20),
    overall_score   NUMERIC(5,1),
    status          VARCHAR(30),
    controls        JSONB DEFAULT '{}',
    computed_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_compliance_time ON compliance_snapshots(computed_at DESC);

-- NOC Audit Trail for Advanced Logging and Audit Trails
CREATE TABLE IF NOT EXISTS noc_audit_trail (
    id              BIGSERIAL PRIMARY KEY,
    action          VARCHAR(100) NOT NULL,
    module          VARCHAR(50),
    user_id         VARCHAR(50) DEFAULT 'system',
    details         JSONB DEFAULT '{}',
    status          VARCHAR(20),
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_noc_audit_time ON noc_audit_trail(timestamp DESC);
"""

def create_schema():
    """Create all tables if they don't exist."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
    print("[DB] Schema created/verified ✓")

# ── Security Events ────────────────────────────────────────────────────────────

def insert_event(event: dict) -> dict:
    """Insert a security event from victim agent."""
    data = event.get("data", {})
    sql = """
        INSERT INTO security_events
            (event_id, agent_id, host_ip, hostname, event_type, severity,
             summary, raw_data, src_ip, rule_triggered, auto_blocked, fail_count, timestamp)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (event_id) DO NOTHING
        RETURNING id
    """
    ts = event.get("timestamp", datetime.datetime.utcnow().isoformat())
    try:
        ts_parsed = datetime.datetime.fromisoformat(ts.replace("Z",""))
    except Exception:
        ts_parsed = datetime.datetime.utcnow()

    src_ip = data.get("src_ip")
    if src_ip in ("unknown", "", None):
        src_ip = None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                event.get("id"),
                event.get("agent_id"),
                event.get("host_ip"),
                event.get("hostname"),
                event.get("event_type"),
                event.get("severity", "Info"),
                data.get("summary"),
                json.dumps(data),
                src_ip,
                data.get("rule_triggered"),
                data.get("auto_block_triggered", False),
                data.get("fail_count_5min", 0),
                ts_parsed
            ))
            row = cur.fetchone()
    event["db_id"] = row[0] if row else None
    return event

def get_event_by_id(event_id: str) -> dict | None:
    """Fetch a single security event by DB id or agent event_id."""
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT id, event_id, host_ip::text, hostname, event_type, severity,
                   summary, raw_data, src_ip::text, rule_triggered,
                   auto_blocked, fail_count,
                   timestamp AT TIME ZONE 'UTC' as timestamp,
                   ingested_at AT TIME ZONE 'UTC' as ingested_at
            FROM security_events
            WHERE id::text = %s OR event_id = %s
            LIMIT 1
            """,
            (event_id, event_id),
        )
        row = cur.fetchone()
        return dict(row) if row else None

def get_events(
    limit: int = 50,
    severity: str = None,
    event_type: str = None,
    since_seconds: int = None,
    host_ip: str = None
) -> list:
    """Query security events with filters."""
    conditions = ["1=1"]
    params = []
    if severity:
        conditions.append("severity = %s"); params.append(severity)
    if event_type:
        conditions.append("event_type = %s"); params.append(event_type)
    if since_seconds:
        conditions.append("timestamp >= NOW() - INTERVAL '%s seconds'")
        params.append(since_seconds)
    if host_ip:
        conditions.append("host_ip::text = %s"); params.append(host_ip)

    sql = f"""
        SELECT id, event_id, host_ip::text, hostname, event_type, severity,
               summary, raw_data, src_ip::text, rule_triggered,
               auto_blocked, fail_count,
               timestamp AT TIME ZONE 'UTC' as timestamp,
               ingested_at AT TIME ZONE 'UTC' as ingested_at
        FROM security_events
        WHERE {' AND '.join(conditions)}
        ORDER BY timestamp DESC
        LIMIT %s
    """
    params.append(limit)
    with get_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

def get_event_stats() -> dict:
    """Aggregate event statistics."""
    with get_cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total_events,
                COUNT(*) FILTER (WHERE severity='Critical') as critical,
                COUNT(*) FILTER (WHERE severity='High') as high,
                COUNT(*) FILTER (WHERE severity='Medium') as medium,
                COUNT(*) FILTER (WHERE severity='Low') as low,
                COUNT(*) FILTER (WHERE severity='Info') as info,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '5 minutes'
                                   AND severity IN ('Critical','High')) as alerts_5min,
                COUNT(*) FILTER (WHERE event_type IN (
                    'reverse_shell_detected','malware_dropped',
                    'ssh_login_success','file_integrity_violation')) as incidents,
                MAX(timestamp) as last_event_at
            FROM security_events
        """)
        row = dict(cur.fetchone())

        # Brute force by IP (last 5 min)
        cur.execute("""
            SELECT src_ip::text, MAX(fail_count) as max_attempts
            FROM security_events
            WHERE event_type IN ('ssh_brute_force','ssh_failed_auth')
              AND timestamp >= NOW() - INTERVAL '5 minutes'
              AND src_ip IS NOT NULL
            GROUP BY src_ip
            HAVING MAX(fail_count) > 0
        """)
        brute = {r["src_ip"]: r["max_attempts"] for r in cur.fetchall()}

        # Event type breakdown
        cur.execute("""
            SELECT event_type, COUNT(*) as cnt
            FROM security_events
            GROUP BY event_type ORDER BY cnt DESC LIMIT 15
        """)
        type_counts = {r["event_type"]: r["cnt"] for r in cur.fetchall()}

    return {
        "total_events": row["total_events"],
        "total_attacks": 0,
        "severity_breakdown": {
            "Critical": row["critical"], "High": row["high"],
            "Medium": row["medium"], "Low": row["low"], "Info": row["info"]
        },
        "alert_count_5min": row["alerts_5min"],
        "incidents": row["incidents"],
        "active_brute_force": brute,
        "event_types": type_counts,
        "last_event_at": str(row["last_event_at"]) if row["last_event_at"] else None
    }

# ── CVE Database ───────────────────────────────────────────────────────────────

def upsert_cves(cves: list) -> int:
    """Bulk upsert CVEs from NVD into DB. Returns count inserted/updated."""
    sql = """
        INSERT INTO cve_database
            (cve_id, description, cvss_score, cvss_vector, cvss_version,
             severity, published, modified, cve_references, affected_products, source)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (cve_id) DO UPDATE SET
            cvss_score = EXCLUDED.cvss_score,
            cvss_vector = EXCLUDED.cvss_vector,
            severity = EXCLUDED.severity,
            modified = EXCLUDED.modified,
            affected_products = EXCLUDED.affected_products
    """
    count = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for cve in cves:
                try:
                    pub = cve.get("published")
                    mod = cve.get("modified")
                    cur.execute(sql, (
                        cve.get("cve_id"),
                        cve.get("description", "")[:500],
                        cve.get("cvss_score", 0.0),
                        cve.get("cvss_vector", ""),
                        cve.get("cvss_version", ""),
                        cve.get("severity", "Unknown"),
                        pub[:19].replace("T"," ") if pub else None,
                        mod[:19].replace("T"," ") if mod else None,
                        json.dumps(cve.get("references", [])),
                        json.dumps(cve.get("affected_products", [])),
                        cve.get("source", "nvd")
                    ))
                    count += 1
                except Exception as e:
                    pass
    print(f"[DB] Upserted {count} CVEs")
    return count

def get_cves(severity: str = None, min_score: float = 0.0,
             limit: int = 100, search: str = None) -> list:
    """Query CVE database with filters."""
    conditions = ["cvss_score >= %s"]
    params = [min_score]
    if severity:
        conditions.append("severity = %s"); params.append(severity)
    if search:
        conditions.append("(cve_id ILIKE %s OR description ILIKE %s)")
        params += [f"%{search}%", f"%{search}%"]
    sql = f"""
        SELECT cve_id, description, cvss_score, cvss_vector, severity,
               published, modified, source
        FROM cve_database
        WHERE {' AND '.join(conditions)}
        ORDER BY cvss_score DESC, published DESC
        LIMIT %s
    """
    params.append(limit)
    with get_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

def get_cve_by_id(cve_id: str) -> dict:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM cve_database WHERE cve_id = %s", (cve_id,))
        row = cur.fetchone()
        return dict(row) if row else None

def get_cve_count() -> int:
    with get_cursor() as cur:
        cur.execute("SELECT COUNT(*) as n FROM cve_database")
        return cur.fetchone()["n"]

# ── Patch Records ──────────────────────────────────────────────────────────────

def upsert_patch_records(records: list) -> int:
    """Bulk upsert patch records."""
    sql = """
        INSERT INTO patch_records
            (cve_id, host_ip, hostname, package, current_version,
             fixed_version, status, cvss_score, severity, last_checked, notes)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (cve_id, host_ip) DO UPDATE SET
            status = EXCLUDED.status,
            last_checked = EXCLUDED.last_checked,
            fixed_version = EXCLUDED.fixed_version,
            notes = EXCLUDED.notes
    """
    count = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for r in records:
                try:
                    cur.execute(sql, (
                        r.get("cve_id"), r.get("host_ip"), r.get("hostname"),
                        r.get("package"), r.get("current_version"),
                        r.get("fixed_version"), r.get("status", "missing"),
                        r.get("cvss_score", 0.0), r.get("severity", "Unknown"),
                        r.get("last_checked", datetime.datetime.utcnow().isoformat()),
                        r.get("notes")
                    ))
                    count += 1
                except Exception:
                    pass
    return count

def get_patch_records(status: str = None, severity: str = None,
                      host_ip: str = None) -> list:
    conditions = ["1=1"]
    params = []
    if status:    conditions.append("status = %s");          params.append(status)
    if severity:  conditions.append("severity = %s");        params.append(severity)
    if host_ip:   conditions.append("host_ip::text = %s");   params.append(host_ip)
    sql = f"""
        SELECT cve_id, host_ip::text as host_ip, hostname, package,
               current_version, fixed_version, status, cvss_score, severity,
               last_checked, applied_at, notes
        FROM patch_records
        WHERE {' AND '.join(conditions)}
        ORDER BY cvss_score DESC
    """
    with get_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

def apply_patch(cve_id: str, host_ip: str, notes: str = "") -> bool:
    sql = """
        UPDATE patch_records
        SET status='applied', applied_at=NOW(), notes=%s
        WHERE cve_id=%s AND host_ip::text=%s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (notes, cve_id, host_ip))
            return cur.rowcount > 0

def get_patch_summary() -> dict:
    with get_cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status='missing')   as missing,
                COUNT(*) FILTER (WHERE status='available') as available,
                COUNT(*) FILTER (WHERE status='scheduled') as scheduled,
                COUNT(*) FILTER (WHERE status='applied')   as applied,
                COUNT(*) FILTER (WHERE status='wontfix')   as wontfix,
                COUNT(*) FILTER (WHERE severity='Critical' AND status='missing') as critical_missing,
                ROUND(
                    COUNT(*) FILTER (WHERE status='applied')::numeric /
                    NULLIF(COUNT(*),0) * 100, 1
                ) as patch_coverage_pct
            FROM patch_records
        """)
        row = dict(cur.fetchone())
        cur.execute("""
            SELECT cve_id FROM patch_records
            WHERE severity='Critical' AND status='missing'
        """)
        critical_cves = [r["cve_id"] for r in cur.fetchall()]

    return {
        "total_vulnerabilities": row["total"],
        "patch_coverage_pct": float(row["patch_coverage_pct"] or 0),
        "by_status": {
            "missing": row["missing"], "available": row["available"],
            "scheduled": row["scheduled"], "applied": row["applied"],
            "wontfix": row["wontfix"]
        },
        "critical_missing": row["critical_missing"],
        "critical_missing_cves": critical_cves
    }

# ── Risk Score History ─────────────────────────────────────────────────────────

def insert_risk_score(score_data: dict):
    """Persist a risk score computation."""
    sql = """
        INSERT INTO risk_score_history
            (score, level, color, voc_component, soc_component, ti_component,
             unpatched_cves, critical_unpatched, soc_alerts, active_incidents,
             threat_intel_hits)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    b = score_data.get("breakdown", {})
    i = score_data.get("inputs", {})
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                score_data.get("score"), score_data.get("level"),
                score_data.get("color"),
                b.get("voc_component"), b.get("soc_component"), b.get("ti_component"),
                i.get("unpatched_cves"), i.get("critical_unpatched"),
                i.get("soc_alerts"), i.get("active_incidents"), i.get("threat_intel_hits")
            ))

def get_risk_history(hours: int = 24, limit: int = 200) -> list:
    """Get risk score time-series for charting."""
    with get_cursor() as cur:
        cur.execute("""
            SELECT score, level, color, voc_component, soc_component, ti_component,
                   computed_at AT TIME ZONE 'UTC' as computed_at
            FROM risk_score_history
            WHERE computed_at >= NOW() - INTERVAL '%s hours'
            ORDER BY computed_at ASC
            LIMIT %s
        """, (hours, limit))
        return [dict(r) for r in cur.fetchall()]

def get_latest_risk_score() -> dict:
    with get_cursor() as cur:
        cur.execute("""
            SELECT score, level, color, voc_component, soc_component,
                   ti_component, computed_at AT TIME ZONE 'UTC' as computed_at
            FROM risk_score_history
            ORDER BY computed_at DESC LIMIT 1
        """)
        row = cur.fetchone()
        return dict(row) if row else {}

# ── Host Inventory ─────────────────────────────────────────────────────────────

def upsert_inventory(entries: list) -> int:
    sql = """
        INSERT INTO host_inventory (host_ip, hostname, os, package, version, scanned_at)
        VALUES (%s,%s,%s,%s,%s, NOW())
        ON CONFLICT (host_ip, package) DO UPDATE SET
            version = EXCLUDED.version, scanned_at = NOW()
    """
    count = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for e in entries:
                try:
                    cur.execute(sql, (
                        e.get("host_ip"), e.get("hostname"), e.get("os"),
                        e.get("package"), e.get("version")
                    ))
                    count += 1
                except Exception:
                    pass
    return count

def get_inventory_summary() -> dict:
    with get_cursor() as cur:
        cur.execute("""
            SELECT COUNT(DISTINCT host_ip) as total_hosts,
                   COUNT(*) as total_packages,
                   MAX(scanned_at) as last_scanned
            FROM host_inventory
        """)
        row = dict(cur.fetchone())
        cur.execute("""
            SELECT host_ip::text, hostname, os,
                   COUNT(*) as package_count, MAX(scanned_at) as scanned_at
            FROM host_inventory
            GROUP BY host_ip, hostname, os ORDER BY host_ip
        """)
        row["hosts"] = [dict(r) for r in cur.fetchall()]
    return row

# ── Attack Log ────────────────────────────────────────────────────────────────

def insert_attack(attack: dict) -> dict:
    sql = """
        INSERT INTO attack_log (attack_id, attacker_ip, victim_ip, attack_type, details)
        VALUES (%s,%s,%s,%s,%s)
        ON CONFLICT (attack_id) DO NOTHING
        RETURNING id
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                attack.get("id"),
                attack.get("attacker_ip"),
                attack.get("victim_ip"),
                attack.get("attack_type"),
                json.dumps(attack.get("details", {}))
            ))
    return attack

def get_attack_log(limit: int = 50) -> list:
    with get_cursor() as cur:
        cur.execute("""
            SELECT id, attack_id, attacker_ip::text, victim_ip::text,
                   attack_type, details,
                   launched_at AT TIME ZONE 'UTC' as launched_at
            FROM attack_log
            ORDER BY launched_at DESC LIMIT %s
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]

# ── Scan Reports ───────────────────────────────────────────────────────────────

def insert_scan_report(report: dict) -> str:
    sql = """
        INSERT INTO scan_reports
            (scan_id, network, mode, total_vulns, critical_count, high_count,
             medium_count, low_count, vt_enriched, results, vt_reports,
             started_at, completed_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (scan_id) DO NOTHING
    """
    sev = report.get("severity_summary", {})
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                report.get("scan_id"),
                report.get("network"),
                report.get("mode", "demo"),
                report.get("total_vulnerabilities", 0),
                sev.get("Critical", 0), sev.get("High", 0),
                sev.get("Medium", 0), sev.get("Low", 0),
                report.get("vt_enriched", 0),
                json.dumps(report.get("vulnerabilities", [])),
                json.dumps(report.get("vt_ip_reports", {})),
                report.get("started_at"),
                report.get("completed_at")
            ))
    return report.get("scan_id")

def get_scan_reports(limit: int = 20) -> list:
    with get_cursor() as cur:
        cur.execute("""
            SELECT scan_id, network, mode, total_vulns, critical_count,
                   high_count, medium_count, low_count, vt_enriched,
                   started_at AT TIME ZONE 'UTC' as started_at,
                   completed_at AT TIME ZONE 'UTC' as completed_at
            FROM scan_reports
            ORDER BY started_at DESC LIMIT %s
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]

# ── Compliance Snapshots ───────────────────────────────────────────────────────

def insert_compliance_snapshot(report: dict):
    sql = """
        INSERT INTO compliance_snapshots (framework, version, overall_score, status, controls)
        VALUES (%s,%s,%s,%s,%s)
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            for fw, data in report.get("frameworks", {}).items():
                cur.execute(sql, (
                    fw, data.get("version"),
                    data.get("overall_score_pct"),
                    data.get("status"),
                    json.dumps(data.get("controls", {}))
                ))

def get_compliance_trend(framework: str, days: int = 30) -> list:
    with get_cursor() as cur:
        cur.execute("""
            SELECT overall_score, status,
                   computed_at AT TIME ZONE 'UTC' as computed_at
            FROM compliance_snapshots
            WHERE framework = %s AND computed_at >= NOW() - INTERVAL '%s days'
            ORDER BY computed_at ASC
        """, (framework, days))
        return [dict(r) for r in cur.fetchall()]

# ── DB Stats (for dashboard) ───────────────────────────────────────────────────

def get_threat_intel_count() -> int:
    """Return count of threat intel entries seeded in DB."""
    try:
        with get_cursor() as cur:
            cur.execute("SELECT COUNT(*) as n FROM threat_intel")
            return cur.fetchone()["n"]
    except Exception:
        return 0


def get_db_stats() -> dict:
    """Return row counts for all tables — shown in dashboard DB tab."""
    tables = [
        "security_events", "cve_database", "patch_records",
        "scan_reports", "risk_score_history", "host_inventory",
        "attack_log", "compliance_snapshots", "threat_intel"
    ]
    stats = {}
    with get_cursor() as cur:
        for table in tables:
            try:
                cur.execute(f"SELECT COUNT(*) as n FROM {table}")
                stats[table] = cur.fetchone()["n"]
            except Exception:
                stats[table] = 0

        # DB size
        cur.execute("""
            SELECT pg_size_pretty(pg_database_size(current_database())) as size
        """)
        stats["db_size"] = cur.fetchone()["size"]

        # Latest event
        cur.execute("SELECT MAX(timestamp) as t FROM security_events")
        row = cur.fetchone()
        stats["latest_event"] = str(row["t"]) if row and row["t"] else None

    return stats


# ── Seed demo data ────────────────────────────────────────────────────────────

def seed_lab_data():
    """
    Seed database with lab demo data on first startup.
    Only runs if tables are empty.
    """
    # Check if already seeded
    with get_cursor() as cur:
        cur.execute("SELECT COUNT(*) as n FROM patch_records")
        if cur.fetchone()["n"] > 0:
            print("[DB] Already seeded — skipping")
            return

    print("[DB] Seeding threat intel and initial risk score only (CVEs populated by nmap scan)...")

    # Seed threat intel
    from ai.fr_ai_05_07 import STATIC_INTEL
    sql = """
        INSERT INTO threat_intel
            (intel_id, source, indicator_type, indicator, severity, description, tags, published)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (intel_id) DO NOTHING
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
    print(f"[DB] Seeded {len(STATIC_INTEL)} threat intel records")

    # Seed initial risk score
    from ai.fr_ai_01_risk_score import calculate_global_risk_score
    score = calculate_global_risk_score(soc_alerts=0, active_incidents=0, threat_intel_hits=11)
    insert_risk_score(score)

    print("[DB] Demo seed complete ✓")

# ── NOC Incident Management ──────────────────────────────────────────────────

def create_noc_incident(host, description, severity, status="Open", assigned_to="Unassigned"):
    """Insert a new NOC incident."""
    import uuid
    incident_id = f"NOC-{uuid.uuid4().hex[:8].upper()}"
    sql = """
        INSERT INTO noc_incidents (incident_id, host, description, severity, status, assigned_to)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING incident_id
    """
    with get_conn() as conn:
        with get_cursor(conn) as cur:
            cur.execute(sql, (incident_id, host, description, severity, status, assigned_to))
            
            # Log this creation to audit trail
            log_noc_action(
                action="CREATE_INCIDENT",
                module="INCIDENTS",
                details={"incident_id": incident_id, "host": host, "severity": severity},
                status="Success"
            )
            return cur.fetchone()["incident_id"]

def get_noc_incidents(status=None):
    """Retrieve NOC incidents with optional status filter."""
    if status:
        sql = "SELECT * FROM noc_incidents WHERE status = %s ORDER BY created_at DESC"
        params = (status,)
    else:
        sql = "SELECT * FROM noc_incidents ORDER BY created_at DESC"
        params = ()
    with get_cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()

def update_noc_incident(incident_id, status=None, notes=None, assigned_to=None):
    """Update an existing NOC incident."""
    updates = []
    params = []
    if status:
        updates.append("status = %s")
        params.append(status)
    if assigned_to:
        updates.append("assigned_to = %s")
        params.append(assigned_to)
    if notes:
        # In a real app, we'd have an activity log table. For now, append to description.
        updates.append("description = description || %s")
        params.append(f"\n\nUpdate: {notes}")
    
    if not updates:
        return False
        
    updates.append("updated_at = NOW()")
    params.append(incident_id)
    
    sql = f"UPDATE noc_incidents SET {', '.join(updates)} WHERE incident_id = %s"
    with get_conn() as conn:
        with get_cursor(conn) as cur:
            cur.execute(sql, tuple(params))
            
            # Log this update to audit trail
            log_noc_action(
                action="UPDATE_INCIDENT",
                module="INCIDENTS",
                details={"incident_id": incident_id, "status": status, "assigned_to": assigned_to, "notes": notes},
                status="Success"
            )
            return True

# ── NOC Audit Trail Functions ────────────────────────────────────────────────

def log_noc_action(action: str, module: str = "NOC", user_id: str = "system", details: dict = None, status: str = "Success"):
    """Insert a new NOC audit trail entry."""
    sql = """
        INSERT INTO noc_audit_trail (action, module, user_id, details, status)
        VALUES (%s, %s, %s, %s, %s)
    """
    with get_conn() as conn:
        with get_cursor(conn) as cur:
            cur.execute(sql, (action, module, user_id, json.dumps(details or {}), status))

def get_noc_audit_trail(limit: int = 100, module: str = None) -> list:
    """Retrieve NOC audit trail entries with optional module filter."""
    if module:
        sql = "SELECT * FROM noc_audit_trail WHERE module = %s ORDER BY timestamp DESC LIMIT %s"
        params = (module, limit)
    else:
        sql = "SELECT * FROM noc_audit_trail ORDER BY timestamp DESC LIMIT %s"
        params = (limit,)
    with get_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

# ── SOC Alert Archives ────────────────────────────────────────────────────────

SOC_ARCHIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_alert_archives (
    id              BIGSERIAL PRIMARY KEY,
    archive_id      VARCHAR(60) UNIQUE NOT NULL,
    filename        VARCHAR(200) NOT NULL,
    filepath        TEXT NOT NULL,
    total_alerts    INTEGER NOT NULL,
    min_level       INTEGER NOT NULL DEFAULT 3,
    date_from       TIMESTAMPTZ,
    date_to         TIMESTAMPTZ,
    sha256_hash     VARCHAR(64) NOT NULL,
    password_hint   VARCHAR(100) DEFAULT 'See ICOC-Lite admin',
    archived_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_by     VARCHAR(50) DEFAULT 'system',
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_soc_archives_time ON soc_alert_archives(archived_at DESC);
"""

def create_soc_archive_table():
    """Create the soc_alert_archives table if it doesn't exist."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(SOC_ARCHIVE_SCHEMA)

def insert_soc_archive(record: dict) -> str:
    """Persist archive metadata to PostgreSQL for forensic integrity tracking."""
    sql = """
        INSERT INTO soc_alert_archives
            (archive_id, filename, filepath, total_alerts, min_level,
             date_from, date_to, sha256_hash, password_hint, archived_by, notes)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (archive_id) DO NOTHING
        RETURNING archive_id
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                record["archive_id"],
                record["filename"],
                record["filepath"],
                record["total_alerts"],
                record.get("min_level", 3),
                record.get("date_from"),
                record.get("date_to"),
                record["sha256_hash"],
                record.get("password_hint", "See ICOC-Lite admin"),
                record.get("archived_by", "system"),
                record.get("notes"),
            ))
    return record["archive_id"]

def get_soc_archives(limit: int = 50) -> list:
    """List all SOC alert archives with their integrity hashes."""
    try:
        create_soc_archive_table()
        with get_cursor() as cur:
            cur.execute("""
                SELECT archive_id, filename, total_alerts, min_level,
                       date_from, date_to, sha256_hash, password_hint,
                       archived_at AT TIME ZONE 'UTC' as archived_at,
                       archived_by, notes
                FROM soc_alert_archives
                ORDER BY archived_at DESC
                LIMIT %s
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


if __name__ == "__main__":
    print("Testing database connection...")
    if test_connection():
        print("✓ Connected to PostgreSQL")
        create_schema()
        seed_lab_data()
        stats = get_db_stats()
        print("\nDatabase stats:")
        for table, count in stats.items():
            print(f"  {table:30s}: {count}")
    else:
        print("✗ Connection failed — check POSTGRES_URL in .env")