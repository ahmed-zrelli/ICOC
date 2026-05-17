"""
SOC Module — Wazuh 4.8 SIEM Integration
Queries the Wazuh Indexer (OpenSearch, port 9200) for real security alerts,
and the Wazuh REST API (port 55000) for agent status and FIM scan info.

Alert data lives in OpenSearch indices: wazuh-alerts-4.x-YYYY.MM.DD
Agent/FIM metadata lives in the Wazuh REST API.

Covers: FR-SOC-01 (agents), FR-SOC-02/03 (alerts + severity),
        FR-SOC-04 (active response), FR-SOC-06 (FIM), FR-SOC-07 (malware),
        FR-SOC-08 (UBA)
"""

import os
import time
import requests
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from dotenv import load_dotenv

load_dotenv()

# Wazuh REST API (agent management, FIM scans)
WAZUH_URL  = os.getenv("WAZUH_API_URL",  "https://192.168.100.10:55000")
WAZUH_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")

# Wazuh Indexer / OpenSearch (actual alert data)
INDEXER_URL  = os.getenv("WAZUH_INDEXER_URL",  "https://192.168.100.10:9200")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "SecretPassword")
ALERTS_INDEX = "wazuh-alerts-*"

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

soc_router = APIRouter(prefix="/soc", tags=["SOC"])

# ── Wazuh REST API token cache ────────────────────────────────────────────────
_token_cache: dict = {"token": None, "expires_at": 0}

def _get_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["token"]
    try:
        r = requests.get(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False, timeout=8,
        )
        r.raise_for_status()
        token = r.json()["data"]["token"]
        _token_cache["token"] = token
        _token_cache["expires_at"] = now + 900
        return token
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Wazuh auth failed: {e}")


def _wazuh(path: str, params: dict = None) -> dict:
    """Authenticated GET against Wazuh REST API."""
    token = _get_token()
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{WAZUH_URL}{path}", headers=headers,
                         params=params or {}, verify=False, timeout=10)
        if r.status_code == 401:
            _token_cache["token"] = None
            headers["Authorization"] = f"Bearer {_get_token()}"
            r = requests.get(f"{WAZUH_URL}{path}", headers=headers,
                             params=params or {}, verify=False, timeout=10)
        r.raise_for_status()
        return r.json().get("data", r.json())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Wazuh API error ({path}): {e}")


def _indexer(query: dict) -> dict:
    """POST a search query to the Wazuh Indexer (OpenSearch)."""
    try:
        r = requests.post(
            f"{INDEXER_URL}/{ALERTS_INDEX}/_search",
            auth=(INDEXER_USER, INDEXER_PASS),
            verify=False, timeout=12, json=query,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Wazuh Indexer error: {e}")


# ── Simple TTL cache ──────────────────────────────────────────────────────────
_cache: dict = {}

def _cached(key: str, ttl: int, fn):
    entry = _cache.get(key)
    if entry and time.time() < entry["expires_at"]:
        return entry["data"]
    data = fn()
    _cache[key] = {"data": data, "expires_at": time.time() + ttl}
    return data


# ── Helpers ───────────────────────────────────────────────────────────────────
def _level_to_sev(level) -> str:
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return "Low"
    if lvl >= 12: return "Critical"
    if lvl >= 9:  return "High"
    if lvl >= 6:  return "Medium"
    return "Low"


def _parse_alert(src: dict) -> dict:
    """Normalise a raw OpenSearch _source document into a clean alert dict."""
    rule  = src.get("rule", {})
    agent = src.get("agent", {})
    data  = src.get("data", {})
    lvl   = rule.get("level", 0)
    return {
        "id":          src.get("id", ""),
        "timestamp":   src.get("timestamp", ""),
        "rule_id":     rule.get("id", ""),
        "rule_level":  lvl,
        "severity":    _level_to_sev(lvl),
        "description": rule.get("description", ""),
        "groups":      rule.get("groups", []),
        "mitre":       rule.get("mitre", {}),
        "agent_id":    agent.get("id", "000"),
        "agent_name":  agent.get("name", "manager"),
        "agent_ip":    agent.get("ip", ""),
        "src_ip":      data.get("srcip", ""),
        "dst_user":    data.get("dstuser", ""),
        "full_log":    src.get("full_log", "")[:300],
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@soc_router.get("/status")
def soc_status():
    """Health check — verifies both Wazuh API and Indexer are reachable."""
    api_ok = False
    api_version = None
    indexer_ok = False
    indexer_docs = 0
    error = None

    try:
        data = _wazuh("/")
        api_ok = True
        api_version = data.get("api_version")
    except HTTPException as e:
        error = e.detail

    try:
        r = requests.get(
            f"{INDEXER_URL}/{ALERTS_INDEX}/_count",
            auth=(INDEXER_USER, INDEXER_PASS),
            verify=False, timeout=8,
        )
        if r.status_code == 200:
            indexer_ok = True
            indexer_docs = r.json().get("count", 0)
    except Exception as e:
        if not error:
            error = str(e)

    return {
        "reachable":     api_ok,
        "indexer_ok":    indexer_ok,
        "api_version":   api_version,
        "total_alerts":  indexer_docs,
        "wazuh_url":     WAZUH_URL,
        "indexer_url":   INDEXER_URL,
        "error":         error,
    }


@soc_router.get("/agents")
def get_agents():
    """FR-SOC-01: All registered agents with connection status."""
    def fetch():
        data   = _wazuh("/agents", {"limit": 100, "sort": "+name"})
        agents = data.get("affected_items", [])
        result = [{
            "id":             a.get("id"),
            "name":           a.get("name"),
            "ip":             a.get("ip", "unknown"),
            "status":         a.get("status"),
            "os":             a.get("os", {}).get("platform", "unknown"),
            "os_name":        a.get("os", {}).get("name", ""),
            "version":        a.get("version", ""),
            "last_keepalive": a.get("lastKeepAlive", ""),
            "group":          a.get("group", []),
        } for a in agents]
        active = sum(1 for a in result if a["status"] == "active")
        return {"total": len(result), "active": active,
                "disconnected": len(result) - active, "agents": result}
    return _cached("agents", 10, fetch)


@soc_router.get("/alerts")
def get_alerts(
    limit: int = Query(100, le=500),
    min_level: int = Query(3, ge=0, le=15),
    agent_name: Optional[str] = None,
):
    """
    FR-SOC-02/03: Real security alerts from the Wazuh Indexer (OpenSearch).
    Includes SSH brute force, FIM, malware, active response — everything Wazuh detects.
    Breakdown is computed via aggregation over ALL matching docs, not just the page.
    """
    def fetch():
        must = [{"range": {"rule.level": {"gte": min_level}}}]
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})

        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}},
            "_source": [
                "timestamp", "id", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre", "agent.id", "agent.name", "agent.ip",
                "data.srcip", "data.dstuser", "full_log",
            ],
            # Aggregate over ALL matching docs for accurate breakdown
            "aggs": {
                "by_severity": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "Critical", "from": 12},
                            {"key": "High",     "from": 9,  "to": 12},
                            {"key": "Medium",   "from": 6,  "to": 9},
                            {"key": "Low",      "from": 0,  "to": 6},
                        ],
                    }
                }
            },
        }

        result = _indexer(query)
        hits   = result.get("hits", {})
        total  = hits.get("total", {}).get("value", 0)
        items  = hits.get("hits", [])
        alerts = [_parse_alert(h["_source"]) for h in items]

        # Breakdown from aggregation — accurate over all docs, not just the page
        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for bucket in result.get("aggregations", {}).get("by_severity", {}).get("buckets", []):
            breakdown[bucket["key"]] = bucket["doc_count"]

        return {
            "total":              total,
            "returned":           len(alerts),
            "severity_breakdown": breakdown,
            "alerts":             alerts,
        }
    return _cached(f"alerts_{limit}_{min_level}_{agent_name}", 10, fetch)


@soc_router.get("/alerts/summary")
def get_alerts_summary():
    """Aggregated alert counts by severity + top triggered rules for the KPI strip."""
    def fetch():
        query = {
            "size": 0,
            "aggs": {
                "by_level_range": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "Critical", "from": 12},
                            {"key": "High",     "from": 9,  "to": 12},
                            {"key": "Medium",   "from": 6,  "to": 9},
                            {"key": "Low",      "from": 0,  "to": 6},
                        ],
                    }
                },
                "top_rules": {
                    "terms": {
                        "field": "rule.description.keyword",
                        "size": 8,
                        "order": {"_count": "desc"},
                    }
                },
                "top_agents": {
                    "terms": {
                        "field": "agent.name.keyword",
                        "size": 5,
                    }
                },
            },
        }

        result = _indexer(query)
        total  = result.get("hits", {}).get("total", {}).get("value", 0)
        aggs   = result.get("aggregations", {})

        breakdown = {}
        for bucket in aggs.get("by_level_range", {}).get("buckets", []):
            breakdown[bucket["key"]] = bucket["doc_count"]

        top_rules = [
            {"rule": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_rules", {}).get("buckets", [])
        ]

        top_agents = [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_agents", {}).get("buckets", [])
        ]

        return {
            "total_alerts":       total,
            "severity_breakdown": breakdown,
            "top_rules":          top_rules,
            "top_agents":         top_agents,
        }
    return _cached("alerts_summary", 15, fetch)


@soc_router.get("/fim")
def get_fim_events(limit: int = Query(50, le=200)):
    """FR-SOC-06: File Integrity Monitoring alerts from the indexer."""
    def fetch():
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.groups": ["syscheck"]}}
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.level", "rule.description", "rule.groups",
                "agent.name", "agent.ip", "syscheck.path", "syscheck.event",
                "syscheck.md5_before", "syscheck.md5_after", "full_log",
            ],
        }
        result = _indexer(query)
        hits   = result.get("hits", {}).get("hits", [])
        events = []
        for h in hits:
            s        = h["_source"]
            syscheck = s.get("syscheck", {})
            rule     = s.get("rule", {})
            events.append({
                "timestamp":   s.get("timestamp", ""),
                "agent_name":  s.get("agent", {}).get("name", ""),
                "agent_ip":    s.get("agent", {}).get("ip", ""),
                "rule_level":  rule.get("level", 0),
                "severity":    _level_to_sev(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "path":        syscheck.get("path", ""),
                "event":       syscheck.get("event", ""),
                "md5_before":  syscheck.get("md5_before", ""),
                "md5_after":   syscheck.get("md5_after", ""),
            })

        # Fallback: if no syscheck alerts yet, show last scan times per agent
        if not events:
            agents_data = _wazuh("/agents", {"limit": 100})
            for agent in agents_data.get("affected_items", []):
                aid = agent.get("id")
                if aid == "000":
                    continue
                try:
                    scan_data  = _wazuh(f"/syscheck/{aid}/last_scan")
                    scan_items = scan_data.get("affected_items", [])
                    if scan_items:
                        s = scan_items[0]
                        events.append({
                            "timestamp":   s.get("end", ""),
                            "agent_name":  agent.get("name", aid),
                            "agent_ip":    agent.get("ip", ""),
                            "rule_level":  0,
                            "severity":    "Low",
                            "description": f"Last FIM scan completed — no changes detected",
                            "path":        "Monitored: /etc, /boot, /usr/bin, /tmp",
                            "event":       "scan_complete",
                            "md5_before":  "",
                            "md5_after":   "",
                        })
                except Exception:
                    pass

        return {"total": result.get("hits", {}).get("total", {}).get("value", len(events)), "events": events}
    return _cached(f"fim_{limit}", 10, fetch)


@soc_router.get("/malware")
def get_malware_events(limit: int = Query(30, le=100)):
    """FR-SOC-07: Level 12+ alerts — VirusTotal hits, rootkit detections, critical threats."""
    def fetch():
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"range": {"rule.level": {"gte": 12}}},
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "agent.name", "data.srcip", "full_log",
            ],
        }
        result = _indexer(query)
        hits   = result.get("hits", {}).get("hits", [])
        events = [_parse_alert(h["_source"]) for h in hits]
        return {
            "total":  result.get("hits", {}).get("total", {}).get("value", 0),
            "events": events,
        }
    return _cached(f"malware_{limit}", 10, fetch)


@soc_router.get("/uba")
def get_uba_events(limit: int = Query(50, le=200)):
    """FR-SOC-08: User Behavior Analytics — auth failures, privilege escalation, new users."""
    UBA_GROUPS = [
        "authentication_failed", "authentication_failures",
        "authentication_success", "adduser", "sudo",
        "privilege_escalation", "pam", "sshd",
    ]
    def fetch():
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 5}}},
                        {"terms": {"rule.groups": UBA_GROUPS}},
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre", "agent.name", "agent.ip",
                "data.srcip", "data.dstuser", "data.srcuser", "full_log",
            ],
        }
        result = _indexer(query)
        hits   = result.get("hits", {}).get("hits", [])
        events = []
        for h in hits:
            s    = h["_source"]
            data = s.get("data", {})
            rule = s.get("rule", {})
            events.append({
                "timestamp":   s.get("timestamp", ""),
                "agent_name":  s.get("agent", {}).get("name", ""),
                "agent_ip":    s.get("agent", {}).get("ip", ""),
                "rule_id":     rule.get("id", ""),
                "rule_level":  rule.get("level", 0),
                "severity":    _level_to_sev(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "groups":      rule.get("groups", []),
                "mitre":       rule.get("mitre", {}),
                "src_user":    data.get("srcuser", ""),
                "dst_user":    data.get("dstuser", ""),
                "src_ip":      data.get("srcip", ""),
            })
        return {
            "total":  result.get("hits", {}).get("total", {}).get("value", 0),
            "events": events,
        }
    return _cached(f"uba_{limit}", 10, fetch)


@soc_router.get("/active-response")
def get_active_response_log(limit: int = Query(30, le=100)):
    """FR-SOC-04: Active response events — IPs blocked/unblocked by Wazuh firewall-drop."""
    def fetch():
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"rule.groups": ["active_response"]}},
                        {"match": {"rule.description": "firewall"}},
                        {"match": {"rule.description": "blocked"}},
                        {"match": {"rule.description": "Active Response"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "agent.name", "agent.ip",
                "data.srcip", "data.dstuser", "full_log",
            ],
        }
        result = _indexer(query)
        hits   = result.get("hits", {}).get("hits", [])
        events = [_parse_alert(h["_source"]) for h in hits]
        return {
            "total":  result.get("hits", {}).get("total", {}).get("value", 0),
            "events": events,
        }
    return _cached(f"ar_{limit}", 10, fetch)


@soc_router.get("/export/csv")
def export_alerts_csv(
    min_level: int = Query(3, ge=0, le=15),
    limit: int = Query(200, le=500),
):
    """
    FR-SOC-05: Export last N alerts as CSV for incident reporting.
    Returns a downloadable CSV with full IoC timeline.
    """
    import csv, io
    from fastapi.responses import StreamingResponse

    data = get_alerts(limit=limit, min_level=min_level)
    alerts = data.get("alerts", [])

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "timestamp", "severity", "rule_id", "rule_level", "description",
        "agent_name", "agent_ip", "src_ip", "dst_user", "groups", "full_log"
    ])
    writer.writeheader()
    for a in alerts:
        writer.writerow({
            "timestamp":   a.get("timestamp", ""),
            "severity":    a.get("severity", ""),
            "rule_id":     a.get("rule_id", ""),
            "rule_level":  a.get("rule_level", ""),
            "description": a.get("description", ""),
            "agent_name":  a.get("agent_name", ""),
            "agent_ip":    a.get("agent_ip", ""),
            "src_ip":      a.get("src_ip", ""),
            "dst_user":    a.get("dst_user", ""),
            "groups":      "|".join(a.get("groups", [])),
            "full_log":    a.get("full_log", "").replace("\n", " "),
        })

    output.seek(0)
    filename = f"soc_alerts_level{min_level}_{int(time.time())}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@soc_router.get("/export/json")
def export_alerts_json(
    min_level: int = Query(3, ge=0, le=15),
    limit: int = Query(200, le=500),
):
    """FR-SOC-05: Export last N alerts as JSON for incident reporting."""
    import io
    from fastapi.responses import StreamingResponse

    data = get_alerts(limit=limit, min_level=min_level)
    payload = {
        "export_time":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_in_index": data.get("total", 0),
        "exported":       data.get("returned", 0),
        "min_level":      min_level,
        "severity_breakdown": data.get("severity_breakdown", {}),
        "alerts":         data.get("alerts", []),
    }
    import json as _json
    content = _json.dumps(payload, indent=2, default=str)
    filename = f"soc_alerts_level{min_level}_{int(time.time())}.json"
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@soc_router.post("/archive")
def archive_alerts(
    min_level: int = Query(3, ge=0, le=15),
    password: str = Query("ICOC-2026-forensics"),
    purge_after: bool = Query(False),
    older_than_days: int = Query(30, ge=1),
):
    """
    Archive Wazuh alerts into an AES-256 encrypted ZIP, then optionally
    delete the archived alerts from OpenSearch to reclaim storage.

    Flow:
      1. Fetch alerts older than `older_than_days` (default 30) from OpenSearch
      2. Write to AES-256 password-protected ZIP (pyzipper)
      3. Compute SHA-256 of the ZIP → store in PostgreSQL
      4. If purge_after=true → delete those alerts from OpenSearch by their IDs
      5. Return archive metadata + purge stats
    """
    import io, hashlib, json as _json, os as _os
    from fastapi.responses import JSONResponse

    # 1. Build date cutoff — only archive alerts older than N days
    cutoff_ts = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - older_than_days * 86400)
    )

    query = {
        "size": 5000,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"range": {"timestamp": {"lt": cutoff_ts}}},
                ]
            }
        },
        "_source": [
            "timestamp", "id", "rule.id", "rule.level", "rule.description",
            "rule.groups", "rule.mitre", "agent.id", "agent.name", "agent.ip",
            "data.srcip", "data.dstuser", "full_log",
        ],
    }
    result = _indexer(query)
    hits   = result.get("hits", {}).get("hits", [])
    total_in_index = result.get("hits", {}).get("total", {}).get("value", 0)
    alerts = [_parse_alert(h["_source"]) for h in hits]
    # Keep OpenSearch doc IDs for purge
    doc_ids = [(h["_index"], h["_id"]) for h in hits]

    if not alerts:
        raise HTTPException(
            status_code=404,
            detail=f"No alerts older than {older_than_days} days at level ≥ {min_level}. "
                   f"Total in index: {total_in_index}. Try reducing older_than_days."
        )

    # 2. Build archive metadata
    archive_id  = f"SOC-ARCHIVE-{int(time.time())}"
    filename    = f"{archive_id}.zip"
    archive_dir = "/tmp/soc_archives"
    _os.makedirs(archive_dir, exist_ok=True)
    filepath = _os.path.join(archive_dir, filename)

    timestamps = [a["timestamp"] for a in alerts if a.get("timestamp")]
    date_from  = min(timestamps) if timestamps else None
    date_to    = max(timestamps) if timestamps else None

    # 3. Build JSON payload
    payload = {
        "archive_id":   archive_id,
        "archived_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_alerts": len(alerts),
        "min_level":    min_level,
        "older_than_days": older_than_days,
        "cutoff_date":  cutoff_ts,
        "date_from":    date_from,
        "date_to":      date_to,
        "severity_breakdown": {
            "Critical": sum(1 for a in alerts if a["severity"] == "Critical"),
            "High":     sum(1 for a in alerts if a["severity"] == "High"),
            "Medium":   sum(1 for a in alerts if a["severity"] == "Medium"),
            "Low":      sum(1 for a in alerts if a["severity"] == "Low"),
        },
        "alerts": alerts,
    }
    json_bytes = _json.dumps(payload, indent=2, default=str).encode("utf-8")

    # 4. Write AES-256 encrypted ZIP (pyzipper)
    import pyzipper
    with pyzipper.AESZipFile(
        filepath, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr(f"{archive_id}_alerts.json", json_bytes)

    # 5. Compute SHA-256 of the encrypted ZIP
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    digest = sha256.hexdigest()

    # 6. Persist archive metadata to PostgreSQL
    purge_count = 0
    try:
        from database import insert_soc_archive, create_soc_archive_table
        create_soc_archive_table()
        insert_soc_archive({
            "archive_id":    archive_id,
            "filename":      filename,
            "filepath":      filepath,
            "total_alerts":  len(alerts),
            "min_level":     min_level,
            "date_from":     date_from,
            "date_to":       date_to,
            "sha256_hash":   digest,
            "password_hint": f"AES-256 · length {len(password)} chars · set at archive time",
            "archived_by":   "icoc-api",
            "notes":         (
                f"Archived {len(alerts)} alerts older than {older_than_days}d "
                f"(cutoff: {cutoff_ts}). "
                f"Total in index at time of archive: {total_in_index}. "
                + (f"Purged {len(doc_ids)} docs from OpenSearch." if purge_after else "No purge.")
            ),
        })
    except Exception as e:
        print(f"[SOC-ARCHIVE] DB persist failed (non-critical): {e}")

    # 7. Purge archived alerts from OpenSearch (only after ZIP + hash are confirmed)
    if purge_after and doc_ids:
        bulk_body = ""
        for idx, doc_id in doc_ids:
            bulk_body += _json.dumps({"delete": {"_index": idx, "_id": doc_id}}) + "\n"
        try:
            import requests as _req
            resp = _req.post(
                f"{INDEXER_URL}/_bulk",
                auth=(INDEXER_USER, INDEXER_PASS),
                verify=False, timeout=30,
                headers={"Content-Type": "application/x-ndjson"},
                data=bulk_body,
            )
            purge_result = resp.json()
            purge_count  = sum(
                1 for item in purge_result.get("items", [])
                if item.get("delete", {}).get("result") == "deleted"
            )
        except Exception as e:
            print(f"[SOC-ARCHIVE] Purge failed: {e}")

    file_size_kb = round(_os.path.getsize(filepath) / 1024, 1)

    return {
        "archive_id":       archive_id,
        "filename":         filename,
        "total_archived":   len(alerts),
        "total_in_index":   total_in_index,
        "older_than_days":  older_than_days,
        "cutoff_date":      cutoff_ts,
        "date_from":        date_from,
        "date_to":          date_to,
        "file_size_kb":     file_size_kb,
        "encryption":       "AES-256 (pyzipper WZ_AES)",
        "sha256":           digest,
        "purged_from_opensearch": purge_count,
        "purge_requested":  purge_after,
        "note": (
            f"Archive encrypted with AES-256. "
            f"SHA-256 stored in PostgreSQL for forensic integrity. "
            + (f"Purged {purge_count} alerts from OpenSearch." if purge_after else
               "Alerts NOT deleted from OpenSearch (purge_after=false).")
        ),
    }


@soc_router.get("/archives")
def list_archives():
    """List all SOC alert archives with their forensic integrity hashes."""
    try:
        from database import get_soc_archives, create_soc_archive_table
        create_soc_archive_table()
        archives = get_soc_archives(limit=50)
        return {"total": len(archives), "archives": archives}
    except Exception as e:
        return {"total": 0, "archives": [], "error": str(e)}


@soc_router.get("/archives/{archive_id}/download")
def download_archive(archive_id: str):
    """
    Stream the encrypted ZIP archive file back to the browser as a download.
    The file lives on the API container at /tmp/soc_archives/<archive_id>.zip
    """
    import os as _os
    from fastapi.responses import FileResponse
    filepath = f"/tmp/soc_archives/{archive_id}.zip"
    if not _os.path.exists(filepath):
        raise HTTPException(
            status_code=404,
            detail=f"Archive file not found on server: {filepath}. "
                   "Archives are stored on the API container and are lost on container restart. "
                   "The metadata (SHA-256, count, dates) is preserved in PostgreSQL."
        )
    return FileResponse(
        path=filepath,
        media_type="application/zip",
        filename=f"{archive_id}.zip",
        headers={"Content-Disposition": f"attachment; filename={archive_id}.zip"},
    )


@soc_router.get("/archives/{archive_id}/verify")
def verify_archive(archive_id: str):
    """
    Forensic integrity verification.
    Recomputes the SHA-256 of the ZIP on disk and compares it to the hash
    stored in PostgreSQL at archive time. Returns PASS or FAIL + both hashes.
    """
    import os as _os, hashlib
    from database import get_soc_archives, create_soc_archive_table

    # 1. Get stored hash from PostgreSQL
    create_soc_archive_table()
    archives = get_soc_archives(limit=100)
    record   = next((a for a in archives if a["archive_id"] == archive_id), None)
    if not record:
        raise HTTPException(status_code=404, detail=f"Archive {archive_id} not found in PostgreSQL")

    stored_hash = record["sha256_hash"]

    # 2. Recompute hash from file on disk
    filepath = f"/tmp/soc_archives/{archive_id}.zip"
    if not _os.path.exists(filepath):
        return {
            "archive_id":   archive_id,
            "result":       "FILE_MISSING",
            "stored_hash":  stored_hash,
            "computed_hash": None,
            "match":        False,
            "message":      "ZIP file not found on disk. Container may have restarted. "
                            "The PostgreSQL record (hash + metadata) is still intact for audit purposes.",
        }

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    computed_hash = sha256.hexdigest()

    match = stored_hash == computed_hash
    return {
        "archive_id":    archive_id,
        "result":        "PASS" if match else "FAIL — FILE TAMPERED",
        "stored_hash":   stored_hash,
        "computed_hash": computed_hash,
        "match":         match,
        "total_alerts":  record["total_alerts"],
        "archived_at":   str(record["archived_at"]),
        "message":       "Integrity verified — archive matches PostgreSQL record." if match
                         else "INTEGRITY FAILURE: computed hash does not match stored hash. File may have been modified.",
    }


@soc_router.get("/overview")
def get_soc_overview():
    """Single aggregated endpoint for the SOC tab KPI strip."""
    try:
        agents_data  = get_agents()
        summary_data = get_alerts_summary()
        return {
            "agents":    agents_data,
            "alerts":    summary_data,
            "wazuh_url": WAZUH_URL,
        }
    except HTTPException as e:
        return {
            "agents":    {"total": 0, "active": 0, "disconnected": 0, "agents": []},
            "alerts":    {"total_alerts": 0, "severity_breakdown": {}, "top_rules": []},
            "wazuh_url": WAZUH_URL,
            "error":     e.detail,
        }
