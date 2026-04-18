import os
import time
import threading
from typing import Any, Dict, Optional

import requests


_state_lock = threading.Lock()
_state: Dict[str, Any] = {
    "running": False,
    "source": None,
    "last_poll_at": None,
    "last_error": None,
    "ingested": 0,
    "dedup_dropped": 0,
    "filtered_low_severity": 0,
    "min_rule_level": MIN_RULE_LEVEL,
    "last_seen_timestamp": None,
    "last_ingested_event_id": None,
}

_seen_ids = set()
_seen_ids_fifo = []


def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _level_to_severity(level: Any) -> str:
    try:
        lvl = int(level)
    except Exception:
        return "Info"

    if lvl >= 12:
        return "Critical"
    if lvl >= 7:
        return "High"
    if lvl >= 4:
        return "Medium"
    if lvl >= 1:
        return "Low"
    return "Info"


def _safe_get(d: dict, path: str, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


# Minimum severity to ingest (filters out noise)
# Levels: 0=Info, 1-3=Low, 4-6=Medium, 7-11=High, 12+=Critical
MIN_RULE_LEVEL = int(os.getenv("WAZUH_MIN_RULE_LEVEL", "4"))  # Default: Medium+

def _build_event_from_wazuh_hit(hit: dict) -> Optional[dict]:
    src = hit.get("_source") or {}

    ts = src.get("@timestamp") or src.get("timestamp")
    if not ts:
        return None

    rule_level = _safe_get(src, "rule.level")
    rule_id = _safe_get(src, "rule.id")
    rule_desc = _safe_get(src, "rule.description")

    # Filter out low-severity noise
    try:
        if rule_level is not None and int(rule_level) < MIN_RULE_LEVEL:
            return None
    except Exception:
        pass  # Keep alerts where level can't be parsed

    agent_id = _safe_get(src, "agent.id")
    agent_name = _safe_get(src, "agent.name")
    agent_ip = _safe_get(src, "agent.ip")

    src_ip = (
        _safe_get(src, "data.srcip")
        or _safe_get(src, "data.src_ip")
        or _safe_get(src, "srcip")
        or _safe_get(src, "src_ip")
    )

    summary = rule_desc or "Wazuh alert"

    return {
        "id": f"WAZUH-{hit.get('_id')}",
        "agent_id": f"wazuh:{agent_id or agent_name or 'unknown'}",
        "host_ip": agent_ip or "unknown",
        "hostname": agent_name or "unknown",
        "timestamp": ts,
        "event_type": "wazuh_alert",
        "severity": _level_to_severity(rule_level),
        "data": {
            "summary": summary,
            "src_ip": src_ip,
            "rule_triggered": f"wazuh_rule:{rule_id}" if rule_id else None,
            "wazuh": {
                "rule": {
                    "id": rule_id,
                    "level": rule_level,
                    "description": rule_desc,
                },
                "groups": _safe_get(src, "rule.groups"),
                "decoder": _safe_get(src, "decoder.name"),
                "manager": _safe_get(src, "manager.name"),
            },
            "raw": src,
        },
    }


def _indexer_search(
    indexer_url: str,
    auth: tuple[str, str],
    verify_tls: bool,
    since_ts: Optional[str],
    size: int,
) -> dict:
    query: Dict[str, Any] = {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"match_all": {}},
    }

    if since_ts:
        query["query"] = {"range": {"@timestamp": {"gt": since_ts}}}

    index_pattern = os.getenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-*").strip() or "wazuh-alerts-*"
    url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
    return requests.post(url, auth=auth, json=query, timeout=10, verify=verify_tls).json()


def _poll_loop():
    from event_store import ingest_event

    indexer_url = os.getenv("WAZUH_INDEXER_URL", "").strip()
    api_url = os.getenv("WAZUH_API_URL", "").strip()
    user = os.getenv("WAZUH_USER", "").strip()
    password = os.getenv("WAZUH_PASS", "").strip()

    verify_tls = _bool_env("WAZUH_VERIFY_TLS", False)
    interval = int(os.getenv("WAZUH_POLL_INTERVAL_SECONDS", "10"))

    source = None
    if indexer_url:
        source = "indexer"
    elif api_url:
        source = "api"

    with _state_lock:
        _state["source"] = source

    if not source:
        with _state_lock:
            _state["last_error"] = "Wazuh not configured: set WAZUH_INDEXER_URL or WAZUH_API_URL"
        return

    # Best-effort: Indexer pull is the stable method. API pull is not implemented here.
    if source != "indexer":
        with _state_lock:
            _state["last_error"] = "Wazuh API polling not configured; set WAZUH_INDEXER_URL to ingest alerts"
        return

    if not (user and password):
        with _state_lock:
            _state["last_error"] = "Wazuh credentials missing: set WAZUH_USER and WAZUH_PASS"
        return

    auth = (user, password)

    while True:
        try:
            with _state_lock:
                since_ts = _state.get("last_seen_timestamp")

            data = _indexer_search(
                indexer_url=indexer_url,
                auth=auth,
                verify_tls=verify_tls,
                since_ts=since_ts,
                size=200,
            )

            hits = ((data or {}).get("hits") or {}).get("hits") or []

            ingested = 0
            dedup = 0
            filtered = 0
            last_ts = since_ts

            for hit in hits:
                hit_id = hit.get("_id")
                if not hit_id:
                    continue

                if hit_id in _seen_ids:
                    dedup += 1
                    continue

                evt = _build_event_from_wazuh_hit(hit)
                if not evt:
                    filtered += 1  # Track filtered (low severity) events
                    continue

                _seen_ids.add(hit_id)
                _seen_ids_fifo.append(hit_id)
                if len(_seen_ids_fifo) > 5000:
                    # Keep memory bounded
                    for _ in range(1000):
                        if not _seen_ids_fifo:
                            break
                        old = _seen_ids_fifo.pop(0)
                        _seen_ids.discard(old)

                ingest_event(evt)
                ingested += 1

                ts = evt.get("timestamp")
                if ts and (last_ts is None or ts > last_ts):
                    last_ts = ts

            with _state_lock:
                _state["last_poll_at"] = time.time()
                _state["last_error"] = None
                _state["ingested"] += ingested
                _state["dedup_dropped"] += dedup
                _state["filtered_low_severity"] += filtered
                _state["last_seen_timestamp"] = last_ts
                if hits:
                    _state["last_ingested_event_id"] = f"WAZUH-{hits[-1].get('_id')}" if hits[-1].get('_id') else _state.get("last_ingested_event_id")

        except Exception as e:
            with _state_lock:
                _state["last_poll_at"] = time.time()
                _state["last_error"] = str(e)

        time.sleep(max(2, interval))


_poller_thread: Optional[threading.Thread] = None


def start_wazuh_poller() -> None:
    global _poller_thread

    with _state_lock:
        if _state.get("running"):
            return
        _state["running"] = True

    t = threading.Thread(target=_poll_loop, name="wazuh-poller", daemon=True)
    _poller_thread = t
    t.start()


def get_wazuh_poller_status() -> dict:
    with _state_lock:
        return dict(_state)
