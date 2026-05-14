import asyncio
import datetime
import aiohttp
from typing import Any, Dict, Optional
from config import config

# Max age of alerts to ingest (hours) - skip old stale alerts
MAX_ALERT_AGE_HOURS = config.WAZUH_MAX_ALERT_AGE_HOURS

# Skip alerts from offline agents (shutdown VMs)
SKIP_OFFLINE_AGENTS = not config.DEMO_MODE # Or some other logic if needed, config has it

# Wazuh API credentials for agent status check
WAZUH_API_URL = config.WAZUH_API_URL
WAZUH_API_USER = config.WAZUH_USER
WAZUH_API_PASS = config.WAZUH_PASS
WAZUH_VERIFY_TLS = config.WAZUH_VERIFY_TLS

# Cache for online agents (refresh every 60 seconds)
_agent_status_cache: Dict[str, tuple] = {}  # {agent_id: (is_active, timestamp)}
_agent_cache_timestamp = 0
_agent_cache_ttl = 60

_state: Dict[str, Any] = {
    "running": False,
    "source": None,
    "last_poll_at": None,
    "last_error": None,
    "ingested": 0,
    "dedup_dropped": 0,
    "skipped_too_old": 0,
    "skipped_offline_agent": 0,
    "max_age_hours": MAX_ALERT_AGE_HOURS,
    "skip_offline_agents": SKIP_OFFLINE_AGENTS,
    "last_seen_timestamp": None,
    "last_ingested_event_id": None,
}

_seen_ids = set()
_seen_ids_fifo = []


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


def _is_fresh_timestamp(ts: str) -> bool:
    """Check if alert timestamp is within acceptable age window."""
    if not ts:
        return False
    try:
        ts_clean = ts.replace('Z', '+00:00')
        alert_time = datetime.datetime.fromisoformat(ts_clean)
        now = datetime.datetime.now(datetime.timezone.utc)
        age_hours = (now - alert_time).total_seconds() / 3600
        return age_hours <= MAX_ALERT_AGE_HOURS
    except Exception:
        return True


async def _get_active_agent_ids() -> set:
    """Query Wazuh API for currently active (online) agents."""
    global _agent_status_cache, _agent_cache_timestamp
    
    import time
    now = time.time()
    if now - _agent_cache_timestamp < _agent_cache_ttl and _agent_status_cache:
        return {agent_id for agent_id, (is_active, _) in _agent_status_cache.items() if is_active}
    
    try:
        ssl_context = False if not WAZUH_VERIFY_TLS else None
        async with aiohttp.ClientSession() as session:
            # Authenticate
            auth = aiohttp.BasicAuth(WAZUH_API_USER, WAZUH_API_PASS)
            async with session.post(
                f"{WAZUH_API_URL}/security/user/authenticate",
                auth=auth,
                ssl=ssl_context,
                timeout=10
            ) as auth_resp:
                if auth_resp.status != 200:
                    return set()
                
                auth_data = await auth_resp.json()
                token = auth_data.get("data", {}).get("token")
                if not token:
                    return set()
            
            # Get agents list
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(
                f"{WAZUH_API_URL}/agents",
                headers=headers,
                params={"select": "id,status", "limit": 1000},
                ssl=ssl_context,
                timeout=15
            ) as agents_resp:
                if agents_resp.status != 200:
                    return set()
                
                agents_data = await agents_resp.json()
                agents = agents_data.get("data", {}).get("affected_items", [])
        
        # Cache agent status
        _agent_status_cache = {}
        active_ids = set()
        for agent in agents:
            agent_id = str(agent.get("id", ""))
            status = agent.get("status", "").lower()
            is_active = status == "active"
            _agent_status_cache[agent_id] = (is_active, now)
            if is_active:
                active_ids.add(agent_id)
        
        _agent_cache_timestamp = now
        return active_ids
        
    except Exception as e:
        print(f"[WAZUH] Failed to get agent status: {e}")
        return set()

async def _build_event_from_wazuh_hit(hit: dict, active_agents: set) -> Optional[dict]:
    src = hit.get("_source") or {}

    ts = src.get("@timestamp") or src.get("timestamp")
    if not ts:
        return None

    # Extract agent info early
    agent_id = _safe_get(src, "agent.id")
    agent_name = _safe_get(src, "agent.name")
    agent_ip = _safe_get(src, "agent.ip")
    
    # Skip old/stale alerts (e.g., from shutdown VMs)
    if not _is_fresh_timestamp(ts):
        return None
    
    # Skip alerts from offline agents (shutdown VMs)
    if SKIP_OFFLINE_AGENTS:
        if active_agents and agent_id and str(agent_id) not in active_agents:
            return None

    rule_level = _safe_get(src, "rule.level")
    rule_id = _safe_get(src, "rule.id")
    rule_desc = _safe_get(src, "rule.description")

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


async def _indexer_search(
    indexer_url: str,
    user: str,
    password: str,
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

    index_pattern = config.WAZUH_INDEXER_INDEX
    url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
    
    ssl_context = False if not verify_tls else None
    auth = aiohttp.BasicAuth(user, password)
    async with aiohttp.ClientSession() as session:
        async with session.post(url, auth=auth, json=query, timeout=10, ssl=ssl_context) as resp:
            return await resp.json()


async def _poll_loop():
    from event_store import ingest_event
    import time

    indexer_url = config.WAZUH_INDEXER_URL
    api_url = config.WAZUH_API_URL
    user = config.WAZUH_USER
    password = config.WAZUH_PASS

    verify_tls = config.WAZUH_VERIFY_TLS
    interval = config.WAZUH_POLL_INTERVAL_SECONDS

    source = None
    if indexer_url:
        source = "indexer"
    elif api_url:
        source = "api"

    _state["source"] = source

    if not source:
        _state["last_error"] = "Wazuh not configured: set WAZUH_INDEXER_URL or WAZUH_API_URL"
        return

    # Best-effort: Indexer pull is the stable method. API pull is not implemented here.
    if source != "indexer":
        _state["last_error"] = "Wazuh API polling not configured; set WAZUH_INDEXER_URL to ingest alerts"
        return

    if not (user and password):
        _state["last_error"] = "Wazuh credentials missing: set WAZUH_USER and WAZUH_PASS"
        return

    while True:
        try:
            since_ts = _state.get("last_seen_timestamp")

            data = await _indexer_search(
                indexer_url=indexer_url,
                user=user,
                password=password,
                verify_tls=verify_tls,
                since_ts=since_ts,
                size=200,
            )

            hits = ((data or {}).get("hits") or {}).get("hits") or []

            ingested = 0
            dedup = 0
            skipped_old = 0
            skipped_offline = 0
            last_ts = since_ts

            # Pre-fetch active agents once per poll cycle
            active_agents = await _get_active_agent_ids() if SKIP_OFFLINE_AGENTS else set()

            for hit in hits:
                hit_id = hit.get("_id")
                if not hit_id:
                    continue

                if hit_id in _seen_ids:
                    dedup += 1
                    continue

                src = hit.get("_source") or {}
                ts = src.get("@timestamp") or src.get("timestamp")
                
                # Check freshness first
                if ts and not _is_fresh_timestamp(ts):
                    skipped_old += 1
                    continue
                
                # Check agent status
                if SKIP_OFFLINE_AGENTS and active_agents:
                    agent_id = _safe_get(src, "agent.id")
                    if agent_id and str(agent_id) not in active_agents:
                        skipped_offline += 1
                        continue

                evt = await _build_event_from_wazuh_hit(hit, active_agents)
                if not evt:
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

            _state["last_poll_at"] = time.time()
            _state["last_error"] = None
            _state["ingested"] += ingested
            _state["dedup_dropped"] += dedup
            _state["skipped_too_old"] += skipped_old
            _state["skipped_offline_agent"] += skipped_offline
            _state["last_seen_timestamp"] = last_ts
            if hits:
                _state["last_ingested_event_id"] = f"WAZUH-{hits[-1].get('_id')}" if hits[-1].get('_id') else _state.get("last_ingested_event_id")

        except Exception as e:
            import time
            _state["last_poll_at"] = time.time()
            _state["last_error"] = str(e)

        await asyncio.sleep(max(2, interval))


def start_wazuh_poller() -> None:
    if _state.get("running"):
        return
    _state["running"] = True
    
    # Start as a background task if an event loop is already running
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_poll_loop())
    except RuntimeError:
        # If no loop is running, this might be called too early
        # main.py startup event should handle it
        pass


def get_wazuh_poller_status() -> dict:
    return dict(_state)
