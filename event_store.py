"""
Event Ingestion Engine — backed by PostgreSQL with in-memory cache fallback.
All events persisted to DB. Cache guarantees <30s latency (FR-AI-04).
"""
import os, time, datetime, threading
from typing import List, Optional, Dict
from collections import deque

_cache: deque = deque(maxlen=200)
_attack_cache: deque = deque(maxlen=50)
_lock = threading.Lock()
_ssh_fail_tracker: Dict[str, List[float]] = {}
_DB_AVAILABLE = False

# Deduplication: track (event_type, host_ip, src_ip) -> last_seen timestamp
# Prevents duplicate events when both installed agent and remote agent run
_dedup_window: Dict[str, float] = {}
_DEDUP_SECONDS = {
    # These fire once per occurrence — short window to catch real repeats
    "ssh_failed_auth":            3,
    "ssh_brute_force":            3,
    "ssh_login_success":          5,
    "port_scan_detected":        10,
    # These should only fire once per actual incident
    "file_integrity_violation":  30,
    "suspicious_file_drop":      30,
    "suspicious_process":        15,
    "reverse_shell_detected":    15,
    "unusual_outbound_connection": 15,
    # Heartbeats: one per agent per interval is fine, deduplicate tightly
    "heartbeat":                  8,
    # Agent start: only once
    "agent_started":             60,
}

def _try_db():
    global _DB_AVAILABLE
    try:
        from database import test_connection
        _DB_AVAILABLE = test_connection()
        if _DB_AVAILABLE:
            print("[EVENTS] PostgreSQL connected ✓")
    except Exception as e:
        print(f"[EVENTS] DB unavailable: {e} — using cache")
threading.Thread(target=_try_db, daemon=True).start()

def _now(): return datetime.datetime.utcnow().isoformat() + "Z"

def ingest_event(event: dict) -> dict:
    event["ingested_at"] = _now()
    event["id"] = event.get("id") or f"EVT-{int(time.time()*1000)}"
    data = event.get("data", {})

    # ── Deduplication ────────────────────────────────────────────────────────
    # Prevents double-firing when both installed agent and remote agent run.
    # Key = event_type + host_ip + src_ip (so different sources still count).
    etype  = event.get("event_type", "")
    window = _DEDUP_SECONDS.get(etype, 0)
    if window > 0:
        dedup_key = "{}|{}|{}".format(
            etype,
            event.get("host_ip", ""),
            data.get("src_ip", ""),
        )
        now_ts = time.time()
        last   = _dedup_window.get(dedup_key, 0)
        if now_ts - last < window:
            # Duplicate within window — silently drop
            return event
        _dedup_window[dedup_key] = now_ts

    # FR-SOC-02: brute-force counting
    if event.get("event_type") in ("ssh_failed_auth", "ssh_brute_force"):
        src = data.get("src_ip", "unknown")
        _ssh_fail_tracker.setdefault(src, [])
        now_ts = time.time()
        _ssh_fail_tracker[src] = [t for t in _ssh_fail_tracker[src] if now_ts-t < 300]
        _ssh_fail_tracker[src].append(now_ts)
        count = len(_ssh_fail_tracker[src])
        event["data"]["fail_count_5min"] = count
        if count >= 5:
            event["severity"] = "Critical"
            event["data"]["auto_block_triggered"] = True
            event["data"]["rule_triggered"] = "FR-SOC-02: >=5 failures in 5 min"

    critical_types = {"reverse_shell_detected","suspicious_file_drop",
                      "file_integrity_violation","cve_exploit_attempt","malware_dropped"}
    if event.get("event_type") in critical_types:
        event["severity"] = "Critical"

    if _DB_AVAILABLE:
        try:
            from database import insert_event
            insert_event(event)
        except Exception as e:
            print(f"[EVENTS] DB insert failed: {e}")

    with _lock:
        _cache.append(event)

    if event.get("severity") in ("Critical","High"):
        threading.Thread(target=_update_risk_score, daemon=True).start()
    return event

def ingest_attack(attack: dict) -> dict:
    attack["id"] = attack.get("id") or f"ATK-{int(time.time()*1000)}"
    attack["ingested_at"] = _now()
    if _DB_AVAILABLE:
        try:
            from database import insert_attack
            insert_attack(attack)
        except Exception as e:
            print(f"[EVENTS] Attack DB insert: {e}")
    with _lock:
        _attack_cache.append(attack)
    return attack

def _update_risk_score():
    try:
        from ai.fr_ai_01_risk_score import calculate_global_risk_score
        score = calculate_global_risk_score(
            soc_alerts=_get_alert_count_5min(),
            active_incidents=_get_incident_count(),
            threat_intel_hits=3)
        if _DB_AVAILABLE:
            from database import insert_risk_score
            insert_risk_score(score)
    except Exception:
        pass

def _get_alert_count_5min() -> int:
    if _DB_AVAILABLE:
        try:
            from database import get_event_stats
            return get_event_stats()["alert_count_5min"]
        except Exception:
            pass
    now_ts = time.time()
    with _lock:
        return sum(1 for e in _cache
                   if e.get("severity") in ("Critical","High"))

def _get_incident_count() -> int:
    incident_types = {"reverse_shell_detected","malware_dropped",
                      "ssh_login_success","file_integrity_violation"}
    with _lock:
        return sum(1 for e in _cache if e.get("event_type") in incident_types)

def get_events(limit=50, severity=None, event_type=None,
               since_seconds=None, host_ip=None) -> list:
    if _DB_AVAILABLE:
        try:
            from database import get_events as db_get
            return db_get(limit, severity, event_type, since_seconds, host_ip)
        except Exception:
            pass
    with _lock:
        events = list(reversed(list(_cache)))
    if severity:   events = [e for e in events if e.get("severity")==severity]
    if event_type: events = [e for e in events if e.get("event_type")==event_type]
    return events[:limit]

def get_attack_log(limit=50) -> list:
    if _DB_AVAILABLE:
        try:
            from database import get_attack_log as db_get
            return db_get(limit)
        except Exception:
            pass
    with _lock:
        return list(reversed(list(_attack_cache)))[:limit]

def get_live_stats() -> dict:
    if _DB_AVAILABLE:
        try:
            from database import get_event_stats, get_attack_log as db_atk
            stats = get_event_stats()
            atks = db_atk(1)
            stats["total_attacks"] = 0
            stats["latest_risk_score"] = {}
            stats["last_attack_at"] = atks[0].get("launched_at") if atks else None
            return stats
        except Exception:
            pass
    with _lock:
        events = list(_cache); attacks = list(_attack_cache)
    sev = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
    typ = {}
    for e in events:
        s=e.get("severity","Info"); sev[s]=sev.get(s,0)+1
        t=e.get("event_type","unknown"); typ[t]=typ.get(t,0)+1
    brute = {ip: len(ts) for ip,ts in _ssh_fail_tracker.items() if ts}
    return {"total_events":len(events),"total_attacks":len(attacks),
            "severity_breakdown":sev,"event_types":typ,
            "active_brute_force":brute,"latest_risk_score":{},
            "alert_count_5min":_get_alert_count_5min(),
            "incidents":_get_incident_count(),
            "last_event_at":events[-1].get("ingested_at") if events else None,
            "last_attack_at":attacks[-1].get("ingested_at") if attacks else None}

def load_persisted():
    if _DB_AVAILABLE:
        try:
            from database import get_events as db_get
            recent = db_get(limit=200)
            with _lock:
                for e in reversed(recent):
                    _cache.append(e)
            print(f"[EVENTS] Loaded {len(recent)} events from DB into cache")
        except Exception as e:
            print(f"[EVENTS] Could not load from DB: {e}")


def clear_all_events() -> dict:
    """
    Full demo reset:
    - Wipes all security events, attacks, SSH fail tracker, dedup window
    - Truncates DB event/attack/risk tables
    - Recalculates risk score at baseline (VOC-only, no SOC alerts)
    Returns the new baseline risk score so the frontend can update immediately.
    """
    global _dedup_window, _ssh_fail_tracker

    with _lock:
        cleared_events  = len(_cache)
        cleared_attacks = len(_attack_cache)
        _cache.clear()
        _attack_cache.clear()

    _ssh_fail_tracker = {}
    _dedup_window     = {}

    db_cleared = False
    if _DB_AVAILABLE:
        try:
            from database import get_conn
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("TRUNCATE TABLE security_events RESTART IDENTITY CASCADE")
                    cur.execute("TRUNCATE TABLE attack_log      RESTART IDENTITY CASCADE")
                    cur.execute("TRUNCATE TABLE risk_score_history RESTART IDENTITY CASCADE")
            db_cleared = True
            print("[EVENTS] DB tables cleared (security_events, attack_log, risk_score_history)")
        except Exception as e:
            print(f"[EVENTS] DB clear failed (non-critical): {e}")

    # Recalculate risk score at baseline — SOC is now 0, only VOC + TI remain
    baseline_score = None
    try:
        from ai.fr_ai_01_risk_score import calculate_global_risk_score
        from ai.fr_ai_05_07 import STATIC_INTEL
        baseline_score = calculate_global_risk_score(
            soc_alerts=0,
            active_incidents=0,
            threat_intel_hits=len(STATIC_INTEL),
        )
        if _DB_AVAILABLE:
            from database import insert_risk_score
            insert_risk_score(baseline_score)
        print(f"[EVENTS] Baseline risk score after reset: {baseline_score['score']}/100 ({baseline_score['level']})")
    except Exception as e:
        print(f"[EVENTS] Baseline recalc failed: {e}")

    print(f"[EVENTS] Reset complete — cleared {cleared_events} events, {cleared_attacks} attacks")
    return {
        "cleared_events":  cleared_events,
        "cleared_attacks": cleared_attacks,
        "db_cleared":      db_cleared,
        "status":          "ok",
        "baseline_score":  baseline_score,
    }
