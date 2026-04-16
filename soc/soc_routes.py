"""
SOC Routes Module
=================
FastAPI routes for SOC-Wazuh integration.

These endpoints allow the VOC/NOC frontend to:
1. Query Wazuh alerts through the ICOC API
2. Control the SOC pipeline (start/stop/configure)
3. View SOC statistics and status
4. Manually trigger Wazuh sync

All routes are prefixed with /soc
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import datetime

from .soc_wazuh_bridge import get_wazuh_bridge, WazuhAlert
from .soc_pipeline import (
    SOCPipeline, start_soc_pipeline, stop_soc_pipeline, get_pipeline_status
)

soc_router = APIRouter(prefix="/soc", tags=["SOC"])


# ── Pydantic Models ────────────────────────────────────────────────────────────

class PipelineConfig(BaseModel):
    """Configuration for SOC pipeline."""
    enabled: bool = True
    sync_interval_seconds: int = Field(default=30, ge=10, le=300)
    lookback_minutes: int = Field(default=2, ge=1, le=60)
    enable_deduplication: bool = True
    enable_escalation: bool = True


class SyncRequest(BaseModel):
    """Request to manually trigger a sync."""
    minutes: int = Field(default=5, ge=1, le=60)
    agent_id: Optional[str] = None
    severity: Optional[str] = None


class AlertResponse(BaseModel):
    """Response model for Wazuh alerts."""
    alert_id: str
    timestamp: str
    agent_id: str
    agent_name: str
    agent_ip: str
    rule_id: int
    rule_description: str
    rule_level: int
    rule_groups: List[str]
    severity: str
    event_type: str
    src_ip: Optional[str]
    dst_ip: Optional[str]


class PipelineStatusResponse(BaseModel):
    """Pipeline status response."""
    running: bool
    sync_interval: int
    lookback_minutes: int
    stats: Dict[str, Any]
    deduplication_enabled: bool
    escalation_enabled: bool


class WazuhStatsResponse(BaseModel):
    """Wazuh cluster statistics."""
    cluster_enabled: bool
    cluster_status: str
    total_agents: int
    active_agents: int
    disconnected_agents: int
    never_connected: int


class AgentInfo(BaseModel):
    """Wazuh agent information."""
    id: str
    name: str
    ip: str
    status: str
    os: Optional[str]
    version: Optional[str]


# ── Global Pipeline Instance ───────────────────────────────────────────────────

_pipeline: Optional[SOCPipeline] = None


def _get_or_create_pipeline(config: Optional[PipelineConfig] = None) -> SOCPipeline:
    """Get existing pipeline or create new one with config."""
    global _pipeline
    
    if _pipeline and _pipeline.is_running():
        return _pipeline
    
    if config:
        _pipeline = SOCPipeline(
            sync_interval=config.sync_interval_seconds,
            lookback_minutes=config.lookback_minutes,
            enable_deduplication=config.enable_deduplication,
            enable_escalation=config.enable_escalation
        )
    else:
        _pipeline = SOCPipeline()
    
    return _pipeline


# ── Routes ─────────────────────────────────────────────────────────────────────

@soc_router.get("/health", response_model=Dict[str, Any])
def soc_health():
    """Check SOC-Wazuh integration health."""
    bridge = get_wazuh_bridge()
    
    wazuh_ok = bridge.check_connectivity()
    pipeline_status = get_pipeline_status()
    
    return {
        "status": "ok" if wazuh_ok else "degraded",
        "wazuh_api_connected": wazuh_ok,
        "pipeline_running": pipeline_status.get("running", False) if pipeline_status else False,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }


@soc_router.get("/wazuh/stats", response_model=WazuhStatsResponse)
def get_wazuh_stats():
    """Get Wazuh cluster and agent statistics."""
    bridge = get_wazuh_bridge()
    
    if not bridge.check_connectivity():
        raise HTTPException(status_code=503, detail="Wazuh API not reachable")
    
    stats = bridge.get_stats()
    return WazuhStatsResponse(**stats)


@soc_router.get("/wazuh/agents", response_model=List[AgentInfo])
def get_wazuh_agents(
    status: Optional[str] = Query(None, description="Filter by status: active, disconnected"),
    ip: Optional[str] = Query(None, description="Find agent by IP")
):
    """Get list of Wazuh agents."""
    bridge = get_wazuh_bridge()
    
    if not bridge.check_connectivity():
        raise HTTPException(status_code=503, detail="Wazuh API not reachable")
    
    if ip:
        agent = bridge.get_agent_by_ip(ip)
        if agent:
            return [AgentInfo(
                id=agent.get("id", ""),
                name=agent.get("name", ""),
                ip=agent.get("ip", ""),
                status=agent.get("status", ""),
                os=agent.get("os", {}).get("name") if agent.get("os") else None,
                version=agent.get("version")
            )]
        return []
    
    agents = bridge.get_agents(status=status)
    return [
        AgentInfo(
            id=a.get("id", ""),
            name=a.get("name", ""),
            ip=a.get("ip", ""),
            status=a.get("status", ""),
            os=a.get("os", {}).get("name") if a.get("os") else None,
            version=a.get("version")
        )
        for a in agents
    ]


@soc_router.get("/wazuh/alerts", response_model=List[AlertResponse])
def get_wazuh_alerts(
    minutes: int = Query(5, ge=1, le=60, description="Look back this many minutes"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    severity: Optional[str] = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    limit: int = Query(100, ge=1, le=500)
):
    """
    Fetch Wazuh alerts directly from Wazuh API.
    
    This endpoint queries Wazuh Manager in real-time and returns
    normalized alerts that can be correlated with VOC data.
    """
    bridge = get_wazuh_bridge()
    
    if not bridge.check_connectivity():
        raise HTTPException(status_code=503, detail="Wazuh API not reachable")
    
    alerts = bridge.fetch_alerts(
        agent_id=agent_id,
        minutes=minutes,
        severity=severity,
        limit=limit
    )
    
    # Convert to response model with severity/event_type mapping
    response = []
    for alert in alerts:
        event = bridge.convert_to_icoc_event(alert)
        response.append(AlertResponse(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp,
            agent_id=alert.agent_id,
            agent_name=alert.agent_name,
            agent_ip=alert.agent_ip,
            rule_id=alert.rule_id,
            rule_description=alert.rule_description,
            rule_level=alert.rule_level,
            rule_groups=alert.rule_groups,
            severity=event["severity"],
            event_type=event["event_type"],
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip
        ))
    
    return response


@soc_router.post("/pipeline/start", response_model=PipelineStatusResponse)
def start_pipeline(config: Optional[PipelineConfig] = None):
    """
    Start the SOC pipeline for continuous Wazuh → ICOC sync.
    
    The pipeline will automatically:
    - Fetch new alerts from Wazuh every N seconds
    - Deduplicate alerts to prevent duplicates
    - Escalate Critical alerts to incidents
    - Sync all alerts to ICOC event_store
    """
    pipeline = _get_or_create_pipeline(config)
    
    if pipeline.is_running():
        # Already running, just return status
        return PipelineStatusResponse(**pipeline.get_status())
    
    pipeline.start()
    return PipelineStatusResponse(**pipeline.get_status())


@soc_router.post("/pipeline/stop", response_model=Dict[str, str])
def stop_pipeline():
    """Stop the SOC pipeline."""
    global _pipeline
    
    if _pipeline and _pipeline.is_running():
        _pipeline.stop()
        return {"status": "stopped", "message": "SOC pipeline stopped successfully"}
    
    return {"status": "idle", "message": "Pipeline was not running"}


@soc_router.get("/pipeline/status", response_model=Optional[PipelineStatusResponse])
def get_pipeline_status_endpoint():
    """Get current pipeline status and statistics."""
    global _pipeline
    
    if _pipeline:
        return PipelineStatusResponse(**_pipeline.get_status())
    
    # Return default if no pipeline exists
    return PipelineStatusResponse(
        running=False,
        sync_interval=30,
        lookback_minutes=2,
        stats={},
        deduplication_enabled=True,
        escalation_enabled=True
    )


@soc_router.post("/pipeline/sync", response_model=Dict[str, Any])
def manual_sync(req: SyncRequest, background: BackgroundTasks = None):
    """
    Manually trigger a one-time sync from Wazuh.
    
    This fetches alerts from the specified time range and
    ingests them into the ICOC event system.
    """
    pipeline = _get_or_create_pipeline()
    
    # Update lookback if specified
    if req.minutes != pipeline.lookback_minutes:
        pipeline.lookback_minutes = req.minutes
    
    # Run sync
    result = pipeline.sync_now()
    
    return {
        "status": result.get("status"),
        "alerts_fetched": result.get("alerts_fetched", 0),
        "alerts_ingested": result.get("alerts_ingested", 0),
        "critical_escalated": result.get("critical_escalated", 0),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }


@soc_router.post("/pipeline/reset")
def reset_pipeline_stats():
    """Reset pipeline statistics and clear deduplication buffer."""
    global _pipeline
    
    if _pipeline:
        _pipeline.reset_stats()
        return {"status": "reset", "message": "Pipeline statistics reset"}
    
    return {"status": "idle", "message": "No active pipeline to reset"}


@soc_router.get("/events/correlated")
def get_correlated_events(
    minutes: int = Query(30, ge=1, le=1440),
    host_ip: Optional[str] = None
):
    """
    Get events correlated between SOC (Wazuh) and VOC data.
    
    Returns security events that have matching vulnerabilities
    in the VOC database, enabling prioritization based on
    both threat detection (SOC) and vulnerability exposure (VOC).
    """
    from event_store import get_events
    from database import get_cves
    
    # Get recent SOC events
    events = get_events(limit=200, since_seconds=minutes*60, host_ip=host_ip)
    
    # Get all known vulnerable hosts from VOC
    try:
        cves = get_cves(limit=1000)
        vulnerable_hosts = {c.get("host_ip") for c in cves if c.get("host_ip")}
    except Exception:
        vulnerable_hosts = set()
    
    # Correlate: find events on hosts with known vulnerabilities
    correlated = []
    for event in events:
        event_ip = event.get("host_ip") or event.get("data", {}).get("src_ip")
        if event_ip in vulnerable_hosts:
            # Get CVEs for this host
            host_cves = [c for c in cves if c.get("host_ip") == event_ip]
            event["correlated_vulnerabilities"] = host_cves[:5]  # Top 5
            correlated.append(event)
    
    return {
        "total_events": len(events),
        "correlated_events": len(correlated),
        "vulnerable_hosts": len(vulnerable_hosts),
        "events": correlated[:50]  # Limit response
    }


@soc_router.get("/dashboard/summary")
def get_soc_dashboard_summary():
    """
    Get SOC summary for the integrated dashboard.
    
    Combines Wazuh stats, pipeline status, and recent alerts
    into a single response for dashboard display.
    """
    bridge = get_wazuh_bridge()
    pipeline_status = get_pipeline_status() or {}
    
    result = {
        "wazuh_connected": False,
        "pipeline_running": pipeline_status.get("running", False),
        "agents": {"total": 0, "active": 0, "disconnected": 0},
        "recent_alerts": {"total": 0, "critical": 0, "high": 0},
        "sync_stats": pipeline_status.get("stats", {}),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    
    try:
        if bridge.check_connectivity():
            result["wazuh_connected"] = True
            
            # Get agent stats
            stats = bridge.get_stats()
            result["agents"] = {
                "total": stats.get("total_agents", 0),
                "active": stats.get("active_agents", 0),
                "disconnected": stats.get("disconnected_agents", 0)
            }
            
            # Get recent alert counts by severity
            critical = bridge.fetch_alerts(minutes=15, severity="Critical", limit=100)
            high = bridge.fetch_alerts(minutes=15, severity="High", limit=100)
            
            result["recent_alerts"] = {
                "total": len(critical) + len(high),
                "critical": len(critical),
                "high": len(high)
            }
    except Exception as e:
        result["error"] = str(e)
    
    return result


# ── Initialization Helper ─────────────────────────────────────────────────────

def init_soc_pipeline_on_startup(auto_start: bool = True):
    """
    Initialize SOC pipeline on application startup.
    
    Call this from main.py to auto-start the pipeline.
    """
    if auto_start:
        try:
            pipeline = start_soc_pipeline(interval_seconds=30, lookback_minutes=2)
            print(f"[SOC] Pipeline auto-started successfully")
            return pipeline
        except Exception as e:
            print(f"[SOC] Failed to auto-start pipeline: {e}")
            return None
    return None
