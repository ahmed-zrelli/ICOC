"""
SOC Pipeline Module
===================
Real-time pipeline that continuously ingests Wazuh alerts into ICOC.

This module provides:
1. Background sync loop (configurable interval)
2. Real-time event streaming via Wazuh websocket (if available)
3. Alert batching and deduplication
4. Automatic incident escalation for Critical alerts

Usage:
    # Start continuous pipeline
    pipeline = start_soc_pipeline(interval_seconds=30)
    
    # Or run one-time sync
    pipeline = SOCPipeline()
    stats = pipeline.sync_now()
"""

import os
import time
import json
import threading
import datetime
from typing import Dict, List, Optional, Callable, Set
from collections import deque
from dataclasses import dataclass, field

from .soc_wazuh_bridge import WazuhBridge, get_wazuh_bridge


@dataclass
class PipelineStats:
    """Statistics for the SOC pipeline."""
    total_syncs: int = 0
    total_alerts_fetched: int = 0
    total_alerts_ingested: int = 0
    total_errors: int = 0
    last_sync_time: Optional[str] = None
    last_sync_status: str = "idle"
    current_alert_count: int = 0
    critical_escalations: int = 0
    deduplicated_alerts: int = 0


@dataclass
class AlertBuffer:
    """Buffer for alert deduplication and batching."""
    max_size: int = 1000
    ttl_seconds: int = 300
    
    _buffer: deque = field(default_factory=lambda: deque(maxlen=1000))
    _seen_hashes: Set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def _hash_alert(self, alert) -> str:
        """Generate hash for alert deduplication."""
        key = f"{alert.rule_id}:{alert.agent_id}:{alert.src_ip}:{alert.timestamp[:16]}"
        return key
    
    def add(self, alert) -> bool:
        """Add alert to buffer, returns True if new, False if duplicate."""
        alert_hash = self._hash_alert(alert)
        
        with self._lock:
            if alert_hash in self._seen_hashes:
                return False
            
            self._seen_hashes.add(alert_hash)
            self._buffer.append({
                "hash": alert_hash,
                "alert": alert,
                "added_at": time.time()
            })
            return True
    
    def get_unique_alerts(self, max_age_seconds: Optional[int] = None) -> List:
        """Get unique alerts, optionally filtering by age."""
        now = time.time()
        max_age = max_age_seconds or self.ttl_seconds
        
        with self._lock:
            # Clean old entries from seen_hashes
            cutoff = now - max_age
            valid_entries = [e for e in self._buffer if e["added_at"] > cutoff]
            self._buffer = deque(valid_entries, maxlen=self.max_size)
            self._seen_hashes = {e["hash"] for e in valid_entries}
            
            return [e["alert"] for e in valid_entries]
    
    def clear(self):
        """Clear the buffer."""
        with self._lock:
            self._buffer.clear()
            self._seen_hashes.clear()


class SOCPipeline:
    """
    Real-time SOC pipeline for Wazuh → ICOC integration.
    
    Features:
    - Automatic sync with configurable intervals
    - Alert deduplication (prevents duplicate ingestion)
    - Critical alert escalation
    - Statistics tracking
    - Callback hooks for custom processing
    """
    
    def __init__(
        self,
        bridge: Optional[WazuhBridge] = None,
        sync_interval: int = 30,
        lookback_minutes: int = 2,
        enable_deduplication: bool = True,
        enable_escalation: bool = True
    ):
        self.bridge = bridge or get_wazuh_bridge()
        self.sync_interval = sync_interval
        self.lookback_minutes = lookback_minutes
        self.enable_deduplication = enable_deduplication
        self.enable_escalation = enable_escalation
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        self.stats = PipelineStats()
        self.buffer = AlertBuffer() if enable_deduplication else None
        
        # Callbacks
        self.on_alert: List[Callable] = []
        self.on_critical: List[Callable] = []
        self.on_sync_complete: List[Callable] = []
        
        # Track escalated incidents to avoid duplicates
        self._escalated_alerts: Set[str] = set()
    
    def add_callback(self, event: str, callback: Callable):
        """Add callback for pipeline events.
        
        Events:
        - 'alert': Called for each ingested alert
        - 'critical': Called for Critical severity alerts
        - 'sync_complete': Called after each sync with stats dict
        """
        if event == "alert":
            self.on_alert.append(callback)
        elif event == "critical":
            self.on_critical.append(callback)
        elif event == "sync_complete":
            self.on_sync_complete.append(callback)
    
    def sync_now(self) -> Dict:
        """Perform one sync cycle immediately."""
        self.stats.last_sync_time = datetime.datetime.utcnow().isoformat() + "Z"
        self.stats.last_sync_status = "running"
        
        try:
            # Check connectivity
            if not self.bridge.check_connectivity():
                self.stats.last_sync_status = "error: no_connectivity"
                self.stats.total_errors += 1
                return {"status": "error", "message": "Wazuh API not reachable"}
            
            # Fetch alerts from Wazuh
            alerts = self.bridge.fetch_recent_alerts(minutes=self.lookback_minutes)
            self.stats.total_alerts_fetched += len(alerts)
            
            # Deduplicate if enabled
            if self.enable_deduplication and self.buffer:
                unique_alerts = []
                for alert in alerts:
                    if self.buffer.add(alert):
                        unique_alerts.append(alert)
                    else:
                        self.stats.deduplicated_alerts += 1
                alerts = unique_alerts
            
            # Process and escalate critical alerts
            critical_alerts = []
            for alert in alerts:
                # Fire alert callbacks
                for callback in self.on_alert:
                    try:
                        callback(alert)
                    except Exception as e:
                        print(f"[SOC-Pipeline] Alert callback error: {e}")
                
                # Handle critical alerts
                if alert.rule_level >= 9 and self.enable_escalation:
                    escalation_key = f"{alert.alert_id}:{alert.timestamp}"
                    if escalation_key not in self._escalated_alerts:
                        critical_alerts.append(alert)
                        self._escalated_alerts.add(escalation_key)
                        
                        for callback in self.on_critical:
                            try:
                                callback(alert)
                            except Exception as e:
                                print(f"[SOC-Pipeline] Critical callback error: {e}")
            
            # Escalate critical alerts to incidents
            if critical_alerts:
                self._escalate_critical_alerts(critical_alerts)
                self.stats.critical_escalations += len(critical_alerts)
            
            # Sync to ICOC
            if alerts:
                sync_result = self.bridge.sync_to_icoc(alerts)
                self.stats.total_alerts_ingested += sync_result.get("ingested", 0)
                self.stats.total_errors += sync_result.get("errors", 0)
            
            self.stats.total_syncs += 1
            self.stats.last_sync_status = "success"
            self.stats.current_alert_count = len(alerts)
            
            result = {
                "status": "success",
                "alerts_fetched": len(alerts),
                "alerts_ingested": len(alerts),
                "critical_escalated": len(critical_alerts),
                "sync_stats": self.stats.__dict__
            }
            
        except Exception as e:
            self.stats.last_sync_status = f"error: {str(e)}"
            self.stats.total_errors += 1
            result = {"status": "error", "message": str(e)}
            print(f"[SOC-Pipeline] Sync error: {e}")
        
        # Fire completion callbacks
        for callback in self.on_sync_complete:
            try:
                callback(result)
            except Exception as e:
                print(f"[SOC-Pipeline] Completion callback error: {e}")
        
        return result
    
    def _escalate_critical_alerts(self, critical_alerts: List):
        """Escalate critical alerts to incidents in ICOC."""
        try:
            from event_store import ingest_event
            
            for alert in critical_alerts:
                # Create incident event
                incident = {
                    "agent_id": f"wazuh-{alert.agent_id}",
                    "host_ip": alert.agent_ip,
                    "hostname": alert.agent_name,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "event_type": "incident_created",
                    "severity": "Critical",
                    "data": {
                        "wazuh_alert_id": alert.alert_id,
                        "wazuh_rule_id": alert.rule_id,
                        "original_rule_description": alert.rule_description,
                        "incident_type": "critical_alert_escalation",
                        "src_ip": alert.src_ip,
                        "dst_ip": alert.dst_ip,
                        "escalation_reason": f"Wazuh rule level {alert.rule_level} >= 9",
                        "auto_escalated": True,
                        "requires_immediate_response": True,
                        "summary": f"[ESCALATED] {alert.rule_description}",
                    }
                }
                ingest_event(incident)
                print(f"[SOC-Pipeline] Escalated critical alert to incident: {alert.rule_description}")
                
        except Exception as e:
            print(f"[SOC-Pipeline] Escalation error: {e}")
    
    def _sync_loop(self):
        """Background sync loop."""
        print(f"[SOC-Pipeline] Starting sync loop (interval: {self.sync_interval}s)")
        
        while not self._stop_event.is_set():
            try:
                self.sync_now()
            except Exception as e:
                print(f"[SOC-Pipeline] Loop error: {e}")
            
            # Wait for interval or stop signal
            self._stop_event.wait(timeout=self.sync_interval)
        
        print("[SOC-Pipeline] Sync loop stopped")
    
    def start(self) -> bool:
        """Start the background sync loop."""
        if self._running:
            print("[SOC-Pipeline] Already running")
            return False
        
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._thread.start()
        
        print(f"[SOC-Pipeline] Started (sync every {self.sync_interval}s)")
        return True
    
    def stop(self):
        """Stop the background sync loop."""
        if not self._running:
            return
        
        self._stop_event.set()
        self._running = False
        
        if self._thread:
            self._thread.join(timeout=5)
        
        print("[SOC-Pipeline] Stopped")
    
    def is_running(self) -> bool:
        """Check if pipeline is running."""
        return self._running and self._thread and self._thread.is_alive()
    
    def get_status(self) -> Dict:
        """Get current pipeline status."""
        return {
            "running": self.is_running(),
            "sync_interval": self.sync_interval,
            "lookback_minutes": self.lookback_minutes,
            "stats": self.stats.__dict__,
            "deduplication_enabled": self.enable_deduplication,
            "escalation_enabled": self.enable_escalation,
        }
    
    def reset_stats(self):
        """Reset pipeline statistics."""
        self.stats = PipelineStats()
        if self.buffer:
            self.buffer.clear()
        self._escalated_alerts.clear()


# Singleton pipeline instance
_pipeline_instance: Optional[SOCPipeline] = None


def start_soc_pipeline(
    interval_seconds: int = 30,
    lookback_minutes: int = 2,
    **kwargs
) -> SOCPipeline:
    """
    Start the global SOC pipeline singleton.
    
    Args:
        interval_seconds: How often to sync (default: 30s)
        lookback_minutes: How far back to fetch alerts (default: 2m)
        **kwargs: Additional arguments for SOCPipeline
    
    Returns:
        Running SOCPipeline instance
    """
    global _pipeline_instance
    
    if _pipeline_instance and _pipeline_instance.is_running():
        print("[SOC-Pipeline] Already running, returning existing instance")
        return _pipeline_instance
    
    _pipeline_instance = SOCPipeline(
        sync_interval=interval_seconds,
        lookback_minutes=lookback_minutes,
        **kwargs
    )
    _pipeline_instance.start()
    
    return _pipeline_instance


def stop_soc_pipeline():
    """Stop the global SOC pipeline."""
    global _pipeline_instance
    if _pipeline_instance:
        _pipeline_instance.stop()
        _pipeline_instance = None


def get_pipeline_status() -> Optional[Dict]:
    """Get status of the global pipeline."""
    global _pipeline_instance
    if _pipeline_instance:
        return _pipeline_instance.get_status()
    return None


if __name__ == "__main__":
    print("Testing SOC Pipeline...")
    
    # Create and run one-time sync
    pipeline = SOCPipeline(sync_interval=30, lookback_minutes=5)
    
    # Add example callbacks
    def on_alert(alert):
        print(f"  [Alert] {alert.rule_description} (Level {alert.rule_level})")
    
    def on_critical(alert):
        print(f"  [CRITICAL] ESCALATING: {alert.rule_description}")
    
    def on_complete(result):
        print(f"  [Sync Complete] Status: {result.get('status')}")
    
    pipeline.add_callback("alert", on_alert)
    pipeline.add_callback("critical", on_critical)
    pipeline.add_callback("sync_complete", on_complete)
    
    # Run one sync
    print("\nRunning one sync cycle...")
    result = pipeline.sync_now()
    print(f"\nResult: {json.dumps(result, indent=2, default=str)}")
    
    # Show stats
    print(f"\nPipeline Stats: {json.dumps(pipeline.stats.__dict__, indent=2, default=str)}")
    
    # Test continuous mode (run for 60 seconds)
    print("\n\nStarting continuous mode for 60 seconds...")
    pipeline.start()
    
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    
    pipeline.stop()
    print(f"\nFinal Stats: {json.dumps(pipeline.stats.__dict__, indent=2, default=str)}")
