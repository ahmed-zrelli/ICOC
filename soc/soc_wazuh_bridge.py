"""
SOC-Wazuh Bridge Module
=========================
Integrates Wazuh Manager API with ICOC-Lite VOC/NOC event system.

This module:
1. Connects to Wazuh Manager API (https://192.168.100.10:55000)
2. Fetches security alerts/alerts from agents
3. Converts Wazuh alerts to ICOC event format
4. Ingests events into the shared event_store

Usage:
    bridge = WazuhBridge()
    alerts = bridge.fetch_recent_alerts(minutes=5)
    bridge.sync_to_icoc(alerts)
"""

import os
import json
import time
import datetime
import urllib3
import requests
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from dotenv import load_dotenv

# Suppress SSL warnings for Wazuh self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


@dataclass
class WazuhAlert:
    """Represents a Wazuh alert normalized for ICOC ingestion."""
    alert_id: str
    timestamp: str
    agent_id: str
    agent_name: str
    agent_ip: str
    rule_id: int
    rule_description: str
    rule_level: int
    rule_groups: List[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    full_log: str
    location: str
    decoder: str


class WazuhBridge:
    """
    Bridge between Wazuh Manager API and ICOC-Lite event system.
    
    Config via environment variables:
    - WAZUH_API_URL: https://192.168.100.10:55000
    - WAZUH_API_USER: wazuh-wui
    - WAZUH_API_PASS: MyS3cr37P450r.*-
    - WAZUH_API_VERIFY_SSL: false
    """
    
    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL", "https://192.168.100.10:55000")
        self.username = os.getenv("WAZUH_API_USER", "wazuh-wui")
        self.password = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")
        self.verify_ssl = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() == "true"
        self.token: Optional[str] = None
        self.token_expires: float = 0
        
        # Mapping of Wazuh rule levels to ICOC severity
        self.level_to_severity = {
            0: "Info",
            1: "Info",
            2: "Info",
            3: "Low",
            4: "Low",
            5: "Medium",
            6: "Medium",
            7: "High",
            8: "High",
            9: "Critical",
            10: "Critical",
            11: "Critical",
            12: "Critical",
            13: "Critical",
            14: "Critical",
            15: "Critical",
        }
        
        # Mapping of Wazuh rule groups to ICOC event types
        self.group_to_event_type = {
            "web": "web_attack",
            "web_scan": "port_scan_detected",
            "scan": "port_scan_detected",
            "authentication_success": "ssh_login_success",
            "authentication_failed": "ssh_failed_auth",
            "authentication": "auth_event",
            "syscheck": "file_integrity_violation",
            "rootcheck": "rootkit_detection",
            "ids": "ids_alert",
            "firewall": "firewall_event",
            "malware": "malware_dropped",
            "syslog": "system_log",
            "ossec": "ossec_alert",
        }
    
    def _get_token(self) -> str:
        """Get or refresh JWT token from Wazuh API."""
        if self.token and time.time() < self.token_expires:
            return self.token
        
        auth_url = f"{self.base_url}/security/user/authenticate"
        try:
            resp = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            self.token = data["data"]["token"]
            # Token expires in 900 seconds (15 min), refresh at 10 min
            self.token_expires = time.time() + 600
            print(f"[SOC-Wazuh] Authenticated successfully, token expires in 10 min")
            return self.token
        except Exception as e:
            print(f"[SOC-Wazuh] Authentication failed: {e}")
            raise
    
    def _api_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make authenticated request to Wazuh API."""
        token = self._get_token()
        url = f"{self.base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {token}"}
        
        try:
            resp = requests.get(
                url,
                headers=headers,
                params=params,
                verify=self.verify_ssl,
                timeout=30
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 401:
                # Token expired, retry once
                self.token = None
                token = self._get_token()
                headers = {"Authorization": f"Bearer {token}"}
                resp = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    verify=self.verify_ssl,
                    timeout=30
                )
                resp.raise_for_status()
                return resp.json()
            raise
    
    def get_agents(self, status: Optional[str] = None) -> List[Dict]:
        """Get list of Wazuh agents.
        
        Args:
            status: Filter by status ('active', 'disconnected', etc.)
        
        Returns:
            List of agent dictionaries
        """
        params = {"limit": 100}
        if status:
            params["status"] = status
        
        data = self._api_request("/agents", params)
        return data.get("data", {}).get("affected_items", [])
    
    def get_agent_by_ip(self, ip: str) -> Optional[Dict]:
        """Find Wazuh agent by IP address."""
        agents = self.get_agents(status="active")
        for agent in agents:
            if agent.get("ip") == ip:
                return agent
        return None
    
    def fetch_alerts(
        self,
        agent_id: Optional[str] = None,
        minutes: int = 5,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[WazuhAlert]:
        """Fetch alerts from Wazuh API.
        
        Args:
            agent_id: Specific agent (None = all agents)
            minutes: Look back this many minutes
            severity: Filter by severity ('Critical', 'High', etc.)
            limit: Maximum alerts to fetch
        
        Returns:
            List of WazuhAlert objects
        """
        # Calculate time range
        now = datetime.datetime.utcnow()
        start_time = now - datetime.timedelta(minutes=minutes)
        
        # Wazuh uses timestamp format: 2024-01-15T10:30:00Z
        q_start = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Build query
        query = f"timestamp>{q_start}"
        if severity:
            # Map ICOC severity to Wazuh level ranges
            level_ranges = {
                "Critical": "(rule.level>8)",
                "High": "(rule.level>6 AND rule.level<=8)",
                "Medium": "(rule.level>4 AND rule.level<=6)",
                "Low": "(rule.level>2 AND rule.level<=4)",
                "Info": "(rule.level<=2)",
            }
            if severity in level_ranges:
                query += f";{level_ranges[severity]}"
        
        params = {
            "q": query,
            "limit": limit,
            "sort": "-timestamp",  # Newest first
        }
        
        endpoint = "/alerts"
        if agent_id and agent_id != "000":  # 000 is the manager itself
            endpoint = f"/agents/{agent_id}/alerts"
        
        try:
            data = self._api_request(endpoint, params)
            alerts_data = data.get("data", {}).get("affected_items", [])
            return [self._parse_alert(a) for a in alerts_data]
        except Exception as e:
            print(f"[SOC-Wazuh] Failed to fetch alerts: {e}")
            return []
    
    def fetch_recent_alerts(self, minutes: int = 5) -> List[WazuhAlert]:
        """Convenience method to fetch recent alerts from all agents."""
        return self.fetch_alerts(minutes=minutes)
    
    def _parse_alert(self, alert_data: Dict) -> WazuhAlert:
        """Parse raw Wazuh alert into WazuhAlert dataclass."""
        agent = alert_data.get("agent", {})
        rule = alert_data.get("rule", {})
        
        # Extract MITRE and other details from full_log if available
        full_log = alert_data.get("full_log", "")
        
        # Try to extract IPs from data fields
        data = alert_data.get("data", {})
        src_ip = data.get("srcip") or data.get("src_ip")
        dst_ip = data.get("dstip") or data.get("dst_ip")
        
        return WazuhAlert(
            alert_id=alert_data.get("id", f"wazuh-{int(time.time()*1000)}"),
            timestamp=alert_data.get("timestamp", datetime.datetime.utcnow().isoformat()),
            agent_id=agent.get("id", "unknown"),
            agent_name=agent.get("name", "unknown"),
            agent_ip=agent.get("ip", "unknown"),
            rule_id=rule.get("id", 0),
            rule_description=rule.get("description", "No description"),
            rule_level=rule.get("level", 0),
            rule_groups=rule.get("groups", []),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=data.get("srcport"),
            dst_port=data.get("dstport"),
            protocol=data.get("protocol"),
            md5=data.get("md5"),
            sha1=data.get("sha1"),
            sha256=data.get("sha256"),
            full_log=full_log,
            location=alert_data.get("location", ""),
            decoder=alert_data.get("decoder", {}).get("name", "")
        )
    
    def convert_to_icoc_event(self, alert: WazuhAlert) -> Dict:
        """Convert WazuhAlert to ICOC event_store format."""
        # Determine severity from rule level
        severity = self.level_to_severity.get(alert.rule_level, "Medium")
        
        # Determine event type from rule groups
        event_type = "unknown"
        for group in alert.rule_groups:
            if group in self.group_to_event_type:
                event_type = self.group_to_event_type[group]
                break
        
        # Special handling for specific rule IDs
        critical_rules = {
            5712: "ssh_brute_force",      # SSH brute force
            5701: "ssh_failed_auth",       # SSH failed auth
            5501: "ssh_login_success",     # SSH login success
            5502: "ssh_failed_auth",       # SSH failed password
            31101: "web_attack",           # Web attack
            31103: "sqli_attack",          # SQL injection
            31104: "lfi_attack",           # LFI/RFI attack
            100200: "reverse_shell_detected",  # Reverse shell
            550: "malware_dropped",         # Malware detection
        }
        
        if alert.rule_id in critical_rules:
            event_type = critical_rules[alert.rule_id]
            if alert.rule_id in [5712, 100200]:
                severity = "Critical"
        
        # Build ICOC event
        event = {
            "agent_id": f"wazuh-{alert.agent_id}",
            "host_ip": alert.agent_ip,
            "hostname": alert.agent_name,
            "timestamp": alert.timestamp,
            "event_type": event_type,
            "severity": severity,
            "data": {
                "wazuh_alert_id": alert.alert_id,
                "wazuh_rule_id": alert.rule_id,
                "wazuh_rule_description": alert.rule_description,
                "wazuh_rule_level": alert.rule_level,
                "wazuh_groups": alert.rule_groups,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "protocol": alert.protocol,
                "md5": alert.md5,
                "sha1": alert.sha1,
                "sha256": alert.sha256,
                "full_log": alert.full_log,
                "location": alert.location,
                "decoder": alert.decoder,
                "summary": alert.rule_description,
            }
        }
        
        return event
    
    def sync_to_icoc(self, alerts: List[WazuhAlert]) -> Dict:
        """Sync Wazuh alerts to ICOC event_store.
        
        Returns:
            Dict with sync statistics
        """
        stats = {"total": len(alerts), "ingested": 0, "errors": 0}
        
        for alert in alerts:
            try:
                event = self.convert_to_icoc_event(alert)
                
                # Import event_store and ingest
                from event_store import ingest_event
                ingest_event(event)
                stats["ingested"] += 1
                
            except Exception as e:
                print(f"[SOC-Wazuh] Failed to ingest alert {alert.alert_id}: {e}")
                stats["errors"] += 1
        
        print(f"[SOC-Wazuh] Synced {stats['ingested']}/{stats['total']} alerts to ICOC")
        return stats
    
    def get_stats(self) -> Dict:
        """Get Wazuh cluster and agent statistics."""
        try:
            # Get cluster status
            cluster_data = self._api_request("/cluster/status")
            
            # Get agents summary
            agents_data = self._api_request("/agents/summary/status")
            
            return {
                "cluster_enabled": cluster_data.get("data", {}).get("enabled", False),
                "cluster_status": cluster_data.get("data", {}).get("running", "unknown"),
                "total_agents": agents_data.get("data", {}).get("total", 0),
                "active_agents": agents_data.get("data", {}).get("active", 0),
                "disconnected_agents": agents_data.get("data", {}).get("disconnected", 0),
                "never_connected": agents_data.get("data", {}).get("never_connected", 0),
            }
        except Exception as e:
            print(f"[SOC-Wazuh] Failed to get stats: {e}")
            return {"error": str(e)}
    
    def check_connectivity(self) -> bool:
        """Check if Wazuh API is reachable."""
        try:
            self._get_token()
            return True
        except Exception:
            return False


# Singleton instance for reuse
_bridge_instance: Optional[WazuhBridge] = None


def get_wazuh_bridge() -> WazuhBridge:
    """Get or create singleton WazuhBridge instance."""
    global _bridge_instance
    if _bridge_instance is None:
        _bridge_instance = WazuhBridge()
    return _bridge_instance


if __name__ == "__main__":
    # Test the bridge
    print("Testing SOC-Wazuh Bridge...")
    bridge = WazuhBridge()
    
    # Check connectivity
    if bridge.check_connectivity():
        print("Wazuh API connection: OK")
        
        # Get stats
        stats = bridge.get_stats()
        print(f"Cluster stats: {json.dumps(stats, indent=2)}")
        
        # Get agents
        agents = bridge.get_agents(status="active")
        print(f"\nActive agents: {len(agents)}")
        for agent in agents:
            print(f"  - {agent.get('name')} ({agent.get('ip')}) - ID: {agent.get('id')}")
        
        # Fetch recent alerts
        print("\nFetching recent alerts...")
        alerts = bridge.fetch_recent_alerts(minutes=5)
        print(f"Found {len(alerts)} alerts in last 5 minutes")
        
        if alerts:
            print("\nSample alert:")
            sample = alerts[0]
            print(f"  Rule: {sample.rule_description}")
            print(f"  Level: {sample.rule_level}")
            print(f"  Agent: {sample.agent_name} ({sample.agent_ip})")
            print(f"  Timestamp: {sample.timestamp}")
        
        # Sync to ICOC
        if alerts:
            print("\nSyncing to ICOC...")
            sync_stats = bridge.sync_to_icoc(alerts)
            print(f"Sync complete: {sync_stats}")
    else:
        print("Wazuh API connection: FAILED")
        print("Please check:")
        print("  1. Wazuh Manager is running at 192.168.100.10")
        print("  2. API credentials are correct in .env")
        print("  3. Network connectivity to port 55000")
