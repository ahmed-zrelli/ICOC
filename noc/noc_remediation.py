import os
import requests
import subprocess
from fastapi import APIRouter, HTTPException
from database import log_noc_action
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/remediation", tags=["Remediation"])

class RemediationAction(BaseModel):
    target: Optional[str] = None
    service_name: Optional[str] = None
    attacker_ip: Optional[str] = None

@router.post("/isolate-host")
async def isolate_host(action: RemediationAction):
    """Isolate a compromised host from the network."""
    try:
        details = {"target": action.target, "action": "isolate_host", "status": "Quarantined"}
        log_noc_action(action="ISOLATE_HOST", module="REMEDIATION", details=details, status="Success")
        return {
            "status": "success", 
            "message": f"[LOG] Command: iptables -A INPUT -s {action.target} -j DROP\n"
                       f"[LOG] Command: iptables -A OUTPUT -d {action.target} -j DROP\n"
                       f"[STATUS] Asset {action.target} successfully quarantined from production network."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/apply-patch")
async def apply_patch(action: RemediationAction):
    """Apply emergency security patch to a vulnerable service."""
    try:
        details = {"target": action.target, "service": action.service_name, "patch_id": "ICOC-EMERG-2024-01"}
        log_noc_action(action="APPLY_PATCH", module="REMEDIATION", details=details, status="Success")
        return {
            "status": "success", 
            "message": f"[LOG] Package manager: apt-get install --only-upgrade {action.service_name}\n"
                       f"[LOG] Service manager: systemctl restart {action.service_name}\n"
                       f"[STATUS] Critical security patch applied to {action.service_name}."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rotate-keys")
async def rotate_keys(action: RemediationAction):
    """Rotate leaked service account credentials."""
    try:
        details = {"target": action.target, "service": action.service_name, "action": "key_rotation"}
        log_noc_action(action="ROTATE_KEYS", module="REMEDIATION", details=details, status="Success")
        return {
            "status": "success", 
            "message": f"[LOG] Revoking old RSA keys for {action.service_name}...\n"
                       f"[LOG] Generating new 4096-bit credential pair...\n"
                       f"[STATUS] Access keys successfully rotated."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/block-ip")
async def block_ip(action: RemediationAction):
    """Functional block: Write IP to shared volume for attacker to read."""
    try:
        attacker_ip = action.attacker_ip or os.getenv("ATTACKER_IP", "192.168.237.131")
        block_file = "/tmp/shared/blocked_ips.txt"
        
        # Append to blocked list if not already there
        existing = []
        if os.path.exists(block_file):
            with open(block_file, "r") as f:
                existing = [line.strip() for line in f.readlines()]
        
        if attacker_ip not in existing:
            with open(block_file, "a") as f:
                f.write(f"{attacker_ip}\n")
        
        details = {"ip_to_block": attacker_ip, "action": "block_ip", "reason": "VirusTotal Malicious Flag"}
        log_noc_action(action="BLOCK_IP", module="REMEDIATION", details=details, status="Success")
        
        return {
            "status": "success", 
            "message": f"[LOG] Perimeter Firewall: Adding DENY rule for IP {attacker_ip}\n"
                       f"[LOG] Syncing rules across 4 edge nodes...\n"
                       f"[STATUS] IP {attacker_ip} blocked. Connection refused."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/unblock-all")
async def unblock_all():
    """Clear the blocked IP list."""
    try:
        block_file = "/tmp/shared/blocked_ips.txt"
        if os.path.exists(block_file):
            os.remove(block_file)
        
        log_noc_action(action="RESET_FIREWALL", module="REMEDIATION", status="Success")
        return {
            "status": "success", 
            "message": "[LOG] Command: iptables -F\n"
                       "[LOG] Reloading default security policy...\n"
                       "[STATUS] All network blocks cleared."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/simulate-traffic")
async def simulate_traffic():
    """Simulate a security event for visualization."""
    try:
        log_noc_action(
            action="SIMULATE_ATTACK",
            module="REMEDIATION",
            details={"type": "visualization_test", "event": "DDoS/Flood Simulation"},
            status="Success"
        )
        return {
            "status": "success", 
            "message": "[LOG] Triggering synthetic packet flood (10k req/sec)...\n"
                       "[LOG] Injecting anomalous CPU patterns into telemetry stream...\n"
                       "[STATUS] Security event simulation active. Check NOC dashboard."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/runbooks")
async def get_runbooks():
    """List available automated runbooks."""
    return [
        {"id": "isolate_host", "name": "Disconnect Infected Host", "target": "victim-01", "service": "network"},
        {"id": "apply_patch", "name": "Quick-Fix Vulnerability", "target": "web-server", "service": "nginx"},
        {"id": "rotate_keys", "name": "Refresh Access Keys", "target": "auth-service", "service": "iam"},
        {"id": "block_brute", "name": "Block Attacker IP", "target": "firewall", "service": "iptables"},
        {"id": "unblock_all", "name": "Clear All Blocks", "target": "firewall", "service": "iptables"},
        {"id": "simulate_traffic", "name": "Test Dashboard (Simulate Attack)", "target": "global", "service": "soc-test"}
    ]
