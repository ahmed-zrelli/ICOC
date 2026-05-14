import os
import requests
import json
import time

# Load config from environment or defaults
ZABBIX_API = os.getenv("ZABBIX_API_URL", "http://localhost:8081/api_jsonrpc.php")
ZABBIX_USER = os.getenv("ZABBIX_USER", "Admin")
ZABBIX_PASS = os.getenv("ZABBIX_PASS", "zabbix")

def call_api(method, params, auth=None):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }
    if auth:
        payload["auth"] = auth
    
    try:
        response = requests.post(ZABBIX_API, json=payload, timeout=10)
        return response.json()
    except Exception as e:
        print(f"Error calling Zabbix API: {e}")
        return None

def fix_interface():
    print(f"Connecting to Zabbix API at {ZABBIX_API}...")
    
    # 1. Login
    login = call_api("user.login", {"username": ZABBIX_USER, "password": ZABBIX_PASS})
    if not login or "result" not in login:
        print("Failed to authenticate with Zabbix.")
        return
    
    auth = login["result"]
    print("Authenticated successfully.")

    # 2. Find "Zabbix server" host
    host_res = call_api("host.get", {"filter": {"host": ["Zabbix server"]}, "output": ["hostid"]}, auth)
    if not host_res or not host_res.get("result"):
        print("Host 'Zabbix server' not found.")
        return
    
    host_id = host_res["result"][0]["hostid"]
    print(f"Found 'Zabbix server' with ID: {host_id}")

    # 3. Get interfaces
    iface_res = call_api("hostinterface.get", {"hostids": host_id, "output": ["interfaceid", "ip", "dns", "useip"]}, auth)
    if not iface_res or not iface_res.get("result"):
        print("No interfaces found for the host.")
        return
    
    for iface in iface_res["result"]:
        iface_id = iface["interfaceid"]
        print(f"Updating interface {iface_id} to use DNS: noc-zabbix-agent")
        
        # 4. Update interface to use DNS name instead of 127.0.0.1
        update_res = call_api("hostinterface.update", {
            "interfaceid": iface_id,
            "dns": "noc-zabbix-agent",
            "useip": 0, # Use DNS
            "port": "10050"
        }, auth)
        
        if update_res and "result" in update_res:
            print(f"Successfully updated interface {iface_id}.")
        else:
            print(f"Failed to update interface {iface_id}: {update_res}")

if __name__ == "__main__":
    # Wait a bit if running via automated script to ensure web is up
    fix_interface()
