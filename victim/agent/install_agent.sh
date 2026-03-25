#!/bin/bash
# ── ICOC-Lite Victim Agent Installer ─────────────────────────────────────────
# Run this on Metasploitable 3 (Ubuntu 14.04) to install the victim agent.
# Usage: scp this file to Metasploitable, then run: sudo bash install_agent.sh

set -e

KALI_IP="192.168.237.1"
API_URL="http://192.168.237.1:8000"
VICTIM_IP="192.168.237.129"

echo "[INSTALL] Installing ICOC-Lite victim agent on Metasploitable 3"
echo "[INSTALL] API URL: ${API_URL}"
echo "[INSTALL] Victim IP: ${VICTIM_IP}"

# Install dependencies
echo "[INSTALL] Installing Python dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip curl

pip3 install requests psutil

# Copy agent to system location
AGENT_DIR="/opt/icoc-agent"
mkdir -p "${AGENT_DIR}"

# Write the agent with correct env vars baked in
cat > "${AGENT_DIR}/agent.py" << PYEOF
import os
os.environ.setdefault("ICOC_API_URL", "${API_URL}")
os.environ.setdefault("VICTIM_IP", "${VICTIM_IP}")
PYEOF

# Append the actual agent code (agent.py must be in same dir as this script)
cat "$(dirname "$0")/agent.py" >> "${AGENT_DIR}/agent.py"

# Create systemd service (if available) or just run in background
if command -v systemctl &>/dev/null; then
    cat > /etc/systemd/system/icoc-agent.service << SVCEOF
[Unit]
Description=ICOC-Lite Victim Agent
After=network.target

[Service]
Environment="ICOC_API_URL=${API_URL}"
Environment="VICTIM_IP=${VICTIM_IP}"
ExecStart=/usr/bin/python3 ${AGENT_DIR}/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable icoc-agent
    systemctl start icoc-agent
    echo "[INSTALL] Agent started as systemd service"
    echo "[INSTALL] Check status: systemctl status icoc-agent"
else
    # Ubuntu 14.04 uses upstart
    cat > /etc/init/icoc-agent.conf << UPEOF
description "ICOC-Lite Victim Agent"
start on runlevel [2345]
stop on runlevel [016]
respawn
env ICOC_API_URL=${API_URL}
env VICTIM_IP=${VICTIM_IP}
exec /usr/bin/python3 ${AGENT_DIR}/agent.py
UPEOF
    start icoc-agent 2>/dev/null || python3 "${AGENT_DIR}/agent.py" &
    echo "[INSTALL] Agent started via upstart (Ubuntu 14.04)"
fi

echo "[INSTALL] Done. Agent is running and reporting to ${API_URL}"
