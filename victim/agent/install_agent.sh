#!/bin/bash
# ── ICOC-Lite Victim Agent Installer ─────────────────────────────────────────
# Compatible with Metasploitable3 (Ubuntu 14.04) — NO internet, NO pip needed.
# Uses only Python 2.7 stdlib (urllib2, hashlib, threading, subprocess, etc.)
#
# Usage:
#   scp install_agent.sh agent_legacy.py vagrant@192.168.100.102:/tmp/
#   ssh vagrant@192.168.100.102
#   sudo bash /tmp/install_agent.sh

API_URL="http://192.168.100.1:8000"
VICTIM_IP="192.168.100.102"
AGENT_DIR="/opt/icoc-agent"
SCRIPT_DIR="$(dirname "$0")"

echo "[INSTALL] ICOC-Lite Legacy Agent installer"
echo "[INSTALL] API: ${API_URL}  |  Victim: ${VICTIM_IP}"

# ── Find Python ───────────────────────────────────────────────────────────────
PYTHON=""
for candidate in python2.7 python2 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        echo "[INSTALL] Using Python: $PYTHON ($(${PYTHON} --version 2>&1))"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[INSTALL] ERROR: No Python found. Install python2.7 manually."
    exit 1
fi

# ── Copy agent ────────────────────────────────────────────────────────────────
mkdir -p "${AGENT_DIR}"

# Copy the agent as-is, then patch the config constants in-place using sed.
# This avoids any Python 2.7 restrictions on import ordering.
cp "${SCRIPT_DIR}/agent_legacy.py" "${AGENT_DIR}/agent.py"
chmod +x "${AGENT_DIR}/agent.py"

# Patch the default values for API_URL and VICTIM_IP directly in the source
sed -i "s|http://192.168.237.1:8000|${API_URL}|g"     "${AGENT_DIR}/agent.py"
sed -i "s|192.168.237.129|${VICTIM_IP}|g"              "${AGENT_DIR}/agent.py"

echo "[INSTALL] Agent written to ${AGENT_DIR}/agent.py"

# ── Quick connectivity test ───────────────────────────────────────────────────
echo "[INSTALL] Testing API connectivity..."
if command -v curl >/dev/null 2>&1; then
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "${API_URL}/health" 2>/dev/null)
    if [ "$HTTP" = "200" ]; then
        echo "[INSTALL] API reachable (HTTP 200)"
    else
        echo "[INSTALL] WARNING: API returned HTTP ${HTTP} — check that docker-compose is running on your PC"
    fi
else
    echo "[INSTALL] curl not found, skipping connectivity test"
fi

# ── Install as service ────────────────────────────────────────────────────────
if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
    # systemd (Ubuntu 15+)
    cat > /etc/systemd/system/icoc-agent.service << SVCEOF
[Unit]
Description=ICOC-Lite Victim Agent
After=network.target

[Service]
Environment="ICOC_API_URL=${API_URL}"
Environment="VICTIM_IP=${VICTIM_IP}"
ExecStart=${PYTHON} ${AGENT_DIR}/agent.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable icoc-agent
    systemctl restart icoc-agent
    sleep 2
    systemctl status icoc-agent --no-pager
    echo "[INSTALL] Done. Check logs: journalctl -u icoc-agent -f"

else
    # Upstart (Ubuntu 14.04 — Metasploitable3)
    cat > /etc/init/icoc-agent.conf << UPEOF
description "ICOC-Lite Victim Agent"
author      "ICOC-Lite"

start on runlevel [2345]
stop on runlevel [016]

respawn
respawn limit 10 5

env ICOC_API_URL=${API_URL}
env VICTIM_IP=${VICTIM_IP}

exec ${PYTHON} ${AGENT_DIR}/agent.py >> /var/log/icoc-agent.log 2>&1
UPEOF

    # Stop any existing instance
    stop icoc-agent 2>/dev/null || true
    sleep 1

    # Start it
    start icoc-agent
    sleep 2

    # Verify
    if status icoc-agent | grep -q "running"; then
        echo "[INSTALL] Agent running via Upstart"
        echo "[INSTALL] Done. Check logs: tail -f /var/log/icoc-agent.log"
    else
        echo "[INSTALL] Upstart failed — running in background instead"
        ICOC_API_URL="${API_URL}" VICTIM_IP="${VICTIM_IP}" \
            nohup ${PYTHON} "${AGENT_DIR}/agent.py" >> /var/log/icoc-agent.log 2>&1 &
        echo "[INSTALL] PID: $!  |  Logs: tail -f /var/log/icoc-agent.log"
    fi
fi
