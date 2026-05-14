#!/bin/bash
# ── Run attacker server directly on Kali (no Docker) ─────────────────────────
# This replaces the attacker Docker container.
# Run once after `docker-compose up` — keep it running in a terminal.

export VICTIM_IP=192.168.100.102
export VICTIM_SSH_PORT=22
export VICTIM_HTTP_PORT=8080
export ATTACKER_IP=192.168.100.200
export ICOC_API_URL=http://192.168.100.1:8000

echo "[ATTACKER] Installing dependencies..."
pip3 install requests sshpass 2>/dev/null || true
apt-get install -y sshpass 2>/dev/null || true

echo "[ATTACKER] Starting attacker server on :5000"
echo "[ATTACKER] Victim: ${VICTIM_IP} | API: ${ICOC_API_URL}"

cd "$(dirname "$0")"
python3 attacker_server.py
