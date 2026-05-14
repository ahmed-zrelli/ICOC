#!/bin/bash
echo "[VICTIM] Starting SSH server..."
/usr/sbin/sshd

echo "[VICTIM] Starting vulnerable web application..."
python3 /webapp.py &

echo "[VICTIM] Starting ICOC victim agent..."
# Use environment variables for the agent configuration
export ICOC_API_URL=${ICOC_API_URL:-"http://192.168.100.1:8000"}
export VICTIM_IP=${VICTIM_IP:-"192.168.100.102"}

# Run the agent in the foreground to keep the container alive
python3 /agent/agent.py
