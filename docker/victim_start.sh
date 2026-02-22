#!/bin/bash
set -e

echo "[VICTIM] Starting ICOC-Lite Victim Container"
echo "[VICTIM] IP: 192.168.100.102"
echo "[VICTIM] SSH on :22 | Web on :8080"

# Start SSH daemon
service ssh start
echo "[VICTIM] SSH started (user: root/labuser | pass: victim123)"

# Write some fake sensitive files for FIM monitoring
echo "root:x:0:0:root:/root:/bin/bash
labuser:x:1000:1000::/home/labuser:/bin/bash" >> /etc/passwd_fake
echo "CVE-2024-6387 unpatched" > /tmp/vuln_notice.txt

# Start vulnerable web app in background
python3 /webapp.py &
echo "[VICTIM] Web app started on :8080"

# Wait for API to be ready
echo "[VICTIM] Waiting for API..."
for i in $(seq 1 20); do
    if curl -sf http://192.168.100.30:8000/health > /dev/null 2>&1; then
        echo "[VICTIM] API ready!"
        break
    fi
    echo "[VICTIM] Waiting... ($i/20)"
    sleep 3
done

# Start agent
echo "[VICTIM] Starting victim agent..."
python3 /agent/agent.py
