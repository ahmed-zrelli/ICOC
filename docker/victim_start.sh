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

# Start Zabbix agent
echo "[VICTIM] Configuring Zabbix agent..."
mkdir -p /etc/zabbix/zabbix_agentd.d /var/log/zabbix /var/run/zabbix
chown -R zabbix:zabbix /var/log/zabbix /var/run/zabbix /etc/zabbix
# Ensure the log directory is writable by zabbix user
chmod 775 /var/log/zabbix
rm -f /var/log/zabbix/zabbix_agentd.log

cat > /etc/zabbix/zabbix_agentd.conf << EOF
PidFile=/tmp/zabbix_agentd.pid
LogFile=/tmp/zabbix_agentd.log
LogFileSize=0
Server=192.168.100.20
ServerActive=192.168.100.20:10051
Hostname=victim
ListenPort=10050
ListenIP=0.0.0.0
RefreshActiveChecks=120
BufferSend=5
BufferSize=100
Timeout=3
EOF

echo "[VICTIM] Starting Zabbix agent..."
service zabbix-agent start
echo "[VICTIM] Zabbix agent started!"

# Also start Python agent (for additional monitoring)
python3 /agent/agent.py &
echo "[VICTIM] Python agent started!"

# Keep container alive
sleep infinity
