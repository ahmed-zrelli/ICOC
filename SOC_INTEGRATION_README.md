# SOC-VOC-NOC Integration Guide

This guide explains how to integrate your SOC (Wazuh SIEM) with the VOC/NOC ICOC-Lite system.

## Network Architecture

| Machine | OS | IP | Role |
|---------|-----|-----|------|
| Wazuh Manager | Ubuntu + Docker | 192.168.100.10 | SIEM core + ICOC API host |
| Windows Endpoint | Windows Server 2012 | 192.168.100.101 | Monitored target |
| Linux Endpoint | Metasploitable3 | 192.168.100.102 | Monitored target |
| Attacker | Kali Linux | 192.168.100.200 | Attack simulation |

## Quick Start

### 1. Configure Environment

The `.env` file is already configured with the correct IPs. Key settings:

```bash
# Wazuh API Configuration
WAZUH_API_URL=https://192.168.100.10:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=MyS3cr37P450r.*-
WAZUH_API_VERIFY_SSL=false

# Lab Network
LAB_NETWORK=192.168.100.0/24
LAB_HOSTS=192.168.100.102,192.168.100.101
```

### 2. Start the ICOC API

On the Wazuh Manager (192.168.100.10):

```bash
cd /path/to/ICOC
docker-compose up -d
```

### 3. Verify SOC Integration

Check if the SOC module is loaded:

```bash
curl http://192.168.100.10:8000/soc/health
```

Expected response:
```json
{
  "status": "ok",
  "wazuh_api_connected": true,
  "pipeline_running": false,
  "timestamp": "2026-04-16T..."
}
```

## SOC Pipeline Usage

### Start Continuous Sync

The pipeline automatically fetches Wazuh alerts every 30 seconds:

```bash
# Start the pipeline
curl -X POST http://192.168.100.10:8000/soc/pipeline/start

# Check status
curl http://192.168.100.10:8000/soc/pipeline/status
```

### Manual Sync

To manually trigger a sync from Wazuh:

```bash
# Sync last 5 minutes of alerts
curl -X POST http://192.168.100.10:8000/soc/pipeline/sync \
  -H "Content-Type: application/json" \
  -d '{"minutes": 5}'
```

### View Wazuh Alerts

Query Wazuh alerts through the ICOC API:

```bash
# Recent alerts from all agents
curl "http://192.168.100.10:8000/soc/wazuh/alerts?minutes=10"

# Critical alerts only
curl "http://192.168.100.10:8000/soc/wazuh/alerts?severity=Critical&minutes=30"

# Alerts from specific agent
curl "http://192.168.100.10:8000/soc/wazuh/alerts?agent_id=001&minutes=60"
```

## Integration Flow

### How It Works

1. **Wazuh Agents** (on Windows Server 2012 and Metasploitable3) send logs to Wazuh Manager
2. **Wazuh Manager** analyzes logs and generates security alerts
3. **SOC Pipeline** (in ICOC API) fetches alerts from Wazuh API every 30 seconds
4. **Event Store** receives normalized alerts in ICOC format
5. **VOC/NOC** can now see SOC alerts alongside vulnerability data

### Data Flow

```
[Windows Agent] ──┐
                  ├──► [Wazuh Manager:55000] ──► [SOC Pipeline] ──► [ICOC Event Store]
[Linux Agent] ────┘                                          └──► [VOC/NOC Dashboard]
```

## API Endpoints

### SOC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/soc/health` | GET | Check SOC-Wazuh connection |
| `/soc/wazuh/stats` | GET | Get Wazuh cluster statistics |
| `/soc/wazuh/agents` | GET | List Wazuh agents |
| `/soc/wazuh/alerts` | GET | Fetch Wazuh alerts |
| `/soc/pipeline/start` | POST | Start continuous sync |
| `/soc/pipeline/stop` | POST | Stop continuous sync |
| `/soc/pipeline/status` | GET | Get pipeline status |
| `/soc/pipeline/sync` | POST | Manual sync |
| `/soc/events/correlated` | GET | Get SOC-VOC correlated events |
| `/soc/dashboard/summary` | GET | Get SOC dashboard data |

### Example: Correlated Events

Get security events that match vulnerabilities in your inventory:

```bash
curl "http://192.168.100.10:8000/soc/events/correlated?minutes=60"
```

This returns attacks on hosts that have known vulnerabilities - perfect for prioritization.

## Troubleshooting

### Wazuh API Connection Failed

1. Check Wazuh API is running:
   ```bash
   curl -k -u wazuh-wui:MyS3cr37P450r.*- https://192.168.100.10:55000/security/user/authenticate
   ```

2. Verify credentials in `.env`

3. Check firewall (port 55000 must be open)

### No Alerts Appearing

1. Check agents are connected:
   ```bash
   curl http://192.168.100.10:8000/soc/wazuh/agents
   ```

2. Verify pipeline is running:
   ```bash
   curl http://192.168.100.10:8000/soc/pipeline/status
   ```

3. Check Wazuh has alerts:
   ```bash
   # On Wazuh Manager
   /var/ossec/bin/cluster_control -l
   ```

### Pipeline Not Starting

Check the logs:
```bash
docker logs icoc-api
```

## Advanced Configuration

### Custom Pipeline Settings

```bash
# Start with custom settings
curl -X POST http://192.168.100.10:8000/soc/pipeline/start \
  -H "Content-Type: application/json" \
  -d '{
    "sync_interval_seconds": 60,
    "lookback_minutes": 5,
    "enable_deduplication": true,
    "enable_escalation": true
  }'
```

### Disable Auto-Escalation

If you don't want Critical alerts automatically escalated to incidents:

```bash
curl -X POST http://192.168.100.10:8000/soc/pipeline/start \
  -H "Content-Type: application/json" \
  -d '{"enable_escalation": false}'
```

## Integration with VOC/NOC

### For VOC Team

The VOC scanner now targets both victims:
- Linux (Metasploitable3): 192.168.100.102
- Windows (Server 2012): 192.168.100.101

Trigger a scan:
```bash
curl -X POST http://192.168.100.10:8000/voc/scan
```

### For NOC Team

SOC events are now available in the shared event store:
```bash
# Get all events (SOC + VOC + NOC)
curl http://192.168.100.10:8000/events/live

# Get SOC-specific events
curl "http://192.168.100.10:8000/events/live?event_type=ssh_brute_force"
```

## Security Notes

- Wazuh API uses HTTPS with self-signed certificate (verify_ssl=false in dev)
- Store production credentials securely
- The pipeline uses token-based authentication with automatic refresh
- Critical alerts (level >= 9) are automatically escalated to incidents

## Support

For issues:
1. Check `/soc/health` endpoint
2. Review docker logs: `docker logs icoc-api`
3. Verify Wazuh API: `curl -k https://192.168.100.10:55000/`
