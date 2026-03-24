# NOC Integration Guide: Moving from Simulated to Real NOC

This guide helps you (the NOC module contributor) transition your simulated NOC components to work with real monitoring infrastructure and integrate properly with the main ICOC project.

---

## Quick Overview

**Your Current Setup:**
- `noc_api.py` - Main NOC router with demo mode fallbacks
- `noc_alerts.py` - Zabbix trigger/alerts fetcher
- `noc_incidents.py` - Incident management
- `noc_metrics.py` - Performance metrics
- `noc_audit.py` - Audit trail logging
- `noc_remediation.py` - Automated remediation
- `noc_sla.py` - SLA monitoring
- `noc_trending.py` - Trend analysis
- `noc_forecasting.py` - Predictive analytics
- `noc_correlation.py` - Event correlation
- `noc_utils.py` - Shared utilities

---

## Step 1: Environment Configuration

### Update `.env` File

Add these environment variables to your `.env`:

```env
# ═══════════════════════════════════════════════════════════════════════════════
# [NOC] REAL MONITORING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Zabbix Server Connection (REQUIRED - Point to your real Zabbix)
ZABBIX_API_URL=http://YOUR_ZABBIX_IP:8080/api_jsonrpc.php
ZABBIX_USER=Admin
ZABBIX_PASS=your_secure_password

# DEMO_MODE - Set to "false" for production
# When false, the system will NOT use simulated data
DEMO_MODE=false

# NOC Module Database Tables (already created by database.py)
# These are automatically managed, no changes needed
```

### Key Changes from Simulation to Real:

| Setting | Simulated | Real |
|---------|-----------|------|
| `ZABBIX_API_URL` | `http://192.168.100.21:8080` | Your actual Zabbix URL |
| `ZABBIX_USER` | `Admin` | Your Zabbix admin user |
| `ZABBIX_PASS` | `zabbix` | Your actual password |
| `DEMO_MODE` | `true` | `false` |

---

## Step 2: Database Schema (Already Done ✅)

The `database.py` file already includes NOC tables:

```python
# noc_incidents - Stores incident records
# noc_audit_trail - Logs all NOC actions
```

**You don't need to change anything here** - the tables are created automatically on startup.

---

## Step 3: Fix Hardcoded IP Addresses

### File: `noc/noc_utils.py`

Look for and update these hardcoded IPs:

```python
# OLD (Simulation):
ZABBIX_API = "http://192.168.100.21:8080/api_jsonrpc.php"

# NEW (Real):
ZABBIX_API = os.getenv("ZABBIX_API_URL", "http://192.168.100.21:8080/api_jsonrpc.php")
```

### File: `noc/noc_alerts.py`

```python
# Line 7 - Update default:
ZABBIX_API = os.getenv("ZABBIX_API_URL", "http://YOUR_ZABBIX_IP:8080/api_jsonrpc.php")
```

### File: `noc/noc_metrics.py`

Same pattern - use environment variables instead of hardcoded IPs.

---

## Step 4: Remove or Keep Simulation Mode

### In `noc_api.py` (Lines 27-53):

The code currently has DEMO_MODE fallbacks:

```python
if not auth and DEMO_MODE:
    return {
        "status": "operational",
        "zabbix_reachable": True,
        "auth_ok": True,
        "demo": True,
        "module": "ICOC NOC Module"
    }
```

**For Real NOC:**
- Set `DEMO_MODE=false` in `.env`
- The system will use actual Zabbix data
- If Zabbix is unreachable, it will return degraded/down status

**To keep simulation as fallback:**
- Leave DEMO_MODE logic in place
- Set `DEMO_MODE=true` for testing without real Zabbix

---

## Step 5: Integrate with Main Project Components

### A. Connect to VOC/AI Risk Scoring

Your NOC metrics should feed into the risk score calculation. In `database.py`, the risk score already combines:

```python
# From ai/fr_ai_01_risk_score.py
voc_component  # VOC scanning results
soc_component  # SOC events (your NOC alerts feed here)
ti_component   # Threat intel
```

**What you need to do:**
Ensure your alert severities map correctly:

```python
# In noc_alerts.py, line 54:
# Critical alerts (priority >= 5) should trigger risk score updates
# This happens automatically through the event system
```

### B. Connect to Event Store

When your NOC creates incidents, they should appear in the main event stream:

```python
# Example integration in your code:
from event_store import ingest_event

ingest_event({
    "event_type": "noc_incident_created",
    "severity": "High",
    "host_ip": host_name,
    "data": {
        "incident_id": incident_id,
        "description": desc,
        "module": "NOC"
    }
})
```

### C. Audit Trail Integration

Your `noc_audit.py` already uses `database.log_noc_action()`. This integrates with the main audit system.

**Verify it's working:**
1. Trigger a NOC action (e.g., acknowledge alert)
2. Check `/db/events?event_type=noc_audit` endpoint
3. Events should appear in the main event feed

---

## Step 6: Frontend Integration

### Current Status:

The main `App.jsx` has these NOC-related tabs:
- Dashboard - Shows NOC summary widget
- Alerts - Shows security events (may need NOC column)
- Database - Shows all NOC tables

### What You Need to Check:

1. **API Endpoints Called by Frontend:**
   ```
   GET /noc/summary - Should return real data
   GET /noc/alerts/active - Real Zabbix alerts
   GET /noc/incidents - From database
   GET /noc/audit - Audit trail
   ```

2. **If Adding NOC Tab to Frontend:**
   The frontend uses this pattern:
   ```javascript
   const { data: nocData } = useApi("/noc/summary", 15000);
   ```

---

## Step 7: Testing Real NOC Integration

### Test Checklist:

```bash
# 1. Check if Zabbix is reachable
curl http://YOUR_ZABBIX_IP:8080/api_jsonrpc.php

# 2. Test NOC API
curl http://localhost:8000/noc/status

# 3. Test alerts endpoint
curl http://localhost:8000/noc/alerts/active

# 4. Verify incidents are stored
curl http://localhost:8000/db/events?event_type=noc_incident_created

# 5. Check audit trail
curl http://localhost:8000/noc/audit
```

### Expected Responses (Real Mode):

```json
// /noc/status
{
  "status": "operational",
  "zabbix_reachable": true,
  "auth_ok": true,
  "module": "ICOC NOC Module"
  // NO "demo": true field when in real mode
}

// /noc/alerts/active
{
  "alerts": [...],  // Real Zabbix triggers
  "count": 5,
  "module": "ICOC NOC Module"
}
```

---

## Common Issues and Fixes

### Issue 1: "Zabbix auth failed"

**Cause:** Wrong credentials or URL
**Fix:**
```bash
# Test Zabbix API manually:
curl -X POST http://YOUR_ZABBIX_IP:8080/api_jsonrpc.php \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {"user": "Admin", "password": "your_password"},
    "id": 1
  }'
```

### Issue 2: "Module not found" errors

**Cause:** Python import paths
**Fix:** Ensure your noc files use proper imports:
```python
# In noc/noc_*.py files:
from database import get_noc_incidents  # Correct
# NOT: from ..database import ...
```

### Issue 3: Alerts not appearing in main dashboard

**Cause:** Event types not matching
**Fix:** Check `event_routes.py` - it should map NOC events to the main event stream.

---

## Integration Checklist for Your Friend

- [ ] Update `.env` with real Zabbix credentials
- [ ] Set `DEMO_MODE=false` in `.env`
- [ ] Verify Zabbix API is reachable from Docker network
- [ ] Test all NOC endpoints return real data
- [ ] Confirm incidents appear in main database
- [ ] Verify audit trail is logging to main system
- [ ] Check risk scoring includes NOC metrics
- [ ] Frontend shows NOC data in dashboard

---

## Quick Reference: File Modifications Needed

| File | Change |
|------|--------|
| `.env` | Add real Zabbix credentials |
| `noc/noc_utils.py` | Remove hardcoded IPs |
| `noc/noc_alerts.py` | Use env var for Zabbix URL |
| `noc/noc_metrics.py` | Use env var for Zabbix URL |
| `noc/noc_api.py` | Keep DEMO_MODE logic (it's fine) |

---

## Docker Compose for Real Zabbix

If using external Zabbix (not Docker containers):

```yaml
# In docker-compose.yml, the api service needs:
environment:
  - ZABBIX_API_URL=http://YOUR_EXTERNAL_ZABBIX:8080/api_jsonrpc.php
  - ZABBIX_USER=Admin
  - ZABBIX_PASS=your_password
  - DEMO_MODE=false
```

**Note:** The current `docker-compose.yml` includes Zabbix containers. If using external Zabbix, you can remove those services.

---

## Appendix: Hardcoded IPs Found in NOC Files

These are the DEFAULT fallback values in your NOC files. They work with environment variables but have simulation IPs as fallbacks.

### Files with Default IPs (Already use os.getenv ✅):

| File | Line | Current Default | What to Change |
|------|------|-----------------|----------------|
| `noc/noc_utils.py` | 7 | `http://192.168.100.21:8080` | Keep as is - uses env var |
| `noc/noc_metrics.py` | 7 | `http://192.168.100.21:8080` | Keep as is - uses env var |
| `noc/noc_alerts.py` | 7 | `http://192.168.100.21:8080` | Keep as is - uses env var |
| `noc/noc_trending.py` | 9 | `http://192.168.100.21:8080` | Keep as is - uses env var |

### What This Means:

Your code is ALREADY correctly written:
```python
ZABBIX_API = os.getenv("ZABBIX_API_URL", "http://192.168.100.21:8080/api_jsonrpc.php")
```

The `192.168.100.21` is just a **fallback default**. When you set the environment variable, it overrides this.

### For Real NOC (Your Action Items):

Just update your `.env` file:
```env
ZABBIX_API_URL=http://YOUR_REAL_ZABBIX_IP:8080/api_jsonrpc.php
ZABBIX_USER=Admin
ZABBIX_PASS=your_real_password
DEMO_MODE=false
```

**No code changes needed!** ✅

---

## Quick Test After Configuration

```bash
# Restart containers
docker-compose down
docker-compose up -d --build

# Check if NOC is using real Zabbix
curl http://localhost:8000/noc/status

# Should return:
{
  "status": "operational",
  "zabbix_reachable": true,
  "auth_ok": true,
  "module": "ICOC NOC Module"
  # Note: NO "demo": true field!
}
```

If you see `"demo": true` in the response, your DEMO_MODE is still enabled.

---

## Integration Complete Checklist for Your Friend

- [ ] `.env` file updated with real Zabbix IP
- [ ] `.env` has DEMO_MODE=false
- [ ] Zabbix server is running and reachable
- [ ] Test `/noc/status` shows real connection
- [ ] Test `/noc/alerts/active` shows real alerts
- [ ] Test `/noc/metrics/summary` shows real metrics

**That's it! Your NOC code is ready to work with real infrastructure.**
