"""
ICOC-Lite API Server — Member 3 (VOC + AI + NOC)
FastAPI backend serving all VOC, AI, and NOC module endpoints.
Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VOC_DIR  = os.path.join(BASE_DIR, "voc")
AI_DIR   = os.path.join(BASE_DIR, "ai")
NOC_DIR  = os.path.join(BASE_DIR, "noc")
SOC_DIR  = os.path.join(BASE_DIR, "soc")
sys.path.insert(0, VOC_DIR)
sys.path.insert(0, AI_DIR)
sys.path.insert(0, NOC_DIR)
sys.path.insert(0, SOC_DIR)

app = FastAPI(
    title="ICOC-Lite Integrated API",
    description="Vulnerability Operations Center (VOC) + Network Operations Center (NOC) + AI Risk Engine",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Simplified for demo or use a config if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Health Endpoints ──────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {"service": "ICOC-Lite VOC/AI/NOC API", "status": "running", "version": "1.1.0"}

@app.get("/health", tags=["Health"])
def health():
    db_ok = False
    try:
        from database import test_connection
        db_ok = test_connection()
    except Exception:
        db_ok = False

    return {
        "status": "ok",
        "db": "ok" if db_ok else "down",
        "demo_mode": os.getenv("DEMO_MODE", "false")
    }

@app.on_event("startup")
def _startup_tasks():
    try:
        from soc.wazuh_poller import start_wazuh_poller
        start_wazuh_poller()
    except Exception as e:
        print(f"⚠️  SOC module not available: {e}")

# ── Include Routers ───────────────────────────────────────────────────────────

from routers import voc, ai, db, vt, attacks, dashboard
from event_routes import events_router

app.include_router(voc.router)
app.include_router(ai.router)
app.include_router(db.router)
app.include_router(vt.router)
app.include_router(attacks.router)
app.include_router(dashboard.router)
app.include_router(events_router)

# ── External Modules (NOC/SOC) ────────────────────────────────────────────────

try:
    from noc.noc_api import noc_router
    app.include_router(noc_router)
    print("✅ NOC module loaded successfully")
except Exception as e:
    print(f"⚠️  NOC module not available: {e}")

try:
    from soc.soc_api import soc_router
    app.include_router(soc_router)
    print("✅ SOC module loaded successfully")
except Exception as e:
    print(f"⚠️  SOC module not available: {e}")

# ── Event Store Initialization ────────────────────────────────────────────────

from event_store import load_persisted
load_persisted()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
