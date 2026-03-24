from fastapi import APIRouter, HTTPException, Query
from database import get_noc_audit_trail, log_noc_action
from typing import Optional

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.get("/")
async def fetch_audit_trail(
    limit: int = Query(50, description="Number of entries to return"),
    module: Optional[str] = Query(None, description="Filter by module (e.g., ALERTS, INCIDENTS, SLA)")
):
    """Retrieve NOC audit trail entries."""
    try:
        entries = get_noc_audit_trail(limit=limit, module=module)
        return entries
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/log")
async def add_audit_log(entry: dict):
    """Manually add an audit log entry."""
    try:
        log_noc_action(
            action=entry.get("action", "MANUAL_LOG"),
            module=entry.get("module", "NOC"),
            user_id=entry.get("user_id", "admin"),
            details=entry.get("details", {}),
            status=entry.get("status", "Success")
        )
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
