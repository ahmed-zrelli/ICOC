from fastapi import APIRouter, HTTPException
from database import get_noc_incidents, create_noc_incident, update_noc_incident
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter()

class IncidentCreate(BaseModel):
    host: str
    description: str
    severity: str
    status: Optional[str] = "Open"
    assigned_to: Optional[str] = "Unassigned"

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None

@router.get("/incidents")
async def fetch_incidents(status: Optional[str] = None):
    """FR-NOC-03: Retrieve all tracked incidents."""
    try:
        return get_noc_incidents(status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/incidents")
async def add_incident(incident: IncidentCreate):
    """FR-NOC-03: Manually create an incident."""
    try:
        incident_id = create_noc_incident(
            incident.host, 
            incident.description, 
            incident.severity, 
            incident.status, 
            incident.assigned_to
        )
        return {"message": "Incident created", "incident_id": incident_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/incidents/{incident_id}")
async def patch_incident(incident_id: str, update: IncidentUpdate):
    """FR-NOC-03: Update incident status or details."""
    try:
        success = update_noc_incident(
            incident_id, 
            update.status, 
            update.notes, 
            update.assigned_to
        )
        if success:
            return {"message": f"Incident {incident_id} updated"}
        return {"message": "No changes made"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
