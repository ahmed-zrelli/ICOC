import aiohttp
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from config import config

router = APIRouter(prefix="/attacks", tags=["Attacks"])

ATTACKER_URL = config.ATTACKER_SERVER_URL

class AttackRequest(BaseModel):
    attack_id: str

@router.post("/run")
async def run_attack(req: AttackRequest):
    """Proxy attack launch to the attacker container HTTP server."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{ATTACKER_URL}/run",
                                  json={"attack_id": req.attack_id}, timeout=5) as resp:
                return await resp.json()
    except Exception as e:
        raise HTTPException(status_code=503,
                            detail=f"Attacker server unreachable: {e}")

@router.get("/status")
async def attack_status():
    """Get currently running attacks."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{ATTACKER_URL}/status", timeout=3) as resp:
                return await resp.json()
    except Exception as e:
        return {"running": {}, "error": str(e)}
