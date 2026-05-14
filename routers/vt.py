from fastapi import APIRouter
from pydantic import BaseModel
from virustotal_client import check_file_hash, check_ip, check_url

router = APIRouter(prefix="/vt", tags=["VirusTotal"])

class VTHashCheck(BaseModel):
    hash: str

class VTIPCheck(BaseModel):
    ip: str

class VTURLCheck(BaseModel):
    url: str

@router.post("/hash")
async def vt_hash(req: VTHashCheck):
    """Check a file hash against VirusTotal."""
    return await check_file_hash(req.hash)

@router.post("/ip")
async def vt_ip(req: VTIPCheck):
    """Check an IP reputation on VirusTotal."""
    return await check_ip(req.ip)

@router.post("/url")
async def vt_url(req: VTURLCheck):
    """Check a URL against VirusTotal."""
    return await check_url(req.url)
