"""
VirusTotal API Client — shared module for VOC/AI modules
Wraps VT API v3 with rate limiting and caching.
"""

import os
import json
import asyncio
import hashlib
import aiohttp
import datetime
from typing import Optional
from config import config

VT_API_KEY = config.VIRUSTOTAL_API_KEY
VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_DIR = os.path.join(os.path.dirname(__file__), "data", "vt_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

HEADERS = {"x-apikey": VT_API_KEY or "", "Accept": "application/json"}

def _cache_key(endpoint: str) -> str:
    return os.path.join(CACHE_DIR, hashlib.md5(endpoint.encode()).hexdigest() + ".json")

def _load_cache(key: str, max_age_hours: int = 24) -> Optional[dict]:
    if os.path.exists(key):
        try:
            with open(key) as f:
                data = json.load(f)
            cached_at = datetime.datetime.fromisoformat(data.get("_cached_at", "2000-01-01"))
            if (datetime.datetime.utcnow() - cached_at).total_seconds() < max_age_hours * 3600:
                return data
        except Exception:
            return None
    return None

def _save_cache(key: str, data: dict):
    data["_cached_at"] = datetime.datetime.utcnow().isoformat()
    try:
        with open(key, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

async def _get(endpoint: str, use_cache: bool = True) -> Optional[dict]:
    """Generic GET with caching and rate limit handling."""
    cache_key = _cache_key(endpoint)
    if use_cache:
        cached = _load_cache(cache_key)
        if cached:
            cached["_from_cache"] = True
            return cached

    if not VT_API_KEY:
        return {"error": "no_api_key"}

    try:
        url = f"{VT_BASE}{endpoint}"
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 429:
                    print("[VT] Rate limited — waiting 60s")
                    await asyncio.sleep(60)
                    async with session.get(url, timeout=15) as resp2:
                        if resp2.status == 200:
                            data = await resp2.json()
                            if use_cache:
                                _save_cache(cache_key, data)
                            return data
                        return {"error": f"http_{resp2.status}"}

                if resp.status == 200:
                    data = await resp.json()
                    if use_cache:
                        _save_cache(cache_key, data)
                    return data
                elif resp.status == 404:
                    return {"error": "not_found", "status": 404}
                else:
                    return {"error": f"http_{resp.status}"}
    except Exception as e:
        return {"error": str(e)}

async def _post(endpoint: str, data: dict) -> Optional[dict]:
    """Generic POST for VT."""
    if not VT_API_KEY:
        return {"error": "no_api_key"}
    try:
        url = f"{VT_BASE}{endpoint}"
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            async with session.post(url, data=data, timeout=15) as resp:
                if resp.status in (200, 201):
                    return await resp.json()
                return {"error": f"http_{resp.status}"}
    except Exception as e:
        return {"error": str(e)}

# ── Public API ────────────────────────────────────────────────────────────────

async def check_file_hash(sha256: str) -> dict:
    """Check a file hash against VirusTotal."""
    result = await _get(f"/files/{sha256}")
    if not result or "error" in result:
        return {"hash": sha256, **result} if result else {"hash": sha256, "error": "failed"}
    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "hash": sha256,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "total_engines": sum(stats.values()),
        "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
        "file_names": attrs.get("names", [])[:5],
        "tags": attrs.get("tags", []),
        "from_cache": result.get("_from_cache", False),
        "source": "virustotal"
    }

async def check_ip(ip: str) -> dict:
    """Check an IP address reputation on VirusTotal."""
    result = await _get(f"/ip_addresses/{ip}")
    if not result or "error" in result:
        return {"ip": ip, **(result or {"error": "failed"})}
    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip": ip,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", "unknown"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner", "unknown"),
        "tags": attrs.get("tags", []),
        "from_cache": result.get("_from_cache", False),
        "source": "virustotal"
    }

async def check_url(url: str) -> dict:
    """Check a URL against VirusTotal."""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    result = await _get(f"/urls/{url_id}")
    if result and "error" not in result:
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "categories": attrs.get("categories", {}),
            "from_cache": result.get("_from_cache", False),
            "source": "virustotal"
        }
    # Try to submit
    post_res = await _post("/urls", {"url": url})
    if post_res and "error" not in post_res:
        return {"url": url, "status": "submitted", "source": "virustotal"}
    return {"url": url, "error": "failed", "source": "virustotal"}

async def check_domain(domain: str) -> dict:
    """Check a domain against VirusTotal."""
    result = await _get(f"/domains/{domain}")
    if not result or "error" in result:
        return {"domain": domain, **(result or {"error": "failed"})}
    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "domain": domain,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "from_cache": result.get("_from_cache", False),
        "source": "virustotal"
    }
