"""
VirusTotal API Client — shared module for VOC/AI modules
Wraps VT API v3 with rate limiting and caching.
"""

import os
import json
import time
import hashlib
import requests
import datetime
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_DIR = os.path.join(os.path.dirname(__file__), "data", "vt_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

def _cache_key(endpoint: str) -> str:
    return os.path.join(CACHE_DIR, hashlib.md5(endpoint.encode()).hexdigest() + ".json")

def _load_cache(key: str, max_age_hours: int = 24) -> Optional[dict]:
    if os.path.exists(key):
        with open(key) as f:
            data = json.load(f)
        cached_at = datetime.datetime.fromisoformat(data.get("_cached_at", "2000-01-01"))
        if (datetime.datetime.utcnow() - cached_at).seconds < max_age_hours * 3600:
            return data
    return None

def _save_cache(key: str, data: dict):
    data["_cached_at"] = datetime.datetime.utcnow().isoformat()
    with open(key, "w") as f:
        json.dump(data, f, indent=2)

def _get(endpoint: str, use_cache: bool = True) -> Optional[dict]:
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
        resp = requests.get(url, headers=HEADERS, timeout=15)

        if resp.status_code == 429:
            print("[VT] Rate limited — waiting 60s")
            time.sleep(60)
            resp = requests.get(url, headers=HEADERS, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            if use_cache:
                _save_cache(cache_key, data)
            return data
        elif resp.status_code == 404:
            return {"error": "not_found", "status": 404}
        else:
            return {"error": f"http_{resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ── Public API ────────────────────────────────────────────────────────────────

def check_file_hash(sha256: str) -> dict:
    """Check a file hash against VirusTotal."""
    result = _get(f"/files/{sha256}")
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

def check_ip(ip: str) -> dict:
    """Check an IP address reputation on VirusTotal."""
    result = _get(f"/ip_addresses/{ip}")
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

def check_url(url: str) -> dict:
    """Check a URL against VirusTotal."""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    result = _get(f"/urls/{url_id}")
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
    try:
        post = requests.post(f"{VT_BASE}/urls", headers=HEADERS,
                             data={"url": url}, timeout=15)
        if post.status_code in (200, 201):
            return {"url": url, "status": "submitted", "source": "virustotal"}
    except Exception:
        pass
    return {"url": url, "error": "failed", "source": "virustotal"}

def check_domain(domain: str) -> dict:
    """Check a domain against VirusTotal."""
    result = _get(f"/domains/{domain}")
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

if __name__ == "__main__":
    print("=== VirusTotal Client Test ===")

    print("\n[1] Checking known malicious hash (EICAR test file SHA256):")
    eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    r = check_file_hash(eicar_sha256)
    print(f"  Malicious: {r.get('malicious')}/{r.get('total_engines')} engines")
    print(f"  Threat: {r.get('threat_label')}")

    print("\n[2] Checking known malicious IP:")
    r2 = check_ip("45.33.32.156")
    print(f"  IP reputation: {r2.get('reputation')}")
    print(f"  Country: {r2.get('country')}")
    print(f"  Malicious: {r2.get('malicious')}")
