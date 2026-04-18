"""
FR-VOC-06: NVD/CVE Database Integration
Downloads and syncs CVE data from NIST NVD API 2.0.
Caches locally for offline use and ML training data.

OFFLINE LAB NOTE
────────────────
The lab network (192.168.100.0/24) has no outbound internet access.
Run this script ONCE from the host machine (which does have internet)
before starting the lab, or use 'python fr_voc_06_nvd_integration.py'
on the dashboard VM if it has a bridged network interface:

    python fr_voc_06_nvd_integration.py --download

This populates voc/data/nvd_cache/cve_database.json which the app
then reads offline. If no cache exists, the API returns [] and logs
a clear error — no fake data is generated as a silent fallback.
"""

import os
import json
import requests
import datetime
import time
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()

NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Strip whitespace and carriage returns (Windows .env files have \r\n)
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip().strip("\r").strip("\n")
CACHE_DIR   = os.path.join(os.path.dirname(__file__), "data", "nvd_cache")
CVE_DB_PATH = os.path.join(CACHE_DIR, "cve_database.json")

os.makedirs(CACHE_DIR, exist_ok=True)


def _nvd_headers() -> dict:
    h = {"Accept": "application/json"}
    if NVD_API_KEY:
        # NVD API 2.0 accepts apiKey as a request header
        h["apiKey"] = NVD_API_KEY
    return h


def _nvd_request(params: dict, timeout: int = 60) -> dict:
    """
    Make a single NVD API request with retry logic.
    Handles 403/404/429 gracefully and logs the response for debugging.
    """
    if NVD_API_KEY:
        print(f"[FR-VOC-06] Using NVD API key: {NVD_API_KEY[:8]}...")
    else:
        print("[FR-VOC-06] WARNING: No NVD_API_KEY set — unauthenticated (5 req/30s limit)")

    for attempt in range(3):
        try:
            resp = requests.get(NVD_BASE, params=params,
                                headers=_nvd_headers(), timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403:
                print(f"[FR-VOC-06] 403 Forbidden — API key invalid or expired. "
                      f"Key used: '{NVD_API_KEY[:8]}...' Check NVD_API_KEY in .env")
                raise Exception(f"403 Forbidden: invalid API key")
            elif resp.status_code == 404:
                print(f"[FR-VOC-06] 404 — URL or params rejected by NVD. "
                      f"Params: {params}")
                raise Exception(f"404 Not Found: {resp.url}")
            elif resp.status_code == 429:
                wait = 35 if not NVD_API_KEY else 7
                print(f"[FR-VOC-06] 429 Rate limited — sleeping {wait}s (attempt {attempt+1}/3)")
                time.sleep(wait)
                continue
            else:
                resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            print(f"[FR-VOC-06] Connection error on attempt {attempt+1}/3")
            time.sleep(5)
    raise Exception("NVD request failed after 3 attempts")


def fetch_recent_cves(days_back: int = 7, max_results: int = 100) -> List[dict]:
    """
    FR-VOC-06: Fetch recently published CVEs from NVD API 2.0.
    Returns [] if network unavailable (expected in offline lab).
    """
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=days_back)

    params = {
        "pubStartDate":  start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":    end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(max_results, 2000),
    }

    try:
        print(f"[FR-VOC-06] Fetching CVEs from NVD ({days_back} days back)...")
        data = _nvd_request(params, timeout=30)
        cves = data.get("vulnerabilities", [])
        normalized = [n for n in (_normalize_cve(c) for c in cves) if n]
        print(f"[FR-VOC-06] Fetched {len(normalized)} CVEs from NVD")
        return normalized

    except requests.exceptions.ConnectionError:
        print("[FR-VOC-06] NVD unreachable (no network) — lab offline mode")
        return load_cached_cves()
    except requests.exceptions.Timeout:
        print("[FR-VOC-06] NVD request timed out — using cache")
        return load_cached_cves()
    except Exception as exc:
        print(f"[FR-VOC-06] NVD fetch failed: {exc} — using cache")
        return load_cached_cves()


def fetch_cve_by_id(cve_id: str) -> Optional[dict]:
    """Fetch a specific CVE by ID from NVD, or from cache if offline."""
    # Check cache first
    cached = load_cached_cves()
    for c in cached:
        if c.get("cve_id") == cve_id:
            return c

    # Try live
    try:
        resp = requests.get(NVD_BASE, params={"cveId": cve_id},
                            headers=_nvd_headers(), timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if vulns:
            return _normalize_cve(vulns[0])
        return None
    except Exception as exc:
        print(f"[FR-VOC-06] Failed to fetch {cve_id}: {exc}")
        return None


def _normalize_cve(raw: dict) -> Optional[dict]:
    """Normalize NVD API 2.0 CVE record to internal format."""
    try:
        cve    = raw.get("cve", {})
        cve_id = cve.get("id", "")

        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d["lang"] == "en"), "No description")

        metrics     = cve.get("metrics", {})
        cvss_score  = 0.0
        cvss_vector = ""
        cvss_version= ""
        severity    = "Unknown"

        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(version):
                m        = metrics[version][0]
                cvss_data= m.get("cvssData", {})
                cvss_score  = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                cvss_version= version
                severity    = m.get("baseSeverity", cvss_data.get("baseSeverity", "Unknown"))
                break

        refs     = [r["url"] for r in cve.get("references", [])[:3]]
        configs  = cve.get("configurations", [])
        affected = []
        for config in configs:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        affected.append(cpe.get("criteria", ""))

        return {
            "cve_id":            cve_id,
            "description":       desc[:300],
            "cvss_score":        cvss_score,
            "cvss_vector":       cvss_vector,
            "cvss_version":      cvss_version,
            "severity":          severity,
            "published":         cve.get("published", ""),
            "modified":          cve.get("lastModified", ""),
            "references":        refs,
            "affected_products": affected[:5],
            "source":            "nvd",
        }
    except Exception:
        return None


def fetch_bulk_for_training(
    start_year: int = 2021,
    end_year:   int = 2024,
    max_per_year: int = 500
) -> List[dict]:
    """
    FR-VOC-06: Download bulk CVE data for ML training (year by year).
    Supports pagination (NVD returns max 2000 per request).
    Run this from a machine with internet access before lab sessions.
    """
    all_cves = []
    page_size = min(max_per_year, 2000)

    for year in range(start_year, end_year + 1):
        year_cves  = []
        start_index = 0

        while True:
            params = {
                "pubStartDate":   f"{year}-01-01T00:00:00.000",
                "pubEndDate":     f"{year}-12-31T23:59:59.000",
                "resultsPerPage": page_size,
                "startIndex":     start_index,
            }
            try:
                print(f"[FR-VOC-06] Fetching {year} CVEs (offset={start_index})...")
                data       = _nvd_request(params, timeout=60)
                total      = data.get("totalResults", 0)
                batch      = data.get("vulnerabilities", [])
                normalized = [n for n in (_normalize_cve(c) for c in batch)
                              if n and n["cvss_score"] > 0]
                year_cves.extend(normalized)

                fetched_so_far = start_index + len(batch)
                print(f"[FR-VOC-06]   {year}: {len(normalized)} valid CVEs "
                      f"({fetched_so_far}/{total} fetched)")

                # Pagination: stop if we have enough or reached the end
                if fetched_so_far >= total or len(year_cves) >= max_per_year:
                    break
                if not batch:
                    break

                start_index = fetched_so_far
                # NVD rate limit: 5 req/30s without key, 50 req/30s with key
                time.sleep(1 if NVD_API_KEY else 7)

            except Exception as exc:
                print(f"[FR-VOC-06]   {year} failed at offset {start_index}: {exc}")
                break

        print(f"[FR-VOC-06]   {year} total: {len(year_cves)} CVEs collected")
        all_cves.extend(year_cves[:max_per_year])

    save_cve_cache(all_cves)
    print(f"[FR-VOC-06] Bulk download complete: {len(all_cves)} CVEs")
    return all_cves


def save_cve_cache(cves: List[dict]):
    """Save CVE list to local cache file."""
    with open(CVE_DB_PATH, "w") as f:
        json.dump({
            "updated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "total": len(cves),
            "cves":  cves
        }, f, indent=2)
    print(f"[FR-VOC-06] Cache saved: {len(cves)} CVEs → {CVE_DB_PATH}")


def load_cached_cves() -> List[dict]:
    """
    Load CVEs from local cache.
    Returns [] if no cache — caller must handle this.
    Does NOT generate synthetic data silently.
    """
    if os.path.exists(CVE_DB_PATH):
        with open(CVE_DB_PATH) as f:
            data = json.load(f)
        source = data.get("cves", [{}])[0].get("source", "unknown") if data.get("cves") else "empty"
        if source == "synthetic":
            print("[FR-VOC-06] WARNING: cache contains synthetic data — run with "
                  "--download to get real NVD data")
        print(f"[FR-VOC-06] Loaded {data['total']} CVEs from cache "
              f"(updated {data['updated_at']}, source={source})")
        return data["cves"]

    print("[FR-VOC-06] No NVD cache found. Run 'python fr_voc_06_nvd_integration.py --download' "
          "from a machine with internet access to populate the cache.")
    return []


def _generate_synthetic_cves(n: int = 1000) -> List[dict]:
    """
    Generate synthetic CVE dataset for ML training.
    ONLY used when explicitly requested via train.py --synthetic.
    Never called automatically.
    Statistically based on real NVD severity distributions.
    """
    import random

    random.seed(42)
    cves       = []
    severities = ["Critical", "High",   "Medium", "Low",  "None"]
    weights    = [0.18,       0.28,     0.32,     0.17,   0.05]
    av_opts    = ["N", "A", "L", "P"]
    ac_opts    = ["L", "H"]
    pr_opts    = ["N", "L", "H"]
    ui_opts    = ["N", "R"]
    s_opts     = ["U", "C"]
    i_opts     = ["N", "L", "H"]

    score_ranges = {
        "Critical": (9.0, 10.0), "High": (7.0, 8.9),
        "Medium":   (4.0, 6.9),  "Low":  (0.1, 3.9), "None": (0.0, 0.0)
    }

    for i in range(n):
        sev  = random.choices(severities, weights=weights)[0]
        lo, hi = score_ranges[sev]
        score  = round(random.uniform(lo, hi), 1) if lo != hi else 0.0
        av, ac, pr, ui = (random.choice(o) for o in (av_opts, ac_opts, pr_opts, ui_opts))
        s,  c,  ig, a  = (random.choice(o) for o in (s_opts,  i_opts,  i_opts,  i_opts))
        year = random.randint(2021, 2024)

        cves.append({
            "cve_id":      f"CVE-{year}-{10000+i:05d}",
            "description": f"Synthetic vulnerability {i} for ML training (--synthetic flag)",
            "cvss_score":  score,
            "cvss_vector": f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{ig}/A:{a}",
            "cvss_version":"cvssMetricV31",
            "severity":    sev,
            "published":   f"{year}-{random.randint(1,12):02d}-{random.randint(1,28):02d}T00:00:00",
            "modified":    f"{year}-{random.randint(1,12):02d}-{random.randint(1,28):02d}T00:00:00",
            "references":  [],
            "affected_products": [],
            "source":      "synthetic",
        })

    return cves


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ICOC-Lite NVD Integration")
    parser.add_argument("--download", action="store_true",
                        help="Download CVEs from NVD (requires internet)")
    parser.add_argument("--years", nargs=2, type=int, default=[2022, 2024],
                        metavar=("START", "END"))
    parser.add_argument("--recent", type=int, default=0,
                        help="Fetch CVEs from last N days")
    args = parser.parse_args()

    if args.download:
        cves = fetch_bulk_for_training(args.years[0], args.years[1])
        print(f"\nDownloaded {len(cves)} CVEs")
    elif args.recent:
        cves = fetch_recent_cves(days_back=args.recent, max_results=50)
        print(f"\nRecent CVEs: {len(cves)}")
        for c in cves[:3]:
            print(f"  {c['cve_id']}: CVSS {c['cvss_score']} ({c['severity']})")
    else:
        cached = load_cached_cves()
        print(f"Cache: {len(cached)} CVEs")