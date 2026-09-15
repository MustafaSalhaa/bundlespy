"""
Passive JS Discovery via Web Archives.

Collects historical JS URLs from:
- Wayback Machine CDX API (HTTPS, correct params)
- CommonCrawl CDX API (latest index, newline-delimited JSON)

Distinguishes clearly between:
- success with results
- success with zero results
- API failure (HTTP error)
- timeout
- malformed response
"""

import json
import logging
from dataclasses import dataclass
from typing import List, Set, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("bundlespy.discovery.passive")

# Wayback CDX — must use HTTPS, not HTTP
CDX_WAYBACK     = "https://web.archive.org/cdx/search/cdx"
REQUEST_TIMEOUT = 20
MAX_RESULTS     = 1000


@dataclass
class PassiveResult:
    """Explicit result from a passive source — never conflates failure with empty."""
    source:    str
    success:   bool
    urls:      List[str]
    error:     Optional[str] = None
    http_code: Optional[int] = None


def _wayback_query(domain: str, limit: int = MAX_RESULTS) -> PassiveResult:
    """
    Query Wayback Machine CDX API for JS files.
    Uses HTTPS and correct CDX parameters.
    """
    params = {
        "url":       f"*.{domain}/*.js",
        "matchType": "wildcard",
        "output":    "json",
        "fl":        "original",
        "filter":    "statuscode:200",
        "collapse":  "urlkey",
        "limit":     str(limit),
    }

    logger.info("Querying Wayback Machine for JS URLs: %s", domain)

    try:
        resp = requests.get(
            CDX_WAYBACK,
            params=params,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; BundleSpy/1.0)"},
        )

        if resp.status_code != 200:
            logger.warning("Wayback CDX returned HTTP %d", resp.status_code)
            return PassiveResult(
                source="wayback", success=False, urls=[],
                error=f"HTTP {resp.status_code}", http_code=resp.status_code,
            )

        try:
            data = resp.json()
        except ValueError:
            return PassiveResult(
                source="wayback", success=False, urls=[],
                error="Malformed JSON response",
            )

        if not data or not isinstance(data, list):
            return PassiveResult(source="wayback", success=True, urls=[])

        # First row is header ["original"]
        urls = []
        for row in data[1:]:
            if row and len(row) >= 1:
                url = row[0]
                if isinstance(url, str) and (url.endswith(".js") or ".js?" in url):
                    urls.append(url)

        urls = list(set(urls))
        logger.info("Wayback Machine returned %d JS URLs for %s", len(urls), domain)
        return PassiveResult(source="wayback", success=True, urls=urls)

    except requests.exceptions.Timeout:
        logger.warning("Wayback Machine timed out for %s", domain)
        return PassiveResult(source="wayback", success=False, urls=[], error="Timeout")

    except requests.exceptions.ConnectionError as e:
        logger.warning("Wayback Machine connection error: %s", e)
        return PassiveResult(source="wayback", success=False, urls=[], error=f"Connection error: {e}")

    except Exception as e:
        logger.warning("Wayback Machine unexpected error: %s", e)
        return PassiveResult(source="wayback", success=False, urls=[], error=str(e))


def _commoncrawl_query(domain: str, limit: int = MAX_RESULTS) -> PassiveResult:
    """
    Query CommonCrawl CDX API for JS files.
    Uses latest available index.
    """
    # Get latest index
    index_url = "https://index.commoncrawl.org/collinfo.json"
    try:
        idx_resp = requests.get(index_url, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0"})
        if idx_resp.status_code == 200:
            indexes = idx_resp.json()
            latest  = indexes[0].get("cdx-api", "") if indexes else ""
        else:
            latest = "https://index.commoncrawl.org/CC-MAIN-2024-51-index"
    except Exception:
        latest = "https://index.commoncrawl.org/CC-MAIN-2024-51-index"

    params = {
        "url":    f"*.{domain}/*.js",
        "output": "json",
        "filter": "status:200",
        "fl":     "url",
        "limit":  str(limit),
    }

    logger.info("Querying CommonCrawl for JS URLs: %s", domain)

    try:
        resp = requests.get(
            latest, params=params, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        if resp.status_code != 200:
            logger.warning("CommonCrawl returned HTTP %d", resp.status_code)
            return PassiveResult(
                source="commoncrawl", success=False, urls=[],
                error=f"HTTP {resp.status_code}", http_code=resp.status_code,
            )

        urls = []
        for line in resp.text.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                if url and (url.endswith(".js") or ".js?" in url):
                    urls.append(url)
            except Exception:
                continue

        urls = list(set(urls))
        logger.info("CommonCrawl returned %d JS URLs for %s", len(urls), domain)
        return PassiveResult(source="commoncrawl", success=True, urls=urls)

    except requests.exceptions.Timeout:
        return PassiveResult(source="commoncrawl", success=False, urls=[], error="Timeout")

    except Exception as e:
        logger.warning("CommonCrawl error: %s", e)
        return PassiveResult(source="commoncrawl", success=False, urls=[], error=str(e))


def collect_passive_js_urls(
    target_url: str,
    limit:      int = MAX_RESULTS,
) -> List[str]:
    """
    Collect JS URLs from all passive sources.
    Returns deduplicated list of JS URLs.
    Logs explicit status for each provider.
    """
    parsed = urlparse(target_url)
    domain = parsed.hostname or ""
    if not domain:
        logger.warning("Could not extract domain from: %s", target_url)
        return []

    all_urls: Set[str] = set()

    wb  = _wayback_query(domain, limit=limit)
    if wb.success:
        all_urls.update(wb.urls)
        if not wb.urls:
            logger.info("Wayback Machine: no JS URLs found for %s (API success)", domain)
    else:
        logger.warning("Wayback Machine failed for %s: %s", domain, wb.error)

    cc = _commoncrawl_query(domain, limit=limit)
    if cc.success:
        all_urls.update(cc.urls)
        if not cc.urls:
            logger.info("CommonCrawl: no JS URLs found for %s (API success)", domain)
    else:
        logger.warning("CommonCrawl failed for %s: %s", domain, cc.error)

    # Filter valid JS URLs
    filtered = [
        url for url in all_urls
        if url.startswith(("http://", "https://"))
        and (url.endswith(".js") or ".js?" in url or ".js#" in url)
    ]

    logger.info(
        "Passive collection: %d unique JS URLs for %s (wayback:%s cc:%s)",
        len(filtered), domain,
        "ok" if wb.success else "fail",
        "ok" if cc.success else "fail",
    )
    return sorted(set(filtered))
