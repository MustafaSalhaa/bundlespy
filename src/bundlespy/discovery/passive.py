"""
Passive JS Discovery via Web Archives.

Collects historical JS URLs from:
- Wayback Machine CDX API
- CommonCrawl CDX API

No direct requests to the target. Zero noise.
Useful for finding old JS files with leaked credentials
that are no longer on the live site.
"""

import re
import json
import time
import logging
from typing import List, Set, Optional
from urllib.parse import urlencode, urlparse, quote

import requests

logger = logging.getLogger("bundlespy.discovery.passive")

CDX_WAYBACK     = "http://web.archive.org/cdx/search/cdx"
CDX_COMMONCRAWL = "http://index.commoncrawl.org/CC-MAIN-2024-10-index"

REQUEST_TIMEOUT = 15
MAX_RESULTS     = 1000


def _cdx_request(url: str, params: dict) -> Optional[list]:
    """Make a CDX API request safely."""
    try:
        resp = requests.get(
            url,
            params=params,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "BundleSpy Security Scanner (authorized assessment)"},
        )
        if resp.status_code != 200:
            logger.warning("CDX API returned %d for %s", resp.status_code, url)
            return None
        return resp.json()
    except requests.exceptions.Timeout:
        logger.warning("CDX API timed out: %s", url)
        return None
    except Exception as e:
        logger.warning("CDX API error: %s", e)
        return None


def wayback_js_urls(domain: str, limit: int = MAX_RESULTS) -> List[str]:
    """
    Query Wayback Machine CDX API for JS files belonging to a domain.
    Returns deduplicated list of JS URLs.
    """
    params = {
        "url":        f"*.{domain}/*.js",
        "matchType":  "wildcard",
        "output":     "json",
        "fl":         "original",
        "filter":     "statuscode:200",
        "collapse":   "urlkey",
        "limit":      str(limit),
    }

    logger.info("Querying Wayback Machine for JS URLs: %s", domain)
    data = _cdx_request(CDX_WAYBACK, params)

    if not data or len(data) < 2:
        return []

    # First row is header
    urls = []
    for row in data[1:]:
        if row and len(row) >= 1:
            url = row[0]
            if url.endswith(".js") or ".js?" in url:
                urls.append(url)

    logger.info("Wayback Machine returned %d JS URLs for %s", len(urls), domain)
    return list(set(urls))


def commoncrawl_js_urls(domain: str, limit: int = MAX_RESULTS) -> List[str]:
    """
    Query CommonCrawl CDX API for JS files.
    Returns deduplicated list of JS URLs.
    """
    params = {
        "url":      f"*.{domain}/*.js",
        "output":   "json",
        "filter":   "status:200",
        "fl":       "url",
        "limit":    str(limit),
    }

    logger.info("Querying CommonCrawl for JS URLs: %s", domain)

    try:
        resp = requests.get(
            CDX_COMMONCRAWL,
            params=params,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "BundleSpy Security Scanner (authorized assessment)"},
        )
        if resp.status_code != 200:
            return []

        urls = []
        for line in resp.text.strip().splitlines():
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                if url.endswith(".js") or ".js?" in url:
                    urls.append(url)
            except Exception:
                continue

        logger.info("CommonCrawl returned %d JS URLs for %s", len(urls), domain)
        return list(set(urls))

    except Exception as e:
        logger.warning("CommonCrawl error: %s", e)
        return []


def collect_passive_js_urls(
    target_url: str,
    sources:    List[str] = None,
    limit:      int = MAX_RESULTS,
) -> List[str]:
    """
    Collect JS URLs from all passive sources for a given target.

    sources: list of ["wayback", "commoncrawl"] — defaults to both
    Returns deduplicated, sorted list of JS URLs.
    """
    if sources is None:
        sources = ["wayback", "commoncrawl"]

    parsed = urlparse(target_url)
    domain = parsed.hostname or ""
    if not domain:
        logger.warning("Could not extract domain from: %s", target_url)
        return []

    all_urls: Set[str] = set()

    if "wayback" in sources:
        wb_urls = wayback_js_urls(domain, limit=limit)
        all_urls.update(wb_urls)

    if "commoncrawl" in sources:
        cc_urls = commoncrawl_js_urls(domain, limit=limit)
        all_urls.update(cc_urls)

    # Filter: only JS files, valid URLs
    filtered = []
    for url in all_urls:
        if not url.startswith(("http://", "https://")):
            continue
        if not (url.endswith(".js") or ".js?" in url or ".js#" in url):
            continue
        filtered.append(url)

    logger.info(
        "Passive collection complete: %d unique JS URLs for %s",
        len(filtered), domain
    )
    return sorted(set(filtered))
