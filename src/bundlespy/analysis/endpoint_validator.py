"""
Endpoint Validation Module.

Safely probes discovered endpoints with GET/HEAD requests only.
Reports status codes, content-types, and response sizes.
Never makes state-changing requests. Never follows redirects off-scope.
Respects rate limits and scope enforcement.
"""

import time
import logging
from typing import List, Optional
from dataclasses import dataclass, field
from datetime import datetime

import requests
import urllib3

from ..storage.models import Endpoint
from ..safety.network import validate_url
from ..utils.stealth import random_ua

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.analysis.endpoint_validator")

MAX_RESPONSE_SIZE = 512 * 1024  # 512 KB for validation only


@dataclass
class ValidationResult:
    endpoint:      str
    method:        str
    status_code:   int
    content_type:  str
    response_size: int
    redirect_url:  str
    server:        str
    interesting:   bool
    notes:         List[str] = field(default_factory=list)
    error:         Optional[str] = None


INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403}
SKIP_EXTENSIONS   = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
}


def _should_skip(url: str) -> bool:
    """Skip non-API URLs to avoid noise."""
    lower = url.lower()
    return any(lower.endswith(ext) for ext in SKIP_EXTENSIONS)


def validate_endpoint(
    url:        str,
    base_url:   str,
    scope,
    timeout:    int   = 8,
    stealth:    bool  = False,
    delay:      float = 0.5,
) -> Optional[ValidationResult]:
    """
    Probe a single endpoint safely.
    Uses HEAD first, falls back to GET if HEAD is not allowed.
    Never sends a body. Never makes POST/PUT/DELETE.
    """
    if _should_skip(url):
        return None

    safe, reason = validate_url(url, check_dns=True)
    if not safe:
        logger.debug("Skipping unsafe endpoint: %s (%s)", url, reason)
        return None

    if not scope.in_scope(url):
        logger.debug("Endpoint out of scope: %s", url)
        return None

    time.sleep(delay)

    headers = {
        "User-Agent": random_ua() if stealth else "BundleSpy/1.0.0 (authorized security assessment)",
        "Accept":     "application/json,text/html,*/*",
        "Referer":    base_url,
    }

    result = ValidationResult(
        endpoint="", method="", status_code=0, content_type="",
        response_size=0, redirect_url="", server="", interesting=False,
    )
    result.endpoint = url

    # Try HEAD first (no body transfer)
    try:
        resp = requests.head(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            stream=False,
        )
        result.method       = "HEAD"
        result.status_code  = resp.status_code
        result.content_type = resp.headers.get("Content-Type", "")
        result.server       = resp.headers.get("Server", "")
        result.redirect_url = resp.headers.get("Location", "")

        # If HEAD not supported, fall back to GET
        if resp.status_code in (405, 501):
            raise ValueError("HEAD not allowed")

    except (ValueError, requests.exceptions.ConnectionError,
            requests.exceptions.Timeout):
        # Fall back to GET with size limit
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                stream=True,
            )
            result.method       = "GET"
            result.status_code  = resp.status_code
            result.content_type = resp.headers.get("Content-Type", "")
            result.server       = resp.headers.get("Server", "")
            result.redirect_url = resp.headers.get("Location", "")

            # Read limited bytes
            body = b""
            for chunk in resp.iter_content(8192):
                body += chunk
                if len(body) >= MAX_RESPONSE_SIZE:
                    break
            result.response_size = len(body)

        except Exception as e:
            result.error = str(e)
            return result

    except Exception as e:
        result.error = str(e)
        return result

    # Flag interesting findings
    result.interesting = result.status_code in INTERESTING_CODES

    if result.status_code == 200:
        result.notes.append("Publicly accessible")
    elif result.status_code == 401:
        result.notes.append("Authentication required - endpoint exists")
    elif result.status_code == 403:
        result.notes.append("Forbidden - endpoint exists, access denied")
    elif result.status_code in (301, 302, 307):
        result.notes.append(f"Redirects to: {result.redirect_url}")

    if "json" in result.content_type.lower():
        result.notes.append("Returns JSON")
    if "graphql" in url.lower():
        result.notes.append("Potential GraphQL endpoint")
    if any(k in url.lower() for k in ["/admin", "/management", "/internal"]):
        result.notes.append("Administrative path")

    return result


def validate_endpoints(
    endpoints:  List[Endpoint],
    base_url:   str,
    scope,
    timeout:    int   = 8,
    stealth:    bool  = False,
    rate:       float = 1.0,
    max_endpoints: int = 100,
) -> List[ValidationResult]:
    """
    Validate a list of discovered endpoints.
    Returns results sorted by interest level.
    """
    results = []
    delay   = 1.0 / max(rate, 0.1)
    count   = 0

    for ep in endpoints:
        if count >= max_endpoints:
            logger.warning("Endpoint validation limit reached (%d)", max_endpoints)
            break

        url = ep.url
        if not url.startswith(("http://", "https://")):
            continue

        result = validate_endpoint(
            url, base_url, scope,
            timeout=timeout, stealth=stealth, delay=delay,
        )
        if result:
            results.append(result)
            count += 1
            if result.interesting:
                logger.info(
                    "Interesting endpoint: %s [%d] %s",
                    result.endpoint, result.status_code,
                    " | ".join(result.notes),
                )

    # Sort: interesting first, then by status code
    results.sort(key=lambda r: (not r.interesting, r.status_code))
    return results
