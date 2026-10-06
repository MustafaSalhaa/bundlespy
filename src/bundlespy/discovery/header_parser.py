"""
HTTP response header parser - extracts URLs from response headers.

Parses three headers that carry navigation targets completely invisible
to HTML body parsing:

  Content-Location  - canonical URL of the resource (may differ from request URL)
  Link              - preload, prefetch, canonical, alternate, api relations
  Refresh           - server-side redirect with a delay and URL

All three return the same type: a list of absolute URL strings, already
filtered for blank values and non-navigable schemes.
"""

import re
import logging
from typing import List, Optional
from urllib.parse import urljoin

logger = logging.getLogger("bundlespy.discovery.header_parser")

# Refresh: 0; url=https://example.com/new-path
# Also handles: 5;URL=/relative/path  (no space, uppercase URL=)
_RE_REFRESH_URL = re.compile(
    r'(?:^|;)\s*url\s*=\s*["\']?([^"\';\s]+)',
    re.IGNORECASE,
)

# Link header value format: </path>; rel="preload"; as="script", </other>; rel="canonical"
# We extract the URL from each entry regardless of rel= type.
_RE_LINK_ENTRY = re.compile(r'<([^>]+)>')

# Schemes we never want to follow
_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "vbscript:", "#")


def _is_navigable(url: str) -> bool:
    """Return False for blank or non-navigable URLs."""
    url = url.strip()
    if not url:
        return False
    lc = url.lower()
    return not any(lc.startswith(s) for s in _SKIP_SCHEMES)


def parse_content_location(headers: dict, base_url: str) -> List[str]:
    """
    Extract the URL from a Content-Location response header.

    Content-Location tells us the canonical URL of what the server actually
    returned — often different from the request URL after normalization or
    content-negotiation.  Worth crawling as a distinct resource.
    """
    raw = headers.get("Content-Location") or headers.get("content-location") or ""
    raw = raw.strip()
    if not raw or not _is_navigable(raw):
        return []
    try:
        return [urljoin(base_url, raw)]
    except Exception:
        return []


def parse_link_header(headers: dict, base_url: str) -> List[str]:
    """
    Extract all URLs from a Link response header.

    Link headers carry preload, prefetch, canonical, alternate, api, and
    stylesheet relations — many of which point to real application routes
    or API endpoints that never appear in the HTML body.

    Each entry is of the form: </path>; rel="type"; ...
    We extract every URL regardless of rel= value.
    """
    raw = headers.get("Link") or headers.get("link") or ""
    if not raw:
        return []

    urls: List[str] = []
    for m in _RE_LINK_ENTRY.finditer(raw):
        candidate = m.group(1).strip()
        if candidate and _is_navigable(candidate):
            try:
                urls.append(urljoin(base_url, candidate))
            except Exception:
                pass
    return urls


def parse_refresh_header(headers: dict, base_url: str) -> List[str]:
    """
    Extract the redirect URL from a Refresh response header.

    Refresh: <seconds>; url=<URL>

    This is the HTTP equivalent of <meta http-equiv="refresh">.  Both carry
    the same semantic — a timed redirect — and both are common on legacy
    apps and login flows.
    """
    raw = headers.get("Refresh") or headers.get("refresh") or ""
    if not raw:
        return []

    m = _RE_REFRESH_URL.search(raw)
    if not m:
        return []

    candidate = m.group(1).strip().strip('"\'')
    if not candidate or not _is_navigable(candidate):
        return []

    try:
        return [urljoin(base_url, candidate)]
    except Exception:
        return []


def extract_header_urls(headers: dict, base_url: str) -> List[str]:
    """
    Run all three header parsers and return deduplicated URL list.

    Drop anything already equal to base_url — the server reflecting the
    request URL back in Content-Location is common and not worth re-queuing.
    """
    seen = {base_url.rstrip("/")}
    results: List[str] = []

    for url in (
        parse_content_location(headers, base_url)
        + parse_link_header(headers, base_url)
        + parse_refresh_header(headers, base_url)
    ):
        key = url.rstrip("/")
        if key not in seen:
            seen.add(key)
            results.append(url)

    return results
