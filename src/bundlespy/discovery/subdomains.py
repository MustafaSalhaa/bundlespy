"""
Subdomain Harvesting Module.

Passively collects subdomains from:
- URLs discovered during crawling
- JS file content references
- Certificate Transparency logs (crt.sh)
- Wayback Machine URL patterns

Never brute-forces. Never sends DNS queries beyond normal resolution.
"""

import re
import json
import logging
from typing import Set, List
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.discovery.subdomains")

RE_SUBDOMAIN   = re.compile(
    r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)',
    re.IGNORECASE,
)

REQUEST_TIMEOUT = 10


def extract_from_content(content: str, base_domain: str) -> Set[str]:
    """Extract subdomains mentioned in JS file content."""
    found = set()
    for match in RE_SUBDOMAIN.finditer(content):
        host = match.group(1).lower()
        if host.endswith(f".{base_domain}") or host == base_domain:
            found.add(host)
    return found


def extract_from_urls(urls: List[str], base_domain: str) -> Set[str]:
    """Extract subdomains from a list of URLs."""
    found = set()
    for url in urls:
        try:
            host = urlparse(url).hostname or ""
            host = host.lower()
            if host.endswith(f".{base_domain}") or host == base_domain:
                found.add(host)
        except Exception:
            continue
    return found


def crtsh_subdomains(domain: str, timeout: int = REQUEST_TIMEOUT) -> Set[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains.
    Completely passive - just reads public CT log data.
    """
    found = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout,
            headers={"User-Agent": "BundleSpy Security Scanner (authorized assessment)"},
        )
        if resp.status_code != 200:
            return found

        for entry in resp.json():
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lower().lstrip("*.")
                if line.endswith(f".{domain}") or line == domain:
                    found.add(line)

        logger.info("crt.sh returned %d subdomains for %s", len(found), domain)

    except Exception as e:
        logger.warning("crt.sh query failed: %s", e)

    return found


def harvest_subdomains(
    target_url:    str,
    js_contents:   List[str] = None,
    discovered_urls: List[str] = None,
    use_crtsh:     bool = True,
) -> List[str]:
    """
    Collect all subdomains from passive sources.
    Returns sorted, deduplicated list.
    """
    parsed      = urlparse(target_url)
    base_domain = parsed.hostname or ""

    # Strip www
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    if not base_domain:
        return []

    all_subs: Set[str] = set()

    # From JS file contents
    for content in (js_contents or []):
        subs = extract_from_content(content, base_domain)
        all_subs.update(subs)

    # From discovered URLs
    if discovered_urls:
        subs = extract_from_urls(discovered_urls, base_domain)
        all_subs.update(subs)

    # From CT logs
    if use_crtsh:
        subs = crtsh_subdomains(base_domain)
        all_subs.update(subs)

    # Remove the apex domain itself
    all_subs.discard(base_domain)
    all_subs.discard(f"www.{base_domain}")

    result = sorted(all_subs)
    logger.info("Harvested %d unique subdomains for %s", len(result), base_domain)
    return result
