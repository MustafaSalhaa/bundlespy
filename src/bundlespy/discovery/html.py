"""
HTML parser for discovering JavaScript files and links from HTML pages.
"""

import re
import logging
from typing import List, Set
from urllib.parse import urljoin, urlparse, urldefrag

logger = logging.getLogger("bundlespy.discovery.html")

# Script src patterns
RE_SCRIPT_SRC   = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_SCRIPT_NOQUOTE = re.compile(r'<script[^>]+src=([^\s>]+)', re.IGNORECASE)

# Preload / modulepreload links
RE_PRELOAD      = re.compile(
    r'<link[^>]+rel=["\'](?:preload|modulepreload)["\'][^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
RE_PRELOAD_ALT  = re.compile(
    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:preload|modulepreload)["\']',
    re.IGNORECASE,
)

# All href links for crawling
RE_HREF         = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)

# Inline scripts
RE_INLINE       = re.compile(r'<script(?:[^>]*)>(.*?)</script>', re.IGNORECASE | re.DOTALL)


def extract_js_urls(html: str, base_url: str) -> List[str]:
    """Extract all JavaScript file URLs from HTML."""
    urls: Set[str] = set()

    for pattern in [RE_SCRIPT_SRC, RE_SCRIPT_NOQUOTE, RE_PRELOAD, RE_PRELOAD_ALT]:
        for match in pattern.finditer(html):
            raw = match.group(1).strip()
            if _looks_like_js(raw):
                absolute = _make_absolute(raw, base_url)
                if absolute:
                    urls.add(absolute)

    return list(urls)


# Additional link sources
RE_FORM_ACTION = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
RE_ONCLICK_LOC = re.compile(r'(?:location\.href|window\.location)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_DATA_HREF   = re.compile(r'data-(?:href|url|link|target)=["\']([^"\']+)["\']', re.IGNORECASE)
RE_META_REFRESH = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]+;\s*url=([^"\']+)["\']', re.IGNORECASE)


def extract_links(html: str, base_url: str) -> List[str]:
    """
    Extract all links from HTML for crawling.
    Covers href, form actions, onclick navigation, data attributes,
    and meta refresh redirects.
    """
    links: Set[str] = set()

    def _add(raw: str) -> None:
        raw = raw.strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return
        absolute = _make_absolute(raw, base_url)
        if absolute:
            url_no_fragment, _ = urldefrag(absolute)
            links.add(url_no_fragment)

    # Standard anchor links
    for match in RE_HREF.finditer(html):
        _add(match.group(1))

    # Form actions — often login/search/contact forms
    for match in RE_FORM_ACTION.finditer(html):
        _add(match.group(1))

    # onclick navigation
    for match in RE_ONCLICK_LOC.finditer(html):
        _add(match.group(1))

    # data-href / data-url attributes
    for match in RE_DATA_HREF.finditer(html):
        _add(match.group(1))

    # meta refresh
    for match in RE_META_REFRESH.finditer(html):
        _add(match.group(1))

    return list(links)


def extract_inline_scripts(html: str) -> List[str]:
    """Extract inline JavaScript content from <script> blocks."""
    scripts = []
    for match in RE_INLINE.finditer(html):
        content = match.group(1).strip()
        if content:
            scripts.append(content)
    return scripts


def _looks_like_js(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _make_absolute(url: str, base: str) -> str:
    try:
        return urljoin(base, url)
    except Exception:
        return ""
