"""
HTML parser for discovering JavaScript files and links from HTML pages.

Extraction coverage:
  - <script src> / <link rel=preload as=script>
  - <a href> crawlable links
  - <form action> — static form submission as navigation request
  - <a ping> / <area ping> — tracking ping URLs
  - HTMX attributes: hx-get, hx-post, hx-put, hx-patch, hx-delete
  - <iframe srcdoc> — inline HTML content (extracts relative endpoints)
  - SVG internal hrefs: <image href>, <script href> inside SVG
  - <isindex action> — legacy isindex tag
  - onclick / data-href / meta-refresh
"""

import re
import logging
from typing import List, Set
from urllib.parse import urljoin, urlparse, urldefrag

logger = logging.getLogger("bundlespy.discovery.html")

# ── Script / preload ──────────────────────────────────────────────────────────

RE_SCRIPT_SRC      = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_SCRIPT_NOQUOTE  = re.compile(r'<script[^>]+src=([^\s>]+)', re.IGNORECASE)

RE_PRELOAD         = re.compile(
    r'<link[^>]+rel=["\'](?:preload|modulepreload)["\'][^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
RE_PRELOAD_ALT     = re.compile(
    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:preload|modulepreload)["\']',
    re.IGNORECASE,
)

# ── Standard link sources ─────────────────────────────────────────────────────

RE_HREF            = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
RE_INLINE          = re.compile(r'<script(?:[^>]*)>(.*?)</script>', re.IGNORECASE | re.DOTALL)
RE_FORM_ACTION     = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
RE_ONCLICK_LOC     = re.compile(r'(?:location\.href|window\.location)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_DATA_HREF       = re.compile(r'data-(?:href|url|link|target)=["\']([^"\']+)["\']', re.IGNORECASE)
RE_META_REFRESH    = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]+;\s*url=([^"\']+)["\']', re.IGNORECASE)

# ── Gap 1: HTMX attributes ────────────────────────────────────────────────────
# hx-get/post/put/patch/delete fire AJAX requests that carry real endpoints.
# We treat them all as navigation targets — same scope/dedup logic applies.
RE_HTMX_ATTRS      = re.compile(
    r'\bhx-(?:get|post|put|patch|delete)=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# ── Gap 4: <a ping> / <area ping> ────────────────────────────────────────────
# The `ping` attribute fires a POST to a space-separated list of URLs when the
# link is clicked.  Each URL is a separate tracking endpoint worth capturing.
RE_A_PING          = re.compile(r'<a\b[^>]+\bping=["\']([^"\']+)["\']', re.IGNORECASE)
RE_AREA_PING       = re.compile(r'<area\b[^>]+\bping=["\']([^"\']+)["\']', re.IGNORECASE)

# ── Gap 5: <iframe srcdoc> ────────────────────────────────────────────────────
# srcdoc is inline HTML.  We extract the attribute value and recurse into it
# to pull relative endpoint references.
# Two patterns: one for double-quoted, one for single-quoted attribute values.
# We can't use [^"'] because real srcdoc content may contain entity-escaped
# quotes which, before unescaping, look like the other quote type.
RE_IFRAME_SRCDOC_DQ = re.compile(r'<iframe\b[^>]+srcdoc="([^"]*)"', re.IGNORECASE | re.DOTALL)
RE_IFRAME_SRCDOC_SQ = re.compile(r"<iframe\b[^>]+srcdoc='([^']*)'", re.IGNORECASE | re.DOTALL)

# ── Gap 6: SVG internal hrefs ─────────────────────────────────────────────────
# <image href> and <script href> inside <svg> blocks can reference external
# resources.  We capture href / xlink:href on those two elements.
RE_SVG_IMAGE_HREF  = re.compile(
    r'<image\b[^>]+(?:xlink:href|href)=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
RE_SVG_SCRIPT_HREF = re.compile(
    r'<script\b[^>]+(?:xlink:href|href)=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# ── Gap 8: <isindex action> ───────────────────────────────────────────────────
# Archaic HTML4 element that pre-dates <form>.  Its `action` attribute is a
# URL target — identical semantic to <form action>.
RE_ISINDEX_ACTION  = re.compile(r'<isindex\b[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)


# ── Public API ────────────────────────────────────────────────────────────────

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

    # SVG <script href> may point to JS files — capture them here too
    for match in RE_SVG_SCRIPT_HREF.finditer(html):
        raw = match.group(1).strip()
        if _looks_like_js(raw):
            absolute = _make_absolute(raw, base_url)
            if absolute:
                urls.add(absolute)

    return list(urls)


def extract_links(html: str, base_url: str) -> List[str]:
    """
    Extract all links from HTML for crawling.

    Covers:
      - <a href> — standard navigation
      - <form action> — GET form targets as navigation
      - onclick= window.location / location.href assignments
      - data-href / data-url / data-link / data-target attributes
      - <meta http-equiv="refresh"> redirects
      - HTMX hx-get/post/put/patch/delete endpoints  [Gap 1]
      - <a ping> / <area ping> tracking URLs          [Gap 4]
      - <iframe srcdoc> inline HTML endpoints         [Gap 5]
      - SVG <image href> resource references          [Gap 6]
      - <isindex action> legacy form targets          [Gap 8]
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

    # Standard sources
    for match in RE_HREF.finditer(html):
        _add(match.group(1))
    for match in RE_FORM_ACTION.finditer(html):
        _add(match.group(1))
    for match in RE_ONCLICK_LOC.finditer(html):
        _add(match.group(1))
    for match in RE_DATA_HREF.finditer(html):
        _add(match.group(1))
    for match in RE_META_REFRESH.finditer(html):
        _add(match.group(1))

    # Gap 1: HTMX attributes — every hx-* value is a live backend endpoint
    for match in RE_HTMX_ATTRS.finditer(html):
        _add(match.group(1))

    # Gap 4: <a ping> / <area ping> — space-separated list of POST ping URLs
    for pattern in (RE_A_PING, RE_AREA_PING):
        for match in pattern.finditer(html):
            for url in match.group(1).split():
                _add(url)

    # Gap 5: <iframe srcdoc> — recurse into the inline HTML (one level deep).
    # We try double-quoted pattern first, then single-quoted.
    _srcdoc_seen: Set[str] = set()
    for pattern in (RE_IFRAME_SRCDOC_DQ, RE_IFRAME_SRCDOC_SQ):
        for match in pattern.finditer(html):
            raw_srcdoc = match.group(1)
            if raw_srcdoc in _srcdoc_seen:
                continue
            _srcdoc_seen.add(raw_srcdoc)
            srcdoc_html = _unescape_attr(raw_srcdoc)
            # Pull links from the inline document; they resolve relative to base_url
            for link in extract_links(srcdoc_html, base_url):
                links.add(link)

    # Gap 6: SVG <image href> — external image/resource references inside SVG
    for match in RE_SVG_IMAGE_HREF.finditer(html):
        raw = match.group(1).strip()
        # Skip inline data URIs and fragment-only references
        if not raw.startswith("data:") and not raw.startswith("#"):
            _add(raw)

    # Gap 8: <isindex action> — legacy form target URL
    for match in RE_ISINDEX_ACTION.finditer(html):
        _add(match.group(1))

    return list(links)


def extract_htmx_endpoints(html: str, base_url: str) -> List[str]:
    """
    Return all HTMX request targets as absolute URLs.

    These are the endpoints that HTMX would call at runtime — they're real
    backend routes that static <a href> scraping misses entirely.
    Covers hx-get, hx-post, hx-put, hx-patch, hx-delete.
    """
    urls: Set[str] = set()
    for match in RE_HTMX_ATTRS.finditer(html):
        raw = match.group(1).strip()
        if raw and not raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            absolute = _make_absolute(raw, base_url)
            if absolute:
                url_no_fragment, _ = urldefrag(absolute)
                urls.add(url_no_fragment)
    return list(urls)


def extract_ping_urls(html: str, base_url: str) -> List[str]:
    """
    Return all <a ping> and <area ping> URLs as absolute URLs.

    ping= is a space-separated list of URLs that receive a POST when the
    link is followed.  They are always tracking/analytics endpoints that
    never appear in href.
    """
    urls: Set[str] = set()
    for pattern in (RE_A_PING, RE_AREA_PING):
        for match in pattern.finditer(html):
            for raw in match.group(1).split():
                raw = raw.strip()
                if raw and not raw.startswith(("javascript:", "data:", "#")):
                    absolute = _make_absolute(raw, base_url)
                    if absolute:
                        urls.add(absolute)
    return list(urls)


def extract_inline_scripts(html: str) -> List[str]:
    """Extract inline JavaScript content from <script> blocks."""
    scripts = []
    for match in RE_INLINE.finditer(html):
        content = match.group(1).strip()
        if content:
            scripts.append(content)
    return scripts


# ── Internal helpers ──────────────────────────────────────────────────────────

def _looks_like_js(url: str) -> bool:
    """
    Matches the same extensions as _is_js_url in crawler.py.
    Must be kept in sync.
    """
    path = urlparse(url).path.lower()
    return (
        path.endswith(".js")  or
        path.endswith(".mjs") or
        path.endswith(".cjs") or
        path.endswith(".jsx") or
        path.endswith(".ts")  or
        path.endswith(".tsx")
    )


def _make_absolute(url: str, base: str) -> str:
    try:
        return urljoin(base, url)
    except Exception:
        return ""


def _unescape_attr(text: str) -> str:
    """
    Minimally unescape HTML entities that appear inside attribute values.
    srcdoc content is HTML-entity-escaped in the outer attribute.
    """
    replacements = (
        ("&amp;",  "&"),
        ("&lt;",   "<"),
        ("&gt;",   ">"),
        ("&quot;", '"'),
        ("&#39;",  "'"),
        ("&#x27;", "'"),
        ("&apos;", "'"),
    )
    for ent, ch in replacements:
        text = text.replace(ent, ch)
    return text
