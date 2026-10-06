"""
HTML parser for discovering JavaScript files and links from HTML pages.

Extraction coverage:
  - <script src> / <link rel=preload as=script>
  - <link href> — all relations (preload, prefetch, canonical, alternate, api…)
  - <a href> crawlable links
  - <form action> — static form submission as navigation request
  - <button formaction> — per-button form override target
  - <html manifest> — PWA manifest JSON reference
  - <a ping> / <area ping> — tracking ping URLs
  - <area href> — image-map navigation links
  - HTMX attributes: hx-get, hx-post, hx-put, hx-patch, hx-delete
  - <iframe src> / <iframe srcdoc> — frame navigation + inline HTML endpoints
  - <frame src> / <embed src> — legacy frame and plugin targets
  - <object data> / <object codebase> + param value — plugin/PDF endpoints
  - SVG: <image href/xlink:href>, <script href/xlink:href>
  - <isindex action> — legacy isindex tag
  - <import implementation> — HTML import (deprecated Web Components spec)
  - <base href> — document base URL hint
  - <blockquote cite> — cited source URL
  - Media: <audio src>, <video src/poster>, <img src/srcset/dynsrc/lowsrc/longdesc>
  - Table backgrounds: <table background>, <td background>
  - <body background> — legacy background image URL
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

# ── Generic <link href> ───────────────────────────────────────────────────────
# Captures ALL <link href> values regardless of rel= type.
# Covers prefetch, canonical, alternate, api, manifest, stylesheet, and more.
# Preload/modulepreload above are kept separately for the extract_js_urls path.
RE_LINK_HREF       = re.compile(r'<link\b[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)

# ── Standard link sources ─────────────────────────────────────────────────────

RE_HREF            = re.compile(r'<a\b[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
RE_INLINE          = re.compile(r'<script(?:[^>]*)>(.*?)</script>', re.IGNORECASE | re.DOTALL)
RE_FORM_ACTION     = re.compile(r'<form\b[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
RE_ONCLICK_LOC     = re.compile(r'(?:location\.href|window\.location)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_DATA_HREF       = re.compile(r'data-(?:href|url|link|target)=["\']([^"\']+)["\']', re.IGNORECASE)
RE_META_REFRESH    = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]+;\s*url=([^"\']+)["\']', re.IGNORECASE)

# ── Button / form overrides ───────────────────────────────────────────────────
# <button formaction="/api/delete"> overrides the parent <form action>.
# The browser submits to formaction, not action — so it's a distinct endpoint.
RE_BUTTON_FORMACTION = re.compile(r'<button\b[^>]+formaction=["\']([^"\']+)["\']', re.IGNORECASE)

# ── PWA manifest ─────────────────────────────────────────────────────────────
# <html manifest="/app.appcache"> — legacy AppCache.
# <link rel="manifest" href="/manifest.json"> is caught by RE_LINK_HREF above.
RE_HTML_MANIFEST   = re.compile(r'<html\b[^>]+manifest=["\']([^"\']+)["\']', re.IGNORECASE)

# ── Blockquote cite ───────────────────────────────────────────────────────────
RE_BLOCKQUOTE_CITE = re.compile(r'<blockquote\b[^>]+cite=["\']([^"\']+)["\']', re.IGNORECASE)

# ── Meta content endpoint extraction ─────────────────────────────────────────
# <meta name="..." content="..."> values occasionally embed relative endpoints.
# We extract any value that looks like a path (starts with /).
RE_META_CONTENT    = re.compile(r'<meta\b[^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
_RE_META_PATH      = re.compile(r'(/[a-zA-Z0-9/_\-%.?=&]{2,})')

# ── Media tags ───────────────────────────────────────────────────────────────
# These carry real resource URLs. <object data> is particularly interesting
# because it can point to internal PDF viewers, internal service endpoints,
# or legacy Flash/Silverlight resources.

# <audio src> and <video src/poster>
RE_AUDIO_SRC       = re.compile(r'<audio\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_VIDEO_SRC       = re.compile(r'<video\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_VIDEO_POSTER    = re.compile(r'<video\b[^>]+poster=["\']([^"\']+)["\']', re.IGNORECASE)

# <source src/srcset> nested inside <audio>/<video>
RE_SOURCE_SRC      = re.compile(r'<source\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_SOURCE_SRCSET   = re.compile(r'<source\b[^>]+srcset=["\']([^"\']+)["\']', re.IGNORECASE)

# <img> - full attribute set including non-standard ones
RE_IMG_SRC         = re.compile(r'<img\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_IMG_SRCSET      = re.compile(r'<img\b[^>]+srcset=["\']([^"\']+)["\']', re.IGNORECASE)
RE_IMG_DYNSRC      = re.compile(r'<img\b[^>]+dynsrc=["\']([^"\']+)["\']', re.IGNORECASE)
RE_IMG_LOWSRC      = re.compile(r'<img\b[^>]+lowsrc=["\']([^"\']+)["\']', re.IGNORECASE)
RE_IMG_LONGDESC    = re.compile(r'<img\b[^>]+longdesc=["\']([^"\']+)["\']', re.IGNORECASE)

# <object data/codebase> + nested <param value>
RE_OBJECT_DATA     = re.compile(r'<object\b[^>]+data=["\']([^"\']+)["\']', re.IGNORECASE)
RE_OBJECT_CODEBASE = re.compile(r'<object\b[^>]+codebase=["\']([^"\']+)["\']', re.IGNORECASE)
RE_PARAM_VALUE     = re.compile(r'<param\b[^>]+value=["\']([^"\']+)["\']', re.IGNORECASE)

# <table background> and <td background> (legacy HTML attribute)
RE_TABLE_BG        = re.compile(r'<table\b[^>]+background=["\']([^"\']+)["\']', re.IGNORECASE)
RE_TD_BG           = re.compile(r'<td\b[^>]+background=["\']([^"\']+)["\']', re.IGNORECASE)

# <body background> - even older legacy attribute
RE_BODY_BG         = re.compile(r'<body\b[^>]+background=["\']([^"\']+)["\']', re.IGNORECASE)

# <frame src> and <embed src>
RE_FRAME_SRC       = re.compile(r'<frame\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_EMBED_SRC       = re.compile(r'<embed\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# <iframe src> — the URL target (not srcdoc which is handled separately)
RE_IFRAME_SRC      = re.compile(r'<iframe\b[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# srcset parser - "url1 1x, url2 2x" or "url1 640w, url2 1280w"
_RE_SRCSET_ENTRY   = re.compile(r'([^\s,][^\s,]*)(?:\s+\d+(?:\.\d+)?[wx])?')

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
      - <button formaction> — per-button form action override
      - <html manifest> — PWA/AppCache manifest reference
      - <link href> — ALL rel types (preload, prefetch, canonical, alternate…)
      - <area href> — image map navigation links
      - onclick= window.location / location.href assignments
      - data-href / data-url / data-link / data-target attributes
      - <meta http-equiv="refresh"> redirects
      - <meta content> embedded path references
      - HTMX hx-get/post/put/patch/delete endpoints
      - <a ping> / <area ping> tracking URLs
      - <iframe src> / <frame src> / <embed src> — frame navigation
      - <iframe srcdoc> inline HTML endpoints (one level deep)
      - <object data/codebase> + <param value> — plugin/PDF endpoints
      - SVG <image href/xlink:href> and <script href/xlink:href>
      - <isindex action> / <import implementation> legacy targets
      - <blockquote cite> — cited source URL
      - <base href> — document base hint
      - Media: <audio src>, <video src/poster>, <source src/srcset>
      - <img src/srcset/dynsrc/lowsrc/longdesc>
      - <table background>, <td background>, <body background>
    """
    links: Set[str] = set()

    def _add(raw: str) -> None:
        raw = raw.strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:", "vbscript:")):
            return
        # Skip static asset extensions - not crawlable navigation targets
        _lower_raw = raw.split("?")[0].split("#")[0].lower()
        if _lower_raw.endswith((
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".tiff", ".tif",
            ".svg", ".ico", ".cur",
            ".mp4", ".webm", ".ogg", ".ogv", ".avi", ".mov", ".mkv", ".flv", ".wmv",
            ".mp3", ".wav", ".flac", ".aac", ".opus", ".m4a",
            ".pdf", ".swf", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        )):
            return
        absolute = _make_absolute(raw, base_url)
        if absolute:
            url_no_fragment, _ = urldefrag(absolute)
            _path_check = urlparse(url_no_fragment).path
            # JPEG base64 SOI - /9j/ prefix is unmistakable binary image data
            if _path_check.startswith("/9j/"):
                return
            # Drop URLs where any path segment is longer than 64 chars
            # (base64-encoded images, binary blobs, obfuscated junk)
            if any(len(seg) > 64 for seg in _path_check.split("/")):
                return
            links.add(url_no_fragment)

    def _add_srcset(srcset_val: str) -> None:
        """Parse a srcset attribute: 'url1 1x, url2 2x' or 'url1 640w, url2 1280w'."""
        for entry in srcset_val.split(","):
            parts = entry.strip().split()
            if parts:
                _add(parts[0])

    # Standard navigation
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

    # Button formaction - overrides parent form action, distinct endpoint
    for match in RE_BUTTON_FORMACTION.finditer(html):
        _add(match.group(1))

    # PWA/AppCache manifest reference on <html> element
    for match in RE_HTML_MANIFEST.finditer(html):
        _add(match.group(1))

    # <link href> — all rel types, not just preload
    for match in RE_LINK_HREF.finditer(html):
        raw = match.group(1).strip()
        # Skip CSS/font/icon links — they're not navigation targets
        if raw and not any(raw.endswith(ext) for ext in (".css", ".woff", ".woff2", ".ttf", ".otf", ".ico")):
            _add(raw)

    # HTMX attributes — every hx-* value is a live backend endpoint
    for match in RE_HTMX_ATTRS.finditer(html):
        _add(match.group(1))

    # <a ping> / <area ping> — space-separated list of POST ping URLs
    for pattern in (RE_A_PING, RE_AREA_PING):
        for match in pattern.finditer(html):
            for url in match.group(1).split():
                _add(url)

    # <frame src>, <embed src>, <iframe src>
    for pattern in (RE_FRAME_SRC, RE_EMBED_SRC, RE_IFRAME_SRC):
        for match in pattern.finditer(html):
            _add(match.group(1))

    # <iframe srcdoc> — recurse into the inline HTML (one level deep)
    _srcdoc_seen: Set[str] = set()
    for pattern in (RE_IFRAME_SRCDOC_DQ, RE_IFRAME_SRCDOC_SQ):
        for match in pattern.finditer(html):
            raw_srcdoc = match.group(1)
            if raw_srcdoc in _srcdoc_seen:
                continue
            _srcdoc_seen.add(raw_srcdoc)
            srcdoc_html = _unescape_attr(raw_srcdoc)
            for link in extract_links(srcdoc_html, base_url):
                links.add(link)

    # <object data/codebase> and nested <param value>
    for pattern in (RE_OBJECT_DATA, RE_OBJECT_CODEBASE, RE_PARAM_VALUE):
        for match in pattern.finditer(html):
            raw = match.group(1).strip()
            # Param values are often not URLs — only add if they look like paths
            if raw and (raw.startswith("/") or raw.startswith("http")):
                _add(raw)

    # SVG <image href/xlink:href> and <script href/xlink:href>
    for match in RE_SVG_IMAGE_HREF.finditer(html):
        raw = match.group(1).strip()
        if not raw.startswith("data:") and not raw.startswith("#"):
            _add(raw)

    # <isindex action> — legacy HTML4 form target
    for match in RE_ISINDEX_ACTION.finditer(html):
        _add(match.group(1))

    # <blockquote cite> — cited source URL
    for match in RE_BLOCKQUOTE_CITE.finditer(html):
        _add(match.group(1))

    # <meta content> — extract path-like values (e.g. Open Graph URLs, API paths)
    for match in RE_META_CONTENT.finditer(html):
        content_val = match.group(1).strip()
        # Full absolute URL in content= value
        if content_val.startswith(("http://", "https://")):
            _add(content_val)
        else:
            # Extract embedded relative paths like /api/v1/something
            for path_m in _RE_META_PATH.finditer(content_val):
                _add(path_m.group(1))

    # Media: <audio src>, <video src/poster>
    for pattern in (RE_AUDIO_SRC, RE_VIDEO_SRC, RE_VIDEO_POSTER):
        for match in pattern.finditer(html):
            _add(match.group(1))

    # <source src/srcset> nested inside audio/video
    for match in RE_SOURCE_SRC.finditer(html):
        _add(match.group(1))
    for match in RE_SOURCE_SRCSET.finditer(html):
        _add_srcset(match.group(1))

    # <img> — skip data: URIs, capture src + srcset + legacy attributes
    for match in RE_IMG_SRC.finditer(html):
        raw = match.group(1).strip()
        if not raw.startswith("data:"):
            _add(raw)
    for match in RE_IMG_SRCSET.finditer(html):
        _add_srcset(match.group(1))
    for pattern in (RE_IMG_DYNSRC, RE_IMG_LOWSRC, RE_IMG_LONGDESC):
        for match in pattern.finditer(html):
            _add(match.group(1))

    # Table and body backgrounds (legacy HTML attribute)
    for pattern in (RE_TABLE_BG, RE_TD_BG, RE_BODY_BG):
        for match in pattern.finditer(html):
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
