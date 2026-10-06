"""
BundleSpy crawler - built for 100% JS discovery accuracy.

Discovery pipeline (in order):
  1.  robots.txt           - passive JS path hints
  2.  sitemap.xml          - full page inventory (all sitemaps, no early return)
  3.  Asset manifests      - CRA, Vite, Next.js, Laravel Mix, Gulp Rev, Nuxt
  4.  Common JS paths      - always probed (small core set + more with --common-paths)
  5.  HTML crawl           - BFS over every reachable page
  6.  JS-in-JS scanning    - chunk refs, dynamic imports, worker URLs inside fetched JS
  7.  Webpack chunk engine - reconstruct full chunk map from runtime (webpack 4 + 5)
  8.  Next.js full mode    - __NEXT_DATA__ buildId -> _buildManifest.js -> every chunk
  9.  Vite manifest        - file + imports array + content scan for hashed chunks
  10. Source maps          - fetch .map files, recover original source
  11. Service workers      - extract precache lists (Workbox + sw-precache)
  12. Import maps          - ES module specifier resolution
  13. Link headers         - preload/prefetch response headers (X-Link, Link)
  14. Protocol-relative    - //cdn.example.com/app.js
  15. data-src lazy loads  - intersection-observer lazy loaders
  16. Worker constructors  - new Worker() / new SharedWorker() inside JS
  17. Module Federation    - remote entry discovery (remoteEntry.js probing)
  18. SvelteKit / Remix    - framework-specific chunk patterns
  19. Angular lazy routes  - loadChildren() chunk extraction
  20. base href            - correct URL resolution on sites using <base>

Design rules:
  - No duplicate fetches: dedup by (normalized URL + content hash)
  - Scope-checked before every network call
  - Safety-filtered via safety.network allow-list
  - Retry once on 5xx
  - Never logs or stores the matched secret value
  - Populates self.js_files in-place; callers see updated objects
"""

import re
import json
import hashlib
import logging
import xml.etree.ElementTree as ET
from collections import deque
from typing import Set, List, Tuple, Optional, Dict
from datetime import datetime
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse

from .fetcher import Fetcher
from .scope import ScopeChecker
from ..discovery.html import (
    extract_js_urls,
    extract_links,
    extract_inline_scripts,
    extract_htmx_endpoints,
    extract_ping_urls,
)
from ..discovery.header_parser import extract_header_urls
from ..storage.models import JSFile, RouteState, AccessState
from ..analysis.html_scanner import scan_html

logger = logging.getLogger("bundlespy.crawler")


# ── Extension sets ────────────────────────────────────────────────────────────

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}


# ── Well-known probe paths ────────────────────────────────────────────────────

COMMON_PAGE_PATHS = [
    "/login", "/signin", "/sign-in", "/log-in",
    "/register", "/signup", "/sign-up", "/join",
    "/logout", "/account", "/my-account", "/profile",
    "/admin", "/administrator", "/dashboard", "/panel",
    "/search", "/contact", "/about", "/help", "/faq",
    "/cart", "/checkout", "/orders", "/settings",
    "/password-reset", "/forgot-password", "/reset-password",
    "/api", "/api/docs", "/swagger", "/graphql",
    "/blog", "/news", "/products", "/catalog",
    "/user", "/users", "/home",
    "/upload", "/download", "/files", "/media",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
]

# Always probed — small, high-value core set
CORE_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js", "/runtime.js",
    "/index.js", "/app.min.js", "/main.min.js",
    "/static/js/main.js", "/static/js/bundle.js", "/static/js/runtime.js",
    "/assets/app.js", "/assets/index.js",
    "/js/app.js", "/js/main.js",
]

# Extended probing when --common-paths is set
EXTENDED_JS_PATHS = [
    "/vendor.js", "/application.js",
    "/assets/main.js", "/assets/vendor.js",
    "/static/js/app.js", "/static/js/vendor.js",
    "/js/bundle.js", "/js/vendor.js",
    "/dist/app.js", "/dist/main.js", "/dist/bundle.js",
    "/build/app.js", "/build/main.js",
    "/public/js/app.js", "/public/js/main.js",
    "/chunk-vendors.js", "/precache-manifest.js",
    "/service-worker.js", "/sw.js",
]

ASSET_MANIFEST_PATHS = [
    "/asset-manifest.json",            # Create React App
    "/static/asset-manifest.json",
    "/.vite/manifest.json",            # Vite
    "/vite-manifest.json",
    "/manifest.json",                  # Generic / PWA
    "/build/asset-manifest.json",      # CRA build output
    "/_next/static/chunks/webpack.js", # Next.js webpack runtime
    "/webpack-manifest.json",
    "/mix-manifest.json",              # Laravel Mix
    "/rev-manifest.json",              # Gulp Rev
    "/assets/manifest.json",
    "/static/manifest.json",
    "/public/mix-manifest.json",
    "/webpack-stats.json",             # webpack-bundle-analyzer output
    "/.nuxt/manifest.json",            # Nuxt.js
    "/__nuxt/manifest.json",
    "/__remix_manifest",               # Remix
    "/__manifest",                     # Remix (alternate)
    "/_app/version.json",              # SvelteKit
]

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/wp-sitemap.xml",
    "/sitemaps/sitemap.xml",
    "/sitemap/sitemap.xml",
]

# Module Federation remote entry filenames to probe
MODULE_FEDERATION_PROBES = [
    "/remoteEntry.js",
    "/remote-entry.js",
    "/remoteentry.js",
    "/mf-manifest.json",
    "/federation-manifest.json",
    "/static/remoteEntry.js",
    "/assets/remoteEntry.js",
    "/dist/remoteEntry.js",
]


# ── Technology fingerprints ───────────────────────────────────────────────────

TECH_PATTERNS: Dict[str, List[str]] = {
    "React":     ["react.development.js", "__REACT_DEVTOOLS", "React.createElement", "_jsx("],
    "Vue":       ["Vue.config", "__vue_router__", "createApp(", "__VUE__"],
    "Angular":   ["ng-version", "platformBrowserDynamic", "NgModule", "definitComponent"],
    "Next.js":   ["__NEXT_DATA__", "/_next/static", "__NEXT_ROUTER"],
    "Nuxt.js":   ["__NUXT__", "/_nuxt/", "__nuxt"],
    "Webpack":   ["__webpack_require__", "webpackBootstrap", "__webpack_modules__"],
    "Vite":      ["/@vite/", "import.meta.hot", "/@fs/", "vite/preload"],
    "Svelte":    ["SvelteComponent", "__svelte", "svelte/internal", "/_app/immutable/"],
    "Ember":     ["Ember.Application", "define('ember", "EmberENV"],
    "Remix":     ["__remixContext", "__remix_manifest", "RemixBrowser"],
    "Astro":     ["astro:scripts/", "_astro/", "astro-island"],
}

# ── Regexes compiled once at import time ─────────────────────────────────────

# JS URLs embedded inside JS content
RE_JS_IN_JS = re.compile(
    r"""(?:import\s*\(|require\s*\(|importScripts\s*\(|fetch\s*\(|loadScript\s*\()\s*['"`]([^'"`]+\.(?:js|mjs|cjs|jsx|ts|tsx))['"`]""",
    re.IGNORECASE,
)

# Dynamic import() with variable path prefix patterns - catches chunk paths
RE_DYNAMIC_IMPORT = re.compile(
    r"""import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)""",
    re.IGNORECASE,
)

# Worker constructors
RE_WORKER = re.compile(
    r"""new\s+(?:Shared)?Worker\s*\(\s*['"`]([^'"`]+\.(?:js|mjs))['"`]""",
    re.IGNORECASE,
)

# Service worker registration
RE_SW_REGISTER = re.compile(
    r"""(?:registerServiceWorker|serviceWorker\.register)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# Protocol-relative JS URLs
RE_PROTO_RELATIVE = re.compile(
    r"""['"]//([a-zA-Z0-9][^'"]*\.(?:js|mjs))['"]"""
)

# data-src lazy-load JS
RE_DATA_SRC_JS = re.compile(
    r"""data-(?:src|lazy|url)=['"]([^'"]*\.(?:js|mjs)[^'"]*)['"]""",
    re.IGNORECASE,
)

# sourceMappingURL
RE_SOURCE_MAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s\"']+)")

# Next.js __NEXT_DATA__ JSON block
RE_NEXT_DATA = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>\s*(\{.*?\})\s*</script>',
    re.IGNORECASE | re.DOTALL,
)

# Vite manifest: imports array inside each entry
RE_VITE_IMPORTS = re.compile(
    r'"imports"\s*:\s*\[([^\]]+)\]',
    re.IGNORECASE,
)

# Webpack publicPath
RE_WP_PUBLIC_PATH = re.compile(
    r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']'
)

# Webpack 5 chunk map inside __webpack_require__.u = (id) => { ... }
RE_WP5_CHUNK_FN = re.compile(
    r'__webpack_require__\.u\s*=\s*\(?\w+\)?\s*=>\s*\{([^}]{0,4000})\}',
    re.DOTALL,
)

# Webpack 4: {0:"abc",1:"def"}[chunkId]+".js"
RE_WP4_CHUNK_MAP = re.compile(
    r'\{([^}]{0,4000})\}\s*\[\s*\w+\s*\]\s*\+\s*["\']\.js["\']',
    re.DOTALL,
)

# Named chunks in webpack runtime: "vendor":"abc123"
RE_NAMED_CHUNK = re.compile(
    r'["\']([a-zA-Z0-9_\-]+)["\']\s*:\s*["\']([a-zA-Z0-9_\-]+)["\']'
)

# Generic chunk URL strings already assembled
RE_CHUNK_URL_STR = re.compile(
    r'["\']([^"\']*chunk[^"\']*\.js(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)

# Vite hashed asset chunks: assets/Foo-AbCdEfGh.js
RE_VITE_CHUNK_STR = re.compile(
    r'["\']([^"\']*assets/[^"\']+\.[a-f0-9]{8,}\.js)["\']',
    re.IGNORECASE,
)

# SvelteKit immutable chunks: /_app/immutable/chunks/Foo-AbCdEfGh.js
RE_SVELTE_CHUNK_STR = re.compile(
    r'["\']([^"\']*/_app/immutable/[^"\']+\.js)["\']',
    re.IGNORECASE,
)

# Import map inside <script type="importmap">
RE_IMPORT_MAP_BLOCK = re.compile(
    r'<script[^>]+type=["\']importmap["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

# Link header: </static/js/main.js>; rel=preload; as=script
RE_LINK_HEADER = re.compile(r'<([^>]+)>')

# Workbox precache list in service workers
RE_SW_PRECACHE = re.compile(
    r'["\']([^"\']*\.(?:js|mjs)(?:\?[^"\']*)?)["\']'
)

# <base href="..."> for URL resolution
RE_BASE_HREF = re.compile(
    r'<base[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# ── Gap 3: Static form submission ─────────────────────────────────────────────
# Extract all <form> blocks to build GET navigation requests from them.
# action + name=value querystring = synthetic GET navigation target.
RE_FORM_BLOCK      = re.compile(
    r'<form\b([^>]*)>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)
RE_FORM_ATTR_ACTION = re.compile(r'\baction=["\']([^"\']*)["\']', re.IGNORECASE)
RE_FORM_ATTR_METHOD = re.compile(r'\bmethod=["\']([^"\']*)["\']', re.IGNORECASE)
RE_INPUT_NAME_VAL   = re.compile(
    r'<input\b[^>]*\bname=["\']([^"\']+)["\'][^>]*(?:\bvalue=["\']([^"\']*)["\'])?[^>]*>',
    re.IGNORECASE,
)
RE_INPUT_VAL_NAME   = re.compile(
    r'<input\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*\bname=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)
RE_SELECT_NAME      = re.compile(r'<select\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE)
RE_TEXTAREA_NAME    = re.compile(r'<textarea\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE)

# Binary content magic-byte prefixes (first 16 bytes are enough for detection)
# Anything matching is treated as binary — body scraping is skipped entirely.
_BINARY_MAGIC: tuple = (
    b"\x89PNG",           # PNG
    b"\xff\xd8\xff",      # JPEG
    b"GIF8",              # GIF
    b"RIFF",              # WAV / AVI / WebP (checks RIFF header)
    b"BM",                # BMP
    b"\x00\x00\x01\x00",  # ICO
    b"\x1f\x8b",          # gzip
    b"PK\x03\x04",        # ZIP / DOCX / XLSX / JAR
    b"\x7fELF",           # ELF binary
    b"MZ",                # PE / DOS executable
    b"\xca\xfe\xba\xbe",  # Java class
    b"%PDF",              # PDF
    b"\x25\x50\x44\x46",  # PDF (alternative)
    b"OggS",              # Ogg audio/video
    b"\x1a\x45\xdf\xa3",  # WebM / MKV
    b"fLaC",              # FLAC
    b"\xff\xfb",          # MP3
    b"ID3",               # MP3 ID3v2
    b"wOFF",              # WOFF font
    b"wOF2",              # WOFF2 font
    b"\x00\x01\x00\x00",  # TTF
    b"OTTO",              # OTF (CFF)
)

# integrity attribute on <script> tags - links to CDN-hosted files
RE_SCRIPT_INTEGRITY = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\'][^>]+integrity=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Angular loadChildren lazy routes: loadChildren: () => import('./module').then(...)
RE_ANGULAR_LAZY = re.compile(
    r"""loadChildren\s*:\s*\(\s*\)\s*=>\s*import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)""",
    re.IGNORECASE,
)

# Module Federation: exposes/remotes config in webpack
RE_MF_REMOTE = re.compile(
    r"""(?:remote|remotes)\s*:\s*\{([^}]{0,2000})\}""",
    re.DOTALL,
)

# Remix asset manifest: imports array
RE_REMIX_IMPORTS = re.compile(
    r'"imports"\s*:\s*\[([^\]]+)\]',
    re.IGNORECASE,
)

# Astro chunk patterns: _astro/Foo.AbCd1234.js
RE_ASTRO_CHUNK = re.compile(
    r'["\']([^"\']*/_astro/[^"\']+\.js)["\']',
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_js_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in JS_EXTENSIONS)


def _normalize_url(url: str) -> str:
    """Strip query + fragment for dedup. /app.js?v=1 and /app.js?v=2 are the same file."""
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def fingerprint_tech(content: str) -> str:
    for tech, patterns in TECH_PATTERNS.items():
        if any(p in content for p in patterns):
            return tech
    return ""


def _extract_base_href(html: str) -> Optional[str]:
    """Extract <base href='...'> from HTML for correct relative URL resolution."""
    m = RE_BASE_HREF.search(html)
    return m.group(1).strip() if m else None


def _resolve_with_base(url: str, base_href: Optional[str], page_url: str) -> str:
    """Resolve a URL using <base href> if present, otherwise use the page URL."""
    if not base_href:
        return urljoin(page_url, url)
    # base_href itself may be relative to the page
    absolute_base = urljoin(page_url, base_href)
    return urljoin(absolute_base, url)


# ── Gap 2: Binary content guard ───────────────────────────────────────────────

def _is_binary_response(content: str) -> bool:
    """
    Return True when the response body is binary data (image, font, archive…).

    We check the first 32 characters of the string representation against
    known binary magic-byte prefixes.  The fetcher decodes bytes to a str
    with errors='replace', so magic bytes survive as latin-1 equivalent
    characters.  A match means we must skip endpoint/link scraping on this
    body — it will produce only garbage matches.

    Equivalent to Katana's isTextualResponse() guard.
    """
    if not content:
        return False
    # Re-encode back to bytes to check magic bytes; take only the header
    try:
        header = content[:32].encode("latin-1", errors="replace")
    except Exception:
        return False
    return any(header.startswith(magic) for magic in _BINARY_MAGIC)


def _is_textual_content_type(content_type: str) -> bool:
    """
    Return True when the Content-Type header indicates textual content.

    We allow text/*, application/json, application/javascript,
    application/xml, application/xhtml+xml, and SVG.  Everything else
    (image/*, audio/*, video/*, application/octet-stream, font/*…)
    is considered non-textual and endpoint scraping is skipped.
    """
    ct = (content_type or "").lower().split(";")[0].strip()
    if not ct:
        return True  # no content-type — assume text (safe default)
    textual_prefixes = (
        "text/",
        "application/json",
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "application/xml",
        "application/xhtml+xml",
        "application/ld+json",
        "image/svg+xml",    # SVG is XML — we can parse it
    )
    return any(ct.startswith(p) for p in textual_prefixes)


# ── Gap 3: Static form → GET navigation request ───────────────────────────────

def _extract_form_get_urls(html: str, base_url: str) -> List[str]:
    """
    Build synthetic GET navigation URLs from every GET/unspecified <form> in the page.

    For each form we:
      1. Resolve the action URL (defaults to current page URL if absent)
      2. Collect name=value pairs from <input>, <select>, <textarea>
      3. Construct a ?name=placeholder_value querystring
      4. Return the full URL — the crawler will visit it as a normal page

    This is what Katana's bodyFormTagParser does for the static (non-headless)
    crawler: it submits forms as real HTTP GET requests to discover parameters
    and server-side routing decisions without a browser.

    POST forms are intentionally excluded here — they mutate state.
    The headless FormInteractor handles them under --forms.
    """
    urls: List[str] = []

    for form_match in RE_FORM_BLOCK.finditer(html):
        attrs_str  = form_match.group(1)
        form_body  = form_match.group(2)

        # Only process GET forms (or forms without an explicit method)
        method_m = RE_FORM_ATTR_METHOD.search(attrs_str)
        method   = method_m.group(1).upper() if method_m else "GET"
        if method != "GET":
            continue

        # Resolve action URL
        action_m  = RE_FORM_ATTR_ACTION.search(attrs_str)
        action    = action_m.group(1).strip() if action_m else ""
        action_url = urljoin(base_url, action) if action else base_url

        # Skip non-HTTP targets
        if not action_url.startswith(("http://", "https://")):
            continue

        # Collect field names (we use placeholder values — no real data)
        params: List[str] = []

        # <input name="foo" value="bar"> — prefer name-then-value order
        seen_names: Set[str] = set()
        for inp_m in RE_INPUT_NAME_VAL.finditer(form_body):
            name = inp_m.group(1).strip()
            val  = (inp_m.group(2) or "").strip()
            if name and name not in seen_names:
                seen_names.add(name)
                # Use the existing value if present, else a safe placeholder
                params.append(f"{name}={val or 'test'}")
        # Catch value-before-name attribute order
        for inp_m in RE_INPUT_VAL_NAME.finditer(form_body):
            val  = (inp_m.group(1) or "").strip()
            name = inp_m.group(2).strip()
            if name and name not in seen_names:
                seen_names.add(name)
                params.append(f"{name}={val or 'test'}")

        # <select name="sort"> — add a placeholder option value
        for sel_m in RE_SELECT_NAME.finditer(form_body):
            name = sel_m.group(1).strip()
            if name and name not in seen_names:
                seen_names.add(name)
                params.append(f"{name}=0")

        # <textarea name="message">
        for ta_m in RE_TEXTAREA_NAME.finditer(form_body):
            name = ta_m.group(1).strip()
            if name and name not in seen_names:
                seen_names.add(name)
                params.append(f"{name}=test")

        if params:
            qs  = "&".join(params)
            sep = "&" if "?" in action_url else "?"
            urls.append(f"{action_url}{sep}{qs}")
        else:
            # Form has no named fields — just add the action URL as a link
            urls.append(action_url)

    return urls


def _extract_js_from_manifest(content: str, base_url: str) -> List[str]:
    """
    Parse asset manifest JSON - handles CRA, Vite, Laravel Mix, Gulp Rev,
    and generic manifest formats. Recursively walks the JSON tree.
    Also extracts Vite's 'imports' arrays which list dynamic chunk filenames.
    """
    urls: List[str] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return urls

    def _collect(obj, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, str):
            if _is_js_url(obj) or obj.endswith(".js"):
                urls.append(urljoin(base_url, obj))
        elif isinstance(obj, dict):
            # Vite manifest: each entry has 'file' and optional 'imports' list
            if "file" in obj and isinstance(obj["file"], str):
                if _is_js_url(obj["file"]):
                    urls.append(urljoin(base_url, obj["file"]))
            if "imports" in obj and isinstance(obj["imports"], list):
                for imp in obj["imports"]:
                    if isinstance(imp, str):
                        # Vite import refs start with _ (e.g. "_vendor-abc.js")
                        # and are relative to the assets/ directory
                        candidate = imp if imp.startswith("/") else "/assets/" + imp.lstrip("_")
                        urls.append(urljoin(base_url, candidate))
            for v in obj.values():
                _collect(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item, depth + 1)

    _collect(data)
    return list(dict.fromkeys(urls))  # preserve order, remove dups


def _parse_robots_for_js(content: str, base_url: str) -> List[str]:
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths: List[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(("disallow:", "allow:")):
            path = line.split(":", 1)[1].strip()
            if path and any(kw in path.lower() for kw in [
                "/js/", "/javascript/", "/static/", "/assets/",
                "/build/", "/dist/", "/public/", "bundle", "chunk",
            ]):
                if not path.endswith("/") and _is_js_url(path):
                    paths.append(base + path)
    return paths


def _extract_js_from_link_header(headers: dict, base_url: str) -> List[str]:
    """Parse Link response header for preloaded/prefetched JS files."""
    # Try both capitalizations; some servers send X-Link
    link_hdr = (
        headers.get("link")
        or headers.get("Link")
        or headers.get("x-link")
        or headers.get("X-Link")
        or ""
    )
    urls: List[str] = []
    for part in link_hdr.split(","):
        part = part.strip()
        m = RE_LINK_HEADER.match(part)
        if not m:
            continue
        url = m.group(1).strip()
        # Include if explicitly as=script, or if path looks like JS
        if "as=script" in part or _is_js_url(url):
            urls.append(urljoin(base_url, url))
    return urls


def _extract_js_from_service_worker(content: str, sw_url: str) -> List[str]:
    """Extract precached JS files from Workbox / sw-precache service workers."""
    urls: Set[str] = set()
    base = sw_url.rsplit("/", 1)[0] + "/"
    parsed = urlparse(sw_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for m in RE_SW_PRECACHE.finditer(content):
        raw = m.group(1)
        if not _is_js_url(raw):
            continue
        if raw.startswith("http://") or raw.startswith("https://"):
            urls.add(raw)
        elif raw.startswith("/"):
            urls.add(origin + raw)
        else:
            urls.add(urljoin(base, raw))

    return list(urls)


def _extract_import_map(html: str, base_url: str) -> List[str]:
    """Parse <script type="importmap"> for ES module specifier -> URL mappings."""
    urls: List[str] = []
    m = RE_IMPORT_MAP_BLOCK.search(html)
    if not m:
        return urls
    try:
        data = json.loads(m.group(1))
        imports = data.get("imports", {})
        for v in imports.values():
            if isinstance(v, str) and _is_js_url(v):
                urls.append(urljoin(base_url, v))
        # Also handle scopes
        for scope_map in data.get("scopes", {}).values():
            if isinstance(scope_map, dict):
                for v in scope_map.values():
                    if isinstance(v, str) and _is_js_url(v):
                        urls.append(urljoin(base_url, v))
    except Exception:
        pass
    return urls


def _extract_next_data(html: str) -> Optional[dict]:
    """Extract __NEXT_DATA__ JSON from a Next.js HTML page."""
    m = RE_NEXT_DATA.search(html)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None


def _extract_remix_chunks(content: str, base_url: str) -> List[str]:
    """Parse Remix asset manifest JSON for JS chunk URLs."""
    urls: List[str] = []
    try:
        data = json.loads(content)
    except Exception:
        return urls
    # Remix manifest: { routes: { "route-id": { module: "...", imports: [...] } } }
    routes = data.get("routes", {})
    for route in routes.values():
        if not isinstance(route, dict):
            continue
        module = route.get("module", "")
        if module and _is_js_url(module):
            urls.append(urljoin(base_url, module))
        for imp in route.get("imports", []):
            if isinstance(imp, str) and _is_js_url(imp):
                urls.append(urljoin(base_url, imp))
    return list(dict.fromkeys(urls))


def _extract_sveltekit_chunks(content: str, base_url: str) -> List[str]:
    """
    Parse SvelteKit version manifest + extract chunk URLs.
    SvelteKit puts chunks at /_app/immutable/chunks/ with content hashes.
    """
    urls: List[str] = []
    # Try JSON first (_app/version.json or manifest.json)
    try:
        data = json.loads(content)
        # SvelteKit manifest.json has nested route entries
        def _walk(obj: object, depth: int = 0) -> None:
            if depth > 6:
                return
            if isinstance(obj, str) and _is_js_url(obj):
                urls.append(urljoin(base_url, obj))
            elif isinstance(obj, dict):
                for v in obj.values():
                    _walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item, depth + 1)
        _walk(data)
    except Exception:
        pass
    # Also scan raw content for /_app/immutable/ patterns
    for m in RE_SVELTE_CHUNK_STR.finditer(content):
        urls.append(urljoin(base_url, m.group(1)))
    return list(dict.fromkeys(urls))


# ── JS-in-JS scanner ─────────────────────────────────────────────────────────

def _scan_js_for_urls(content: str, js_url: str, origin: str) -> List[str]:
    """
    Scan JS content for more JS URLs: dynamic imports, workers,
    chunk URL strings, Vite hashed chunks, protocol-relative, Astro chunks,
    SvelteKit chunks, and Angular lazy routes.
    Returns absolute URLs only.
    """
    urls: Set[str] = set()
    base_dir = js_url.rsplit("/", 1)[0] + "/"

    def _abs(raw: str) -> Optional[str]:
        raw = raw.strip()
        if not raw:
            return None
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        if raw.startswith("//"):
            parsed = urlparse(js_url)
            return f"{parsed.scheme}:{raw}"
        if raw.startswith("/"):
            return origin + raw
        return urljoin(base_dir, raw)

    # import("./foo.js"), require("./bar.js"), importScripts(...), fetch(...), loadScript(...)
    for m in RE_JS_IN_JS.finditer(content):
        abs_url = _abs(m.group(1))
        if abs_url:
            urls.add(abs_url)

    # import("./chunk-123.js") - dynamic imports
    for m in RE_DYNAMIC_IMPORT.finditer(content):
        raw = m.group(1)
        if _is_js_url(raw):
            abs_url = _abs(raw)
            if abs_url:
                urls.add(abs_url)

    # new Worker("/workers/sw.js")
    for m in RE_WORKER.finditer(content):
        abs_url = _abs(m.group(1))
        if abs_url:
            urls.add(abs_url)

    # Generic chunk URL strings already assembled in bundle
    for m in RE_CHUNK_URL_STR.finditer(content):
        raw = m.group(1)
        if raw.startswith("/") or raw.startswith("http"):
            abs_url = _abs(raw)
            if abs_url:
                urls.add(abs_url)

    # Vite hashed chunks: "assets/Foo-Ab12Cd34.js"
    for m in RE_VITE_CHUNK_STR.finditer(content):
        abs_url = _abs("/" + m.group(1).lstrip("/"))
        if abs_url:
            urls.add(abs_url)

    # SvelteKit immutable chunks: "/_app/immutable/chunks/Foo-Ab12Cd34.js"
    for m in RE_SVELTE_CHUNK_STR.finditer(content):
        abs_url = _abs(m.group(1))
        if abs_url:
            urls.add(abs_url)

    # Astro chunks: "/_astro/Foo.Ab12Cd34.js"
    for m in RE_ASTRO_CHUNK.finditer(content):
        abs_url = _abs(m.group(1))
        if abs_url:
            urls.add(abs_url)

    # Angular lazy routes: loadChildren: () => import('./some.module')
    for m in RE_ANGULAR_LAZY.finditer(content):
        raw = m.group(1)
        # Convert module path to JS file if not already
        if not raw.endswith(".js"):
            raw = raw + ".js"
        abs_url = _abs(raw)
        if abs_url:
            urls.add(abs_url)

    # Protocol-relative: "//cdn.example.com/lib.js"
    for m in RE_PROTO_RELATIVE.finditer(content):
        parsed = urlparse(js_url)
        urls.add(f"{parsed.scheme}://{m.group(1)}")

    return [u for u in urls if _is_js_url(u)]


# ── Webpack full chunk reconstruction ─────────────────────────────────────────

def _extract_webpack_public_path(content: str, js_url: str) -> str:
    m = RE_WP_PUBLIC_PATH.search(content)
    if m:
        pp = m.group(1)
        if pp and pp not in ("auto", "") and not pp.startswith("__"):
            if pp.startswith("http"):
                return pp
            return urljoin(js_url, pp)
    # Default: same directory as the runtime JS file
    parsed = urlparse(js_url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}/"


def _reconstruct_webpack_chunks(content: str, js_url: str) -> List[str]:
    """
    Reconstruct every chunk URL from a webpack runtime file.
    Handles webpack 4 and webpack 5, named and numeric chunk IDs.
    """
    urls: Set[str] = set()
    public_path = _extract_webpack_public_path(content, js_url)

    def _chunk_url(filename: str) -> str:
        if filename.startswith("http"):
            return filename
        return urljoin(public_path, filename)

    # Webpack 5: __webpack_require__.u = (id) => { return {0:"abc", 1:"def"}[id]+".js" }
    m5 = RE_WP5_CHUNK_FN.search(content)
    if m5:
        body = m5.group(1)
        # Named chunks: "main":"abc123"
        for nm in RE_NAMED_CHUNK.finditer(body):
            name, hash_val = nm.group(1), nm.group(2)
            for pat in [
                f"{name}.{hash_val}.chunk.js",
                f"{name}.{hash_val}.js",
                f"{hash_val}.chunk.js",
                f"{hash_val}.js",
            ]:
                urls.add(_chunk_url(pat))
        # Numeric IDs - try to extract the hash mapping
        # Pattern: case 123: return "abc123.chunk.js"
        for case_m in re.finditer(r'["\']?(\d+)["\']?\s*:\s*["\']([a-f0-9]+)["\']', body):
            cid, h = case_m.group(1), case_m.group(2)
            for pat in [f"{cid}.{h}.chunk.js", f"{cid}.{h}.js", f"{h}.js"]:
                urls.add(_chunk_url(pat))

    # Webpack 4: {0:"abc",1:"def"}[chunkId]+".js"
    for m4 in RE_WP4_CHUNK_MAP.finditer(content):
        body = m4.group(1)
        for nm in RE_NAMED_CHUNK.finditer(body):
            name, hash_val = nm.group(1), nm.group(2)
            for pat in [
                f"{name}.{hash_val}.chunk.js",
                f"{name}.{hash_val}.js",
                f"{hash_val}.js",
            ]:
                urls.add(_chunk_url(pat))

    # Chunk URL strings already assembled in the runtime
    for m in RE_CHUNK_URL_STR.finditer(content):
        raw = m.group(1)
        if raw.startswith("/") or raw.startswith("http"):
            urls.add(_chunk_url(raw))
        else:
            urls.add(_chunk_url(raw))

    return [u for u in urls if _is_js_url(u)]


# ── Vite manifest full parser ─────────────────────────────────────────────────

def _extract_vite_chunks(manifest_content: str, base_url: str) -> List[str]:
    """
    Parse Vite manifest.json fully.
    Each entry: { "file": "assets/main-abc.js", "imports": ["_vendor-def.js"], "css": [...] }
    The 'imports' array contains additional chunk filenames we must fetch.
    """
    urls: Set[str] = set()
    try:
        data = json.loads(manifest_content)
    except Exception:
        return []

    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        # Primary file
        file_path = entry.get("file", "")
        if file_path and _is_js_url(file_path):
            urls.add(urljoin(base_url, "/" + file_path.lstrip("/")))
        # Imported chunks (Vite uses _chunkName.js convention)
        for imp in entry.get("imports", []):
            if isinstance(imp, str):
                # imp is a key in the manifest itself, look it up
                sub_entry = data.get(imp, {})
                sub_file = sub_entry.get("file", imp)
                if _is_js_url(sub_file):
                    urls.add(urljoin(base_url, "/" + sub_file.lstrip("/")))

    return list(urls)


# ── Next.js full coverage ─────────────────────────────────────────────────────

def _discover_nextjs_chunks(html: str, base_url: str, fetcher: "Fetcher") -> List[str]:
    """
    Full Next.js chunk discovery:
    1. Parse __NEXT_DATA__ to get buildId
    2. Fetch /_next/static/<buildId>/_buildManifest.js - lists every page chunk
    3. Fetch /_next/static/<buildId>/_ssgManifest.js - SSG routes
    4. Probe /_next/static/chunks/ common entry names
    Returns all chunk URLs found.
    """
    urls: Set[str] = set()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    next_data = _extract_next_data(html)
    build_id = None
    if next_data:
        build_id = next_data.get("buildId")

    if build_id:
        manifest_paths = [
            f"/_next/static/{build_id}/_buildManifest.js",
            f"/_next/static/{build_id}/_ssgManifest.js",
        ]
        for mpath in manifest_paths:
            content, status, _, _ = fetcher.get(origin + mpath)
            if content and status == 200:
                # _buildManifest.js assigns self.__BUILD_MANIFEST = {...}
                # Parse out all chunk paths from the JS
                for m in re.finditer(r'["\']([^"\']*/_next/static/[^"\']+\.js)["\']', content):
                    urls.add(urljoin(base_url, m.group(1)))
                # Also any string that looks like a page chunk
                for m in re.finditer(r'["\']([^"\']+\.js)["\']', content):
                    raw = m.group(1)
                    if raw.startswith("/_next/") or raw.startswith("/_next/static/"):
                        urls.add(urljoin(base_url, raw))

    # Probe known Next.js static chunk paths
    static_probes = [
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/webpack.js",
        "/_next/static/chunks/pages/_app.js",
        "/_next/static/chunks/pages/_error.js",
        "/_next/static/chunks/pages/index.js",
        "/_next/static/chunks/framework.js",
        "/_next/static/chunks/polyfills.js",
    ]
    for path in static_probes:
        url = origin + path
        content, status, _, _ = fetcher.get(url)
        if content and status == 200:
            urls.add(url)
            # Scan the chunk itself for more references
            for m in re.finditer(r'["\']([^"\']*/_next/static/[^"\']+\.js)["\']', content):
                urls.add(urljoin(base_url, m.group(1)))

    return [u for u in urls if _is_js_url(u)]


# ── Source map helper ─────────────────────────────────────────────────────────

def _get_source_map_url(content: str, js_url: str) -> Optional[str]:
    """Extract sourceMappingURL from tail of JS content (last 3000 chars)."""
    tail = content[-3000:]
    m = RE_SOURCE_MAP.search(tail)
    if not m:
        m = RE_SOURCE_MAP.search(content)
    if not m:
        return None
    raw = m.group(1).strip()
    if raw.startswith("data:"):
        return raw
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return urljoin(js_url, raw)


# ── Main Crawler class ────────────────────────────────────────────────────────

class Crawler:
    def __init__(
        self,
        target_url:   str,
        fetcher:      Fetcher,
        scope:        ScopeChecker,
        max_depth:    int  = 2,
        max_pages:    int  = 100,
        max_js_files: int  = 1000,
        common_paths: bool = False,
    ):
        self.target_url   = target_url
        self.fetcher      = fetcher
        self.scope        = scope
        self.max_depth    = max_depth
        self.max_pages    = max_pages
        self.max_js_files = max_js_files
        self.common_paths = common_paths

        # Dedup state
        self.visited_pages:      Set[str] = set()
        self.visited_js:         Set[str] = set()   # normalized URLs
        self.seen_js_hashes:     Set[str] = set()   # content SHA256
        self.seen_inline_hashes: Set[str] = set()

        # Output
        self.js_files:       List[JSFile] = []
        self.inline_scripts: List[Tuple[str, str]] = []
        self.html_findings:  List = []
        self.errors:         List[str] = []
        self.pages_crawled:  int = 0
        self.page_access_states: Dict[str, int] = {}  # url -> http_status

        # Internal: framework detection per-run
        self._nextjs_detected = False
        self._nextjs_html: Optional[str] = None
        self._svelte_detected = False
        self._remix_detected = False
        self._astro_detected = False

    @property
    def _origin(self) -> str:
        p = urlparse(self.target_url)
        return f"{p.scheme}://{p.netloc}"

    def crawl(self) -> None:
        """Full crawl pipeline - runs all discovery methods."""
        origin = self._origin

        # Phase 1: robots.txt
        self._discover_from_robots(origin)

        # Phase 2: asset manifests (CRA, Vite, Next.js runtime, Laravel Mix, Remix, SvelteKit, etc.)
        self._discover_from_manifests(origin)

        # Phase 3: core JS paths always probed; extended set with --common-paths
        for path in CORE_JS_PATHS:
            self._fetch_js(origin + path, self.target_url)
        if self.common_paths:
            for path in EXTENDED_JS_PATHS:
                self._fetch_js(origin + path, self.target_url)

        # Phase 4: Module Federation remote entry probing (always)
        self._discover_module_federation(origin)

        # Phase 5: sitemap -> page queue
        queue: deque = deque()
        queue.append((self.target_url, 0))
        self.visited_pages.add(self.target_url)
        self._feed_sitemap_to_queue(origin, queue)

        # Phase 6: common page probes -> add live ones to queue
        for path in COMMON_PAGE_PATHS:
            probe_url = origin + path
            if probe_url in self.visited_pages:
                continue
            c, s, ct, _ = self.fetcher.get(probe_url)
            if s and s > 0:
                self.page_access_states[probe_url] = s
            if c and 200 <= s < 300 and ("html" in (ct or "").lower() or "text" in (ct or "").lower()):
                self.visited_pages.add(probe_url)
                queue.append((probe_url, 1))

        # Phase 7: BFS HTML crawl
        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            self._crawl_page(url, depth, queue)

        # Phase 8: JS-in-JS pass + webpack/Vite/Next.js deep chunk pull
        # (runs against every JS file collected during HTML crawl; iterative)
        self._deep_js_pass()

        # Phase 9: framework-specific post-crawl passes
        if self._svelte_detected:
            self._discover_sveltekit_chunks(origin)
        if self._astro_detected:
            self._discover_astro_chunks(origin)

        logger.info(
            "Crawl complete: %d pages, %d JS files",
            self.pages_crawled, len(self.js_files),
        )

    # ── HTML crawl ────────────────────────────────────────────────────────────

    def _crawl_page(self, url: str, depth: int, queue: deque) -> None:
        logger.debug("Crawling page: %s (depth %d)", url, depth)
        content, status, content_type, _sha256, headers = self.fetcher.get_with_headers(url)

        if status and status > 0:
            self.page_access_states[url] = status

        if not content or status not in range(200, 300):
            return

        ct_lower = (content_type or "").lower()

        # Gap 2: Binary content guard — skip body scraping on binary responses.
        # Check Content-Type first (fast), then magic bytes (reliable fallback).
        # This prevents false-positive endpoint matches from binary bodies.
        if not _is_textual_content_type(content_type):
            logger.debug("Skipping binary Content-Type %s for %s", content_type, url)
            return
        if _is_binary_response(content):
            logger.debug("Skipping binary magic-byte response for %s", url)
            return

        # JSON pages: extract any embedded JS URLs
        if "json" in ct_lower:
            for m in re.finditer(r'["\']([^"\']*\.js)["\']', content):
                raw = m.group(1)
                if raw.startswith("/") or raw.startswith("http"):
                    js_url = urljoin(url, raw)
                    if self.scope.in_scope(js_url) and _is_js_url(js_url):
                        self._fetch_js(js_url, url)
            return

        if "html" not in ct_lower and "text" not in ct_lower and "xml" not in ct_lower:
            return

        self.pages_crawled += 1

        # Framework detection
        if not self._nextjs_detected and "__NEXT_DATA__" in content:
            self._nextjs_detected = True
            self._nextjs_html = content
            logger.info("Next.js detected on %s", url)

        if not self._svelte_detected and ("/_app/immutable/" in content or "__svelte" in content or "SvelteComponent" in content):
            self._svelte_detected = True
            logger.info("SvelteKit detected on %s", url)

        if not self._remix_detected and ("__remixContext" in content or "__remix_manifest" in content):
            self._remix_detected = True
            logger.info("Remix detected on %s", url)

        if not self._astro_detected and ("astro-island" in content or "_astro/" in content):
            self._astro_detected = True
            logger.info("Astro detected on %s", url)

        # Scan HTML attributes/comments for secrets
        html_findings = scan_html(content, url)
        if html_findings:
            self.html_findings.extend(html_findings)

        # Extract base href for correct URL resolution
        base_href = _extract_base_href(content)

        # Extract all JS from this page
        for js_url in self._extract_all_js_from_html(content, url, base_href=base_href):
            if len(self.js_files) >= self.max_js_files:
                break
            self._fetch_js(js_url, url)

        # Link response headers from the page itself
        if headers and isinstance(headers, dict):
            for js_url in _extract_js_from_link_header(headers, url):
                if self.scope.in_scope(js_url):
                    self._fetch_js(js_url, url)

            # Response header URL extraction: Content-Location, Link, Refresh.
            # These surface redirect targets, API gateway endpoints, and CDN
            # references that never appear anywhere in the HTML body.
            for header_url in extract_header_urls(headers, url):
                norm = header_url.rstrip("/")
                if norm not in self.visited_pages and self.scope.in_scope(header_url):
                    self.visited_pages.add(norm)
                    queue.append((header_url, depth + 1))

        # Inline scripts
        for script in extract_inline_scripts(content):
            script = script.strip()
            if not script or len(script) < 10:
                continue
            h = _content_hash(script)
            if h not in self.seen_inline_hashes:
                self.seen_inline_hashes.add(h)
                self.inline_scripts.append((script, url))

        # Queue new pages — standard links
        effective_base_url = urljoin(url, base_href) if base_href else url
        if depth < self.max_depth:
            for link in extract_links(content, effective_base_url):
                link_norm = link.rstrip("/")
                if link_norm not in self.visited_pages and self.scope.in_scope(link):
                    self.visited_pages.add(link_norm)
                    queue.append((link, depth + 1))

            # Gap 1: HTMX endpoints — hx-get/post/put/patch/delete targets
            for htmx_url in extract_htmx_endpoints(content, effective_base_url):
                norm = htmx_url.rstrip("/")
                if norm not in self.visited_pages and self.scope.in_scope(htmx_url):
                    self.visited_pages.add(norm)
                    queue.append((htmx_url, depth + 1))

            # Gap 3: Static GET form → navigation request
            # Build ?name=value querystrings from GET forms and crawl them.
            for form_url in _extract_form_get_urls(content, effective_base_url):
                norm = form_url.rstrip("/")
                if norm not in self.visited_pages and self.scope.in_scope(form_url):
                    self.visited_pages.add(norm)
                    queue.append((form_url, depth + 1))

            # Gap 4: <a ping> / <area ping> — add as visited endpoints
            # These are POST tracking URLs; we don't crawl them but record them
            # as visited pages so they appear in the access state map.
            for ping_url in extract_ping_urls(content, effective_base_url):
                norm = ping_url.rstrip("/")
                if norm not in self.visited_pages and self.scope.in_scope(ping_url):
                    self.visited_pages.add(norm)
                    # Record at depth+1 but don't recurse — ping targets are
                    # POST endpoints that return 200 with no navigable content.
                    self.page_access_states[ping_url] = 0  # unverified

    def _extract_all_js_from_html(
        self,
        html: str,
        base_url: str,
        base_href: Optional[str] = None,
    ) -> List[str]:
        """
        Extract JS URLs from every possible location in an HTML page.
        Respects <base href> for correct URL resolution.
        """
        urls: Set[str] = set()
        # Effective base for URL resolution
        effective_base = urljoin(base_url, base_href) if base_href else base_url

        # Standard <script src> and <link rel=preload>
        for url in extract_js_urls(html, effective_base):
            urls.add(url)

        # ES module import maps
        for url in _extract_import_map(html, effective_base):
            urls.add(url)

        # data-src / data-lazy lazy loaders
        for m in RE_DATA_SRC_JS.finditer(html):
            urls.add(urljoin(effective_base, m.group(1)))

        # Protocol-relative: "//cdn.example.com/app.js"
        for m in RE_PROTO_RELATIVE.finditer(html):
            parsed = urlparse(base_url)
            urls.add(f"{parsed.scheme}://{m.group(1)}")

        # <script src="..." integrity="..."> - CDN-hosted scripts with SRI
        for m in RE_SCRIPT_INTEGRITY.finditer(html):
            src = m.group(1)
            js_url = urljoin(effective_base, src)
            if _is_js_url(js_url):
                urls.add(js_url)

        # Service worker registration
        sw_m = RE_SW_REGISTER.search(html)
        if sw_m:
            sw_url = urljoin(effective_base, sw_m.group(1))
            sw_content, sw_status, _, _ = self.fetcher.get(sw_url)
            if sw_content and sw_status == 200:
                for u in _extract_js_from_service_worker(sw_content, sw_url):
                    if self.scope.in_scope(u):
                        urls.add(u)

        return [
            u for u in urls
            if self.scope.in_scope(u) and _is_js_url(u)
        ]

    # ── JS fetch ──────────────────────────────────────────────────────────────

    def _fetch_js(self, url: str, source_page: str, retry: bool = True) -> Optional[JSFile]:
        """
        Fetch and store a single JavaScript file.
        Returns the JSFile if newly fetched, None if deduped or failed.
        Also processes Link headers from the JS response.
        """
        norm = _normalize_url(url)
        if norm in self.visited_js:
            return None
        self.visited_js.add(norm)

        if len(self.js_files) >= self.max_js_files:
            return None

        content, status, content_type, sha256, resp_headers = self.fetcher.get_with_headers(url)

        # One retry on transient server errors
        if status in (500, 502, 503, 504) and retry:
            import time
            time.sleep(1)
            content, status, content_type, sha256, resp_headers = self.fetcher.get_with_headers(url)

        if not content or status not in range(200, 300):
            if status not in (404, 403, 0):
                self.errors.append(f"Failed {url} (HTTP {status})")
            return None

        # Gap 2: Binary content guard — skip binary responses even at JS URLs.
        # A CDN misconfiguration or redirect can serve an image at a .js path.
        if _is_binary_response(content):
            logger.debug("Skipping binary response at JS URL %s", url)
            return None

        # Loose content-type check (CDNs often return text/plain)
        ct_lower = (content_type or "").lower()
        if content_type and not any(t in ct_lower for t in [
            "javascript", "text/plain", "application/",
            "text/html", "text/javascript", "text/typescript",
        ]):
            logger.debug("Skipping non-JS content-type %s for %s", content_type, url)
            return None

        # Content dedup
        content_h = _content_hash(content)
        if content_h in self.seen_js_hashes:
            logger.debug("Duplicate content, skipping: %s", url)
            return None
        self.seen_js_hashes.add(content_h)

        # Process Link headers from the JS response itself
        if resp_headers and isinstance(resp_headers, dict):
            for linked_url in _extract_js_from_link_header(resp_headers, url):
                if self.scope.in_scope(linked_url) and linked_url not in self.visited_js:
                    # Queue for processing; _deep_js_pass will pick it up
                    self._fetch_js(linked_url, url)

        tech = fingerprint_tech(content)
        has_map = "sourceMappingURL=" in content
        map_url_str = ""
        if has_map:
            m = RE_SOURCE_MAP.search(content[-3000:]) or RE_SOURCE_MAP.search(content)
            if m:
                map_url_str = m.group(1)

        js_file = JSFile(
            url            = url,
            source_page    = source_page,
            status_code    = status,
            content_type   = content_type,
            size_bytes     = len(content.encode("utf-8", errors="replace")),
            sha256         = content_h,
            content        = content,
            discovered_at  = datetime.utcnow(),
            has_source_map = has_map,
            source_map_url = map_url_str,
            technology     = tech,
        )
        self.js_files.append(js_file)
        logger.debug("Fetched JS: %s (%d bytes, %s)", url, js_file.size_bytes, tech or "?")
        return js_file

    # ── Deep JS pass ──────────────────────────────────────────────────────────

    def _deep_js_pass(self) -> None:
        """
        After the HTML crawl, scan every fetched JS file for:
        - More JS URLs (dynamic imports, workers, chunk strings)
        - Webpack chunk reconstruction
        - Vite chunk content scanning (hashed chunks found inline)
        - Next.js full build manifest
        - Angular lazy route extraction
        - SvelteKit/Astro chunk patterns

        Iterative: newly discovered chunks are added to the work queue
        so transitive chunk chains are fully resolved.
        """
        origin = self._origin

        # Use an index to process newly added files during iteration
        i = 0
        while i < len(self.js_files):
            js_file = self.js_files[i]
            i += 1

            if not js_file.content:
                continue

            # 1. JS-in-JS URL scan (includes Angular lazy routes, Svelte, Astro)
            for url in _scan_js_for_urls(js_file.content, js_file.url, origin):
                if self.scope.in_scope(url):
                    self._fetch_js(url, js_file.url)

            # 2. Webpack chunk reconstruction
            if any(m in js_file.content for m in [
                "__webpack_require__", "webpackBootstrap", "__webpack_modules__",
            ]):
                for url in _reconstruct_webpack_chunks(js_file.content, js_file.url):
                    if self.scope.in_scope(url):
                        self._fetch_js(url, js_file.url)

            # 3. Worker URL extraction from JS
            for m in RE_WORKER.finditer(js_file.content):
                raw = m.group(1)
                abs_url = urljoin(js_file.url, raw)
                if self.scope.in_scope(abs_url) and _is_js_url(abs_url):
                    self._fetch_js(abs_url, js_file.url)

            # 4. Vite chunk content scan: hashed assets referenced inline
            # (catches chunks not listed in vite manifest if manifest wasn't found)
            for m in RE_VITE_CHUNK_STR.finditer(js_file.content):
                raw = "/" + m.group(1).lstrip("/")
                abs_url = origin + raw
                if self.scope.in_scope(abs_url):
                    self._fetch_js(abs_url, js_file.url)

            # 5. Framework detection updates from JS content
            if not self._svelte_detected and "/_app/immutable/" in js_file.content:
                self._svelte_detected = True
            if not self._astro_detected and "/_astro/" in js_file.content:
                self._astro_detected = True
            if not self._remix_detected and "__remixContext" in js_file.content:
                self._remix_detected = True

        # 6. Next.js full coverage (run once after crawl)
        if self._nextjs_detected and self._nextjs_html:
            logger.info("Running Next.js full chunk discovery")
            for url in _discover_nextjs_chunks(self._nextjs_html, self.target_url, self.fetcher):
                if self.scope.in_scope(url):
                    self._fetch_js(url, self.target_url)

    # ── Discovery helpers ─────────────────────────────────────────────────────

    def _discover_from_robots(self, origin: str) -> None:
        content, status, _, _ = self.fetcher.get(origin + "/robots.txt")
        if not content or status != 200:
            return
        for path in _parse_robots_for_js(content, origin):
            if self.scope.in_scope(path):
                self._fetch_js(path, origin + "/robots.txt")

    def _discover_from_manifests(self, origin: str) -> None:
        """
        Try all known asset manifest paths.
        For Vite manifests, also runs the dedicated Vite chunk extractor.
        For Remix manifests, runs the Remix chunk extractor.
        For SvelteKit manifests, runs the SvelteKit extractor.
        """
        for path in ASSET_MANIFEST_PATHS:
            url = origin + path
            content, status, ct, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            ct_lower = (ct or "").lower()
            if not any(t in ct_lower for t in ["json", "javascript", "text"]):
                continue

            # Vite manifest gets dedicated handling
            if "vite" in path or (content and '"imports"' in content and '"file"' in content):
                for js_url in _extract_vite_chunks(content, origin):
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)
                self._svelte_detected = False  # don't double-flag vite as svelte

            # Remix manifests
            if "remix" in path or "remix" in (ct_lower):
                for js_url in _extract_remix_chunks(content, origin):
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)

            # SvelteKit version.json or manifest.json under /_app/
            if "_app" in path or "svelte" in path.lower():
                for js_url in _extract_sveltekit_chunks(content, origin):
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)

            # Generic manifest parser (handles CRA, Laravel Mix, etc.)
            for js_url in _extract_js_from_manifest(content, origin):
                if self.scope.in_scope(js_url):
                    self._fetch_js(js_url, url)

    def _feed_sitemap_to_queue(self, origin: str, queue: deque) -> None:
        """
        Process ALL sitemap paths - no early return after first valid sitemap.
        Handles sitemap indexes recursively and regular sitemaps.
        Queues all discovered pages across every sitemap found.
        """
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        total_queued = 0

        for path in SITEMAP_PATHS:
            url = origin + path
            content, status, _, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            try:
                root = ET.fromstring(content)

                # sitemap index: recurse into child sitemaps
                child_sitemaps = root.findall(".//sm:sitemap/sm:loc", ns)
                if child_sitemaps:
                    for sitemap_elem in child_sitemaps:
                        if not sitemap_elem.text:
                            continue
                        child_url = sitemap_elem.text.strip()
                        child_content, child_status, _, _ = self.fetcher.get(child_url)
                        if not child_content or child_status != 200:
                            continue
                        try:
                            child_root = ET.fromstring(child_content)
                            for loc in child_root.findall(".//sm:url/sm:loc", ns):
                                if loc.text:
                                    page = loc.text.strip()
                                    if page not in self.visited_pages and self.scope.in_scope(page):
                                        self.visited_pages.add(page)
                                        queue.append((page, 1))
                                        total_queued += 1
                        except Exception:
                            pass

                # regular sitemap: direct <url><loc> entries
                for loc in root.findall(".//sm:url/sm:loc", ns):
                    if loc.text:
                        page = loc.text.strip()
                        if page not in self.visited_pages and self.scope.in_scope(page):
                            self.visited_pages.add(page)
                            queue.append((page, 1))
                            total_queued += 1

                if total_queued > 0:
                    logger.info("Sitemap %s: queued %d URLs total", path, total_queued)

            except Exception:
                pass

    def _discover_module_federation(self, origin: str) -> None:
        """
        Probe well-known Module Federation remote entry paths.
        remoteEntry.js exposes federation config and often contains
        paths to all other federation chunks.
        """
        for path in MODULE_FEDERATION_PROBES:
            url = origin + path
            if url in self.visited_js:
                continue
            content, status, ct, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            ct_lower = (ct or "").lower()

            # remoteEntry.js: fetch and scan for more chunk refs
            if path.endswith(".js"):
                if self.scope.in_scope(url):
                    self._fetch_js(url, origin)
                    logger.info("Module Federation remote entry found: %s", url)

            # mf-manifest.json or federation-manifest.json
            elif path.endswith(".json") and any(t in ct_lower for t in ["json", "text"]):
                try:
                    data = json.loads(content)
                    # Common MF manifest shapes
                    for key in ("exposes", "remotes", "chunks", "files"):
                        section = data.get(key, {})
                        if isinstance(section, dict):
                            for v in section.values():
                                if isinstance(v, str) and _is_js_url(v):
                                    abs_url = urljoin(origin, v)
                                    if self.scope.in_scope(abs_url):
                                        self._fetch_js(abs_url, url)
                        elif isinstance(section, list):
                            for item in section:
                                if isinstance(item, str) and _is_js_url(item):
                                    abs_url = urljoin(origin, item)
                                    if self.scope.in_scope(abs_url):
                                        self._fetch_js(abs_url, url)
                except Exception:
                    pass

    def _discover_sveltekit_chunks(self, origin: str) -> None:
        """
        SvelteKit-specific chunk discovery after crawl.
        Probes /_app/immutable/ paths and parses SvelteKit manifest.
        """
        svelte_paths = [
            "/_app/immutable/entry/start.js",
            "/_app/immutable/entry/app.js",
            "/_app/manifest.json",
            "/_app/version.json",
        ]
        for path in svelte_paths:
            url = origin + path
            content, status, ct, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            if path.endswith(".js") and self.scope.in_scope(url):
                self._fetch_js(url, origin)
            elif path.endswith(".json"):
                for js_url in _extract_sveltekit_chunks(content, origin):
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)

    def _discover_astro_chunks(self, origin: str) -> None:
        """
        Astro-specific chunk discovery.
        Astro puts page chunks at /_astro/<name>.<hash>.js.
        Scans already-fetched JS for cross-references to other Astro chunks.
        """
        # Already handled in _deep_js_pass via RE_ASTRO_CHUNK
        # This post-pass probes the Astro manifest if it exists
        astro_manifest_paths = [
            "/_astro/manifest.json",
            "/dist/client/_astro/manifest.json",
        ]
        for path in astro_manifest_paths:
            url = origin + path
            content, status, ct, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            try:
                data = json.loads(content)
                # Walk JSON for .js references
                def _walk_astro(obj: object, depth: int = 0) -> None:
                    if depth > 5:
                        return
                    if isinstance(obj, str) and _is_js_url(obj):
                        abs_url = urljoin(origin, obj)
                        if self.scope.in_scope(abs_url):
                            self._fetch_js(abs_url, url)
                    elif isinstance(obj, (dict, list)):
                        items = obj.values() if isinstance(obj, dict) else obj
                        for item in items:
                            _walk_astro(item, depth + 1)
                _walk_astro(data)
            except Exception:
                pass
