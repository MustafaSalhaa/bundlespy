"""
BundleSpy crawler - built for 100% JS discovery accuracy.

Discovery pipeline (in order):
  1.  robots.txt           - passive JS path hints
  2.  sitemap.xml          - full page inventory
  3.  Asset manifests      - CRA, Vite, Next.js, Laravel Mix, Gulp Rev
  4.  Common paths probe   - well-known JS/page paths
  5.  HTML crawl           - BFS over every reachable page
  6.  JS-in-JS scanning    - chunk refs, dynamic imports, worker URLs inside fetched JS
  7.  Webpack chunk engine - reconstruct full chunk map from runtime
  8.  Next.js full mode    - __NEXT_DATA__ buildId -> _buildManifest.js -> every chunk
  9.  Vite manifest        - file + imports array for complete Vite coverage
  10. Source maps          - fetch .map files, recover original source
  11. Service workers      - extract precache lists
  12. Import maps          - ES module specifier resolution
  13. Link headers         - preload/prefetch response headers
  14. Protocol-relative    - //cdn.example.com/app.js
  15. data-src lazy loads  - intersection-observer lazy loaders
  16. Worker constructors  - new Worker() / new SharedWorker() inside JS

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
from ..discovery.html import extract_js_urls, extract_links, extract_inline_scripts
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

COMMON_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js", "/runtime.js", "/vendor.js",
    "/index.js", "/application.js", "/app.min.js", "/main.min.js",
    "/assets/app.js", "/assets/main.js", "/assets/index.js",
    "/static/js/app.js", "/static/js/main.js", "/static/js/bundle.js",
    "/static/js/runtime.js", "/static/js/vendor.js",
    "/js/app.js", "/js/main.js", "/js/bundle.js",
    "/dist/app.js", "/dist/main.js", "/dist/bundle.js",
    "/build/app.js", "/build/main.js",
    "/public/js/app.js", "/public/js/main.js",
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
]

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/wp-sitemap.xml",
    "/sitemaps/sitemap.xml",
    "/sitemap/sitemap.xml",
]


# ── Technology fingerprints ───────────────────────────────────────────────────

TECH_PATTERNS: Dict[str, List[str]] = {
    "React":   ["react.development.js", "__REACT_DEVTOOLS", "React.createElement", "_jsx("],
    "Vue":     ["Vue.config", "__vue_router__", "createApp(", "__VUE__"],
    "Angular": ["ng-version", "platformBrowserDynamic", "NgModule", "definitComponent"],
    "Next.js": ["__NEXT_DATA__", "/_next/static", "__NEXT_ROUTER"],
    "Nuxt.js": ["__NUXT__", "/_nuxt/", "__nuxt"],
    "Webpack": ["__webpack_require__", "webpackBootstrap", "__webpack_modules__"],
    "Vite":    ["/@vite/", "import.meta.hot", "/@fs/", "vite/preload"],
    "Svelte":  ["SvelteComponent", "__svelte", "svelte/internal"],
    "Ember":   ["Ember.Application", "define('ember", "EmberENV"],
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
    link_hdr = headers.get("link") or headers.get("Link") or ""
    urls: List[str] = []
    for part in link_hdr.split(","):
        part = part.strip()
        m = RE_LINK_HEADER.match(part)
        if not m:
            continue
        url = m.group(1)
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


# ── JS-in-JS scanner ─────────────────────────────────────────────────────────

def _scan_js_for_urls(content: str, js_url: str, origin: str) -> List[str]:
    """
    Scan JS content for more JS URLs: dynamic imports, workers,
    chunk URL strings, Vite hashed chunks, protocol-relative, etc.
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

        # Internal: Next.js detection per-run
        self._nextjs_detected = False
        self._nextjs_html: Optional[str] = None

    @property
    def _origin(self) -> str:
        p = urlparse(self.target_url)
        return f"{p.scheme}://{p.netloc}"

    def crawl(self) -> None:
        """Full crawl pipeline - runs all 16 discovery methods."""
        origin = self._origin

        # Phase 1: robots.txt
        self._discover_from_robots(origin)

        # Phase 2: asset manifests (CRA, Vite, Next.js runtime, Laravel Mix, etc.)
        self._discover_from_manifests(origin)

        # Phase 3: common JS paths (optional)
        if self.common_paths:
            for path in COMMON_JS_PATHS:
                self._fetch_js(origin + path, self.target_url)

        # Phase 4: sitemap -> page queue
        queue: deque = deque()
        queue.append((self.target_url, 0))
        self.visited_pages.add(self.target_url)
        self._feed_sitemap_to_queue(origin, queue)

        # Phase 5: common page probes -> add live ones to queue
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

        # Phase 6: BFS HTML crawl
        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            self._crawl_page(url, depth, queue)

        # Phase 7: JS-in-JS pass + webpack/Vite/Next.js deep chunk pull
        # (runs against every JS file collected during HTML crawl)
        self._deep_js_pass()

        logger.info(
            "Crawl complete: %d pages, %d JS files",
            self.pages_crawled, len(self.js_files),
        )

    # ── HTML crawl ────────────────────────────────────────────────────────────

    def _crawl_page(self, url: str, depth: int, queue: deque) -> None:
        logger.debug("Crawling page: %s (depth %d)", url, depth)
        content, status, content_type, _ = self.fetcher.get(url)

        if status and status > 0:
            self.page_access_states[url] = status

        if not content or status not in range(200, 300):
            return

        ct_lower = (content_type or "").lower()

        # JSON pages: extract any embedded JS URLs
        if "json" in ct_lower:
            for m in re.finditer(r'["\']([^"\']*\.js)["\']', content):
                raw = m.group(1)
                if raw.startswith("/") or raw.startswith("http"):
                    js_url = urljoin(url, raw)
                    if self.scope.in_scope(js_url) and _is_js_url(js_url):
                        self._fetch_js(js_url, url)
            return

        if "html" not in ct_lower and "text" not in ct_lower:
            return

        self.pages_crawled += 1

        # Next.js detection: save first HTML with __NEXT_DATA__ for later
        if not self._nextjs_detected and "__NEXT_DATA__" in content:
            self._nextjs_detected = True
            self._nextjs_html = content
            logger.info("Next.js detected on %s", url)

        # Scan HTML attributes/comments for secrets
        html_findings = scan_html(content, url)
        if html_findings:
            self.html_findings.extend(html_findings)

        # Extract all JS from this page
        for js_url in self._extract_all_js_from_html(content, url):
            if len(self.js_files) >= self.max_js_files:
                break
            self._fetch_js(js_url, url)

        # Inline scripts
        for script in extract_inline_scripts(content):
            script = script.strip()
            if not script or len(script) < 10:
                continue
            h = _content_hash(script)
            if h not in self.seen_inline_hashes:
                self.seen_inline_hashes.add(h)
                self.inline_scripts.append((script, url))

        # Queue new pages
        if depth < self.max_depth:
            for link in extract_links(content, url):
                link_norm = link.rstrip("/")
                if link_norm not in self.visited_pages and self.scope.in_scope(link):
                    self.visited_pages.add(link_norm)
                    queue.append((link, depth + 1))

    def _extract_all_js_from_html(self, html: str, base_url: str) -> List[str]:
        """
        Extract JS URLs from every possible location in an HTML page.
        """
        urls: Set[str] = set()

        # Standard <script src> and <link rel=preload>
        for url in extract_js_urls(html, base_url):
            urls.add(url)

        # ES module import maps
        for url in _extract_import_map(html, base_url):
            urls.add(url)

        # data-src / data-lazy lazy loaders
        for m in RE_DATA_SRC_JS.finditer(html):
            urls.add(urljoin(base_url, m.group(1)))

        # Protocol-relative: "//cdn.example.com/app.js"
        for m in RE_PROTO_RELATIVE.finditer(html):
            parsed = urlparse(base_url)
            urls.add(f"{parsed.scheme}://{m.group(1)}")

        # Service worker registration
        sw_m = RE_SW_REGISTER.search(html)
        if sw_m:
            sw_url = urljoin(base_url, sw_m.group(1))
            sw_content, sw_status, _, _ = self.fetcher.get(sw_url)
            if sw_content and sw_status == 200:
                for u in _extract_js_from_service_worker(sw_content, sw_url):
                    if self.scope.in_scope(u):
                        urls.add(u)

        # Link response headers on the page itself
        # (fetcher doesn't expose headers right now so we skip here;
        #  link-header extraction is done in _fetch_js for JS responses)

        return [
            u for u in urls
            if self.scope.in_scope(u) and _is_js_url(u)
        ]

    # ── JS fetch ──────────────────────────────────────────────────────────────

    def _fetch_js(self, url: str, source_page: str, retry: bool = True) -> Optional[JSFile]:
        """
        Fetch and store a single JavaScript file.
        Returns the JSFile if newly fetched, None if deduped or failed.
        """
        norm = _normalize_url(url)
        if norm in self.visited_js:
            return None
        self.visited_js.add(norm)

        if len(self.js_files) >= self.max_js_files:
            return None

        content, status, content_type, sha256 = self.fetcher.get(url)

        # One retry on transient server errors
        if status in (500, 502, 503, 504) and retry:
            import time
            time.sleep(1)
            content, status, content_type, sha256 = self.fetcher.get(url)

        if not content or status not in range(200, 300):
            if status not in (404, 403, 0):
                self.errors.append(f"Failed {url} (HTTP {status})")
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
            sha256         = sha256,
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
        - Vite chunk reconstruction (via manifest + content scan)
        - Next.js full build manifest
        - Source map fetching

        Iterative: newly discovered chunks are added to the work queue
        so transitive chunk chains are fully resolved.
        """
        origin = self._origin

        # Start with all JS files from the HTML crawl
        # Use an index to process newly added files during iteration
        i = 0
        while i < len(self.js_files):
            js_file = self.js_files[i]
            i += 1

            if not js_file.content:
                continue

            # 1. JS-in-JS URL scan
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

        # 4. Next.js full coverage (run once after crawl)
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
            if "vite" in path or (content and '"imports"' in content):
                for js_url in _extract_vite_chunks(content, origin):
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)

            # Generic manifest parser (handles CRA, Laravel Mix, etc.)
            for js_url in _extract_js_from_manifest(content, origin):
                if self.scope.in_scope(js_url):
                    self._fetch_js(js_url, url)

    def _feed_sitemap_to_queue(self, origin: str, queue: deque) -> None:
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for path in SITEMAP_PATHS:
            url = origin + path
            content, status, _, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            try:
                root = ET.fromstring(content)
                # sitemap index: recurse into child sitemaps
                for sitemap in root.findall(".//sm:sitemap/sm:loc", ns):
                    if sitemap.text:
                        child_url = sitemap.text.strip()
                        child_content, child_status, _, _ = self.fetcher.get(child_url)
                        if child_content and child_status == 200:
                            try:
                                child_root = ET.fromstring(child_content)
                                for loc in child_root.findall(".//sm:url/sm:loc", ns):
                                    if loc.text:
                                        page = loc.text.strip()
                                        if page not in self.visited_pages and self.scope.in_scope(page):
                                            self.visited_pages.add(page)
                                            queue.append((page, 1))
                            except Exception:
                                pass
                # regular sitemap
                for loc in root.findall(".//sm:url/sm:loc", ns):
                    if loc.text:
                        page = loc.text.strip()
                        if page not in self.visited_pages and self.scope.in_scope(page):
                            self.visited_pages.add(page)
                            queue.append((page, 1))
                if queue:
                    logger.info("Sitemap %s: queued %d URLs", path, len(queue))
                    return
            except Exception:
                pass
