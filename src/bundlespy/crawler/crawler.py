"""
BundleSpy crawler - built for 100% JS discovery accuracy.

Goes beyond standard crawling:
- Inline script deduplication by content hash
- JS URL normalization (strips query strings before dedup)
- asset-manifest.json / manifest.json discovery (Next.js, CRA, Vue CLI)
- robots.txt parsing for JS paths
- Service worker discovery
- Link header parsing for preloaded assets
- Protocol-relative URL handling
- Retry on transient 5xx failures
- Content-hash based JS dedup (same file, different URL)
- data-src and lazy-load attribute extraction
"""

import re
import json
import hashlib
import logging
from collections import deque
from typing import Set, List, Tuple, Optional
from datetime import datetime
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse

from .fetcher import Fetcher
from .scope import ScopeChecker
from ..discovery.html import extract_js_urls, extract_links, extract_inline_scripts
from ..storage.models import JSFile

logger = logging.getLogger("bundlespy.crawler")


# Common JS paths to probe
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

# Asset manifest paths checked by all major build tools
ASSET_MANIFEST_PATHS = [
    "/asset-manifest.json",          # Create React App
    "/static/asset-manifest.json",
    "/.vite/manifest.json",          # Vite
    "/manifest.json",                # Generic / PWA
    "/build/asset-manifest.json",    # CRA build output
    "/_next/static/chunks/webpack.js",  # Next.js entry
    "/webpack-manifest.json",
    "/mix-manifest.json",            # Laravel Mix
    "/rev-manifest.json",            # Gulp Rev
    "/assets/manifest.json",
    "/static/manifest.json",
    "/public/mix-manifest.json",
]

# Technology fingerprints
TECH_PATTERNS = {
    "React":   ["react.development.js", "__REACT_DEVTOOLS", "React.createElement", "_jsx("],
    "Vue":     ["Vue.config", "__vue_router__", "createApp(", "__VUE__"],
    "Angular": ["ng-version", "platformBrowserDynamic", "NgModule", "ɵɵdefineComponent"],
    "Next.js": ["__NEXT_DATA__", "/_next/static", "__NEXT_ROUTER"],
    "Webpack": ["__webpack_require__", "webpackBootstrap", "__webpack_modules__"],
    "Vite":    ["/@vite/", "import.meta.hot", "/@fs/"],
}


def fingerprint_tech(content: str) -> str:
    for tech, patterns in TECH_PATTERNS.items():
        if any(p in content for p in patterns):
            return tech
    return ""


def _normalize_js_url(url: str) -> str:
    """
    Normalize a JS URL for deduplication.
    Strips query strings and fragments — /app.js?v=1.0 and /app.js?v=2.0 are the same file.
    """
    try:
        parsed = urlparse(url)
        # Keep scheme, netloc, path — drop query and fragment
        normalized = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, "", "", ""
        ))
        return normalized
    except Exception:
        return url


def _content_hash(content: str) -> str:
    """SHA256 of content for dedup by content rather than URL."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _is_js_url(url: str) -> bool:
    """Check if a URL points to a JavaScript file."""
    path = urlparse(url).path.lower()
    return (
        path.endswith(".js") or
        path.endswith(".mjs") or
        path.endswith(".cjs") or
        path.endswith(".jsx") or
        path.endswith(".ts") or
        path.endswith(".tsx")
    )


def _extract_js_from_manifest(content: str, base_url: str) -> List[str]:
    """
    Parse asset manifest JSON and extract all JS file paths.
    Handles CRA, Vite, Laravel Mix, and generic manifest formats.
    """
    urls = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return urls

    def _collect(obj, depth=0):
        if depth > 6:
            return
        if isinstance(obj, str):
            if _is_js_url(obj) or obj.endswith(".js"):
                absolute = urljoin(base_url, obj)
                urls.append(absolute)
        elif isinstance(obj, dict):
            for v in obj.values():
                _collect(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item, depth + 1)

    _collect(data)
    return list(set(urls))


def _parse_robots_txt(content: str, base_url: str) -> List[str]:
    """
    Parse robots.txt and extract JS-related paths.
    Some sites list their JS directories in Disallow rules.
    """
    parsed   = urlparse(base_url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    js_paths = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and any(kw in path.lower() for kw in [
                "/js/", "/javascript/", "/static/", "/assets/",
                "/build/", "/dist/", "/public/", "bundle", "chunk",
            ]):
                if path.endswith("/"):
                    # Directory listing hint - note it but don't fetch
                    logger.debug("robots.txt JS dir hint: %s", path)
                elif _is_js_url(path):
                    js_paths.append(base + path)
        elif line.lower().startswith("sitemap:"):
            pass  # Could parse sitemap for JS too but out of scope

    return js_paths


def _extract_js_from_link_headers(headers: dict, base_url: str) -> List[str]:
    """
    Parse Link response headers for preloaded JS assets.
    e.g. Link: </static/js/main.js>; rel=preload; as=script
    """
    link_header = headers.get("link", "") or headers.get("Link", "")
    if not link_header:
        return []

    urls = []
    for part in link_header.split(","):
        part = part.strip()
        m = re.match(r'<([^>]+)>', part)
        if not m:
            continue
        url = m.group(1)
        if "as=script" in part or _is_js_url(url):
            absolute = urljoin(base_url, url)
            urls.append(absolute)
    return urls


def _extract_js_from_service_worker(content: str, sw_url: str) -> List[str]:
    """
    Extract precached JS files from service worker content.
    Service workers often list every JS file in the app.
    """
    urls = []
    base = sw_url.rsplit("/", 1)[0] + "/"

    # Workbox / sw-precache patterns
    patterns = [
        re.compile(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'),
        re.compile(r'url:\s*["\']([^"\']*\.js[^"\']*)["\']'),
        re.compile(r'cacheName.*?["\']([^"\']*\.js)["\']'),
    ]

    for pat in patterns:
        for m in pat.finditer(content):
            raw = m.group(1)
            if raw.startswith(("http://", "https://")):
                urls.append(raw)
            elif raw.startswith("/"):
                parsed = urlparse(sw_url)
                urls.append(f"{parsed.scheme}://{parsed.netloc}{raw}")
            else:
                urls.append(urljoin(base, raw))

    return list(set(urls))


def _extract_data_src_js(html: str, base_url: str) -> List[str]:
    """
    Extract JS URLs from data-src, data-lazy, data-url attributes
    used by lazy loaders.
    """
    urls = []
    patterns = [
        re.compile(r'data-src=["\']([^"\']*\.js[^"\']*)["\']', re.IGNORECASE),
        re.compile(r'data-lazy=["\']([^"\']*\.js[^"\']*)["\']', re.IGNORECASE),
        re.compile(r'data-url=["\']([^"\']*\.js[^"\']*)["\']', re.IGNORECASE),
    ]
    for pat in patterns:
        for m in pat.finditer(html):
            raw = m.group(1)
            absolute = urljoin(base_url, raw)
            urls.append(absolute)
    return urls


def _extract_import_map(html: str, base_url: str) -> List[str]:
    """
    Parse <script type="importmap"> for module URLs.
    Used by modern ES module apps.
    """
    urls = []
    m = re.search(
        r'<script[^>]+type=["\']importmap["\'][^>]*>(.*?)</script>',
        html, re.IGNORECASE | re.DOTALL
    )
    if not m:
        return urls
    try:
        data = json.loads(m.group(1))
        imports = data.get("imports", {})
        for v in imports.values():
            if isinstance(v, str) and _is_js_url(v):
                urls.append(urljoin(base_url, v))
    except Exception:
        pass
    return urls


class Crawler:
    def __init__(
        self,
        target_url:   str,
        fetcher:      Fetcher,
        scope:        ScopeChecker,
        max_depth:    int  = 2,
        max_pages:    int  = 100,
        max_js_files: int  = 500,
        common_paths: bool = False,
    ):
        self.target_url   = target_url
        self.fetcher      = fetcher
        self.scope        = scope
        self.max_depth    = max_depth
        self.max_pages    = max_pages
        self.max_js_files = max_js_files
        self.common_paths = common_paths

        self.visited_pages:   Set[str] = set()
        self.visited_js:      Set[str] = set()  # normalized URLs
        self.seen_js_hashes:  Set[str] = set()  # content hashes
        self.seen_inline_hashes: Set[str] = set()  # inline script hashes

        self.js_files:        List[JSFile] = []
        self.inline_scripts:  List[Tuple[str, str]] = []
        self.errors:          List[str] = []
        self.pages_crawled:   int = 0

    def crawl(self) -> None:
        """Full crawl pipeline."""

        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: robots.txt
        self._discover_from_robots(base)

        # Phase 2: asset manifests
        self._discover_from_manifests(base)

        # Phase 3: common paths (if enabled)
        if self.common_paths:
            for path in COMMON_JS_PATHS:
                self._fetch_js(base + path, self.target_url)

        # Phase 4: main crawl
        queue: deque = deque()
        queue.append((self.target_url, 0))
        self.visited_pages.add(self.target_url)

        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            self._crawl_page(url, depth, queue)

        logger.info(
            "Crawl complete: %d pages, %d JS files",
            self.pages_crawled, len(self.js_files),
        )

    def _crawl_page(self, url: str, depth: int, queue: deque) -> None:
        """Crawl a single HTML page and extract everything from it."""
        logger.debug("Crawling: %s (depth %d)", url, depth)

        content, status, content_type, _ = self.fetcher.get(url)

        if not content or status not in range(200, 300):
            return

        ct_lower = content_type.lower()
        if "html" not in ct_lower and "text" not in ct_lower:
            return

        self.pages_crawled += 1

        # Extract JS from all possible locations in the HTML
        js_urls = self._extract_all_js_from_html(content, url)
        for js_url in js_urls:
            if len(self.js_files) >= self.max_js_files:
                break
            self._fetch_js(js_url, url)

        # Extract and dedup inline scripts by content hash
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
            links = extract_links(content, url)
            for link in links:
                link_norm = link.rstrip("/")
                if link_norm not in self.visited_pages and self.scope.in_scope(link):
                    self.visited_pages.add(link_norm)
                    queue.append((link, depth + 1))

    def _extract_all_js_from_html(self, html: str, base_url: str) -> List[str]:
        """
        Extract JS URLs from every possible location in an HTML page.
        Covers standard script tags, preload links, import maps,
        data attributes, and protocol-relative URLs.
        """
        urls: Set[str] = set()

        # Standard script src and preload links
        for url in extract_js_urls(html, base_url):
            urls.add(url)

        # Import maps (ES modules)
        for url in _extract_import_map(html, base_url):
            urls.add(url)

        # data-src lazy loaders
        for url in _extract_data_src_js(html, base_url):
            urls.add(url)

        # Protocol-relative URLs (//cdn.example.com/app.js)
        for m in re.finditer(r'["\']//([a-zA-Z0-9][^"\']*\.js)["\']', html):
            raw = m.group(1)
            parsed = urlparse(base_url)
            urls.add(f"{parsed.scheme}://{raw}")

        # Service worker registration
        sw_m = re.search(
            r'registerServiceWorker\s*\(\s*["\']([^"\']+)["\']|'
            r'serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if sw_m:
            sw_path = sw_m.group(1) or sw_m.group(2)
            sw_url  = urljoin(base_url, sw_path)
            sw_content, sw_status, _, _ = self.fetcher.get(sw_url)
            if sw_content and sw_status == 200:
                for u in _extract_js_from_service_worker(sw_content, sw_url):
                    if self.scope.in_scope(u):
                        urls.add(u)

        # Filter to in-scope JS URLs only
        result = []
        for url in urls:
            try:
                if self.scope.in_scope(url) and _is_js_url(url):
                    result.append(url)
            except Exception:
                pass

        return result

    def _discover_from_manifests(self, base: str) -> None:
        """
        Try all known asset manifest paths and extract JS files from them.
        This is the single highest-value discovery method for modern apps.
        """
        for path in ASSET_MANIFEST_PATHS:
            url = base + path
            content, status, ct, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue

            ct_lower = ct.lower()
            if "json" not in ct_lower and "javascript" not in ct_lower and "text" not in ct_lower:
                continue

            js_urls = _extract_js_from_manifest(content, base)
            if js_urls:
                logger.info(
                    "Asset manifest found: %s - %d JS files",
                    path, len(js_urls)
                )
                for js_url in js_urls:
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)

    def _discover_from_robots(self, base: str) -> None:
        """
        Parse robots.txt for JS path hints.
        Passive - just reads what's already publicly listed.
        """
        robots_url = base + "/robots.txt"
        content, status, _, _ = self.fetcher.get(robots_url)
        if not content or status != 200:
            return

        js_paths = _parse_robots_txt(content, base)
        for path in js_paths:
            if self.scope.in_scope(path):
                self._fetch_js(path, robots_url)

    def _fetch_js(self, url: str, source_page: str, retry: bool = True) -> None:
        """
        Fetch and store a single JavaScript file.
        - Normalizes URL before dedup (strips query string)
        - Deduplicates by content hash (same content, different URL = skip)
        - Retries once on 5xx
        """
        # Normalize URL for dedup
        norm_url = _normalize_js_url(url)
        if norm_url in self.visited_js:
            return
        self.visited_js.add(norm_url)

        if len(self.js_files) >= self.max_js_files:
            return

        content, status, content_type, sha256 = self.fetcher.get(url)

        # Retry once on transient server errors
        if status in (500, 502, 503, 504) and retry:
            import time
            time.sleep(1)
            content, status, content_type, sha256 = self.fetcher.get(url)

        if not content or status not in range(200, 300):
            if status not in (404, 403) and status != 0:
                self.errors.append(f"Failed to fetch {url} (HTTP {status})")
            return

        # Content-type sanity check (loose — some CDNs return text/plain)
        ct_lower = content_type.lower() if content_type else ""
        if content_type and not any(t in ct_lower for t in [
            "javascript", "text/plain", "application/", "text/html",
            "text/javascript", "application/json", "text/typescript",
        ]):
            logger.debug("Skipping non-JS content-type for %s: %s", url, content_type)
            return

        # Skip if we've already seen this exact content from another URL
        content_h = _content_hash(content)
        if content_h in self.seen_js_hashes:
            logger.debug("Skipping duplicate content: %s", url)
            return
        self.seen_js_hashes.add(content_h)

        tech = fingerprint_tech(content)

        # Source map detection
        has_source_map = "sourceMappingURL=" in content
        source_map_url = ""
        if has_source_map:
            m = re.search(r"sourceMappingURL=([^\s]+)", content)
            if m:
                source_map_url = m.group(1)

        js_file = JSFile(
            url            = url,
            source_page    = source_page,
            status_code    = status,
            content_type   = content_type,
            size_bytes     = len(content.encode("utf-8", errors="replace")),
            sha256         = sha256,
            content        = content,
            discovered_at  = datetime.utcnow(),
            has_source_map = has_source_map,
            source_map_url = source_map_url,
            technology     = tech,
        )

        self.js_files.append(js_file)
        logger.debug(
            "Fetched JS: %s (%d bytes, %s)",
            url, js_file.size_bytes, tech or "unknown"
        )
