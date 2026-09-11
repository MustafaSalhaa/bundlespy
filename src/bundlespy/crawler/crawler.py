"""
Main crawler. Controlled, bounded, rate-limited.
Discovers HTML pages and JavaScript files within scope.
"""

import logging
from collections import deque
from typing import Set, List, Tuple
from datetime import datetime
from urllib.parse import urlparse

from .fetcher import Fetcher
from .scope import ScopeChecker
from ..discovery.html import extract_js_urls, extract_links, extract_inline_scripts
from ..storage.models import JSFile

logger = logging.getLogger("bundlespy.crawler")

COMMON_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js", "/runtime.js", "/vendor.js",
    "/assets/app.js", "/assets/main.js", "/static/js/app.js",
    "/static/js/main.js", "/js/app.js", "/js/main.js",
    "/static/js/chunk.js", "/assets/index.js",
]

# Technologies fingerprinted by content patterns
TECH_PATTERNS = {
    "React":   ["react.development.js", "__REACT_DEVTOOLS", "React.createElement"],
    "Vue":     ["Vue.config", "__vue_router__", "createApp("],
    "Angular": ["ng-version", "platformBrowserDynamic", "NgModule"],
    "Next.js": ["__NEXT_DATA__", "/_next/static"],
    "Webpack": ["__webpack_require__", "webpackBootstrap"],
    "Vite":    ["/@vite/", "import.meta.hot"],
}


def fingerprint_tech(content: str) -> str:
    for tech, patterns in TECH_PATTERNS.items():
        if any(p in content for p in patterns):
            return tech
    return ""


class Crawler:
    def __init__(
        self,
        target_url: str,
        fetcher: Fetcher,
        scope: ScopeChecker,
        max_depth: int = 2,
        max_pages: int = 100,
        max_js_files: int = 200,
        common_paths: bool = False,
    ):
        self.target_url   = target_url
        self.fetcher      = fetcher
        self.scope        = scope
        self.max_depth    = max_depth
        self.max_pages    = max_pages
        self.max_js_files = max_js_files
        self.common_paths = common_paths

        self.visited_pages:  Set[str] = set()
        self.visited_js:     Set[str] = set()
        self.js_files:       List[JSFile] = []
        self.inline_scripts: List[Tuple[str, str]] = []  # (content, source_page)
        self.errors:         List[str] = []
        self.pages_crawled:  int = 0

    def crawl(self) -> None:
        """Start crawling from the target URL."""
        queue: deque = deque()
        queue.append((self.target_url, 0))
        self.visited_pages.add(self.target_url)

        # Queue common JS paths if enabled
        if self.common_paths:
            parsed = urlparse(self.target_url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            for path in COMMON_JS_PATHS:
                js_url = base + path
                if js_url not in self.visited_js:
                    self._fetch_js(js_url, self.target_url)

        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()

            logger.debug("Crawling page: %s (depth %d)", url, depth)
            content, status, content_type, _ = self.fetcher.get(url)

            if not content or status not in range(200, 300):
                continue

            if "html" not in content_type.lower():
                continue

            self.pages_crawled += 1

            # Extract and fetch JS files
            js_urls = extract_js_urls(content, url)
            for js_url in js_urls:
                if len(self.js_files) >= self.max_js_files:
                    break
                if js_url not in self.visited_js and self.scope.in_scope(js_url):
                    self._fetch_js(js_url, url)

            # Extract inline scripts
            for script in extract_inline_scripts(content):
                self.inline_scripts.append((script, url))

            # Queue new pages to crawl
            if depth < self.max_depth:
                links = extract_links(content, url)
                for link in links:
                    if link not in self.visited_pages and self.scope.in_scope(link):
                        self.visited_pages.add(link)
                        queue.append((link, depth + 1))

        logger.info(
            "Crawl complete: %d pages, %d JS files",
            self.pages_crawled, len(self.js_files),
        )

    def _fetch_js(self, url: str, source_page: str) -> None:
        """Fetch and store a single JavaScript file."""
        self.visited_js.add(url)
        content, status, content_type, sha256 = self.fetcher.get(url)

        if not content or status not in range(200, 300):
            self.errors.append(f"Failed to fetch {url} (HTTP {status})")
            return

        # Basic content-type sanity check
        ct_lower = content_type.lower()
        if content_type and not any(t in ct_lower for t in [
            "javascript", "text/plain", "application/json", "text/html", "application/",
        ]):
            logger.warning("Unexpected content-type for JS file %s: %s", url, content_type)

        tech = fingerprint_tech(content)

        # Check for source map reference
        has_source_map = "sourceMappingURL=" in content
        source_map_url = ""
        if has_source_map:
            import re
            m = re.search(r"sourceMappingURL=([^\s]+)", content)
            if m:
                source_map_url = m.group(1)

        js_file = JSFile(
            url            = url,
            source_page    = source_page,
            status_code    = status,
            content_type   = content_type,
            size_bytes     = len(content.encode("utf-8")),
            sha256         = sha256,
            content        = content,
            discovered_at  = datetime.utcnow(),
            has_source_map = has_source_map,
            source_map_url = source_map_url,
            technology     = tech,
        )

        self.js_files.append(js_file)
        logger.debug("Fetched JS: %s (%d bytes, %s)", url, js_file.size_bytes, tech or "unknown")
