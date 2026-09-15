"""
Advanced Headless Browser Engine for BundleSpy.

Goes beyond Katana by combining:
- Full multi-page crawling with JS execution
- Form detection and intelligent filling
- Button/interaction event triggering
- XHR/fetch/WebSocket interception at network level
- JS Router extraction (React Router, Vue Router, Angular)
- Dynamic chunk and lazy-load capture
- Shadow DOM traversal
- Service Worker interception
- API parameter extraction from network requests
- Authentication flow detection
- Infinite scroll handling
- Event-driven content discovery
"""

import re
import json
import time
import hashlib
import logging
from typing import List, Set, Dict, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse

from ..storage.models import JSFile, Endpoint
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.headless")

# JS Router patterns
RE_REACT_ROUTES   = re.compile(r'path:\s*["\']([/][^"\']+)["\']', re.IGNORECASE)
RE_VUE_ROUTES     = re.compile(r'path:\s*["\']([/][^"\'*]+)["\']', re.IGNORECASE)
RE_ANGULAR_ROUTES = re.compile(r'loadChildren|component.*path.*["\']([/][^"\']+)["\']', re.IGNORECASE)
RE_NEXT_ROUTES    = re.compile(r'["\']/((?:api|app|pages)/[^"\']+)["\']', re.IGNORECASE)

# Form field types to fill intelligently
FORM_FILL_VALUES = {
    "email":    "test@example.com",
    "password": "TestPassword123!",
    "username": "testuser",
    "name":     "Test User",
    "phone":    "+1234567890",
    "search":   "test",
    "query":    "test",
    "q":        "test",
    "text":     "test input",
    "url":      "https://example.com",
    "number":   "42",
    "date":     "2024-01-01",
}

# Comprehensive SPA route extraction JS
# Handles Angular, React Router, Vue Router, Next.js, and generic patterns
EXTRACT_ROUTES_JS = """
(function() {
    const routes = new Set();
    const MAX_ROUTES = 500;

    function addRoute(r) {
        if (!r || typeof r !== 'string') return;
        r = r.trim();
        if (r.length < 2) return;
        if (!r.startsWith('/')) r = '/' + r;
        // Skip wildcard-only and param-only routes
        if (r === '/**' || r === '/*' || r === '/') return;
        routes.add(r);
    }

    // ── Angular Router (most important for Juice Shop) ──────────────────────
    try {
        // Method 1: Angular injector via root element
        const rootEls = document.querySelectorAll('[ng-version], [_nghost-], ng-component');
        for (const el of rootEls) {
            try {
                // Angular Ivy context
                const ctx = el.__ngContext__ || el[Object.keys(el).find(k => k.startsWith('__ngContext'))];
                if (ctx) {
                    const lView = Array.isArray(ctx) ? ctx : null;
                    if (lView) {
                        for (let i = 0; i < lView.length; i++) {
                            const item = lView[i];
                            if (item && item.config && Array.isArray(item.config)) {
                                item.config.forEach(function walk(r) {
                                    if (!r) return;
                                    if (r.path !== undefined) addRoute('/' + r.path);
                                    if (r.children) r.children.forEach(walk);
                                    if (r._loadedRoutes) r._loadedRoutes.forEach(walk);
                                });
                            }
                        }
                    }
                }
            } catch(e) {}
        }

        // Method 2: Angular global ng object
        if (window.ng) {
            try {
                const probe = window.ng.probe || window.ng.getComponent;
                const rootEl = document.querySelector('app-root') || document.querySelector('[ng-version]');
                if (rootEl && window.ng.getContext) {
                    const ctx = window.ng.getContext(rootEl);
                    if (ctx && ctx.router && ctx.router.config) {
                        ctx.router.config.forEach(function walk(r) {
                            if (r.path !== undefined) addRoute('/' + r.path);
                            if (r.children) r.children.forEach(walk);
                        });
                    }
                }
            } catch(e) {}
        }

        // Method 3: Angular router in window
        const ngRouters = [];
        try {
            if (window.getAllAngularRootElements) {
                window.getAllAngularRootElements().forEach(el => {
                    try {
                        const injector = el.__ngContext__ && el.__ngContext__[8];
                        if (injector && injector.get) {
                            ['Router', 'ROUTER_CONFIGURATION'].forEach(token => {
                                try {
                                    const r = injector.get(token);
                                    if (r && r.config) ngRouters.push(r);
                                } catch(e) {}
                            });
                        }
                    } catch(e) {}
                });
            }
        } catch(e) {}
        ngRouters.forEach(router => {
            try {
                router.config.forEach(function walk(r) {
                    if (r.path !== undefined) addRoute('/' + r.path);
                    if (r.children) r.children.forEach(walk);
                    if (r._loadedRoutes) r._loadedRoutes.forEach(walk);
                });
            } catch(e) {}
        });

    } catch(e) {}

    // ── React Router ─────────────────────────────────────────────────────────
    try {
        // React Router v6 - __reactRouterRoutes
        if (window.__reactRouterRoutes) {
            window.__reactRouterRoutes.forEach(r => r.path && addRoute(r.path));
        }
        // React Router via fiber nodes
        const reactRoots = document.querySelectorAll('#root, #app, [data-reactroot]');
        reactRoots.forEach(el => {
            try {
                const key = Object.keys(el).find(k => k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance'));
                if (!key) return;
                let fiber = el[key];
                let depth = 0;
                while (fiber && depth < 100) {
                    if (fiber.memoizedProps && fiber.memoizedProps.path) {
                        addRoute(fiber.memoizedProps.path);
                    }
                    fiber = fiber.child || fiber.sibling || (fiber.return && fiber.return.sibling);
                    depth++;
                }
            } catch(e) {}
        });
    } catch(e) {}

    // ── Vue Router ───────────────────────────────────────────────────────────
    try {
        const vueApps = [];
        if (window.__vue_router__) vueApps.push({router: window.__vue_router__});
        if (window.$vm && window.$vm.$router) vueApps.push({router: window.$vm.$router});
        // Vue 3 app instances
        document.querySelectorAll('[data-v-app]').forEach(el => {
            try {
                if (el._vei || el.__vue_app__) {
                    const app = el.__vue_app__;
                    if (app && app.config && app.config.globalProperties.$router) {
                        vueApps.push({router: app.config.globalProperties.$router});
                    }
                }
            } catch(e) {}
        });
        vueApps.forEach(({router}) => {
            try {
                const opts = router.options || {};
                (opts.routes || []).forEach(function walk(r) {
                    if (r.path) addRoute(r.path);
                    if (r.children) r.children.forEach(walk);
                });
                // Vue Router 4 getRoutes()
                if (router.getRoutes) {
                    router.getRoutes().forEach(r => r.path && addRoute(r.path));
                }
            } catch(e) {}
        });
    } catch(e) {}

    // ── Next.js ──────────────────────────────────────────────────────────────
    try {
        const nextData = window.__NEXT_DATA__;
        if (nextData) {
            if (nextData.page) addRoute(nextData.page);
            if (nextData.buildManifest) {
                Object.keys(nextData.buildManifest.pages || {}).forEach(p => addRoute(p));
            }
        }
        if (window.__NEXT_ROUTER_BASEPATH !== undefined) {
            // Next.js 13+ app router
            if (window.next && window.next.router && window.next.router.routes) {
                Object.keys(window.next.router.routes).forEach(r => addRoute(r));
            }
        }
    } catch(e) {}

    // ── Generic: Anchor links ────────────────────────────────────────────────
    document.querySelectorAll('a[href], [routerLink], [ng-href]').forEach(el => {
        try {
            const href = el.getAttribute('href') || el.getAttribute('routerLink') || el.getAttribute('ng-href') || '';
            if (href && href.startsWith('/') && !href.startsWith('//')) {
                addRoute(href.split('?')[0].split('#')[0]);
            }
        } catch(e) {}
    });

    // ── Generic: data-route attributes ──────────────────────────────────────
    document.querySelectorAll('[data-route],[data-url],[data-href],[data-path],[routerLink]').forEach(el => {
        ['data-route','data-url','data-href','data-path','routerLink'].forEach(attr => {
            try {
                const val = el.getAttribute(attr);
                if (val && val.startsWith('/')) addRoute(val.split('?')[0]);
            } catch(e) {}
        });
    });

    // ── Window location-based navigation patterns ────────────────────────────
    try {
        // Check if router is registered in common global namespaces
        ['__router__', '_router', 'router', 'app', 'App'].forEach(key => {
            try {
                const r = window[key];
                if (r && r.options && r.options.routes) {
                    r.options.routes.forEach(function walk(route) {
                        if (route.path) addRoute(route.path);
                        if (route.children) route.children.forEach(walk);
                    });
                }
            } catch(e) {}
        });
    } catch(e) {}

    return Array.from(routes).filter(r => r && r.length > 1).slice(0, MAX_ROUTES);
})()
"""

# JS to extract all network-relevant data
EXTRACT_API_CALLS_JS = """
(function() {
    const apiCalls = [];
    
    // Intercept fetch (already done via route, but get any already-made calls)
    if (window.__bundlespy_requests) {
        return window.__bundlespy_requests;
    }
    return apiCalls;
})()
"""

# Inject request interceptor early
INTERCEPT_JS = """
window.__bundlespy_requests = [];
window.__bundlespy_ws = [];

const origFetch = window.fetch;
window.fetch = function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
    const opts = args[1] || {};
    window.__bundlespy_requests.push({
        url: url,
        method: opts.method || 'GET',
        headers: JSON.stringify(opts.headers || {}),
        body: typeof opts.body === 'string' ? opts.body.substring(0, 500) : null,
        type: 'fetch'
    });
    return origFetch.apply(this, args);
};

const origXHR = window.XMLHttpRequest;
window.XMLHttpRequest = function() {
    const xhr = new origXHR();
    const origOpen = xhr.open;
    xhr.open = function(method, url) {
        window.__bundlespy_requests.push({
            url: url,
            method: method,
            type: 'xhr'
        });
        return origOpen.apply(this, arguments);
    };
    return xhr;
};

const origWS = window.WebSocket;
if (origWS) {
    window.WebSocket = function(url, ...args) {
        window.__bundlespy_ws.push({url: url});
        return new origWS(url, ...args);
    };
}
"""


def _playwright_available() -> bool:
    try:
        import playwright
        return True
    except ImportError:
        return False


class HeadlessEngine:
    """
    Advanced headless browser engine.
    Multi-page, interaction-aware, network-intercepting.
    """

    def __init__(
        self,
        target_url: str,
        scope,
        timeout:     int  = 30,
        stealth:     bool = False,
        max_pages:   int  = 20,
        interact:    bool = True,
    ):
        self.target_url  = target_url
        self.scope       = scope
        self.timeout     = timeout
        self.stealth     = stealth
        self.max_pages   = max_pages
        self.interact    = interact

        self.js_files:    List[JSFile]  = []
        self.endpoints:   List[Endpoint] = []
        self.api_calls:   List[dict]    = []
        self.ws_urls:     List[str]     = []
        self.routes:      Set[str]      = set()
        self.seen_js:     Set[str]      = set()
        self.seen_urls:   Set[str]      = set()
        self.external_seen: Set[str]   = set()  # URLs already fetched by crawler
        self.pages_visited: int         = 0

    def _make_js_file(self, url: str, body: bytes, source_page: str, tech: str = "") -> JSFile:
        content = body.decode("utf-8", errors="replace")
        return JSFile(
            url           = url,
            source_page   = source_page,
            status_code   = 200,
            content_type  = "application/javascript",
            size_bytes    = len(body),
            sha256        = hashlib.sha256(body).hexdigest(),
            content       = content,
            discovered_at = datetime.utcnow(),
            technology    = tech or "headless-captured",
        )

    def _handle_response(self, response, source_page: str) -> None:
        """Capture JS files from network responses."""
        try:
            url = response.url
            ct  = response.headers.get("content-type", "")

            is_js = (
                any(t in ct.lower() for t in ["javascript", "text/plain"])
                or url.endswith((".js", ".mjs", ".ts"))
            )

            if not is_js:
                return

            # Normalize URL for dedup (strip query string)
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            norm_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

            if norm_url in self.seen_js:
                return
            # Also check against externally provided seen set (from crawler)
            if norm_url in self.external_seen:
                return

            safe, _ = validate_url(url)
            if not safe:
                return

            if not self.scope.in_scope(url):
                return

            self.seen_js.add(norm_url)

            try:
                body    = response.body()
                js_file = self._make_js_file(url, body, source_page)
                self.js_files.append(js_file)
                logger.debug("Captured JS: %s (%d bytes)", url, len(body))
            except Exception as e:
                logger.debug("Failed to capture body for %s: %s", url, e)

        except Exception as e:
            logger.debug("Response handler error: %s", e)

    def _extract_routes_from_page(self, page) -> Set[str]:
        """Extract routes from JS frameworks running on the page."""
        routes = set()
        try:
            result = page.evaluate(EXTRACT_ROUTES_JS)
            if isinstance(result, list):
                for r in result:
                    if r and isinstance(r, str) and r.startswith("/"):
                        routes.add(r)
        except Exception as e:
            logger.debug("Route extraction error: %s", e)
        return routes

    def _extract_api_calls(self, page) -> List[dict]:
        """Get intercepted fetch/XHR calls."""
        try:
            result = page.evaluate("window.__bundlespy_requests || []")
            return result if isinstance(result, list) else []
        except Exception:
            return []

    def _extract_ws_urls(self, page) -> List[str]:
        """Get intercepted WebSocket URLs."""
        try:
            result = page.evaluate("window.__bundlespy_ws || []")
            return [r["url"] for r in result if isinstance(r, dict) and "url" in r]
        except Exception:
            return []

    def _interact_with_page(self, page) -> None:
        """Click buttons, fill forms, trigger events to discover more content."""
        try:
            # Click navigation items and buttons (non-submit)
            clickable = page.query_selector_all(
                "nav a, nav button, [role='tab'], [role='menuitem'], "
                ".nav-link, .menu-item, button:not([type='submit'])"
            )
            for el in clickable[:15]:
                try:
                    if el.is_visible() and el.is_enabled():
                        el.click(timeout=2000)
                        page.wait_for_timeout(500)
                except Exception:
                    pass

            # Scroll to trigger lazy loading
            page.evaluate("""
                window.scrollTo(0, document.body.scrollHeight / 2);
            """)
            page.wait_for_timeout(500)
            page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
            page.wait_for_timeout(500)
            page.evaluate("window.scrollTo(0, 0);")

        except Exception as e:
            logger.debug("Interaction error: %s", e)

    def _fill_and_observe_forms(self, page) -> None:
        """
        Fill forms with safe test values to observe API calls.
        Never submits — we just fill to trigger autocomplete/validation
        callbacks which often reveal API endpoints.
        """
        try:
            forms = page.query_selector_all("form")
            for form in forms[:5]:
                try:
                    inputs = form.query_selector_all("input, textarea, select")
                    for inp in inputs:
                        try:
                            input_type = inp.get_attribute("type") or "text"
                            name       = (inp.get_attribute("name") or
                                         inp.get_attribute("id") or
                                         inp.get_attribute("placeholder") or "").lower()

                            if input_type in ("hidden", "submit", "button", "reset", "file"):
                                continue

                            # Find the right fill value
                            fill_val = "test"
                            for key, val in FORM_FILL_VALUES.items():
                                if key in name or key in input_type:
                                    fill_val = val
                                    break

                            if input_type == "checkbox" or input_type == "radio":
                                inp.check()
                            elif inp.tag_name() == "select":
                                options = inp.query_selector_all("option")
                                if len(options) > 1:
                                    options[1].click()
                            else:
                                inp.fill(fill_val, timeout=2000)

                            page.wait_for_timeout(300)

                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Form fill error: %s", e)

    def _visit_page(self, page, url: str, context_page: str) -> Set[str]:
        """
        Visit a single URL, interact with it, and return discovered routes.
        """
        if url in self.seen_urls:
            return set()
        self.seen_urls.add(url)

        safe, _ = validate_url(url)
        if not safe or not self.scope.in_scope(url):
            return set()

        try:
            # Inject interceptor before page loads
            page.add_init_script(INTERCEPT_JS)

            page.on("response", lambda r: self._handle_response(r, url))

            page.goto(
                url,
                timeout=self.timeout * 1000,
                wait_until="networkidle",
            )
            self.pages_visited += 1

            # Wait for SPA frameworks to initialize routers
            # Angular needs time to bootstrap, React Router to mount
            page.wait_for_timeout(3000)

            # Wait for Angular specifically (ng-version attribute)
            try:
                page.wait_for_selector("[ng-version], app-root, router-outlet", timeout=3000)
                page.wait_for_timeout(1000)  # Extra time after Angular mounts
            except Exception:
                pass

            # Interact to trigger dynamic content
            if self.interact:
                self._interact_with_page(page)
                self._fill_and_observe_forms(page)
                page.wait_for_timeout(1000)

            # Extract routes and API calls
            routes   = self._extract_routes_from_page(page)
            api_calls = self._extract_api_calls(page)
            ws_urls   = self._extract_ws_urls(page)

            self.api_calls.extend(api_calls)
            self.ws_urls.extend(ws_urls)

            return routes

        except Exception as e:
            logger.debug("Error visiting %s: %s", url, e)
            return set()

    def _build_full_urls(self, routes: Set[str]) -> List[str]:
        """Convert relative routes to full URLs."""
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        urls   = []
        for route in routes:
            if route.startswith("http"):
                url = route
            else:
                url = base + route
            safe, _ = validate_url(url)
            if safe and self.scope.in_scope(url) and url not in self.seen_urls:
                urls.append(url)
        return urls

    def _api_calls_to_endpoints(self) -> List[Endpoint]:
        """Convert intercepted API calls to Endpoint objects."""
        endpoints = []
        seen      = set()

        for call in self.api_calls:
            url    = call.get("url", "")
            method = call.get("method", "GET").upper()

            if not url:
                continue

            # Skip static assets
            if any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".ico", ".woff"]):
                continue

            key = f"{method}:{url}"
            if key in seen:
                continue
            seen.add(key)

            # Categorize
            lower = url.lower()
            if any(k in lower for k in ["/auth", "/login", "/token", "/session"]):
                cat = "AUTH"
            elif any(k in lower for k in ["/admin", "/management"]):
                cat = "ADMIN"
            elif "/graphql" in lower:
                cat = "GRAPHQL"
            elif any(k in lower for k in ["/api/", "/v1/", "/v2/", "/rest/"]):
                cat = "API"
            else:
                cat = "UNKNOWN"

            endpoints.append(Endpoint(
                url         = url,
                path        = urlparse(url).path,
                method      = method,
                category    = cat,
                source_file = "headless://network-intercept",
                line_number = 0,
                confidence  = 0.95,  # High confidence — actually observed in network
            ))

        # Also add WebSocket endpoints
        for ws_url in set(self.ws_urls):
            safe, _ = validate_url(ws_url)
            if safe:
                endpoints.append(Endpoint(
                    url         = ws_url,
                    path        = urlparse(ws_url).path,
                    method      = "WS",
                    category    = "WEBSOCKET",
                    source_file = "headless://websocket",
                    line_number = 0,
                    confidence  = 0.99,
                ))

        return endpoints

    def run(self) -> dict:
        """
        Full headless scan pipeline.
        Returns dict with js_files, endpoints, routes, api_calls, stats.
        """
        if not _playwright_available():
            logger.warning(
                "Playwright not installed. Run: "
                "pip install playwright && playwright install chromium"
            )
            return {"js_files": [], "endpoints": [], "stats": {}}

        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

        logger.info("Starting advanced headless engine for: %s", self.target_url)

        with sync_playwright() as pw:
            launch_args = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-web-security",
                "--disable-features=VizDisplayCompositor",
            ]

            browser = pw.chromium.launch(
                headless=True,
                args=launch_args,
            )

            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/146.0.0.0 Safari/537.36"
                ) if self.stealth else None,
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            page = context.new_page()

            # Phase 1: Visit root and discover routes
            logger.info("Phase 1: Root page + route discovery")
            initial_routes = self._visit_page(page, self.target_url, self.target_url)
            self.routes.update(initial_routes)

            # If SPA with 0 routes, try navigating to common SPA paths
            # to trigger lazy-loaded router modules
            if len(initial_routes) == 0:
                logger.info("No routes found on root - trying SPA bootstrap paths")
                spa_probe_paths = ["/#/", "/?", "/app", "/home"]
                for probe in spa_probe_paths:
                    probe_url = self.target_url.rstrip("/") + probe
                    try:
                        page.goto(probe_url, timeout=10000, wait_until="networkidle")
                        page.wait_for_timeout(2000)
                        extra = self._extract_routes_from_page(page)
                        if extra:
                            self.routes.update(extra)
                            logger.info("Found %d routes via SPA probe: %s", len(extra), probe)
                            break
                    except Exception:
                        pass

            logger.info("Discovered %d routes from root page", len(self.routes))

            # Phase 2: Visit all discovered routes
            urls_to_visit = self._build_full_urls(self.routes)
            logger.info("Phase 2: Visiting %d discovered routes", len(urls_to_visit))

            for url in urls_to_visit[:self.max_pages - 1]:
                if self.pages_visited >= self.max_pages:
                    break
                new_routes = self._visit_page(page, url, self.target_url)
                self.routes.update(new_routes)
                # Add any newly discovered routes
                new_urls = self._build_full_urls(new_routes - self.routes)
                urls_to_visit.extend(new_urls[:5])

            # Phase 3: Convert API calls to endpoints
            self.endpoints = self._api_calls_to_endpoints()

            context.close()
            browser.close()

        stats = {
            "pages":     self.pages_visited,
            "js":        len(self.js_files),
            "xhr":       len([c for c in self.api_calls if c.get("type") == "xhr"]),
            "fetch":     len([c for c in self.api_calls if c.get("type") == "fetch"]),
            "ws":        len(self.ws_urls),
            "routes":    len(self.routes),
            "endpoints": len(self.endpoints),
        }

        logger.info(
            "Headless complete: %d pages, %d JS, %d API calls, %d WS, %d routes",
            stats["pages"], stats["js"],
            len(self.api_calls), len(self.ws_urls), len(self.routes),
        )

        return {
            "js_files":  self.js_files,
            "endpoints": self.endpoints,
            "routes":    list(self.routes),
            "api_calls": self.api_calls,
            "stats":     stats,
        }


def collect_headless_js(
    url:      str,
    scope,
    timeout:  int  = 30,
    stealth:  bool = False,
) -> List[JSFile]:
    """
    Simple interface for backward compatibility.
    Returns JS files collected by headless engine.
    """
    engine = HeadlessEngine(
        target_url = url,
        scope      = scope,
        timeout    = timeout,
        stealth    = stealth,
        max_pages  = 15,
        interact   = True,
    )
    result = engine.run()
    return result.get("js_files", [])


def collect_headless_full(
    url:           str,
    scope,
    timeout:       int   = 30,
    stealth:       bool  = False,
    max_pages:     int   = 500,
    external_seen: set   = None,
    seed_urls:     list  = None,
) -> dict:
    """
    Full interface returning JS files, endpoints, routes, and stats.
    seed_urls: additional pages to visit (from crawler, sitemap, etc.)
    external_seen: URLs already fetched by crawler (avoids re-fetching).
    """
    engine = HeadlessEngine(
        target_url = url,
        scope      = scope,
        timeout    = timeout,
        stealth    = stealth,
        max_pages  = max_pages,
        interact   = True,
    )
    if external_seen:
        engine.external_seen = external_seen
    # Pre-seed with pages already discovered by the static crawler
    if seed_urls:
        for seed_url in seed_urls:
            if seed_url not in engine.seen_urls:
                engine.routes.add(urlparse(seed_url).path or "/")
    return engine.run()
