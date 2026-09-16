"""
BundleSpy Advanced Headless Engine — optimized for speed and coverage.

Optimization principles:
- Adaptive waits instead of fixed sleeps
- DOM stability detection instead of networkidle
- Concurrent page processing with worker pool
- Event-driven pipeline — react to actual activity
- Central deduplication registry — never analyze same asset twice
- Priority queue — high-value routes first
- Resource blocking — skip images/fonts/ads, keep JS/XHR/WS
- Shared page stabilization helper
- Phase timing metrics
"""

import re
import json
import time
import hashlib
import logging
import threading
import queue
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlunparse

from ..storage.models import JSFile, Endpoint
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.headless")


# ── Route priority — high-value routes processed first ───────────────────────

ROUTE_PRIORITY = {
    "admin": 0, "administration": 0, "dashboard": 0,
    "login": 1, "signin": 1, "auth": 1,
    "account": 2, "profile": 2, "settings": 2,
    "api": 3, "graphql": 3, "upload": 3, "download": 3,
    "users": 4, "orders": 4, "products": 4,
}

def _route_priority(url: str) -> int:
    lower = url.lower()
    for key, pri in ROUTE_PRIORITY.items():
        if key in lower:
            return pri
    return 99


# ── Resource types to block (no JS intelligence value) ───────────────────────

BLOCK_RESOURCE_TYPES = {
    "image", "media", "font", "texttrack",
    "eventsource", "manifest",
}

# Analytics/ad domains to block
BLOCK_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.net", "twitter.com", "linkedin.com", "hotjar.com",
    "mixpanel.com", "segment.io", "amplitude.com", "fullstory.com",
    "intercom.io", "zendesk.com", "hubspot.com",
}


# ── Destructive keywords — never click these ─────────────────────────────────

DESTRUCTIVE_KEYWORDS = {
    "delete", "remove", "cancel", "purchase", "pay now", "pay",
    "checkout", "submit order", "confirm order", "place order",
    "unsubscribe", "deactivate", "reset", "destroy", "wipe",
    "clear data", "close account", "terminate", "disable",
    "send payment", "transfer", "withdraw", "confirm delete",
}

SKIP_FORM_CONTEXTS = {
    "payment", "checkout", "billing", "credit", "card",
    "order", "purchase", "buy", "transaction", "stripe",
    "paypal", "braintree", "adyen", "square", "invoice",
}


# ── Form fill values ──────────────────────────────────────────────────────────

FORM_FILL_VALUES = {
    "email": "test@example.com",
    "search": "test", "q": "test", "query": "test",
    "find": "test", "keyword": "test", "filter": "test",
    "username": "testuser", "user": "testuser",
}

SAFE_INPUT_NAMES = {
    "search", "q", "query", "find", "keyword", "keywords",
    "filter", "username", "user", "email",
}


# ── DOM stability detection JS ────────────────────────────────────────────────

STABILITY_INIT_JS = """
window.__bspy_mutations   = 0;
window.__bspy_requests    = 0;
window.__bspy_last_active = Date.now();

const obs = new MutationObserver(muts => {
    const meaningful = muts.filter(m =>
        m.addedNodes.length > 0 ||
        m.type === 'attributes' ||
        m.type === 'childList'
    ).length;
    if (meaningful > 0) {
        window.__bspy_mutations  += meaningful;
        window.__bspy_last_active = Date.now();
    }
});
obs.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true
});

const origFetch = window.fetch;
window.fetch = function(...args) {
    window.__bspy_requests++;
    window.__bspy_last_active = Date.now();
    const p = origFetch.apply(this, args);
    p.then(() => { window.__bspy_last_active = Date.now(); }).catch(() => {});
    return p;
};
const origXHR = window.XMLHttpRequest.prototype.send;
window.XMLHttpRequest.prototype.send = function(...args) {
    window.__bspy_requests++;
    window.__bspy_last_active = Date.now();
    return origXHR.apply(this, args);
};

window.__bspy_stable = function(quietMs) {
    return (Date.now() - window.__bspy_last_active) >= quietMs;
};
"""


# ── Main intercept JS ─────────────────────────────────────────────────────────

INTERCEPT_JS = """
window.__bundlespy_requests = [];
window.__bundlespy_ws       = [];
window.__bundlespy_workers  = [];
window.__bundlespy_iframes  = [];

// Fetch interception
const _origFetch = window.fetch;
window.fetch = function(...args) {
    try {
        const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url);
        const opts = args[1] || {};
        if (url) window.__bundlespy_requests.push({
            url, method: (opts.method || 'GET').toUpperCase(),
            body: typeof opts.body === 'string' ? opts.body.substring(0, 500) : null,
            type: 'fetch'
        });
    } catch(e) {}
    return _origFetch.apply(this, args);
};

// XHR interception
const _origXHR = window.XMLHttpRequest;
window.XMLHttpRequest = function() {
    const xhr = new _origXHR();
    const _open = xhr.open;
    xhr.open = function(method, url) {
        try {
            if (url) window.__bundlespy_requests.push({
                url: String(url), method: String(method).toUpperCase(), type: 'xhr'
            });
        } catch(e) {}
        return _open.apply(this, arguments);
    };
    return xhr;
};

// WebSocket
const _origWS = window.WebSocket;
if (_origWS) {
    window.WebSocket = function(url, ...a) {
        try { window.__bundlespy_ws.push({url: String(url)}); } catch(e) {}
        const ws = new _origWS(url, ...a);
        return ws;
    };
    window.WebSocket.prototype = _origWS.prototype;
}

// WebWorker
const _origWorker = window.Worker;
if (_origWorker) {
    window.Worker = function(url, ...a) {
        try { window.__bundlespy_workers.push({url: String(url)}); } catch(e) {}
        return new _origWorker(url, ...a);
    };
}

// SharedWorker
const _origSW = window.SharedWorker;
if (_origSW) {
    window.SharedWorker = function(url, ...a) {
        try { window.__bundlespy_workers.push({url: String(url), shared: true}); } catch(e) {}
        return new _origSW(url, ...a);
    };
}

// Dynamic iframe tracking
const _origCE = document.createElement.bind(document);
document.createElement = function(tag, ...a) {
    const el = _origCE(tag, ...a);
    if (tag && tag.toLowerCase() === 'iframe') {
        try {
            const desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
            if (desc && desc.set) {
                Object.defineProperty(el, 'src', {
                    set(v) { try { window.__bundlespy_iframes.push({url: String(v)}); } catch(e) {} return desc.set.call(this, v); },
                    get() { return desc.get.call(this); }
                });
            }
        } catch(e) {}
    }
    return el;
};
""" + STABILITY_INIT_JS


# ── SPA route extraction JS ───────────────────────────────────────────────────

EXTRACT_ROUTES_JS = """
(function() {
    const routes = new Set();
    const MAX = 300;

    function add(r) {
        if (!r || typeof r !== 'string') return;
        r = r.trim();
        if (!r || r === '**' || r === '*') return;
        if (!r.startsWith('/')) r = '/' + r;
        if (r.length > 1) routes.add(r);
    }

    // Angular Ivy
    try {
        document.querySelectorAll('[ng-version],[_nghost-],ng-component,app-root').forEach(el => {
            try {
                const ctx = el.__ngContext__ || el[Object.keys(el).find(k => k.startsWith('__ngContext')) || ''];
                if (Array.isArray(ctx)) {
                    ctx.forEach(item => {
                        if (item && item.config && Array.isArray(item.config)) {
                            item.config.forEach(function w(r) {
                                if (!r) return;
                                if (r.path !== undefined) add('/' + r.path);
                                if (r.children) r.children.forEach(w);
                                if (r._loadedRoutes) r._loadedRoutes.forEach(w);
                            });
                        }
                    });
                }
            } catch(e) {}
        });
    } catch(e) {}

    // React Router (fiber)
    try {
        if (window.__reactRouterRoutes) {
            window.__reactRouterRoutes.forEach(r => r.path && add(r.path));
        }
        document.querySelectorAll('#root,#app,[data-reactroot]').forEach(el => {
            try {
                const k = Object.keys(el).find(k => k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance'));
                if (!k) return;
                let f = el[k], d = 0;
                while (f && d++ < 80) {
                    if (f.memoizedProps && f.memoizedProps.path) add(f.memoizedProps.path);
                    f = f.child || f.sibling || (f.return && f.return.sibling);
                }
            } catch(e) {}
        });
    } catch(e) {}

    // Vue Router
    try {
        ['__vue_router__', '$vm', '_vm'].forEach(k => {
            try {
                const r = window[k] && (window[k].$router || window[k]);
                if (r && r.options && r.options.routes) {
                    r.options.routes.forEach(function w(route) {
                        if (route.path) add(route.path);
                        if (route.children) route.children.forEach(w);
                    });
                }
                if (r && r.getRoutes) r.getRoutes().forEach(r => r.path && add(r.path));
            } catch(e) {}
        });
        document.querySelectorAll('[data-v-app]').forEach(el => {
            try {
                const app = el.__vue_app__;
                if (app) {
                    const r = app.config.globalProperties.$router;
                    if (r && r.getRoutes) r.getRoutes().forEach(r => r.path && add(r.path));
                }
            } catch(e) {}
        });
    } catch(e) {}

    // Next.js
    try {
        const nd = window.__NEXT_DATA__;
        if (nd) {
            if (nd.page) add(nd.page);
            Object.keys((nd.buildManifest || {}).pages || {}).forEach(p => add(p));
        }
    } catch(e) {}

    // Anchor links
    document.querySelectorAll('a[href],[routerLink],[ng-href]').forEach(el => {
        try {
            const h = el.getAttribute('href') || el.getAttribute('routerLink') || el.getAttribute('ng-href') || '';
            if (h && h.startsWith('/') && !h.startsWith('//')) add(h.split('?')[0].split('#')[0]);
        } catch(e) {}
    });

    // data-route attrs
    document.querySelectorAll('[data-route],[data-path],[routerLink]').forEach(el => {
        ['data-route','data-path','routerLink'].forEach(attr => {
            try {
                const v = el.getAttribute(attr);
                if (v && v.startsWith('/')) add(v.split('?')[0]);
            } catch(e) {}
        });
    });

    return Array.from(routes).filter(r => r.length > 1).slice(0, MAX);
})()
"""


# ── Asset registry — central dedup ───────────────────────────────────────────

class AssetRegistry:
    """
    Central deduplication registry for all discovered assets.
    Thread-safe. Tracks by normalized URL and content hash.
    """
    def __init__(self, external_seen: Set[str] = None):
        self._lock      = threading.Lock()
        self._urls:     Set[str] = set(external_seen or set())
        self._hashes:   Set[str] = set()
        self._routes:   Set[str] = set()
        self._pending:  Set[str] = set()

    def seen_url(self, url: str) -> bool:
        norm = self._normalize(url)
        with self._lock:
            return norm in self._urls

    def register_url(self, url: str) -> bool:
        """Returns True if new, False if already seen."""
        norm = self._normalize(url)
        with self._lock:
            if norm in self._urls:
                return False
            self._urls.add(norm)
            return True

    def seen_hash(self, h: str) -> bool:
        with self._lock:
            return h in self._hashes

    def register_hash(self, h: str) -> bool:
        with self._lock:
            if h in self._hashes:
                return False
            self._hashes.add(h)
            return True

    def seen_route(self, route: str) -> bool:
        with self._lock:
            return route in self._routes

    def register_route(self, route: str) -> bool:
        with self._lock:
            if route in self._routes:
                return False
            self._routes.add(route)
            return True

    @staticmethod
    def _normalize(url: str) -> str:
        try:
            p = urlparse(url)
            return urlunparse((p.scheme, p.netloc, p.path, "", "", "")).lower()
        except Exception:
            return url.lower()


# ── Phase timer ───────────────────────────────────────────────────────────────

class PhaseTimer:
    def __init__(self):
        self._phases: Dict[str, float] = {}
        self._start:  Dict[str, float] = {}
        self._total = time.monotonic()

    def start(self, phase: str) -> None:
        self._start[phase] = time.monotonic()

    def stop(self, phase: str) -> float:
        elapsed = time.monotonic() - self._start.get(phase, time.monotonic())
        self._phases[phase] = self._phases.get(phase, 0) + elapsed
        return elapsed

    def summary(self) -> Dict[str, float]:
        result = dict(self._phases)
        result["total"] = time.monotonic() - self._total
        return result


# ── Page stabilizer ───────────────────────────────────────────────────────────

class PageStabilizer:
    """
    Adaptive page stabilization — waits for actual quiet, not a fixed delay.
    Replaces all hardcoded wait_for_timeout calls.
    """

    QUIET_THRESHOLD_MS = 150   # ms of inactivity = stable
    POLL_INTERVAL_MS   = 80    # check every 80ms
    MAX_WAIT_MS        = 4000  # never wait more than 4s

    def __init__(self, page):
        self.page = page

    def wait(self, max_ms: int = None, quiet_ms: int = None) -> None:
        """
        Wait until page is stable — DOM mutations and network quiet.
        Returns as soon as quiet_threshold is reached.
        """
        max_ms   = max_ms   or self.MAX_WAIT_MS
        quiet_ms = quiet_ms or self.QUIET_THRESHOLD_MS

        start    = time.monotonic()
        deadline = start + max_ms / 1000

        while time.monotonic() < deadline:
            try:
                stable = self.page.evaluate(
                    f"window.__bspy_stable ? window.__bspy_stable({quiet_ms}) : true"
                )
                if stable:
                    return
            except Exception:
                return
            self.page.wait_for_timeout(self.POLL_INTERVAL_MS)

    def wait_for_load(self, max_ms: int = 8000) -> None:
        """
        Wait for initial page load — uses DOMContentLoaded + network quiet
        instead of networkidle which can hang on SPAs with polling.
        """
        start = time.monotonic()
        try:
            self.page.wait_for_load_state("domcontentloaded",
                                          timeout=min(max_ms, 5000))
        except Exception:
            pass

        # Then wait for actual stability
        remaining_ms = max_ms - int((time.monotonic() - start) * 1000)
        self.wait(max_ms=max(remaining_ms, 500), quiet_ms=200)

    def wait_after_interaction(self, max_ms: int = 1500) -> None:
        """Short adaptive wait after a click/hover/scroll."""
        self.wait(max_ms=max_ms, quiet_ms=100)

    def wait_for_framework(self, max_ms: int = 3000) -> None:
        """
        Wait for SPA framework to mount — Angular/React/Vue.
        Detects actual framework readiness, not a fixed delay.
        """
        start = time.monotonic()
        deadline = start + max_ms / 1000
        framework_ready = False

        while time.monotonic() < deadline:
            try:
                ready = self.page.evaluate("""
                    (function() {
                        // Angular
                        if (document.querySelector('[ng-version]') ||
                            document.querySelector('app-root') ||
                            document.querySelector('router-outlet')) return true;
                        // React
                        if (document.querySelector('#root > *') ||
                            document.querySelector('[data-reactroot] > *')) return true;
                        // Vue
                        if (document.querySelector('[data-v-app] > *')) return true;
                        // Generic — any meaningful content loaded
                        if (document.body && document.body.children.length > 2) return true;
                        return false;
                    })()
                """)
                if ready:
                    framework_ready = True
                    break
            except Exception:
                break
            self.page.wait_for_timeout(100)

        if framework_ready:
            # Brief stability wait after framework mounts
            self.wait(max_ms=1000, quiet_ms=150)


# ── HeadlessEngine ────────────────────────────────────────────────────────────

def _parse_cookie_string(cookie_str: str, domain: str) -> List[dict]:
    """
    Parse a browser-style cookie string into Playwright cookie dicts.
    e.g. "laravel-session=abc123; XSRF-TOKEN=xyz" -> [{name, value, domain, path}]
    """
    cookies = []
    if not cookie_str:
        return cookies
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            name, _, value = pair.partition("=")
            name  = name.strip()
            value = value.strip()
        else:
            name  = pair.strip()
            value = ""
        if name:
            cookies.append({
                "name":   name,
                "value":  value,
                "domain": domain,
                "path":   "/",
            })
    return cookies


def _parse_extra_headers(extra_headers: dict) -> dict:
    """
    Return only non-Cookie headers suitable for Playwright context.
    Cookies are injected separately via add_cookies.
    """
    return {k: v for k, v in (extra_headers or {}).items() if k.lower() != "cookie"}


# ── Login-page indicators ──────────────────────────────────────────────────────

LOGIN_PATH_KEYWORDS = {
    "/login", "/signin", "/sign-in", "/log-in", "/auth/login",
    "/account/login", "/user/login", "/session/new",
}

def _is_login_url(url: str) -> bool:
    """Return True if the URL looks like a login/auth page."""
    lower = urlparse(url).path.lower().rstrip("/")
    return any(lower == kw or lower.endswith(kw) for kw in LOGIN_PATH_KEYWORDS)


class HeadlessEngine:
    """
    Optimized headless engine.
    - Concurrent page processing
    - Adaptive waits
    - Central asset registry
    - Resource blocking
    - Priority queue
    - Authenticated scanning with cookie injection + session verification
    """

    def __init__(
        self,
        target_url:    str,
        scope,
        timeout:       int   = 30,
        stealth:       bool  = False,
        max_pages:     int   = 100,
        interact:      bool  = False,
        workers:       int   = 3,
        external_seen: Set[str]  = None,
        cookies:       List[dict] = None,
        extra_headers: dict       = None,
        seen_hashes:   Set[str]  = None,
    ):
        self.target_url  = target_url
        self.scope       = scope
        self.timeout     = timeout
        self.stealth     = stealth
        self.max_pages   = max_pages
        self.interact    = interact
        self.num_workers = max(1, min(workers, 5))
        self.cookies       = cookies or []        # Playwright cookie dicts
        self.extra_headers = _parse_extra_headers(extra_headers)
        self.seen_hashes   = seen_hashes or set()

        self.registry    = AssetRegistry(external_seen)
        # Pre-seed content hash registry with hashes from crawler
        for h in self.seen_hashes:
            self.registry.register_hash(h)
        self.timer       = PhaseTimer()

        self._lock       = threading.Lock()
        self.js_files:   List[JSFile]  = []
        self.endpoints:  List[Endpoint] = []
        self.api_calls:  List[dict]    = []
        self.ws_urls:    List[str]     = []
        self.routes:     Set[str]      = set()
        self.pages_visited: int        = 0
        self.auth_result: Optional[dict] = None  # populated during run()

        # Seed urls provided externally (from crawler/static analysis)
        self.seed_urls:  List[str]     = []
        self.external_seen = external_seen or set()

    def _add_js_file(self, js_file: JSFile) -> bool:
        """Thread-safe JS file registration."""
        if not self.registry.register_hash(js_file.sha256):
            return False
        with self._lock:
            self.js_files.append(js_file)
        return True

    def _add_route(self, route: str) -> bool:
        """Thread-safe route registration. Returns True if new."""
        if self.registry.register_route(route):
            with self._lock:
                self.routes.add(route)
            return True
        return False

    def _make_js_file(self, url: str, body: bytes,
                      source_page: str, tech: str = "") -> JSFile:
        content = body.decode("utf-8", errors="replace")
        return JSFile(
            url=url, source_page=source_page, status_code=200,
            content_type="application/javascript",
            size_bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            content=content, discovered_at=datetime.utcnow(),
            technology=tech or "headless-captured",
        )

    def _should_block(self, url: str, resource_type: str) -> bool:
        """Decide whether to block a resource request."""
        if resource_type in BLOCK_RESOURCE_TYPES:
            return True
        lower = url.lower()
        return any(domain in lower for domain in BLOCK_DOMAINS)

    def _handle_response(self, response, source_page: str) -> None:
        """Capture JS files from network responses. Non-blocking."""
        try:
            url = response.url
            ct  = response.headers.get("content-type", "")
            is_js = (
                any(t in ct.lower() for t in ["javascript", "text/plain"])
                or url.split("?")[0].endswith((".js", ".mjs", ".cjs"))
            )
            if not is_js:
                return

            norm = self.registry._normalize(url)
            if not self.registry.register_url(norm):
                return

            safe, _ = validate_url(url)
            if not safe or not self.scope.in_scope(url):
                return

            try:
                body = response.body()
                if not body:
                    return
                h = hashlib.sha256(body).hexdigest()
                if self.registry.seen_hash(h):
                    return
                js_file = self._make_js_file(url, body, source_page)
                self._add_js_file(js_file)
            except Exception:
                pass
        except Exception:
            pass

    def _is_destructive(self, text: str) -> bool:
        lower = (text or "").lower().strip()
        return any(kw in lower for kw in DESTRUCTIVE_KEYWORDS)

    def _extract_routes(self, page) -> Set[str]:
        try:
            result = page.evaluate(EXTRACT_ROUTES_JS)
            if isinstance(result, list):
                return {r for r in result if r and isinstance(r, str) and len(r) > 1}
        except Exception:
            pass
        return set()

    def _extract_api_calls(self, page) -> List[dict]:
        try:
            r = page.evaluate("window.__bundlespy_requests || []")
            return r if isinstance(r, list) else []
        except Exception:
            return []

    def _extract_ws_urls(self, page) -> List[str]:
        try:
            r = page.evaluate("window.__bundlespy_ws || []")
            return [x["url"] for x in r if isinstance(x, dict) and "url" in x]
        except Exception:
            return []

    def _extract_worker_urls(self, page) -> List[str]:
        try:
            r = page.evaluate("window.__bundlespy_workers || []")
            return [x["url"] for x in r if isinstance(x, dict) and "url" in x]
        except Exception:
            return []

    def _extract_iframe_urls(self, page) -> List[str]:
        try:
            parsed = urlparse(self.target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            dynamic = page.evaluate("window.__bundlespy_iframes || []")
            dynamic_urls = [x["url"] for x in dynamic if isinstance(x, dict)]
            dom_urls = page.evaluate("""
                Array.from(document.querySelectorAll('iframe[src]'))
                    .map(f => f.src).filter(u => u && u.length > 0);
            """) or []
            all_urls = list(set(dynamic_urls + dom_urls))
            return [u for u in all_urls
                    if u.startswith(origin) or u.startswith("/")]
        except Exception:
            return []

    def _fetch_worker_js(self, worker_url: str, source_page: str) -> None:
        """Fetch WebWorker JS file. Thread-safe."""
        try:
            if worker_url.startswith("/"):
                parsed = urlparse(self.target_url)
                worker_url = f"{parsed.scheme}://{parsed.netloc}{worker_url}"

            if not self.registry.register_url(worker_url):
                return

            safe, _ = validate_url(worker_url)
            if not safe or not self.scope.in_scope(worker_url):
                return

            import requests as _req
            resp = _req.get(worker_url, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"})
            if resp.status_code == 200 and resp.content:
                h = hashlib.sha256(resp.content).hexdigest()
                if self.registry.register_hash(h):
                    js_file = self._make_js_file(worker_url, resp.content, source_page, "webworker")
                    self._add_js_file(js_file)
                    logger.info("WebWorker captured: %s", worker_url)
        except Exception as e:
            logger.debug("Worker fetch failed %s: %s", worker_url, e)

    def _interact(self, page, stabilizer: PageStabilizer) -> None:
        """
        Safe interaction engine. Adaptive waits after each action.
        """
        # Phase 1: Adaptive scroll
        try:
            heights = [0.25, 0.5, 0.75, 1.0, 0]
            for frac in heights:
                page.evaluate(f"window.scrollTo(0, document.body.scrollHeight * {frac});")
                stabilizer.wait_after_interaction(max_ms=500)
        except Exception:
            pass

        # Phase 2: Tabs, accordions, toggles
        tab_selectors = [
            "[role='tab']", "[role='menuitem']",
            "[data-toggle='tab']", "[data-bs-toggle='tab']",
            ".nav-link:not(.active)", "[aria-selected='false']",
            ".accordion-button", "[aria-expanded='false']",
        ]
        for sel in tab_selectors:
            try:
                for el in page.query_selector_all(sel)[:6]:
                    try:
                        if not el.is_visible() or not el.is_enabled():
                            continue
                        if self._is_destructive(el.inner_text()):
                            continue
                        el.click(timeout=800)
                        stabilizer.wait_after_interaction(max_ms=800)
                    except Exception:
                        pass
            except Exception:
                pass

        # Phase 3: Dropdown toggles
        try:
            for el in page.query_selector_all(
                "button[data-toggle],button[data-bs-toggle],"
                "button[aria-expanded],.dropdown-toggle"
            )[:8]:
                try:
                    if not el.is_visible() or not el.is_enabled():
                        continue
                    if self._is_destructive(el.inner_text()):
                        continue
                    el.click(timeout=800)
                    stabilizer.wait_after_interaction(max_ms=600)
                except Exception:
                    pass
        except Exception:
            pass

        # Phase 4: Hover over nav items
        try:
            for el in page.query_selector_all(
                ".dropdown,.has-submenu,nav > ul > li"
            )[:6]:
                try:
                    if el.is_visible():
                        el.hover(timeout=600)
                        stabilizer.wait_after_interaction(max_ms=400)
                except Exception:
                    pass
        except Exception:
            pass

    def _observe_forms(self, page, stabilizer: PageStabilizer) -> None:
        """
        Safe read-only form observation.
        NEVER submits. Only types in search boxes then clears.
        """
        try:
            for form in page.query_selector_all("form")[:8]:
                try:
                    ctx = (
                        (form.get_attribute("id") or "") +
                        (form.get_attribute("class") or "") +
                        (form.get_attribute("action") or "")
                    ).lower()
                    if any(kw in ctx for kw in SKIP_FORM_CONTEXTS):
                        continue

                    for inp in form.query_selector_all("input,textarea")[:5]:
                        try:
                            itype = (inp.get_attribute("type") or "text").lower()
                            iname = (
                                inp.get_attribute("name") or
                                inp.get_attribute("id") or
                                inp.get_attribute("placeholder") or ""
                            ).lower()
                            if itype not in ("text", "search", "email"):
                                continue
                            if not any(s in iname for s in SAFE_INPUT_NAMES):
                                continue
                            if not inp.is_visible() or not inp.is_enabled():
                                continue
                            inp.click(timeout=800)
                            inp.type("test", delay=20)
                            stabilizer.wait_after_interaction(max_ms=400)
                            inp.clear()
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    def _visit_page(self, page, url: str, context_page: str) -> Set[str]:
        """Visit a single page and extract all intelligence."""

        if not self.registry.register_url(url):
            return set()

        safe, _ = validate_url(url)
        if not safe or not self.scope.in_scope(url):
            return set()

        stabilizer = PageStabilizer(page)

        # Attach response handler ONCE per page
        page.on("response", lambda r: self._handle_response(r, url))

        try:
            # Use DOMContentLoaded + stability instead of networkidle
            page.goto(
                url,
                timeout=self.timeout * 1000,
                wait_until="domcontentloaded",
            )
            with self._lock:
                self.pages_visited += 1

            # Adaptive framework wait
            stabilizer.wait_for_framework(max_ms=3000)

            # Interact if enabled
            if self.interact:
                self._interact(page, stabilizer)
                self._observe_forms(page, stabilizer)

            # Extract everything
            new_routes  = self._extract_routes(page)
            api_calls   = self._extract_api_calls(page)
            ws_urls     = self._extract_ws_urls(page)
            worker_urls = self._extract_worker_urls(page)
            iframe_urls = self._extract_iframe_urls(page)

            with self._lock:
                self.api_calls.extend(api_calls)
                self.ws_urls.extend(ws_urls)

            # WebWorkers — fetch in background
            for w_url in worker_urls:
                threading.Thread(
                    target=self._fetch_worker_js,
                    args=(w_url, url),
                    daemon=True,
                ).start()

            # Same-origin iframes — add to routes
            parsed = urlparse(self.target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for iframe_url in iframe_urls:
                if iframe_url.startswith(origin):
                    new_routes.add(urlparse(iframe_url).path or "/")
                elif iframe_url.startswith("/"):
                    new_routes.add(iframe_url)

            return new_routes

        except Exception as e:
            logger.debug("Error visiting %s: %s", url, e)
            return set()

    def _build_urls(self, routes: Set[str]) -> List[str]:
        """Convert routes to full URLs, sorted by priority."""
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        urls   = []
        for route in routes:
            if route.startswith("http"):
                url = route
            else:
                url = base + route
            safe, _ = validate_url(url)
            if safe and self.scope.in_scope(url) and not self.registry.seen_url(url):
                urls.append(url)
        return sorted(urls, key=_route_priority)

    def _api_calls_to_endpoints(self) -> List[Endpoint]:
        endpoints = []
        seen      = set()
        for call in self.api_calls:
            url    = call.get("url", "")
            method = call.get("method", "GET").upper()
            if not url:
                continue
            if any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".ico", ".woff"]):
                continue
            key = f"{method}:{url.rstrip('/').lower().split('?')[0]}"
            if key in seen:
                continue
            seen.add(key)
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
                url=url, path=urlparse(url).path,
                method=method, category=cat,
                source_file="headless://network-intercept",
                line_number=0, confidence=0.95,
            ))
        for ws_url in set(self.ws_urls):
            safe, _ = validate_url(ws_url)
            if safe:
                endpoints.append(Endpoint(
                    url=ws_url, path=urlparse(ws_url).path,
                    method="WS", category="WEBSOCKET",
                    source_file="headless://websocket",
                    line_number=0, confidence=0.99,
                ))
        return endpoints

    def _verify_auth(self, page, initial_url: str) -> dict:
        """
        Navigate to the target and verify the session is authenticated.

        Returns a dict with:
          credentials_supplied  bool
          cookies_injected      int
          initial_url           str
          status                int
          final_url             str
          redirect_chain        list[str]
          cookies_present       list[str]  (cookie names from browser)
          authenticated         bool
          reason                str        (why auth failed, empty if OK)
        """
        result = {
            "credentials_supplied": bool(self.cookies or self.extra_headers),
            "cookies_injected":     len(self.cookies),
            "initial_url":          initial_url,
            "status":               0,
            "final_url":            initial_url,
            "redirect_chain":       [],
            "cookies_present":      [],
            "authenticated":        False,
            "reason":               "",
        }

        if not result["credentials_supplied"]:
            # Anonymous scan — skip verification entirely
            return result

        redirect_chain: List[str] = []
        final_status   = 0

        def _on_response(response):
            nonlocal final_status
            if response.url == page.url or not redirect_chain:
                final_status = response.status

        def _on_request(request):
            if request.is_navigation_request() and request.url != initial_url:
                redirect_chain.append(request.url)

        page.on("response",  _on_response)
        page.on("request",   _on_request)

        try:
            resp = page.goto(
                initial_url,
                timeout=self.timeout * 1000,
                wait_until="domcontentloaded",
            )
            if resp:
                final_status = resp.status
            PageStabilizer(page).wait_for_framework(max_ms=3000)
        except Exception as e:
            result["reason"] = f"Navigation failed: {e}"
            return result

        final_url = page.url

        # Collect cookies that landed in the browser after navigation
        try:
            browser_cookies = page.context.cookies()
            result["cookies_present"] = [c["name"] for c in browser_cookies]
        except Exception:
            pass

        result["status"]         = final_status
        result["final_url"]      = final_url
        result["redirect_chain"] = redirect_chain

        # ── Auth verification logic ────────────────────────────────────────
        redirected_to_login = _is_login_url(final_url)

        if redirected_to_login:
            result["authenticated"] = False
            result["reason"]        = "Redirected to login page — session rejected or expired"
            return result

        if final_status in (401, 403):
            result["authenticated"] = False
            result["reason"]        = f"Server returned {final_status} — credentials not accepted"
            return result

        # If we stayed on the intended URL (or a sub-path of it) with 200, we're in
        from urllib.parse import urlparse as _up
        intended_path = _up(initial_url).path.rstrip("/") or "/"
        actual_path   = _up(final_url).path.rstrip("/")   or "/"

        if final_status == 200 and (
            actual_path == intended_path
            or actual_path.startswith(intended_path)
        ):
            result["authenticated"] = True
            result["reason"]        = ""
            return result

        # Redirected somewhere other than login (e.g. /home, /dashboard/overview) — still authenticated
        if final_status in (200, 302) and not redirected_to_login:
            result["authenticated"] = True
            result["reason"]        = ""
            return result

        result["authenticated"] = False
        result["reason"]        = (
            f"Ended at {final_url} with status {final_status} — "
            "could not confirm authenticated state"
        )
        return result

    def run(self) -> dict:
        if not _playwright_available():
            logger.warning("Playwright not installed.")
            return {"js_files": [], "endpoints": [], "stats": {}, "timings": {}, "auth_result": None}

        from playwright.sync_api import sync_playwright

        logger.info("Starting headless engine: %s", self.target_url)
        self.timer.start("total")

        with sync_playwright() as pw:
            self.timer.start("browser_start")
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--disable-features=VizDisplayCompositor",
                    "--blink-settings=imagesEnabled=false",  # Disable images
                    "--disable-background-networking",
                    "--disable-sync",
                ],
            )
            self.timer.stop("browser_start")

            def _new_context():
                kwargs = dict(
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                if self.stealth:
                    kwargs["user_agent"] = (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/146.0.0.0 Safari/537.36"
                    )
                if self.extra_headers:
                    kwargs["extra_http_headers"] = self.extra_headers

                ctx = browser.new_context(**kwargs)

                # Inject cookies BEFORE any navigation
                if self.cookies:
                    try:
                        ctx.add_cookies(self.cookies)
                        logger.info("Injected %d cookies into browser context", len(self.cookies))
                    except Exception as e:
                        logger.warning("Failed to inject cookies: %s", e)

                ctx.add_init_script(INTERCEPT_JS)
                # Block images, fonts, media, analytics
                ctx.route(
                    "**/*",
                    lambda route: route.abort()
                    if self._should_block(route.request.url, route.request.resource_type)
                    else route.continue_()
                )
                return ctx

            # Phase 1: Root page (+ auth verification when credentials supplied)
            self.timer.start("phase1_root")
            ctx1  = _new_context()
            page1 = ctx1.new_page()

            if self.cookies or self.extra_headers:
                # Verify auth first — navigate, check final URL + status
                self.auth_result = self._verify_auth(page1, self.target_url)
                logger.info(
                    "Auth verification: authenticated=%s final_url=%s status=%s",
                    self.auth_result["authenticated"],
                    self.auth_result["final_url"],
                    self.auth_result["status"],
                )
                # Mark root URL as visited so _visit_page doesn't re-navigate
                self.registry.register_url(self.target_url)
                with self._lock:
                    self.pages_visited += 1

                # Extract routes from the page we already landed on
                initial_routes = set()
                try:
                    initial_routes = self._extract_routes(page1)
                    api_calls = self._extract_api_calls(page1)
                    ws_urls   = self._extract_ws_urls(page1)
                    with self._lock:
                        self.api_calls.extend(api_calls)
                        self.ws_urls.extend(ws_urls)
                except Exception:
                    pass

                # Attach response handler for any remaining network activity
                page1.on("response", lambda r: self._handle_response(r, self.target_url))
            else:
                initial_routes = self._visit_page(page1, self.target_url, self.target_url)

            for r in initial_routes:
                self._add_route(r)

            # Add seed URLs from static analysis
            for seed_url in self.seed_urls:
                parsed = urlparse(seed_url)
                self._add_route(parsed.path or "/")

            # SPA probe if 0 routes
            if not self.routes:
                for probe in ["/#/", "/app", "/home"]:
                    probe_url = self.target_url.rstrip("/") + probe
                    try:
                        page1.goto(probe_url, timeout=8000, wait_until="domcontentloaded")
                        PageStabilizer(page1).wait(max_ms=2000)
                        extra = self._extract_routes(page1)
                        if extra:
                            for r in extra:
                                self._add_route(r)
                            break
                    except Exception:
                        pass

            ctx1.close()
            self.timer.stop("phase1_root")
            logger.info("Phase 1 done: %d routes", len(self.routes))

            # Phase 2: Visit all routes concurrently
            self.timer.start("phase2_routes")
            urls_to_visit = self._build_urls(self.routes)

            # Sort by priority — admin/auth/api first
            urls_to_visit = sorted(urls_to_visit, key=_route_priority)

            # Limit to max_pages
            remaining = self.max_pages - self.pages_visited
            urls_to_visit = urls_to_visit[:max(0, remaining)]

            if urls_to_visit:
                logger.info("Phase 2: visiting %d routes", len(urls_to_visit))

                # Playwright sync API is NOT thread-safe — must run on main thread
                # Use a single persistent page for all route visits (fast — no context reload)
                ctx2  = _new_context()
                page2 = ctx2.new_page()
                new_routes_found = set()

                try:
                    for url in urls_to_visit:
                        if self.pages_visited >= self.max_pages:
                            break
                        new_routes = self._visit_page(page2, url, self.target_url)
                        new_routes_found.update(new_routes)
                finally:
                    try:
                        ctx2.close()
                    except Exception:
                        pass

                # Add newly discovered routes
                for r in new_routes_found:
                    self._add_route(r)

            self.timer.stop("phase2_routes")
            browser.close()

        # Phase 3: Build endpoints
        self.timer.start("endpoint_build")
        self.endpoints = self._api_calls_to_endpoints()
        self.timer.stop("endpoint_build")
        self.timer.stop("total")

        timings = self.timer.summary()
        workers_found = [js for js in self.js_files if js.technology == "webworker"]

        stats = {
            "pages":     self.pages_visited,
            "js":        len(self.js_files),
            "xhr":       sum(1 for c in self.api_calls if c.get("type") == "xhr"),
            "fetch":     sum(1 for c in self.api_calls if c.get("type") == "fetch"),
            "ws":        len(self.ws_urls),
            "routes":    len(self.routes),
            "endpoints": len(self.endpoints),
            "workers":   len(workers_found),
            "timings":   timings,
        }

        logger.info(
            "Headless done: %d pages, %d JS, %d routes, %.1fs total",
            self.pages_visited, len(self.js_files),
            len(self.routes), timings.get("total", 0),
        )
        return {
            "js_files":   self.js_files,
            "endpoints":  self.endpoints,
            "routes":     list(self.routes),
            "api_calls":  self.api_calls,
            "stats":      stats,
            "timings":    timings,
            "auth_result": self.auth_result,
        }


def _playwright_available() -> bool:
    try:
        import playwright
        return True
    except ImportError:
        return False


def collect_headless_js(url: str, scope, timeout: int = 30,
                        stealth: bool = False) -> List[JSFile]:
    """Backward-compatible interface."""
    engine = HeadlessEngine(url, scope, timeout=timeout, stealth=stealth, max_pages=15)
    return engine.run().get("js_files", [])


def collect_headless_full(
    url:           str,
    scope,
    timeout:       int   = 30,
    stealth:       bool  = False,
    max_pages:     int   = 100,
    external_seen: set   = None,
    seed_urls:     list  = None,
    interact:      bool  = False,
    workers:       int   = 3,
    cookies:       list  = None,
    extra_headers: dict  = None,
    seen_hashes:   set   = None,
) -> dict:
    """
    Full headless scan.
    seed_urls:     routes from static analysis to pre-seed the engine.
    workers:       concurrent page processing (default 3).
    interact:      enable tab/dropdown interaction (slower, more coverage).
    cookies:       Playwright cookie dicts injected before first navigation.
    extra_headers: extra HTTP headers (non-Cookie) applied to every request.
    seen_hashes:   content SHA-256 hashes already seen by the crawler (for dedup).
    """
    engine = HeadlessEngine(
        target_url    = url,
        scope         = scope,
        timeout       = timeout,
        stealth       = stealth,
        max_pages     = max_pages,
        interact      = interact,
        workers       = workers,
        external_seen = external_seen or set(),
        cookies       = cookies or [],
        extra_headers = extra_headers or {},
        seen_hashes   = seen_hashes or set(),
    )
    if seed_urls:
        engine.seed_urls = list(seed_urls)
    return engine.run()
