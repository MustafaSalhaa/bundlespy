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
    "eventsource",
    # NOTE: "manifest" intentionally removed — some servers serve JS chunk
    # manifests (webpack, Vite) with resource type "manifest". Blocking it
    # causes those files to never fire a response event and be missed entirely.
}

# Content-type fragments that indicate JavaScript — intentionally broad.
# Servers use wildly inconsistent values: text/javascript, application/javascript,
# application/x-javascript, text/plain (for CDN-served bundles), even
# application/octet-stream. We catch all of them and fall back to URL pattern.
_JS_CT_FRAGMENTS = (
    "javascript",
    "ecmascript",
    "text/plain",         # CDN bundles, S3-hosted files
    "application/octet-stream",  # misconfigured servers
    "x-javascript",
)

# JS file extensions — includes compiled/transpiled variants
_JS_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx",        # transpiled — server may serve compiled output at .ts URL
    ".es", ".es6",
)

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

# Logout link keywords — never click these, they invalidate the session
LOGOUT_KEYWORDS = {
    "logout", "log out", "log-out", "sign out", "signout", "sign-out",
    "logoff", "log off", "log-off", "cerrar sesión", "déconnexion",
    "abmelden", "выход", "odhlásit", "注销", "ログアウト", "로그아웃",
    "çıkış", "uitloggen", "uitloggen", "sair", "saída",
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
window.__bundlespy_requests   = [];
window.__bundlespy_ws         = [];
window.__bundlespy_ws_messages = [];
window.__bundlespy_workers    = [];
window.__bundlespy_sw         = [];
window.__bundlespy_iframes    = [];

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

// WebSocket — capture URL + message payloads (send and receive)
const _origWS = window.WebSocket;
if (_origWS) {
    window.WebSocket = function(url, ...a) {
        var wsUrl = String(url);
        try { window.__bundlespy_ws.push({url: wsUrl}); } catch(e) {}
        const ws = new _origWS(url, ...a);
        // Capture outbound messages
        var _origSend = ws.send.bind(ws);
        ws.send = function(data) {
            try {
                var d = typeof data === 'string' ? data.substring(0, 1000) : '[binary]';
                window.__bundlespy_ws_messages.push({url: wsUrl, data: d, dir: 'send'});
            } catch(e2) {}
            return _origSend(data);
        };
        // Capture inbound messages
        ws.addEventListener('message', function(e) {
            try {
                var d = typeof e.data === 'string' ? e.data.substring(0, 1000) : '[binary]';
                window.__bundlespy_ws_messages.push({url: wsUrl, data: d, dir: 'recv'});
            } catch(e2) {}
        });
        return ws;
    };
    // Copy static properties (CONNECTING, OPEN, CLOSING, CLOSED)
    Object.assign(window.WebSocket, _origWS);
    window.WebSocket.prototype = _origWS.prototype;
}

// Service Worker registration — capture SW script URL before browser fetches it
if (navigator.serviceWorker) {
    try {
        var _origSwReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
        navigator.serviceWorker.register = function(scriptURL, opts) {
            try { window.__bundlespy_sw.push({url: String(scriptURL)}); } catch(e) {}
            return _origSwReg(scriptURL, opts);
        };
    } catch(e) {}
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
const _origSharedWorker = window.SharedWorker;
if (_origSharedWorker) {
    window.SharedWorker = function(url, ...a) {
        try { window.__bundlespy_workers.push({url: String(url), shared: true}); } catch(e) {}
        return new _origSharedWorker(url, ...a);
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

    // React Router (fiber) — full BFS traversal of the fiber tree
    try {
        if (window.__reactRouterRoutes) {
            window.__reactRouterRoutes.forEach(r => r.path && add(r.path));
        }
        document.querySelectorAll('#root,#app,[data-reactroot]').forEach(el => {
            try {
                const k = Object.keys(el).find(k =>
                    k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance')
                );
                if (!k) return;
                // True BFS — never misses branches that a simple child/sibling walk skips
                const queue = [el[k]];
                let visited = 0;
                while (queue.length && visited++ < 2000) {
                    const f = queue.shift();
                    if (!f) continue;
                    try {
                        const mp = f.memoizedProps;
                        if (mp) {
                            if (typeof mp.path   === 'string') add(mp.path);
                            if (typeof mp.to     === 'string') add(mp.to);
                            if (typeof mp.href   === 'string' && mp.href.startsWith('/')) add(mp.href);
                            // React Router v6 route objects
                            if (Array.isArray(mp.routes)) {
                                mp.routes.forEach(function w(r) {
                                    if (!r) return;
                                    if (r.path) add(r.path);
                                    if (r.children) r.children.forEach(w);
                                });
                            }
                        }
                        // Traverse: child first, then sibling
                        if (f.child)    queue.push(f.child);
                        if (f.sibling)  queue.push(f.sibling);
                    } catch(e) {}
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

# Path segments that strongly indicate an authentication page.
# Intentionally broad — false negatives (missing a login page) are worse than
# false positives (pausing on a legitimate page with "auth" in the path).
LOGIN_PATH_KEYWORDS = {
    "/login", "/signin", "/sign-in", "/log-in", "/logon", "/log-on",
    "/auth/login", "/auth/signin", "/auth", "/authenticate",
    "/account/login", "/account/signin",
    "/user/login", "/user/signin",
    "/session/new", "/sessions/new",
    "/sso", "/saml", "/oauth", "/oidc",
    "/wp-login", "/wp-admin/login",
    "/admin/login", "/admin/signin",
    "/portal/login", "/portal/signin",
    "/access", "/gate",
}

# DOM text patterns that indicate a login form — used as fallback when the URL
# doesn't match (custom auth paths like /enter, /start, /verify).
_LOGIN_DOM_PATTERNS = (
    'input[type="password"]',
    'form[action*="login"]',
    'form[action*="signin"]',
    'form[action*="authenticate"]',
    '[name="password"]',
    '[id="password"]',
    '[autocomplete="current-password"]',
)

def _is_login_url(url: str) -> bool:
    """Return True if the URL path looks like a login/auth page."""
    lower = urlparse(url).path.lower().rstrip("/")
    return any(lower == kw or lower.endswith(kw) for kw in LOGIN_PATH_KEYWORDS)

def _is_login_page(page) -> bool:
    """
    Return True if the current page looks like an auth/login wall.
    Checks both URL and DOM — catches custom login paths that _is_login_url misses.
    """
    try:
        if _is_login_url(page.url):
            return True
        # DOM check: any password field = login/auth page
        for sel in _LOGIN_DOM_PATTERNS:
            try:
                if page.query_selector(sel):
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


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
        self.ws_messages: List[dict]   = []   # WS payload capture (item 9)
        self.routes:     Set[str]      = set()
        self.pages_visited: int        = 0
        self.auth_result: Optional[dict] = None  # populated during run()
        self._seen_interact_states: Set[str] = set()  # DOM states already interacted with

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

    def _is_js_response(self, url: str, ct: str, resource_type: str) -> bool:
        """
        Determine if a response is JavaScript using multiple signals.

        Playwright's resource_type is the most reliable signal when available
        ("script" covers all JS regardless of Content-Type). We then fall back
        to content-type fragments and URL extension. This three-layer check
        ensures we never miss a JS file regardless of how the server labels it.
        """
        # Layer 1: Playwright resource type — most reliable, set by browser
        if resource_type in ("script", "worker"):
            return True

        ct_lower = ct.lower()

        # Layer 2: Content-Type header — catch all known JS MIME types
        if any(frag in ct_lower for frag in _JS_CT_FRAGMENTS):
            # Sanity-check: text/plain and octet-stream are also used for CSS,
            # images etc — only accept them if the URL also looks like JS.
            if ct_lower.startswith("text/plain") or "octet-stream" in ct_lower:
                path = url.split("?")[0].split("#")[0].lower()
                return path.endswith(_JS_EXTENSIONS)
            return True

        # Layer 3: URL extension fallback — catches misconfigured servers that
        # return an empty or wrong Content-Type for JS files.
        path = url.split("?")[0].split("#")[0].lower()
        return path.endswith(_JS_EXTENSIONS)

    def _handle_response(self, response, source_page: str) -> None:
        """
        Capture JS files from network responses.

        Called from the context-level response handler (fires for every
        request across all pages). Uses three-layer JS detection to handle
        servers with missing, wrong, or non-standard Content-Type headers.
        """
        try:
            url           = response.url
            ct            = response.headers.get("content-type", "")
            resource_type = response.request.resource_type

            if not self._is_js_response(url, ct, resource_type):
                return

            # Skip cross-origin JS that's outside our scope
            safe, _ = validate_url(url)
            if not safe or not self.scope.in_scope(url):
                return

            # URL-level dedup — normalize strips query/fragment for comparison
            norm = self.registry._normalize(url)
            if not self.registry.register_url(norm):
                return

            # Read the response body — body() can throw if the response was
            # already consumed (e.g. aborted, or a streaming response that
            # completed before we got here). Always handle it explicitly.
            try:
                body = response.body()
            except Exception as e:
                logger.debug("Could not read response body for %s: %s", url, e)
                return

            if not body:
                return

            # Content-level dedup — same file served at multiple URLs
            h = hashlib.sha256(body).hexdigest()
            if self.registry.seen_hash(h):
                return

            # Verify it actually looks like JS (not an HTML error page served
            # with a JS content-type — common on misconfigured servers)
            try:
                snippet = body[:512].decode("utf-8", errors="replace").lstrip()
                # HTML error pages returned with JS content-type
                if snippet.startswith(("<!DOCTYPE", "<!doctype", "<html", "<HTML")):
                    logger.debug("Skipping HTML-disguised-as-JS: %s", url)
                    return
            except Exception:
                pass

            js_file = self._make_js_file(url, body, source_page)
            added = self._add_js_file(js_file)
            if added:
                logger.debug("Captured JS [%s] %s (%d bytes)", resource_type, url, len(body))

        except Exception as e:
            logger.debug("_handle_response error for %s: %s",
                         getattr(response, "url", "?"), e)

    def _is_destructive(self, text: str) -> bool:
        lower = (text or "").lower().strip()
        return any(kw in lower for kw in DESTRUCTIVE_KEYWORDS)

    def _is_logout_link(self, element) -> bool:
        """
        Return True if the element is a logout/sign-out link.
        Checks visible text, href, id, and class — covers all common patterns.
        Never click a logout link: it invalidates the session and silently
        breaks all subsequent authenticated page crawls.
        """
        try:
            text  = (element.inner_text() or "").lower().strip()
            href  = (element.get_attribute("href")  or "").lower()
            eid   = (element.get_attribute("id")    or "").lower()
            cls   = (element.get_attribute("class") or "").lower()
            combined = f"{text} {href} {eid} {cls}"
            return any(kw in combined for kw in LOGOUT_KEYWORDS)
        except Exception:
            return False

    def _current_origin(self, page) -> str:
        """Return the current page's origin (scheme + netloc) or empty string on error."""
        try:
            return "{0.scheme}://{0.netloc}".format(urlparse(page.url))
        except Exception:
            return ""

    def _recover_drift(self, page, expected_url: str, stabilizer: PageStabilizer) -> bool:
        """
        Detect and recover from browser origin drift.

        Drift happens when a page JS redirect, meta-refresh, or external link
        moves the browser to an unexpected origin between navigations. If drift
        is detected, we navigate back to expected_url before the next action
        fires so actions never execute on the wrong page.

        Returns True if drift was detected (and recovered), False if the browser
        is already on the expected origin.
        """
        try:
            expected_origin = "{0.scheme}://{0.netloc}".format(urlparse(expected_url))
            current_origin  = self._current_origin(page)
            if not current_origin or not expected_origin:
                return False
            if current_origin == expected_origin:
                return False
            # Drift detected — navigate back
            logger.debug(
                "Browser drift: expected=%s got=%s — recovering",
                expected_origin, current_origin,
            )
            try:
                page.goto(expected_url, timeout=self.timeout * 1000,
                          wait_until="domcontentloaded")
                stabilizer.wait_for_framework(max_ms=2000)
            except Exception as nav_err:
                logger.debug("Drift recovery navigation failed: %s", nav_err)
            return True
        except Exception:
            return False

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

    def _extract_ws_messages(self, page) -> List[dict]:
        """
        Extract WebSocket message payloads captured by the INTERCEPT_JS patch.
        Returns list of {url, data, dir} dicts.
        Message payloads frequently contain API endpoint paths, auth tokens,
        and data structures not visible anywhere in static JS.
        """
        try:
            r = page.evaluate("window.__bundlespy_ws_messages || []")
            return r if isinstance(r, list) else []
        except Exception:
            return []

    def _extract_sw_urls(self, page) -> List[str]:
        """
        Extract service worker script URLs intercepted from navigator.serviceWorker.register().
        Returns a list of absolute or relative SW script URLs.
        """
        try:
            r = page.evaluate("window.__bundlespy_sw || []")
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

    def _auth_headers(self, referer: str = "") -> dict:
        """
        Build HTTP headers for off-thread fetches (worker, DOM-scrape fallback).
        Injects auth cookies as a Cookie header + any extra_headers supplied
        by the user. This mirrors what the browser context sends, so
        authenticated resources are accessible even outside Playwright.
        """
        hdrs = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/146.0.0.0 Safari/537.36"
            ),
        }
        if referer:
            hdrs["Referer"] = referer

        # Rebuild Cookie header from injected Playwright cookie dicts
        if self.cookies:
            cookie_str = "; ".join(
                f"{c['name']}={c['value']}"
                for c in self.cookies
                if c.get("name") and c.get("value") is not None
            )
            if cookie_str:
                hdrs["Cookie"] = cookie_str

        # Merge any extra headers (non-Cookie ones were already filtered in __init__)
        if self.extra_headers:
            hdrs.update(self.extra_headers)

        return hdrs

    def _fetch_worker_js(self, worker_url: str, source_page: str) -> None:
        """Fetch WebWorker JS file. Thread-safe. Sends auth cookies+headers."""
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
            resp = _req.get(
                worker_url,
                timeout=8,
                verify=False,
                headers=self._auth_headers(referer=source_page),
            )
            if resp.status_code == 200 and resp.content:
                h = hashlib.sha256(resp.content).hexdigest()
                if self.registry.register_hash(h):
                    js_file = self._make_js_file(worker_url, resp.content, source_page, "webworker")
                    self._add_js_file(js_file)
                    logger.info("WebWorker captured: %s", worker_url)
        except Exception as e:
            logger.debug("Worker fetch failed %s: %s", worker_url, e)

    def _fetch_service_worker(self, sw_url: str, source_page: str) -> None:
        """
        Fetch a service worker script, register it as a JSFile, and then
        extract any importScripts() or static import paths it references so
        those secondary scripts are also captured and analyzed.

        Service workers intercept all network traffic for a scope — they're
        prime targets for hidden API endpoints, auth bypass logic, and cache
        poisoning primitives. They never show up in response events because
        the browser registers them via the SW API, not a normal fetch.
        """
        try:
            # Resolve relative URLs against the target origin
            if sw_url.startswith("/"):
                parsed = urlparse(self.target_url)
                sw_url = f"{parsed.scheme}://{parsed.netloc}{sw_url}"
            elif not sw_url.startswith(("http://", "https://")):
                sw_url = urljoin(source_page, sw_url)

            if not self.registry.register_url(sw_url):
                return  # already captured

            safe, _ = validate_url(sw_url)
            if not safe or not self.scope.in_scope(sw_url):
                return

            import requests as _req
            resp = _req.get(
                sw_url,
                timeout=8,
                verify=False,
                headers=self._auth_headers(referer=source_page),
            )
            if resp.status_code != 200 or not resp.content:
                logger.debug("Service worker fetch failed: %s (%d)", sw_url, resp.status_code)
                return

            h = hashlib.sha256(resp.content).hexdigest()
            if self.registry.register_hash(h):
                js_file = self._make_js_file(sw_url, resp.content, source_page, "service-worker")
                if self._add_js_file(js_file):
                    logger.info("Service worker captured: %s (%d bytes)", sw_url, len(resp.content))

            # Extract importScripts() and static import paths from the SW body
            # so any sub-scripts are also fetched and analyzed.
            sw_text = resp.content.decode("utf-8", errors="replace")
            self._fetch_sw_imports(sw_text, sw_url, source_page)

        except Exception as e:
            logger.debug("Service worker fetch error %s: %s", sw_url, e)

    def _fetch_sw_imports(self, sw_text: str, sw_url: str, source_page: str) -> None:
        """
        Parse importScripts() calls and static ES import paths from a service
        worker script body and fetch each referenced file.

        importScripts('a.js', 'b.js') is the classic SW pattern.
        Modern SWs (Workbox etc.) may also use ES module syntax.
        """
        imported: List[str] = []

        # importScripts('a.js', 'b.js', ...)
        for m in re.finditer(r'importScripts\s*\(([^)]+)\)', sw_text):
            for arg in re.finditer(r'["\']([^"\']+)["\']', m.group(1)):
                imported.append(arg.group(1))

        # static: import '...' / import "..." / import ... from '...'
        for m in re.finditer(
            r'import\s+(?:[^"\']*\s+from\s+)?["\']([^"\']+)["\']', sw_text
        ):
            imported.append(m.group(1))

        for path in imported:
            if not path or path.startswith("data:"):
                continue
            abs_url = urljoin(sw_url, path)
            safe, _ = validate_url(abs_url)
            if not safe or not self.scope.in_scope(abs_url):
                continue
            if not self.registry.register_url(abs_url):
                continue
            try:
                import requests as _req
                resp = _req.get(abs_url, timeout=8, verify=False,
                                headers=self._auth_headers(referer=sw_url))
                if resp.status_code == 200 and resp.content:
                    h = hashlib.sha256(resp.content).hexdigest()
                    if self.registry.register_hash(h):
                        js_file = self._make_js_file(abs_url, resp.content, sw_url, "service-worker-import")
                        self._add_js_file(js_file)
                        logger.debug("SW import captured: %s", abs_url)
            except Exception as e:
                logger.debug("SW import fetch failed %s: %s", abs_url, e)

    def _interact(self, page, stabilizer: PageStabilizer) -> None:
        """
        Interaction engine — scroll, tabs, dropdowns, nav hovers.
        Safe: never clicks destructive actions, never submits forms.
        Adaptive waits after each action so JS-driven UI settles before the
        next step fires.
        """
        # DOM simhash guard: skip interaction on states we've already triggered.
        # Prevents re-firing the same JS events on SPAs that render the same
        # component under different URLs (common in React Router / Vue Router apps).
        try:
            _ifp = self._dom_fingerprint(page)
            if _ifp and _ifp in self._seen_interact_states:
                logger.debug("Skipping interaction — duplicate DOM state")
                return
            if _ifp:
                self._seen_interact_states.add(_ifp)
        except Exception:
            pass

        # Phase 1: Adaptive scroll — triggers lazy-load and infinite-scroll JS
        try:
            for frac in [0.25, 0.5, 0.75, 1.0, 0]:
                page.evaluate(f"window.scrollTo(0, document.body.scrollHeight * {frac});")
                stabilizer.wait_after_interaction(max_ms=500)
        except Exception:
            pass

        # Phase 2: Tabs, accordions, toggles — reveal hidden panels
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
                        if self._is_logout_link(el):
                            continue
                        el.click(timeout=800)
                        stabilizer.wait_after_interaction(max_ms=800)
                    except Exception:
                        pass
            except Exception:
                pass

        # Phase 3: Dropdown and menu toggles
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
                    if self._is_logout_link(el):
                        continue
                    el.click(timeout=800)
                    stabilizer.wait_after_interaction(max_ms=600)
                except Exception:
                    pass
        except Exception:
            pass

        # Phase 4: Nav hover — reveals mega-menus and sub-nav JS
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

        # Phase 5: Multi-step form engine — drives conditional field reveal
        # and modal appearance without ever submitting or touching payment flows.
        self._interact_forms(page, stabilizer)

    def _interact_forms(self, page, stabilizer: PageStabilizer) -> None:
        """
        Multi-step form interaction engine.

        Goals:
        - Fill safe text/search/email fields to trigger JS-driven validation
          and conditional field reveal (e.g. "if email entered → show password").
        - Click Next/Continue buttons to advance multi-step wizards and expose
          new API calls made on each step transition.
        - Detect modals that open after a step (aria-modal, [role=dialog]) and
          interact with their content so any extra JS they load is captured.

        Safety rules (never violated):
        - Skip any form whose context touches payment/checkout keywords.
        - Never click Submit / Place Order / Pay / Confirm Order buttons.
        - Never click buttons whose text is in DESTRUCTIVE_KEYWORDS.
        - At most MAX_STEPS steps per form so we can't loop forever.
        - Clear every input field after interacting so state is not persisted.
        """
        MAX_STEPS       = 4   # max wizard steps per form
        MAX_FORMS       = 6   # max forms to interact with per page
        NEXT_SELECTORS  = [
            "button[type='button']",          # generic next buttons
            "button:not([type='submit'])",     # non-submit buttons in a form
            "[data-action='next']",
            "[data-step='next']",
            "button.next", "button.continue",
            "a.next", "a.continue",
        ]
        MODAL_SELECTORS = [
            "[role='dialog']:not([hidden])",
            "[aria-modal='true']:not([hidden])",
            ".modal:not(.hidden):not(.d-none)",
            ".dialog:not(.hidden)",
        ]

        try:
            forms = page.query_selector_all("form")[:MAX_FORMS]
        except Exception:
            return

        for form in forms:
            try:
                # Skip payment / destructive form contexts
                ctx = " ".join(filter(None, [
                    form.get_attribute("id"),
                    form.get_attribute("class"),
                    form.get_attribute("action"),
                    form.get_attribute("data-form-type"),
                ])).lower()
                if any(kw in ctx for kw in SKIP_FORM_CONTEXTS):
                    continue

                for _step in range(MAX_STEPS):
                    # --- Fill visible safe inputs in current step ---
                    try:
                        inputs = form.query_selector_all(
                            "input:not([type='hidden']):not([type='submit'])"
                            ":not([type='radio']):not([type='checkbox']),"
                            "textarea"
                        )[:8]
                    except Exception:
                        inputs = []

                    filled_any = False
                    for inp in inputs:
                        try:
                            if not inp.is_visible() or not inp.is_enabled():
                                continue
                            itype = (inp.get_attribute("type") or "text").lower()
                            iname = " ".join(filter(None, [
                                inp.get_attribute("name"),
                                inp.get_attribute("id"),
                                inp.get_attribute("placeholder"),
                                inp.get_attribute("autocomplete"),
                            ])).lower()

                            # Only fill safe field types
                            if itype not in ("text", "search", "email", "tel", "url", ""):
                                continue
                            # Only interact with recognisably safe field names
                            if not any(s in iname for s in SAFE_INPUT_NAMES):
                                continue

                            fill_val = FORM_FILL_VALUES.get(
                                next((k for k in FORM_FILL_VALUES if k in iname), None),
                                "test",
                            )
                            inp.click(timeout=600)
                            inp.fill(fill_val)
                            stabilizer.wait_after_interaction(max_ms=300)
                            filled_any = True
                        except Exception:
                            pass

                    if not filled_any and _step > 0:
                        break  # nothing new appeared — wizard is done

                    # --- Conditional field trigger: Tab through inputs ---
                    try:
                        page.keyboard.press("Tab")
                        stabilizer.wait_after_interaction(max_ms=300)
                    except Exception:
                        pass

                    # --- Look for a Next/Continue button (NOT submit) ---
                    advanced = False
                    for sel in NEXT_SELECTORS:
                        if advanced:
                            break
                        try:
                            for btn in form.query_selector_all(sel)[:4]:
                                try:
                                    if not btn.is_visible() or not btn.is_enabled():
                                        continue
                                    btn_text = (btn.inner_text() or "").lower().strip()
                                    # Skip destructive and submit-like buttons
                                    if self._is_destructive(btn_text):
                                        continue
                                    if any(w in btn_text for w in ("submit", "place order", "pay", "confirm order", "checkout")):
                                        continue
                                    # Only click Next/Continue/Continue-style buttons
                                    if not any(w in btn_text for w in ("next", "continue", "proceed", "forward", "step", "go →", "→", ">")):
                                        continue
                                    btn.click(timeout=800)
                                    stabilizer.wait_after_interaction(max_ms=1000)
                                    advanced = True
                                    break
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    # --- Check for modals that appeared after the step ---
                    for modal_sel in MODAL_SELECTORS:
                        try:
                            modal = page.query_selector(modal_sel)
                            if not modal or not modal.is_visible():
                                continue
                            # Interact with visible inputs inside the modal
                            for inp in modal.query_selector_all(
                                "input:not([type='hidden']):not([type='submit']),textarea"
                            )[:4]:
                                try:
                                    itype = (inp.get_attribute("type") or "text").lower()
                                    iname = " ".join(filter(None, [
                                        inp.get_attribute("name"),
                                        inp.get_attribute("id"),
                                        inp.get_attribute("placeholder"),
                                    ])).lower()
                                    if itype not in ("text", "search", "email") or \
                                       not any(s in iname for s in SAFE_INPUT_NAMES):
                                        continue
                                    if not inp.is_visible() or not inp.is_enabled():
                                        continue
                                    inp.fill("test")
                                    stabilizer.wait_after_interaction(max_ms=300)
                                    inp.fill("")  # clear
                                except Exception:
                                    pass
                            # Close the modal so it doesn't block the next step
                            for close_sel in [
                                "[aria-label='Close']", "[data-dismiss='modal']",
                                "[data-bs-dismiss='modal']", "button.close",
                                ".modal-header button",
                            ]:
                                try:
                                    close_btn = modal.query_selector(close_sel)
                                    if close_btn and close_btn.is_visible():
                                        close_btn.click(timeout=600)
                                        stabilizer.wait_after_interaction(max_ms=500)
                                        break
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    if not advanced:
                        break  # no Next button found — form exploration done

                # Clear all inputs we touched before moving to next form
                try:
                    for inp in form.query_selector_all(
                        "input:not([type='hidden']):not([type='radio']):not([type='checkbox'])"
                    )[:10]:
                        try:
                            if inp.is_visible():
                                inp.fill("")
                        except Exception:
                            pass
                except Exception:
                    pass

            except Exception:
                pass

    def _observe_forms(self, page, stabilizer: PageStabilizer) -> None:
        """
        Legacy shim — kept for backward compatibility with call sites that
        invoke _observe_forms directly. The new _interact_forms (called from
        _interact Phase 5) now handles all form observation. This is a no-op.
        """
        pass

    def _collect_inline_scripts(self, page, source_page: str) -> None:
        """
        Extract and register all inline <script> blocks from the rendered DOM,
        including scripts inside Shadow DOM trees (web components).

        Inline scripts are never a network response — they're embedded in the
        HTML — so _handle_response never fires for them. This method reads them
        directly from the DOM via page.evaluate() and registers each unique
        block as a JSFile immediately.

        Shadow DOM piercing: document.querySelectorAll() cannot cross shadow
        root boundaries. We walk the entire element tree recursively via
        el.shadowRoot, collecting inline scripts from every shadow host found.
        Depth limit of 10 prevents infinite loops in pathological cases.

        Skips:
        - Empty / whitespace-only blocks
        - type="text/template", type="text/html", type="application/ld+json", etc.
        - Content already seen by crawler (hash dedup)
        - Blocks < 20 bytes (noise)
        """
        try:
            blocks = page.evaluate("""
                (function() {
                    var results = [];
                    var globalIdx = 0;

                    function isExecutable(tag) {
                        var t = (tag.getAttribute('type') || '').toLowerCase().trim();
                        return !t || t === 'text/javascript' || t === 'module' ||
                               t === 'application/javascript';
                    }

                    function collectFromRoot(root, depth) {
                        if (depth > 10) return;

                        // Collect inline scripts at this root level
                        root.querySelectorAll('script:not([src])').forEach(function(s) {
                            if (!isExecutable(s)) return;
                            var content = s.textContent || '';
                            if (content.trim().length < 20) return;
                            var isModule = (s.getAttribute('type') || '').toLowerCase() === 'module';
                            results.push({
                                idx:      globalIdx++,
                                content:  content,
                                isModule: isModule,
                                inShadow: depth > 0,
                            });
                        });

                        // Recurse into all shadow roots at this level
                        root.querySelectorAll('*').forEach(function(el) {
                            if (el.shadowRoot) {
                                collectFromRoot(el.shadowRoot, depth + 1);
                            }
                        });
                    }

                    collectFromRoot(document, 0);
                    return results;
                })()
            """) or []
        except Exception:
            return

        for block in blocks:
            try:
                content = block.get("content", "")
                if not content or len(content.strip()) < 20:
                    continue

                body = content.encode("utf-8", errors="replace")
                h = hashlib.sha256(body).hexdigest()

                # Hash-level dedup — skip if crawler or a previous headless
                # page already registered this exact content
                if not self.registry.register_hash(h):
                    continue

                idx       = block.get("idx", 0)
                in_shadow = block.get("inShadow", False)
                is_module = block.get("isModule", False)

                # Technology label for reporting
                if in_shadow and is_module:
                    tech = "shadow-dom-module"
                elif in_shadow:
                    tech = "shadow-dom-inline"
                elif is_module:
                    tech = "headless-module-inline"
                else:
                    tech = "headless-inline"

                # Synthetic URL consistent with static crawler's inline scheme
                inline_url = f"inline:{source_page}#script-{idx + 1}-{h[:12]}"

                js_file = JSFile(
                    url=inline_url,
                    source_page=source_page,
                    status_code=200,
                    content_type="text/javascript",
                    size_bytes=len(body),
                    sha256=h,
                    content=content,
                    discovered_at=datetime.utcnow(),
                    technology=tech,
                )
                if self._add_js_file(js_file):
                    shadow_note = " [shadow-dom]" if in_shadow else ""
                    logger.debug("Inline script captured [%d bytes]%s from %s",
                                 len(body), shadow_note, source_page)
            except Exception as e:
                logger.debug("Inline script registration error: %s", e)

    def _collect_dom_script_urls(self, page) -> list:
        """
        Extract all <script src> URLs from the rendered DOM.
        Must be called from the Playwright thread — returns a plain list
        of URL strings so the actual HTTP fetching can happen off-thread.
        """
        try:
            return page.evaluate("""
                (function() {
                    var seen = new Set();
                    var results = [];
                    document.querySelectorAll('script[src]').forEach(function(s) {
                        var src = s.src;
                        if (src && !seen.has(src)) {
                            seen.add(src);
                            results.push(src);
                        }
                    });
                    return results;
                })()
            """) or []
        except Exception:
            return []

    def _collect_module_script_urls(self, page) -> list:
        """
        Collect ES module entry points: <script type="module" src="..."> URLs
        from the rendered DOM. Must run in the Playwright thread.

        The response handler should already capture these via network events,
        but modules loaded with `type="module"` are sometimes served from
        a different path or cached, so we also collect them explicitly here
        as a fallback — same pattern as _collect_dom_script_urls.
        """
        try:
            return page.evaluate("""
                (function() {
                    var seen = new Set();
                    var results = [];
                    document.querySelectorAll('script[type="module"][src]').forEach(function(s) {
                        var src = s.src;
                        if (src && !seen.has(src)) {
                            seen.add(src);
                            results.push(src);
                        }
                    });
                    return results;
                })()
            """) or []
        except Exception:
            return []

    def _extract_es_imports(self, js_content: str, base_url: str) -> List[str]:
        """
        Parse static and dynamic ES module import paths from a JS file body
        and resolve them to absolute URLs against base_url.

        Patterns handled:
        - Static:  import X from './mod.js'
        - Static:  import { a } from '../lib/utils.js'
        - Static:  export { b } from './other.js'
        - Dynamic: import('./lazy.js')
        - Re-export: export * from './all.js'

        CDN / absolute URLs (http/https) are excluded — they're out of scope
        for same-origin analysis and already captured by the response handler.
        """
        # Match the module specifier string in import/export statements and
        # dynamic import() calls. We intentionally only handle string literals
        # (not computed import expressions) — those can't be statically resolved.
        _IMPORT_RE = re.compile(
            r"""(?:import|export)\s+(?:[^'"]*?\s+from\s+)?['"](\.{1,2}/[^'"]+)['"]\s*[;,)]?"""
            r"""|import\s*\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)""",
            re.MULTILINE,
        )
        urls = []
        for m in _IMPORT_RE.finditer(js_content):
            path = m.group(1) or m.group(2)
            if not path:
                continue
            abs_url = urljoin(base_url, path)
            safe, _ = validate_url(abs_url)
            if safe and self.scope.in_scope(abs_url):
                urls.append(abs_url)
        return urls

    def _fetch_es_module(self, mod_url: str, source_url: str, depth: int = 0) -> None:
        """
        Fetch an ES module JS file, register it, then recursively follow its
        static import graph up to a fixed depth so transitive dependencies are
        all captured and analyzed.

        depth limit prevents runaway recursion on circular import graphs.
        """
        MAX_DEPTH = 3
        if depth > MAX_DEPTH:
            return
        try:
            if not mod_url.startswith(("http://", "https://")):
                mod_url = urljoin(source_url, mod_url)

            safe, _ = validate_url(mod_url)
            if not safe or not self.scope.in_scope(mod_url):
                return

            if not self.registry.register_url(mod_url):
                return  # already fetched

            import requests as _req
            resp = _req.get(
                mod_url,
                timeout=8,
                verify=False,
                headers=self._auth_headers(referer=source_url),
            )
            if resp.status_code != 200 or not resp.content:
                return

            # Reject HTML error pages at JS URLs
            snippet = resp.content[:256].lstrip()
            if snippet.startswith((b"<!DOCTYPE", b"<!doctype", b"<html")):
                return

            h = hashlib.sha256(resp.content).hexdigest()
            if not self.registry.register_hash(h):
                return

            js_file = self._make_js_file(mod_url, resp.content, source_url, "es-module")
            if self._add_js_file(js_file):
                logger.debug("ES module captured: %s (depth=%d)", mod_url, depth)

            # Recurse — follow transitive static imports
            body_text = resp.content.decode("utf-8", errors="replace")
            child_urls = self._extract_es_imports(body_text, mod_url)
            for child_url in child_urls:
                self._fetch_es_module(child_url, mod_url, depth + 1)

        except Exception as e:
            logger.debug("ES module fetch failed %s: %s", mod_url, e)

    def _fetch_dom_scripts(self, script_urls: list, source_page: str) -> None:
        """
        Fetch JS URLs collected from the DOM via plain HTTP (no Playwright).
        Safe to call from a background thread — never touches page/context objects.

        Catches JS files the response handler missed: browser cache hits
        (cached responses fire no network event), service worker intercepts,
        and any timing gaps between ctx.route() and ctx.on("response").

        Sends the same auth cookies+headers as the browser context so
        authenticated JS bundles (behind a CDN auth gate or session cookie
        check) are accessible.
        """
        import requests as _req
        hdrs = self._auth_headers(referer=source_page)
        for js_url in script_urls:
            try:
                if not js_url or not js_url.startswith(("http://", "https://")):
                    continue
                safe, _ = validate_url(js_url)
                if not safe or not self.scope.in_scope(js_url):
                    continue
                norm = self.registry._normalize(js_url)
                if not self.registry.register_url(norm):
                    continue  # already captured by response handler — skip

                resp = _req.get(js_url, timeout=8, verify=False, headers=hdrs)
                if resp.status_code != 200 or not resp.content:
                    continue

                # Skip HTML error pages served at JS URLs
                snippet = resp.content[:256].lstrip()
                if snippet.startswith((b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML")):
                    continue

                h = hashlib.sha256(resp.content).hexdigest()
                if self.registry.register_hash(h):
                    js_file = self._make_js_file(js_url, resp.content, source_page, "dom-scrape-fallback")
                    if self._add_js_file(js_file):
                        logger.debug("DOM-scrape fallback captured: %s", js_url)
            except Exception as e:
                logger.debug("DOM-scrape fetch failed %s: %s", js_url, e)

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

    @staticmethod
    def _is_parametric_route(route: str) -> bool:
        """
        Return True if the route contains a framework-level parameter placeholder.
        These are route definitions, not real URLs — passing them to page.goto
        would make the browser request the literal string "/users/:id" or
        "/post/{slug}" and get a 404 (or navigate to an unintended page).

        Patterns caught: React Router :param, Angular :param, Vue :param,
        Next.js [param], Express :param, OpenAPI {param}.
        """
        seg_re = re.compile(r'(^|/)(:\w+|\[\w+\]|\{\w+\}|\*\*?)(/|$)')
        return bool(seg_re.search(route))

    def _build_urls(self, routes: Set[str]) -> List[str]:
        """Convert routes to full URLs, sorted by priority. Filters parametric routes."""
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        urls   = []
        for route in routes:
            # Skip framework-level route definitions — they're not real URLs
            if self._is_parametric_route(route):
                logger.debug("Skipping parametric route: %s", route)
                continue
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

        # Mine WebSocket message payloads for embedded API paths (item 9).
        # WS messages frequently contain action types, resource paths, and
        # query structures that reveal hidden API endpoints.
        ws_endpoint_seen: Set[str] = set()
        _WS_PATH_RE = re.compile(
            r'["\'](?:url|path|endpoint|resource|action|route|href|api)'
            r'["\']\s*:\s*["\'](/[A-Za-z0-9/_\-\.]+)["\']',
            re.IGNORECASE,
        )
        for msg in self.ws_messages:
            data = msg.get("data", "")
            if not data or not isinstance(data, str):
                continue
            for m in _WS_PATH_RE.finditer(data):
                path = m.group(1)
                key  = f"WS-MSG:{path}"
                if key in ws_endpoint_seen:
                    continue
                ws_endpoint_seen.add(key)
                # Reconstruct a full URL from the WS connection URL
                ws_conn_url = msg.get("url", "")
                try:
                    parsed_ws = urlparse(ws_conn_url)
                    scheme    = "https" if parsed_ws.scheme in ("wss", "https") else "http"
                    full_url  = f"{scheme}://{parsed_ws.netloc}{path}"
                except Exception:
                    full_url = path
                lower = path.lower()
                if any(k in lower for k in ["/auth", "/login", "/token", "/session"]):
                    cat = "AUTH"
                elif any(k in lower for k in ["/admin", "/management"]):
                    cat = "ADMIN"
                elif "/graphql" in lower:
                    cat = "GRAPHQL"
                else:
                    cat = "API"
                endpoints.append(Endpoint(
                    url=full_url, path=path,
                    method="WS-MSG", category=cat,
                    source_file="headless://ws-message-payload",
                    line_number=0, confidence=0.75,
                ))

        return endpoints

    def _verify_auth(self, page, initial_url: str) -> dict:
        """
        Navigate to the target and verify the session is authenticated.

        Listeners are always removed in a finally block — they must not persist
        after this method returns or they fire on every future navigation in
        the context and write to dead closures (Bug 6 fix).

        If auth fails (redirected to login), we navigate back to initial_url
        before returning so that _flush_page_intel runs on the target page,
        not the login page (Bug 7 fix).

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
            try:
                if response.url == page.url or not redirect_chain:
                    final_status = response.status
            except Exception:
                pass

        def _on_request(request):
            try:
                if request.is_navigation_request() and request.url != initial_url:
                    redirect_chain.append(request.url)
            except Exception:
                pass

        page.on("response", _on_response)
        page.on("request",  _on_request)

        try:
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
            # Use _is_login_page (DOM-aware) for the post-navigation check so
            # custom login paths (not matching keyword list) are still detected.
            redirected_to_login = _is_login_page(page)

            if redirected_to_login:
                result["authenticated"] = False
                result["reason"]        = "Redirected to login page — session rejected or expired"
                # Bug 7 fix: navigate back to the target so _flush_page_intel
                # runs on the actual target page, not the login wall.
                try:
                    page.goto(initial_url, timeout=self.timeout * 1000,
                              wait_until="domcontentloaded")
                except Exception:
                    pass
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

        finally:
            # Bug 6 fix: always remove listeners — they must not persist
            # after this method returns or they fire on all future navigations.
            try:
                page.remove_listener("response", _on_response)
            except Exception:
                pass
            try:
                page.remove_listener("request", _on_request)
            except Exception:
                pass

    def _dom_fingerprint(self, page) -> str:
        """
        DOM state fingerprint — pathname + title + element count + heading text.

        pathname is the primary key: two SPA states with the same title but
        different URLs are different states and must both be explored.
        title/count/heading catch cases where a SPA renders different content
        at the same path (e.g. a modal that replaces the whole page body).
        """
        try:
            sig = page.evaluate("""
                (function() {
                    var path  = window.location.pathname || '/';
                    var t     = document.title || '';
                    var c     = document.body ? document.body.children.length : 0;
                    var h     = document.querySelector('h1,h2,[class*="title"],[class*="header"]');
                    var txt   = h ? h.innerText.trim().slice(0,80) : '';
                    var forms = document.querySelectorAll('form').length;
                    return path + '|' + t + '|' + c + '|' + txt + '|' + forms;
                })()
            """)
            return __import__('hashlib').sha256((sig or "").encode()).hexdigest()[:16]
        except Exception:
            return ""

    def _flush_page_intel(self, page, source_url: str) -> set:
        """
        Extract all intelligence from the current page in one pass.
        Each step is independently guarded — one failure never kills the rest.
        Clears interceptor buffers after reading so the next page starts fresh.
        """
        new_routes = set()

        # Route extraction — most important, runs first
        try:
            new_routes = self._extract_routes(page)
        except Exception as e:
            logger.debug("Route extraction error %s: %s", source_url, e)

        # API / WS intercepts
        try:
            api_calls   = self._extract_api_calls(page)
            ws_urls     = self._extract_ws_urls(page)
            ws_messages = self._extract_ws_messages(page)   # item 9
            with self._lock:
                self.api_calls.extend(api_calls)
                self.ws_urls.extend(ws_urls)
                self.ws_messages.extend(ws_messages)
        except Exception as e:
            logger.debug("API/WS extraction error %s: %s", source_url, e)

        # WebWorkers + Service Workers (item 6)
        try:
            worker_urls = self._extract_worker_urls(page)
            sw_urls     = self._extract_sw_urls(page)
            import threading as _t
            for w_url in worker_urls:
                _t.Thread(target=self._fetch_worker_js, args=(w_url, source_url), daemon=True).start()
            for sw_url in sw_urls:
                _t.Thread(target=self._fetch_service_worker, args=(sw_url, source_url), daemon=True).start()
        except Exception as e:
            logger.debug("Worker/SW extraction error %s: %s", source_url, e)

        # Iframes — add same-origin ones as routes
        try:
            iframe_urls = self._extract_iframe_urls(page)
            parsed = urlparse(self.target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for iframe_url in iframe_urls:
                if iframe_url.startswith(origin):
                    new_routes.add(urlparse(iframe_url).path or "/")
                elif iframe_url.startswith("/"):
                    new_routes.add(iframe_url)
        except Exception as e:
            logger.debug("Iframe extraction error %s: %s", source_url, e)

        # Inline scripts — extract content directly from DOM (no HTTP fetch needed).
        # Must run in the Playwright thread; _collect_inline_scripts registers
        # JSFile objects immediately using hash dedup so duplicates across pages
        # are automatically skipped.
        try:
            self._collect_inline_scripts(page, source_url)
        except Exception as e:
            logger.debug("Inline script capture error %s: %s", source_url, e)

        # DOM scrape fallback — collect <script src> URLs in Playwright thread,
        # fetch the actual JS files off-thread (catches cache hits the response
        # handler missed).
        try:
            _dom_script_urls = self._collect_dom_script_urls(page)
            if _dom_script_urls:
                import threading as _t
                _t.Thread(
                    target=self._fetch_dom_scripts,
                    args=(_dom_script_urls, source_url),
                    daemon=True,
                ).start()
        except Exception as e:
            logger.debug("DOM scrape error %s: %s", source_url, e)

        # ES module entry points — collect <script type="module" src> URLs
        # in the Playwright thread, then fetch + recurse off-thread (item 8).
        try:
            _module_urls = self._collect_module_script_urls(page)
            if _module_urls:
                import threading as _t
                for _murl in _module_urls:
                    _t.Thread(
                        target=self._fetch_es_module,
                        args=(_murl, source_url, 0),
                        daemon=True,
                    ).start()
        except Exception as e:
            logger.debug("ES module collection error %s: %s", source_url, e)

        # Reset interceptor buffers for next page
        try:
            page.evaluate("""
                window.__bundlespy_requests   = [];
                window.__bundlespy_ws         = [];
                window.__bundlespy_ws_messages = [];
                window.__bundlespy_workers    = [];
                window.__bundlespy_sw         = [];
                window.__bundlespy_iframes    = [];
                window.__bspy_mutations       = 0;
                window.__bspy_requests        = 0;
                window.__bspy_last_active     = Date.now();
            """)
        except Exception:
            pass

        return new_routes

    def run(self) -> dict:
        if not _playwright_available():
            logger.warning("Playwright not installed.")
            return {"js_files": [], "endpoints": [], "stats": {}, "timings": {}, "auth_result": None}

        from playwright.sync_api import sync_playwright

        logger.info("Starting headless engine: %s", self.target_url)
        self.timer.start("total")

        _seen_dom_states: Set[str] = set()

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
                    "--blink-settings=imagesEnabled=false",
                    "--disable-background-networking",
                    "--disable-sync",
                ],
            )
            self.timer.stop("browser_start")

            # ── Single context — created once, cookies injected once ──────────
            # Always set a realistic Chrome UA — Playwright's default headless
            # UA ("HeadlessChrome/...") is fingerprinted and blocked by most
            # WAFs and CDNs (Cloudflare, Akamai, Imperva all check this).
            _chrome_ua = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/146.0.0.0 Safari/537.36"
            )
            kwargs = dict(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                java_script_enabled=True,
                user_agent=_chrome_ua,
            )
            if self.stealth:
                # stealth mode: same UA (already set above) — additional
                # evasion comes from the --disable-blink-features flag above
                pass
            if self.extra_headers:
                kwargs["extra_http_headers"] = self.extra_headers

            ctx = browser.new_context(**kwargs)

            if self.cookies:
                try:
                    ctx.add_cookies(self.cookies)
                    logger.info("Injected %d cookies into browser context", len(self.cookies))
                except Exception as e:
                    logger.warning("Failed to inject cookies: %s", e)

            ctx.add_init_script(INTERCEPT_JS)

            # Central response handler on context — fires for every request
            # across all pages in this context. We use the request's frame URL
            # as the source_page so attribution is accurate (r.url is the asset
            # URL, not the page that loaded it — a common confusion).
            def _on_response(r):
                try:
                    # frame.url is the page that triggered this request
                    source = r.frame.url if r.frame else r.url
                except Exception:
                    source = r.url
                self._handle_response(r, source)

            ctx.on("response", _on_response)

            ctx.route(
                "**/*",
                lambda route: route.abort()
                if self._should_block(route.request.url, route.request.resource_type)
                else route.continue_()
            )

            # ── Single persistent page — reused across all navigation ─────────
            page = ctx.new_page()
            stabilizer = PageStabilizer(page)

            # ── Phase 1: Auth verification + root page ────────────────────────
            self.timer.start("phase1_root")

            if self.cookies or self.extra_headers:
                self.auth_result = self._verify_auth(page, self.target_url)
                logger.info(
                    "Auth: authenticated=%s final=%s status=%s",
                    self.auth_result["authenticated"],
                    self.auth_result["final_url"],
                    self.auth_result["status"],
                )
                # Extra stability wait after auth — SPAs may still be mounting
                # their router after the framework detect fires in _verify_auth
                stabilizer.wait_for_framework(max_ms=2000)
                self.registry.register_url(self.target_url)
                with self._lock:
                    self.pages_visited += 1
                fp = self._dom_fingerprint(page)
                if fp:
                    _seen_dom_states.add(fp)
                initial_routes = self._flush_page_intel(page, self.target_url)
            else:
                try:
                    page.goto(self.target_url, timeout=self.timeout * 1000,
                              wait_until="domcontentloaded")
                    with self._lock:
                        self.pages_visited += 1
                    stabilizer.wait_for_framework(max_ms=3000)
                except Exception as e:
                    logger.debug("Root page error: %s", e)
                self.registry.register_url(self.target_url)
                fp = self._dom_fingerprint(page)
                if fp:
                    _seen_dom_states.add(fp)
                initial_routes = self._flush_page_intel(page, self.target_url)

            for r in initial_routes:
                self._add_route(r)

            for seed_url in self.seed_urls:
                self._add_route(urlparse(seed_url).path or "/")

            if not self.routes:
                for probe in ["/#/", "/app", "/home"]:
                    probe_url = self.target_url.rstrip("/") + probe
                    try:
                        page.goto(probe_url, timeout=8000, wait_until="domcontentloaded")
                        stabilizer.wait(max_ms=2000)
                        for r in self._extract_routes(page):
                            self._add_route(r)
                        if self.routes:
                            break
                    except Exception:
                        pass

            self.timer.stop("phase1_root")
            logger.info("Phase 1 done: %d routes", len(self.routes))

            # ── Phase 2: BFS route exploration ────────────────────────────────
            # Bug 19 fix: use a real BFS deque so routes discovered during the
            # loop are fed back into the queue immediately and visited in the
            # same run. The old code collected new_routes_found and only added
            # them after the loop ended — they were never visited.
            self.timer.start("phase2_routes")

            initial_urls = self._build_urls(self.routes)
            # Bug 11 fix: _build_urls already sorts by priority; don't sort again.
            bfs_queue: deque = deque(initial_urls)
            login_loop_count = 0

            while bfs_queue:
                if self.pages_visited >= self.max_pages:
                    break

                url = bfs_queue.popleft()

                if not self.registry.register_url(url):
                    continue

                safe, _ = validate_url(url)
                if not safe or not self.scope.in_scope(url):
                    continue

                try:
                    # Drift guard: recover if a previous page's JS moved the
                    # browser to an unexpected origin before we navigate here.
                    self._recover_drift(page, self.target_url, stabilizer)

                    page.goto(url, timeout=self.timeout * 1000, wait_until="domcontentloaded")
                    with self._lock:
                        self.pages_visited += 1

                    # Session state check — detect silent mid-crawl session loss.
                    # If we have credentials but land on a login page for a non-login
                    # URL, the session was lost (expired cookie, server logout event).
                    if _is_login_page(page) and not _is_login_url(url):
                        login_loop_count += 1
                        if login_loop_count >= 2:
                            logger.warning(
                                "Session lost mid-crawl after %d consecutive login "
                                "redirects — stopping route exploration to avoid "
                                "silent unauthenticated crawl",
                                login_loop_count,
                            )
                            # Update auth_result so callers know the session dropped
                            if self.auth_result is not None:
                                self.auth_result["authenticated"] = False
                                self.auth_result["reason"] = (
                                    "Session lost mid-crawl — "
                                    "server invalidated the session after login"
                                )
                            break
                        continue
                    else:
                        login_loop_count = 0  # reset on successful non-login page

                    # DOM state dedup — skip identical states
                    stabilizer.wait_for_framework(max_ms=2000)
                    fp = self._dom_fingerprint(page)
                    if fp and fp in _seen_dom_states:
                        logger.debug("Duplicate DOM state, skipping: %s", url)
                        continue
                    if fp:
                        _seen_dom_states.add(fp)

                    if self.interact:
                        self._interact(page, stabilizer)
                        self._observe_forms(page, stabilizer)

                    new_routes = self._flush_page_intel(page, url)

                    # Feed newly discovered routes straight back into the BFS
                    # queue so they're visited this run, not a future run.
                    new_urls = self._build_urls(new_routes)
                    for new_url in new_urls:
                        if not self.registry.seen_url(new_url):
                            self._add_route(urlparse(new_url).path or "/")
                            bfs_queue.append(new_url)

                except Exception as e:
                    logger.debug("Error visiting %s: %s", url, e)

            self.timer.stop("phase2_routes")

            try:
                ctx.close()
            except Exception:
                pass
            browser.close()

        # ── Phase 3: Build endpoints ──────────────────────────────────────────
        self.timer.start("endpoint_build")
        self.endpoints = self._api_calls_to_endpoints()
        self.timer.stop("endpoint_build")
        self.timer.stop("total")

        timings = self.timer.summary()
        workers_found = [js for js in self.js_files if js.technology == "webworker"]

        sw_found      = [js for js in self.js_files if js.technology in ("service-worker", "service-worker-import")]
        es_mod_found  = [js for js in self.js_files if js.technology in ("es-module",)]
        shadow_found  = [js for js in self.js_files if "shadow-dom" in (js.technology or "")]

        stats = {
            "pages":      self.pages_visited,
            "js":         len(self.js_files),
            "xhr":        sum(1 for c in self.api_calls if c.get("type") == "xhr"),
            "fetch":      sum(1 for c in self.api_calls if c.get("type") == "fetch"),
            "ws":         len(self.ws_urls),
            "ws_messages":len(self.ws_messages),
            "routes":     len(self.routes),
            "endpoints":  len(self.endpoints),
            "workers":    len(workers_found),
            "sw":         len(sw_found),
            "es_modules": len(es_mod_found),
            "shadow_dom": len(shadow_found),
            "timings":    timings,
        }

        logger.info(
            "Headless done: %d pages, %d JS, %d routes, %.1fs total",
            self.pages_visited, len(self.js_files),
            len(self.routes), timings.get("total", 0),
        )
        return {
            "js_files":    self.js_files,
            "endpoints":   self.endpoints,
            "routes":      list(self.routes),
            "api_calls":   self.api_calls,
            "ws_messages": self.ws_messages,
            "stats":       stats,
            "timings":     timings,
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
