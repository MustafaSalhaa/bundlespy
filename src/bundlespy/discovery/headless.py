"""
BundleSpy Advanced Headless Engine — optimized for speed and coverage.

Optimization principles:
- Adaptive waits instead of fixed sleeps
- CDP-level network idle + JS in-flight counter (two-phase stability)
- Action-based crawl queue — models state transitions, not just URLs
- Concurrent page processing with worker pool
- Event-driven pipeline — react to actual activity
- Central deduplication registry — never analyze same asset twice
- Structural DOM simhash — skips layout-identical SPA pages
- Priority queue — high-value routes first
- Resource blocking — skip images/fonts/ads, keep JS/XHR/WS
- Logout guard — href + text detection in 10 languages
- Browser drift detection + auto-recovery
- Session state verification with mid-crawl loss detection
- Phase timing metrics
- Recorded auth flow replay (multi-step SSO/MFA)
- Auto-login fallback when recorded flow fails
- Typed error classification for click failures
- Hooks system for lifecycle callbacks
- Terminal visible assertion in auth verification
- ScrollIntoView before all clicks
- loggedIn state tracking
- CrawlGraph DOT file export
- PageLoadStrategy passthrough
- Sub-page (popup/new-tab) detection
- Response body URL extraction — parse every HTTP response for embedded URLs
  (HTML attrs, JS fetch/axios calls, JSON endpoint fields, CSS url(), sourcemaps)
- Cookie jar pre-loading — load Netscape-format cookie files (Burp Suite export)
  and inject into browser context before crawl starts
- URL structural deduplication (PathTrie) — collapse /item/1 /item/2 /item/3
  into /item/* so parameterized routes don't get crawled N times
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
from .form_interactor import FormInteractor

logger = logging.getLogger("bundlespy.discovery.headless")


# ── Typed crawl actions — models page state transitions ──────────────────────

from enum import Enum

class ActionType(Enum):
    LOAD_URL   = "load_url"
    FILL_FORM  = "fill_form"
    LEFT_CLICK = "left_click"

@dataclass
class CrawlAction:
    """
    A typed crawl action — models a state transition, not just a URL visit.
    Inspired by Katana's action-based crawl graph.

    origin_id: SHA-256 prefix of the DOM fingerprint of the page state from
    which this action was discovered.  Before executing the action the engine
    checks that the browser is still on that state; if not it navigates back
    (navigateBackToStateOrigin pattern from Katana's crawler.go).
    """
    action_type: ActionType
    url:         str
    selector:    str  = ""   # CSS selector for FillForm / LeftClick targets
    depth:       int  = 0
    parent_url:  str  = ""
    origin_id:   str  = ""   # DOM-state hash at discovery time (OriginID)

    def key(self) -> str:
        """Deduplication key — same action on same element = same key."""
        return hashlib.sha256(
            f"{self.action_type.value}:{self.url}:{self.selector}".encode()
        ).hexdigest()[:16]



# ── CrawlGraph — DAG of page states and action edges ─────────────────────────

@dataclass
class _PageState:
    """A single node in the crawl DAG — one unique DOM state."""
    state_id:   str        # DOM fingerprint hash (origin_id)
    url:        str
    depth:      int        = 0
    discovered: float      = field(default_factory=time.time)


class CrawlGraph:
    """
    Directed Acyclic Graph of page states and the action edges that connect them.
    Mirrors Katana's CrawlGraph (crawler.go).

    Nodes = page states (keyed by DOM fingerprint / origin_id).
    Edges = CrawlActions that transition between states.

    Thread-safe for concurrent readers.  Mutations go through add_page_state()
    and add_edge() which hold the internal lock.
    """

    def __init__(self) -> None:
        self._lock:  threading.Lock       = threading.Lock()
        self._nodes: Dict[str, _PageState] = {}   # origin_id -> PageState
        self._edges: List[CrawlAction]     = []   # all action edges

    def add_page_state(self, state_id: str, url: str, depth: int = 0) -> bool:
        """Register a page state. Returns True if newly added, False if seen."""
        with self._lock:
            if state_id in self._nodes:
                return False
            self._nodes[state_id] = _PageState(
                state_id=state_id, url=url, depth=depth
            )
        return True

    def add_edge(self, action: CrawlAction) -> None:
        """Record a CrawlAction as a directed edge in the graph."""
        with self._lock:
            self._edges.append(action)

    def nodes(self) -> List[_PageState]:
        with self._lock:
            return list(self._nodes.values())

    def edges(self) -> List[CrawlAction]:
        with self._lock:
            return list(self._edges)

    def summary(self) -> dict:
        with self._lock:
            return {
                "nodes":       len(self._nodes),
                "edges":       len(self._edges),
                "fill_forms":  sum(1 for e in self._edges if e.action_type == ActionType.FILL_FORM),
                "left_clicks": sum(1 for e in self._edges if e.action_type == ActionType.LEFT_CLICK),
                "load_urls":   sum(1 for e in self._edges if e.action_type == ActionType.LOAD_URL),
            }

    def draw_dot(self, path: str) -> None:
        """Export the crawl graph as a Graphviz .dot file.
        Nodes = page states (labeled with truncated URL + state_id).
        Edges = typed crawl actions (LOAD_URL / FILL_FORM / LEFT_CLICK).
        Called automatically when enable_diagnostics=True at end of run().
        (Enhancement 8 — CrawlGraph DOT file export)"""
        with self._lock:
            lines = [
                "digraph CrawlGraph {",
                '  rankdir=LR;',
                '  node [shape=box fontname="monospace" fontsize=10];',
                '  edge [fontname="monospace" fontsize=9];',
            ]
            for sid, state in self._nodes.items():
                # Truncate URL for readability; escape quotes/backslashes
                short_url = state.url[:60].replace('"', '\\"').replace("\\", "\\\\")
                label = f"{short_url}\\n[{sid[:8]}]"
                lines.append(f'  "{sid}" [label="{label}"];')
            for edge in self._edges:
                src = edge.origin_id[:16] if edge.origin_id else "start"
                dst = edge.key()
                lbl = edge.action_type.value
                if edge.selector:
                    # include first 30 chars of selector for readability
                    sel = edge.selector[:30].replace('"', '\\"')
                    lbl = f"{lbl}\\n{sel}"
                lines.append(f'  "{src}" -> "{dst}" [label="{lbl}"];')
            lines.append("}")
        dot_content = "\n".join(lines)
        try:
            import os as _os
            _os.makedirs(_os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(dot_content)
            logger.info("CrawlGraph DOT exported: %s (%d nodes, %d edges)",
                        path, len(self._nodes), len(self._edges))
        except Exception as e:
            logger.warning("CrawlGraph DOT export failed: %s", e)


# ── DiagnosticsWriter — optional per-action screenshot + action log ───────────

import os as _os
import tempfile as _tempfile

class DiagnosticsWriter:
    """
    When enable_diagnostics=True is passed to HeadlessEngine, this writer
    captures a screenshot + metadata entry for every action executed.

    All output goes to a temp directory under /tmp (or the system tmp) that
    is printed to the log at startup.  Screenshots are written as PNG files
    named by action index.  A JSON-lines action log is also written.

    Mirrors Katana's DiagnosticsWriter pattern.
    """

    def __init__(self, label: str = "bundlespy") -> None:
        self.dir = _tempfile.mkdtemp(prefix=f"bundlespy_diag_{label}_")
        self._log_path = _os.path.join(self.dir, "actions.jsonl")
        self._idx = 0
        self._lock = threading.Lock()
        logger.info("DiagnosticsWriter: output dir = %s", self.dir)

    def record(self, page, action: CrawlAction, note: str = "") -> None:
        """Capture a screenshot and write an action log entry."""
        with self._lock:
            idx = self._idx
            self._idx += 1

        # Screenshot
        try:
            ss_path = _os.path.join(self.dir, f"action_{idx:05d}.png")
            page.screenshot(path=ss_path, full_page=False)
        except Exception:
            ss_path = ""

        # Log entry
        entry = {
            "idx":         idx,
            "ts":          time.time(),
            "action_type": action.action_type.value,
            "url":         action.url,
            "selector":    action.selector,
            "origin_id":   action.origin_id,
            "note":        note,
            "screenshot":  ss_path,
        }
        try:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def close(self) -> None:
        """Flush and close the log."""
        logger.info("DiagnosticsWriter: closed — %d actions logged in %s",
                    self._idx, self.dir)


# ── Recorded auth flow types ──────────────────────────────────────────────────

@dataclass
class LoginStep:
    """
    One step in a recorded authentication flow.
    Mirrors Katana's auth.StepsFromFile / RecordedFlow replay.

    step_type values:
      "navigate"       — navigate the browser to `url`
      "fill"           — fill `selector` input with `value`
      "click"          — click element at `selector`
      "wait"           — pause for `timeout_ms` milliseconds
      "assert_visible" — verify `assertion_text` is visible on-screen
                          (terminal visible assertion — Enhancement 5)
    """
    step_type:      str
    selector:       str = ""          # CSS selector (fill / click / assert_visible)
    value:          str = ""          # Value to type (fill)
    url:            str = ""          # URL to navigate to (navigate)
    timeout_ms:     int = 2000        # Timeout / wait duration in ms
    assertion_text: str = ""          # Text that must be visible to confirm login


@dataclass
class CrawlHooks:
    """
    Lifecycle callback hooks injected into HeadlessEngine.
    All callbacks receive the Playwright `page` object (and the action where
    relevant) and are called synchronously in the Playwright thread.
    None = no-op for that hook.

    Mirrors Katana's Hooks interface.
    (Enhancement 4 — Hooks system)
    """
    before_action:       Optional[callable] = None  # (page, action: CrawlAction) -> None
    after_action:        Optional[callable] = None  # (page, action: CrawlAction) -> None
    on_navigation:       Optional[callable] = None  # (url: str) -> None
    on_login_detected:   Optional[callable] = None  # (page) -> None
    on_captcha_detected: Optional[callable] = None  # (page) -> None


# ── Typed click error classes — precise failure recovery ──────────────────────

class ElementCoveredError(Exception):
    """Element exists and is visible but a foreground overlay intercepts the
    hit-test at the element's center point. Recovery: dismiss consent banner /
    modal and retry. (Enhancement 3 — typed click errors)"""

class ElementInvisibleError(Exception):
    """Element was found in the DOM but is not visible (display:none,
    visibility:hidden, opacity:0, zero-size bounding box). Recovery: skip.
    (Enhancement 3 — typed click errors)"""

class ElementNoPointerEventsError(Exception):
    """Element has pointer-events:none set, so no click will ever reach it.
    Recovery: try JavaScript click() fallback or skip.
    (Enhancement 3 — typed click errors)"""


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


# ── Cookie consent bypass selectors ──────────────────────────────────────────
# Ordered roughly by effectiveness across EU/global GDPR banner frameworks.
# We try each selector in order and click the first visible match.
CONSENT_SELECTORS = [
    # Common Accept / Allow buttons
    'button[id*="accept"]',
    'button[id*="agree"]',
    'button[id*="allow"]',
    'button[class*="accept"]',
    'button[class*="agree"]',
    'button[class*="allow"]',
    # aria-label variants
    'button[aria-label*="Accept"]',
    'button[aria-label*="Agree"]',
    'button[aria-label*="Allow"]',
    # data-* attributes (OneTrust, Cookiebot, etc.)
    'button[data-testid*="accept"]',
    '#onetrust-accept-btn-handler',
    '#CybotCookiebotDialogBodyButtonAccept',
    '#cookie-accept',
    '#cookies-accept',
    '#accept-cookies',
    '#accept_cookies',
    '.cookie-accept',
    '.js-cookie-accept',
    '[data-action="accept-cookies"]',
    '[data-accept-cookies]',
    # Generic text-based match — last resort
    'button:has-text("Accept")',
    'button:has-text("Accept all")',
    'button:has-text("Accept All")',
    'button:has-text("Allow all")',
    'button:has-text("I agree")',
    'button:has-text("Agree")',
    'button:has-text("I Accept")',
    'button:has-text("Got it")',
    'button:has-text("OK")',
    'a:has-text("Accept")',
    'a:has-text("I agree")',
]

# ── Captcha page indicators ───────────────────────────────────────────────────
# Detects both embedded captcha widgets and full captcha challenge pages.
_CAPTCHA_SELECTORS = [
    # reCAPTCHA v2/v3
    '.g-recaptcha',
    'iframe[src*="recaptcha"]',
    'iframe[src*="google.com/recaptcha"]',
    # hCaptcha
    '.h-captcha',
    'iframe[src*="hcaptcha.com"]',
    # Cloudflare Turnstile / IUAM
    '.cf-turnstile',
    'iframe[src*="challenges.cloudflare.com"]',
    'div#cf-please-wait',
    'div.cf-challenge-running',
    # FunCaptcha / Arkose Labs
    'iframe[src*="arkoselabs.com"]',
    'iframe[src*="funcaptcha.com"]',
    # Generic
    '[class*="captcha"]',
    '[id*="captcha"]',
]

_CAPTCHA_TEXT_MARKERS = (
    "complete the captcha",
    "verify you are human",
    "i'm not a robot",
    "human verification",
    "bot detection",
    "security check",
    "prove you're human",
    "ddos protection by cloudflare",
    "checking your browser",
)

# ── DIT-style login form heuristics (enhanced) ───────────────────────────────
# Katana uses a DIT classifier for login form detection that handles obfuscated
# field names and React-rendered forms where field names are hashed or minified.
# These patterns capture field name variants used by common obfuscated forms.

_DIT_PASSWORD_NAMES = re.compile(
    r"(pass(w(or)?d?)?|psw|pwd|secret|credential|cred|pin|token"
    r"|auth[_-]?key|private[_-]?key|api[_-]?key|access[_-]?token"
    r"|session[_-]?key|security[_-]?code|otp|mfa[_-]?code|totp)",
    re.IGNORECASE,
)

_DIT_USERNAME_NAMES = re.compile(
    r"(user(name|id)?|u[_-]?name|login|email|e[_-]?mail|account"
    r"|ident(ifier)?|nick(name)?|handle|logon|signin|member[_-]?id"
    r"|customer[_-]?id|employee[_-]?id|uid|userid|member)",
    re.IGNORECASE,
)


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
window.__bspy_mutations     = 0;
window.__bspy_requests      = 0;
window.__bspy_inflight      = 0;
window.__bspy_last_active   = Date.now();

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

// Note: fetch and XHR are already hooked in INTERCEPT_JS above.
// Stability counters are incremented inside those hooks via
// window.__bspy_inflight_inc / __bspy_inflight_dec helpers below.
window.__bspy_inflight_inc = function() {
    window.__bspy_requests++;
    window.__bspy_inflight++;
    window.__bspy_last_active = Date.now();
};
window.__bspy_inflight_dec = function() {
    window.__bspy_inflight = Math.max(0, window.__bspy_inflight - 1);
    window.__bspy_last_active = Date.now();
};

window.__bspy_stable = function(quietMs) {
    return window.__bspy_inflight === 0 &&
           (Date.now() - window.__bspy_last_active) >= quietMs;
};
window.__bspy_inflight_count = function() {
    return window.__bspy_inflight;
};
"""


# ── Main intercept JS ─────────────────────────────────────────────────────────

INTERCEPT_JS = """
(function() {

// ── Storage arrays ────────────────────────────────────────────────────────────
window.__bundlespy_requests    = [];
window.__bundlespy_ws          = [];
window.__bundlespy_ws_messages = [];
window.__bundlespy_workers     = [];
window.__bundlespy_sw          = [];
window.__bundlespy_iframes     = [];
window.__bundlespy_sse         = [];   // EventSource endpoints
window.__bundlespy_nav         = [];   // history.pushState / replaceState URLs
window.__bundlespy_listeners   = [];   // dynamically registered event listeners

// ── CSS selector helpers ──────────────────────────────────────────────────────

// Returns true if c is valid unescaped in a CSS identifier
function __bspyIsCSSIdentChar(c) {
    if (/[a-zA-Z0-9_-]/.test(c)) return true;
    return c.charCodeAt(0) >= 0xa0;
}
function __bspyIsCSSIdent(v) {
    return /^-{0,2}[a-zA-Z_][a-zA-Z0-9_-]*$/.test(v);
}
function __bspyEscAscii(c, isLast) {
    return '\\\\' + c.charCodeAt(0).toString(16).padStart(2, '0') + (isLast ? '' : ' ');
}
function __bspyEscIdent(ident) {
    if (__bspyIsCSSIdent(ident)) return ident;
    var shouldEscFirst = /^(?:[0-9]|-[0-9-]?)/.test(ident);
    var last = ident.length - 1;
    return ident.replace(/./g, function(c, i) {
        return (shouldEscFirst && i === 0) || !__bspyIsCSSIdentChar(c)
            ? __bspyEscAscii(c, i === last) : c;
    });
}
function __bspyPrefixedClasses(node) {
    var cls = node.getAttribute('class');
    if (!cls) return [];
    return cls.split(/\\s+/g).filter(Boolean).map(function(n) { return '$' + n; });
}

// Build a stable CSS selector - Chrome DevTools algorithm
function __bspyCssPath(node) {
    try {
        if (!node || node.nodeType !== 1) return '';
        var steps = [];
        var cur   = node;
        while (cur) {
            var id = cur.getAttribute && cur.getAttribute('id');
            if (id) {
                steps.push(cur.nodeName + '#' + __bspyEscIdent(id));
                break;
            }
            var nodeName = cur.nodeName;
            var parent   = cur.parentNode;
            if (!parent || parent.nodeType === 9) {
                steps.push(nodeName);
                break;
            }
            var siblings = parent.children;
            var prefixedOwn = __bspyPrefixedClasses(cur);
            var needsClass  = false;
            var needsNth    = false;
            var ownIdx      = -1;
            var elIdx       = -1;
            for (var i = 0; (ownIdx === -1 || !needsNth) && i < siblings.length; i++) {
                var sib = siblings[i];
                if (sib.nodeType !== 1) continue;
                elIdx++;
                if (sib === cur) { ownIdx = elIdx; continue; }
                if (needsNth) continue;
                if (sib.nodeName.toLowerCase() !== nodeName.toLowerCase()) continue;
                needsClass = true;
                var ownSet = new Set(prefixedOwn);
                if (!ownSet.size) { needsNth = true; continue; }
                var sibCls = __bspyPrefixedClasses(sib);
                for (var j = 0; j < sibCls.length; j++) {
                    if (!ownSet.has(sibCls[j])) continue;
                    ownSet.delete(sibCls[j]);
                    if (!ownSet.size) { needsNth = true; break; }
                }
            }
            var result = nodeName;
            // For input elements, include type when there's no id/class to differentiate
            if (cur === node && nodeName.toLowerCase() === 'input' &&
                cur.getAttribute('type') && !cur.getAttribute('id') && !cur.getAttribute('class')) {
                result += '[type="' + cur.getAttribute('type') + '"]';
            }
            if (needsNth) {
                result += ':nth-child(' + (ownIdx + 1) + ')';
            } else if (needsClass) {
                for (var k = 0; k < prefixedOwn.length; k++) {
                    result += '.' + __bspyEscIdent(prefixedOwn[k].substr(1));
                }
            }
            steps.push(result);
            cur = parent;
        }
        steps.reverse();
        return steps.join(' > ');
    } catch(e) { return ''; }
}

// ── XPath helper ──────────────────────────────────────────────────────────────

function __bspyXPathIndex(node) {
    function similar(a, b) {
        if (a === b) return true;
        if (a.nodeType === 1 && b.nodeType === 1) return a.localName === b.localName;
        if (a.nodeType === b.nodeType) return true;
        var at = a.nodeType === 4 ? 3 : a.nodeType;
        var bt = b.nodeType === 4 ? 3 : b.nodeType;
        return at === bt;
    }
    var siblings = node.parentNode ? node.parentNode.childNodes : null;
    if (!siblings) return 0;
    var hasSame = false;
    for (var i = 0; i < siblings.length; i++) {
        if (similar(node, siblings[i]) && siblings[i] !== node) { hasSame = true; break; }
    }
    if (!hasSame) return 0;
    var own = 1;
    for (var j = 0; j < siblings.length; j++) {
        if (similar(node, siblings[j])) {
            if (siblings[j] === node) return own;
            own++;
        }
    }
    return -1;
}

// Build an XPath for any element
function __bspyXPath(node) {
    try {
        if (!node) return '';
        if (node.nodeType === 9) return '/';
        var steps = [];
        var cur   = node;
        while (cur) {
            if (cur.nodeType === 9) { steps.push(''); break; }
            if (cur.nodeType !== 1) { cur = cur.parentNode; continue; }
            var attrId = cur.getAttribute && cur.getAttribute('id');
            if (attrId) {
                // id is unique - short-circuit with absolute path and stop walking
                steps = ['//*[@id="' + attrId + '"]'];
                break;
            }
            var idx = __bspyXPathIndex(cur);
            if (idx === -1) break;
            var tag = (cur.localName || cur.nodeName || '').toLowerCase();
            var val = tag;
            if (idx > 0) val += '[' + idx + ']';
            steps.push(val);
            cur = cur.parentNode;
        }
        steps.reverse();
        // if steps[0] is already an absolute //*[@id=...] path, return it directly
        if (steps.length === 1 && steps[0].startsWith('//*')) return steps[0];
        return '/' + steps.filter(Boolean).join('/');
    } catch(e) { return ''; }
}

// ── addEventListener hook - captures all JS-registered event listeners ────────
// Tags that cover the whole page are too broad to be useful click targets
var _BSPY_SKIP_TAGS = new Set(['HTML','HEAD','BODY','SCRIPT','STYLE','META','LINK','NOSCRIPT']);
var _BSPY_CLICK_TYPES = new Set(['click','mousedown','mouseup','touchstart','touchend','pointerdown','pointerup','keydown','keyup','keypress','change','submit','input']);
var _origAEL = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, listener, options) {
    try {
        if (
            this instanceof Element &&
            this.tagName &&
            !_BSPY_SKIP_TAGS.has(this.tagName) &&
            _BSPY_CLICK_TYPES.has(type) &&
            window.__bundlespy_listeners.length < 500
        ) {
            var el = this;
            var txt = '';
            try { txt = (el.textContent || '').replace(/\\s+/g,' ').trim().substring(0, 120); } catch(e2) {}
            var rec = {
                tagName:     el.tagName,
                id:          el.id || '',
                classes:     el.className || '',
                textContent: txt,
                type:        el.type   || '',
                name:        el.name   || '',
                hidden:      el.hidden || false,
                eventType:   type,
                cssSelector: __bspyCssPath(el),
                xpath:       __bspyXPath(el),
            };
            window.__bundlespy_listeners.push(rec);
        }
    } catch(e) {}
    return _origAEL.call(this, type, listener, options);
};

// ── Inline on* handler scan - captures onclick/onchange/etc attributes ────────
// Runs once at inject time to snapshot elements that have inline handlers
// but won't trigger addEventListener (e.g. <div onclick="...">)
(function() {
    try {
        var _ON_EVENTS = ['onclick','onchange','onsubmit','oninput','onmousedown','onkeydown','onkeypress','onpointerdown','ontouchstart'];
        document.querySelectorAll('*').forEach(function(el) {
            if (!el || !el.tagName) return;
            if (_BSPY_SKIP_TAGS.has(el.tagName)) return;
            if (window.__bundlespy_listeners.length >= 500) return;
            for (var ei = 0; ei < _ON_EVENTS.length; ei++) {
                var evName = _ON_EVENTS[ei];
                var handler = el[evName] || el.getAttribute(evName);
                if (!handler) continue;
                var txt = '';
                try { txt = (el.textContent || '').replace(/\\s+/g,' ').trim().substring(0, 120); } catch(e2) {}
                window.__bundlespy_listeners.push({
                    tagName:     el.tagName,
                    id:          el.id || '',
                    classes:     el.className || '',
                    textContent: txt,
                    type:        el.type || '',
                    name:        el.name || '',
                    hidden:      el.hidden || false,
                    eventType:   evName.replace('on', ''),
                    cssSelector: __bspyCssPath(el),
                    xpath:       __bspyXPath(el),
                    source:      'inline',
                });
                break; // one entry per element is enough
            }
        });
    } catch(e) {}
})();

// ── history API hook - captures SPA client-side route transitions ─────────────
(function() {
    var _origPush    = history.pushState.bind(history);
    var _origReplace = history.replaceState.bind(history);
    function _wrapPush(state, title, url) {
        try { if (url) window.__bundlespy_nav.push({url: String(url), source: 'pushState'}); } catch(e) {}
        return _origPush(state, title, url);
    }
    function _wrapReplace(state, title, url) {
        try { if (url) window.__bundlespy_nav.push({url: String(url), source: 'replaceState'}); } catch(e) {}
        return _origReplace(state, title, url);
    }
    try {
        Object.defineProperty(history, 'pushState',    {value: _wrapPush,    writable: false, configurable: false});
        Object.defineProperty(history, 'replaceState', {value: _wrapReplace, writable: false, configurable: false});
    } catch(e) {}
    window.addEventListener('hashchange', function() {
        try { window.__bundlespy_nav.push({url: String(document.location.href), source: 'hashchange'}); } catch(e) {}
    });
})();

// ── Timer speedup - run setTimeout/setInterval 10x faster ────────────────────
// Accelerates deferred content and lazy API calls during crawl
(function() {
    var _origST  = window.setTimeout;
    var _origSI  = window.setInterval;
    var _FACTOR  = 0.1;
    function _wrapST(fn, delay) {
        var rest = Array.prototype.slice.call(arguments, 2);
        return _origST.apply(window, [fn, (delay || 0) * _FACTOR].concat(rest));
    }
    function _wrapSI(fn, delay) {
        var rest = Array.prototype.slice.call(arguments, 2);
        return _origSI.apply(window, [fn, (delay || 0) * _FACTOR].concat(rest));
    }
    try {
        Object.defineProperty(window, 'setTimeout',  {value: _wrapST, writable: false, configurable: false});
        Object.defineProperty(window, 'setInterval', {value: _wrapSI, writable: false, configurable: false});
    } catch(e) {}
})();

// ── window.close prevention - stops page context from being killed ────────────
try {
    Object.defineProperty(window, 'close', {
        value: function() {},
        writable: false, configurable: false
    });
} catch(e) {}

// ── Form reset prevention - stops JS from wiping filled fields ────────────────
(function() {
    var _origReset = HTMLFormElement.prototype.reset;
    Object.defineProperty(HTMLFormElement.prototype, 'reset', {
        value: function() {
            // Allow reset only if the crawl hasn't started filling forms yet
            if (window.__bundlespy_prevent_reset === true) return;
            return _origReset.apply(this, arguments);
        },
        writable: false, configurable: false
    });
})();

// ── Fetch interception - tamper-resistant, also drives stability counters ──────
(function() {
    var _origFetch = window.fetch;
    function _wrappedFetch() {
        try {
            var arg0 = arguments[0];
            var opts = arguments[1] || {};
            var url  = typeof arg0 === 'string' ? arg0 : (arg0 && arg0.url) ? arg0.url : null;
            if (url) window.__bundlespy_requests.push({
                url:    url,
                method: (opts.method || 'GET').toUpperCase(),
                body:   typeof opts.body === 'string' ? opts.body.substring(0, 500) : null,
                type:   'fetch',
            });
        } catch(e) {}
        // Stability tracking - increment before call, decrement on settle
        try { window.__bspy_requests++; window.__bspy_inflight++; window.__bspy_last_active = Date.now(); } catch(e) {}
        var p = _origFetch.apply(this, arguments);
        p.then(function() {
            try { window.__bspy_inflight = Math.max(0, window.__bspy_inflight - 1); window.__bspy_last_active = Date.now(); } catch(e) {}
        }).catch(function() {
            try { window.__bspy_inflight = Math.max(0, window.__bspy_inflight - 1); } catch(e) {}
        });
        return p;
    }
    try {
        Object.defineProperty(window, 'fetch', {value: _wrappedFetch, writable: false, configurable: false});
    } catch(e) {}
})();

// ── XHR interception - also drives stability counters ─────────────────────────
(function() {
    var _origXHR  = window.XMLHttpRequest;
    var _origOpen = _origXHR.prototype.open;
    var _origSend = _origXHR.prototype.send;
    _origXHR.prototype.open = function(method, url) {
        try {
            if (url) window.__bundlespy_requests.push({
                url:    String(url),
                method: String(method).toUpperCase(),
                type:   'xhr',
            });
        } catch(e) {}
        return _origOpen.apply(this, arguments);
    };
    _origXHR.prototype.send = function() {
        try { window.__bspy_requests++; window.__bspy_inflight++; window.__bspy_last_active = Date.now(); } catch(e) {}
        this.addEventListener('loadend', function() {
            try { window.__bspy_inflight = Math.max(0, window.__bspy_inflight - 1); window.__bspy_last_active = Date.now(); } catch(e) {}
        });
        return _origSend.apply(this, arguments);
    };
})();

// ── WebSocket - capture URL and message payloads ──────────────────────────────
(function() {
    var _origWS = window.WebSocket;
    if (!_origWS) return;
    function _wrappedWS(url, protocols) {
        var wsUrl = String(url);
        try { window.__bundlespy_ws.push({url: wsUrl}); } catch(e) {}
        var ws = protocols !== undefined
            ? Reflect.construct(_origWS, [url, protocols], new.target || _wrappedWS)
            : Reflect.construct(_origWS, [url], new.target || _wrappedWS);
        // Outbound
        var _origSend = ws.send.bind(ws);
        ws.send = function(data) {
            try {
                var d = typeof data === 'string' ? data.substring(0, 1000) : '[binary]';
                window.__bundlespy_ws_messages.push({url: wsUrl, data: d, dir: 'send'});
            } catch(e2) {}
            return _origSend(data);
        };
        // Inbound
        _origAEL.call(ws, 'message', function(e) {
            try {
                var d = typeof e.data === 'string' ? e.data.substring(0, 1000) : '[binary]';
                window.__bundlespy_ws_messages.push({url: wsUrl, data: d, dir: 'recv'});
            } catch(e2) {}
        });
        return ws;
    }
    _wrappedWS.prototype = _origWS.prototype;
    Object.setPrototypeOf(_wrappedWS, _origWS);
    try {
        Object.defineProperty(window, 'WebSocket', {value: _wrappedWS, writable: false, configurable: false});
    } catch(e) { window.WebSocket = _wrappedWS; }
})();

// ── EventSource (SSE) - capture endpoint URLs ─────────────────────────────────
(function() {
    var _origES = window.EventSource;
    if (!_origES) return;
    function _wrappedES(url, init) {
        try { window.__bundlespy_sse.push({url: String(url)}); } catch(e) {}
        return init !== undefined
            ? Reflect.construct(_origES, [url, init], new.target || _wrappedES)
            : Reflect.construct(_origES, [url], new.target || _wrappedES);
    }
    _wrappedES.prototype = _origES.prototype;
    Object.setPrototypeOf(_wrappedES, _origES);
    try {
        Object.defineProperty(window, 'EventSource', {value: _wrappedES, writable: false, configurable: false});
    } catch(e) { window.EventSource = _wrappedES; }
})();

// ── Service Worker registration ───────────────────────────────────────────────
if (navigator.serviceWorker) {
    try {
        var _origSwReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
        navigator.serviceWorker.register = function(scriptURL, opts) {
            try { window.__bundlespy_sw.push({url: String(scriptURL)}); } catch(e) {}
            return _origSwReg(scriptURL, opts);
        };
    } catch(e) {}
}

// ── WebWorker / SharedWorker ──────────────────────────────────────────────────
(function() {
    var _origWorker = window.Worker;
    if (_origWorker) {
        function _wrappedWorker(url) {
            var rest = Array.prototype.slice.call(arguments, 1);
            try { window.__bundlespy_workers.push({url: String(url)}); } catch(e) {}
            return Reflect.construct(_origWorker, [url].concat(rest), new.target || _wrappedWorker);
        }
        _wrappedWorker.prototype = _origWorker.prototype;
        Object.setPrototypeOf(_wrappedWorker, _origWorker);
        try {
            Object.defineProperty(window, 'Worker', {value: _wrappedWorker, writable: false, configurable: false});
        } catch(e) { window.Worker = _wrappedWorker; }
    }
    var _origShared = window.SharedWorker;
    if (_origShared) {
        function _wrappedShared(url) {
            var rest = Array.prototype.slice.call(arguments, 1);
            try { window.__bundlespy_workers.push({url: String(url), shared: true}); } catch(e) {}
            return Reflect.construct(_origShared, [url].concat(rest), new.target || _wrappedShared);
        }
        _wrappedShared.prototype = _origShared.prototype;
        Object.setPrototypeOf(_wrappedShared, _origShared);
        try {
            Object.defineProperty(window, 'SharedWorker', {value: _wrappedShared, writable: false, configurable: false});
        } catch(e) { window.SharedWorker = _wrappedShared; }
    }
})();

// ── Dynamic iframe src tracking ───────────────────────────────────────────────
(function() {
    var _origCE = document.createElement.bind(document);
    document.createElement = function(tag) {
        var rest = Array.prototype.slice.call(arguments, 1);
        var el   = _origCE.apply(document, [tag].concat(rest));
        if (tag && tag.toLowerCase() === 'iframe') {
            try {
                var desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
                if (desc && desc.set) {
                    Object.defineProperty(el, 'src', {
                        set: function(v) {
                            try { window.__bundlespy_iframes.push({url: String(v)}); } catch(e) {}
                            return desc.set.call(this, v);
                        },
                        get: function() { return desc.get.call(this); },
                        configurable: true,
                    });
                }
            } catch(e) {}
        }
        return el;
    };
})();

})(); // end IIFE
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

    // Anchor links — preserve query strings so filter URLs like
    // /projects?category=E-Commerce are discovered (Katana gap fix)
    document.querySelectorAll('a[href],[routerLink],[ng-href]').forEach(el => {
        try {
            const h = el.getAttribute('href') || el.getAttribute('routerLink') || el.getAttribute('ng-href') || '';
            if (!h || h.startsWith('//') || h.startsWith('http') || h.startsWith('#') || h.startsWith('javascript:') || h.startsWith('mailto:')) return;
            if (h.startsWith('/')) {
                // Strip fragment but keep query string — /projects?category=foo is a real URL
                add(h.split('#')[0]);
            }
        } catch(e) {}
    });

    // data-route attrs
    document.querySelectorAll('[data-route],[data-path],[routerLink]').forEach(el => {
        ['data-route','data-path','routerLink'].forEach(attr => {
            try {
                const v = el.getAttribute(attr);
                if (v && v.startsWith('/')) add(v.split('#')[0]);
            } catch(e) {}
        });
    });

    // link[rel] tags — manifest, canonical, alternate (Katana gap fix)
    // Katana picks up /site.webmanifest via link[rel=manifest]; we were missing it
    document.querySelectorAll('link[rel][href]').forEach(el => {
        try {
            const rel = (el.getAttribute('rel') || '').toLowerCase();
            const h   = el.getAttribute('href') || '';
            if (['manifest', 'canonical', 'alternate', 'sitemap'].some(r => rel.includes(r))) {
                if (h.startsWith('/') && !h.startsWith('//')) add(h.split('#')[0]);
            }
        } catch(e) {}
    });

    // Vue reactive filter/tag options — scrape values from v-bind:to / :to / to attrs
    // and from rendered filter buttons (e.g. <button @click="$router.push({query:{category:'foo'}})">)
    // that never appear as plain hrefs but produce ?category= URLs when clicked.
    try {
        document.querySelectorAll('[data-category],[data-tag],[data-filter]').forEach(el => {
            try {
                ['data-category','data-tag','data-filter'].forEach(attr => {
                    const v = el.getAttribute(attr);
                    if (v) {
                        // Attempt to reconstruct the parameterized URL from the current path
                        const path = window.location.pathname;
                        const param = attr.replace('data-', '');
                        add(path + '?' + param + '=' + encodeURIComponent(v));
                    }
                });
            } catch(e) {}
        });
    } catch(e) {}

    // Vue router-link :to objects — Vue compiles these into href attrs at render time,
    // but catch any that slipped through as JSON in data attrs
    try {
        document.querySelectorAll('[to]').forEach(el => {
            try {
                const to = el.getAttribute('to') || '';
                if (to.startsWith('/') || to.startsWith('{')) {
                    if (to.startsWith('/')) {
                        add(to.split('#')[0]);
                    } else {
                        // Try parsing {path, query} object
                        const obj = JSON.parse(to.replace(/'/g, '"'));
                        if (obj && obj.path) {
                            let r = obj.path;
                            if (obj.query && typeof obj.query === 'object') {
                                const qs = Object.entries(obj.query).map(([k,v]) => k + '=' + encodeURIComponent(v)).join('&');
                                if (qs) r += '?' + qs;
                            }
                            add(r);
                        }
                    }
                }
            } catch(e) {}
        });
    } catch(e) {}

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
        """Normalize a URL for deduplication.

        Query strings are preserved when they look like content filters
        (key=slug-value pairs such as ?category=laravel or ?tag=ai).
        Tracking parameters (utm_*, fbclid, gclid, ref, etc.) and
        fragments are always stripped.

        This lets BundleSpy discover filter pages like
        /projects?category=E-Commerce that Katana finds via anchor hrefs,
        while still collapsing pagination noise like ?page=2&page=3.
        """
        # Tracking / noise params to always strip
        _TRACKING = frozenset([
            "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
            "fbclid","gclid","msclkid","_ga","ref","referrer","source",
            "sid","session_id","timestamp","ts","t","rand","_","cb",
        ])
        try:
            p = urlparse(url)
            if not p.query:
                # No query string — standard normalization (strip fragment)
                return urlunparse((p.scheme, p.netloc, p.path, "", "", "")).lower()

            # Parse query string — keep content-filter params, drop tracking noise
            import urllib.parse as _up
            qs_pairs = _up.parse_qsl(p.query, keep_blank_values=False)
            kept = []
            for k, v in qs_pairs:
                if k.lower() in _TRACKING:
                    continue
                # Keep short slug-like values (category, tag, filter, sort, type, etc.)
                # Drop long values — they're likely tokens, cursors, or encoded data
                if len(v) <= 120:
                    kept.append((k, v))

            if not kept:
                # All params were noise — normalize without query
                return urlunparse((p.scheme, p.netloc, p.path, "", "", "")).lower()

            # Rebuild with sorted params so ?a=1&b=2 == ?b=2&a=1
            qs_norm = _up.urlencode(sorted(kept))
            return urlunparse((p.scheme, p.netloc, p.path, "", qs_norm, "")).lower()
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
        Wait for initial page load using a two-phase approach:
        1. Playwright's networkidle (CDP-level, catches all XHR/fetch) with a
           short cap so SPA polling loops don't stall it.
        2. Our JS in-flight counter as a fallback — catches requests that fired
           before our init script landed or after networkidle returned early.
        """
        start = time.monotonic()

        # Phase A: CDP networkidle — most accurate, capped to avoid SPA hangs
        try:
            self.page.wait_for_load_state("networkidle",
                                          timeout=min(max_ms // 2, 3000))
        except Exception:
            # networkidle timed out (SPA with polling) — fall through to JS check
            pass

        # Phase B: JS in-flight counter + DOM quiet
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


def _wait_heuristic(page, max_ms: int = 15000) -> None:
    """
    Gap 1: Heuristic page-load strategy — ported from Katana's WaitPageLoadHeurisitics.

    Katana's heuristic is the most robust strategy for modern SPAs. Instead of
    blindly waiting for a fixed event, it:

    1. Waits for the basic load event (DOMContentLoaded).
    2. Captures the current URL and polls every 100ms for up to 2s to detect
       a client-side route change (history.pushState, SPA router navigation).
    3. If the URL changed  → short 300ms grace period to let the new route
       settle its network requests, then done.
    4. If the URL didn't change → fall back to network-idle (1s quiet window)
       + DOM stability check (mutation observer quiet for 1s).

    This keeps fast pages fast (exits as soon as the URL change is confirmed)
    while still succeeding on heavy SPAs that defer rendering by seconds.

    Playwright equivalent:
    - Step 1: page.wait_for_load_state("domcontentloaded")
    - Step 2: JS URL polling loop
    - Step 3/4: page.wait_for_load_state("networkidle") with timeout
    """
    import time as _time

    _URL_POLL_INTERVAL_MS  = 100   # ms between URL polls
    _URL_POLL_TIMEOUT_MS   = 2000  # how long to poll for a URL change
    _POST_CHANGE_WAIT_MS   = 300   # grace period after URL change
    _IDLE_WAIT_MS          = 1000  # network-idle window when URL unchanged
    _DOM_STABLE_WAIT_MS    = 1000  # DOM-quiet window after idle

    deadline = _time.monotonic() + max_ms / 1000.0

    # Step 1: Wait for DOMContentLoaded — this is fast and always needed.
    try:
        page.wait_for_load_state(
            "domcontentloaded",
            timeout=min(max_ms, 10000),
        )
    except Exception:
        pass  # Timed out or navigated away — carry on with the rest

    if _time.monotonic() >= deadline:
        return

    # Step 2: Read the current URL and poll for a client-side route change.
    try:
        start_url = page.evaluate("() => window.location.href")
    except Exception:
        start_url = None

    url_changed = False
    if start_url:
        poll_end = _time.monotonic() + _URL_POLL_TIMEOUT_MS / 1000.0
        while _time.monotonic() < min(poll_end, deadline):
            _time.sleep(_URL_POLL_INTERVAL_MS / 1000.0)
            try:
                cur = page.evaluate("() => window.location.href")
                if cur and cur != start_url:
                    url_changed = True
                    break
            except Exception:
                break  # Page is gone / navigating — stop polling

    if _time.monotonic() >= deadline:
        return

    if url_changed:
        # Step 3: URL changed — short grace period for the new route's requests.
        try:
            page.wait_for_timeout(_POST_CHANGE_WAIT_MS)
        except Exception:
            pass
        return

    # Step 4: URL didn't change — broader heuristics for non-SPA or slow SPAs.
    remaining_ms = max(0, int((deadline - _time.monotonic()) * 1000))

    # 4a: Wait for network idle (1s quiet window, capped at remaining time).
    idle_timeout = min(_IDLE_WAIT_MS + 500, remaining_ms)
    if idle_timeout > 0:
        try:
            page.wait_for_load_state("networkidle", timeout=idle_timeout)
        except Exception:
            pass  # Timeout is normal — page may have long-running connections

    remaining_ms = max(0, int((deadline - _time.monotonic()) * 1000))

    # 4b: DOM stability — wait for mutation activity to go quiet.
    dom_timeout = min(_DOM_STABLE_WAIT_MS + 500, remaining_ms)
    if dom_timeout > 0:
        try:
            page.evaluate(f"""
                () => new Promise((resolve) => {{
                    const t = {_DOM_STABLE_WAIT_MS};
                    let timer = setTimeout(resolve, t);
                    const obs = new MutationObserver(() => {{
                        clearTimeout(timer);
                        timer = setTimeout(resolve, t);
                    }});
                    obs.observe(document.body || document.documentElement,
                        {{childList: true, subtree: true, attributes: true}});
                    setTimeout(() => {{ obs.disconnect(); resolve(); }}, t * 3);
                }})
            """)
        except Exception:
            pass


# ── Gap 2: CDP FetchRequestPaused interception ───────────────────────────────

def _attach_cdp_fetch_interception(
    page,
    on_request_body_fn,
    on_response_body_fn,
    resource_patterns: Optional[List[str]] = None,
    capture_response_types: Optional[set] = None,
) -> Optional[object]:
    """
    Gap 2: CDP-level Fetch.requestPaused interception — ported from Katana's
    FetchRequestStage/FetchResponseStage pipeline in browser.go.

    Katana intercepts every request and response at the CDP Fetch domain level,
    giving access to raw POST bodies and raw response bytes that Playwright's
    high-level response event can miss (cached responses, service-worker
    intercepts, partial reads).

    Architecture:
    - Opens a raw CDP session on the page via page.context.new_cdp_session(page).
    - Enables Fetch domain with patterns=['*'] so every request is paused.
    - Subscribes to Fetch.requestPaused events.
    - Each event is either a REQUEST pause (no responseStatusCode) or a
      RESPONSE pause (has responseStatusCode).
    - REQUEST phase: capture raw post body from request.postData; call
      Fetch.continueRequest so the request proceeds.
    - RESPONSE phase: call Fetch.getResponseBody to read the raw response bytes
      (base64-encoded by Chrome); decode and forward to handler; call
      Fetch.continueResponse so the response is delivered to the page.
    - Every continueRequest/continueResponse MUST be called — failing to do so
      hangs the page indefinitely.

    Parameters:
        page: Playwright page object.
        on_request_body_fn: Callable(url, method, headers, body_bytes) called
            for every intercepted request. Must be non-blocking (fast).
        on_response_body_fn: Callable(url, status, headers, body_bytes) called
            for every intercepted response body. Must be non-blocking (fast).
        resource_patterns: Optional list of URL patterns to intercept
            (default: ['*'] for everything). Use ['*.json', '*/api/*'] to
            limit to API calls only.
        capture_response_types: Optional set of resource types to capture
            responses for (e.g. {'xhr', 'fetch', 'document'}). None = all.

    Returns the CDP session object so the caller can close it, or None if
    CDP interception could not be enabled (non-fatal — Playwright's response
    event is the fallback).
    """
    import base64 as _base64
    import threading as _threading

    if resource_patterns is None:
        resource_patterns = ["*"]

    _REQUEST_STAGE  = "Request"
    _RESPONSE_STAGE = "Response"

    # Build the Fetch.enable patterns — intercept both request and response
    # stages for every URL matching our patterns.
    fetch_patterns = [
        {"urlPattern": pat, "requestStage": _REQUEST_STAGE}
        for pat in resource_patterns
    ] + [
        {"urlPattern": pat, "requestStage": _RESPONSE_STAGE}
        for pat in resource_patterns
    ]

    try:
        cdp = page.context.new_cdp_session(page)
    except Exception as e:
        logger.debug("CDP session creation failed: %s", e)
        return None

    # Lock protects concurrent CDP send calls from multiple event firings.
    _cdp_lock = _threading.Lock()

    def _safe_cdp_send(method: str, params: dict) -> Optional[dict]:
        """Send a CDP command; swallow all errors — page may be closing."""
        try:
            with _cdp_lock:
                return cdp.send(method, params)
        except Exception as ex:
            logger.debug("CDP %s error: %s", method, ex)
            return None

    def _on_fetch_paused(params: dict) -> None:
        """
        Handle Fetch.requestPaused CDP event.

        Two phases distinguished by presence of responseStatusCode:
        - Request phase (no responseStatusCode): capture POST body, continue.
        - Response phase (has responseStatusCode): read body, continue.

        CRITICAL: continueRequest/continueResponse MUST always be called to
        avoid hanging the page. Every code path ends with one of them.
        """
        request_id   = params.get("requestId", "")
        url          = params.get("request", {}).get("url", "")
        method       = params.get("request", {}).get("method", "GET")
        req_headers  = params.get("request", {}).get("headers", {})
        resource_type = params.get("resourceType", "").lower()

        is_response = "responseStatusCode" in params

        if not is_response:
            # ── REQUEST PHASE ────────────────────────────────────────────────
            # Capture the raw POST body if present, then immediately continue
            # so we don't stall the page.
            post_data_str = params.get("request", {}).get("postData", "")
            body_bytes: Optional[bytes] = None
            if post_data_str:
                try:
                    body_bytes = post_data_str.encode("utf-8", errors="replace")
                except Exception:
                    body_bytes = None

            # Forward to caller's handler (non-blocking)
            if on_request_body_fn and (body_bytes or method.upper() != "GET"):
                try:
                    on_request_body_fn(url, method, req_headers, body_bytes or b"")
                except Exception as hnd_err:
                    logger.debug("CDP request handler error for %s: %s", url, hnd_err)

            # MUST continue — do not stall the request
            _safe_cdp_send("Fetch.continueRequest", {"requestId": request_id})

        else:
            # ── RESPONSE PHASE ───────────────────────────────────────────────
            status   = params.get("responseStatusCode", 0)
            resp_hdrs_list = params.get("responseHeaders", [])
            resp_headers = {h["name"]: h["value"] for h in resp_hdrs_list}

            # Filter by resource type if requested
            if capture_response_types and resource_type not in capture_response_types:
                _safe_cdp_send("Fetch.continueResponse", {"requestId": request_id})
                return

            # Read the raw response body
            resp_bytes: Optional[bytes] = None
            body_result = _safe_cdp_send("Fetch.getResponseBody", {"requestId": request_id})
            if body_result:
                encoded_body = body_result.get("body", "")
                is_base64    = body_result.get("base64Encoded", False)
                if encoded_body:
                    try:
                        if is_base64:
                            resp_bytes = _base64.b64decode(encoded_body)
                        else:
                            resp_bytes = encoded_body.encode("utf-8", errors="replace")
                    except Exception as dec_err:
                        logger.debug("CDP body decode error for %s: %s", url, dec_err)

            # Forward to caller's handler (non-blocking)
            if on_response_body_fn and resp_bytes is not None:
                try:
                    on_response_body_fn(url, status, resp_headers, resp_bytes)
                except Exception as hnd_err:
                    logger.debug("CDP response handler error for %s: %s", url, hnd_err)

            # MUST continue — do not stall the response delivery
            _safe_cdp_send("Fetch.continueResponse", {"requestId": request_id})

    # Subscribe to Fetch.requestPaused BEFORE enabling the domain to avoid
    # missing any events that fire immediately on enable.
    cdp.on("Fetch.requestPaused", _on_fetch_paused)

    # Enable the Fetch domain — this is the point at which interception starts.
    result = _safe_cdp_send("Fetch.enable", {"patterns": fetch_patterns})
    if result is None:
        # Fetch.enable failed (e.g. browser doesn't support it) — detach.
        logger.debug("Fetch.enable failed — CDP interception disabled for this page")
        try:
            cdp.detach()
        except Exception:
            pass
        return None

    logger.debug("CDP Fetch interception active on %s", page.url or "page")
    return cdp


def _detach_cdp_session(cdp) -> None:
    """Safely disable Fetch interception and detach a CDP session."""
    if cdp is None:
        return
    try:
        cdp.send("Fetch.disable", {})
    except Exception:
        pass
    try:
        cdp.detach()
    except Exception:
        pass


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


# ── PathTrie — URL structural deduplication ───────────────────────────────────
# Mirrors Katana's FilterSimilar / PathTrie implementation.
# Replaces numeric / UUID path segments with a wildcard token so that
# /item/1, /item/2, /item/1337 all collapse to /item/* and are treated as
# one unique structural pattern.  Configurable threshold controls how many
# concrete values a segment must be seen with before it is wildcarded.

import re as _re

_NUMERIC_SEG   = _re.compile(r'^\d+$')
_UUID_SEG      = _re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    _re.IGNORECASE,
)
_HEX_ID_SEG    = _re.compile(r'^[0-9a-f]{16,}$', _re.IGNORECASE)  # long hex IDs
_SLUG_NUMERIC  = _re.compile(r'^[a-z0-9-]{2,50}$', _re.IGNORECASE)  # slug with digits

_WILDCARD = "*"


class PathTrie:
    """
    URL-path structural deduplication trie.

    Each path segment becomes a node in the trie.  When the same position in
    the path has been seen with >= `threshold` *different* concrete values, all
    future values at that position are replaced with the wildcard token "*".

    Thread-safe — all mutations hold the internal lock.

    Usage::

        trie = PathTrie(threshold=3)
        for url in urls:
            fingerprint = trie.fingerprint(url)
            if not seen.add(fingerprint):   # set.add returns False on duplicate
                continue   # structurally identical to a URL we already visited
    """

    def __init__(self, threshold: int = 3) -> None:
        self._threshold: int = max(1, threshold)
        self._lock: threading.Lock = threading.Lock()
        # trie node: dict[segment -> {"_children": dict, "_values": set, "_wildcard": bool}]
        self._root: dict = {"_children": {}, "_values": set(), "_wildcard": False}

    # ── public ────────────────────────────────────────────────────────────────

    def fingerprint(self, url: str) -> str:
        """
        Return a structural fingerprint of the URL's path.
        Numeric / UUID / frequently-varying segments are replaced with "*".
        Fragment is stripped.

        Query strings are preserved and included in the fingerprint when
        they contain content-filter parameters (short slug-like values).
        This lets /projects?category=laravel and /projects?category=vuejs
        produce distinct fingerprints so both get visited, while
        /item/1 and /item/2 still collapse to /item/* as before.

        Examples::
            /product/42                    -> /product/*
            /product/99                    -> /product/*   (same fingerprint)
            /user/abc-def/orders           -> /user/*/orders
            /about                         -> /about        (stable, returned as-is)
            /projects?category=laravel     -> /projects?category=laravel  (distinct)
            /projects?category=vuejs       -> /projects?category=vuejs    (distinct)
        """
        try:
            parsed  = urlparse(url)
            path    = parsed.path or "/"
            segs    = [s for s in path.split("/")]   # keep empty strings for leading /
            result  = self._walk(self._root, segs, mutate=True)
            # Rebuild path from fingerprinted segments
            fingerprint_path = "/".join(result)
            # Preserve content-filter query strings in the fingerprint
            # so filter pages aren't collapsed into their base path
            qs = parsed.query or ""
            return urlunparse((parsed.scheme, parsed.netloc, fingerprint_path, "", qs, ""))
        except Exception:
            return url

    def is_known_pattern(self, url: str) -> bool:
        """
        Return True if this URL's structural pattern has already been seen
        (i.e. the fingerprint matches a wildcard node in the trie).
        Does NOT mutate the trie — read-only check.
        """
        try:
            parsed = urlparse(url)
            path   = parsed.path or "/"
            segs   = [s for s in path.split("/")]
            result = self._walk(self._root, segs, mutate=False)
            return _WILDCARD in result
        except Exception:
            return False

    # ── internal ──────────────────────────────────────────────────────────────

    def _walk(self, node: dict, segs: List[str], mutate: bool) -> List[str]:
        """Recursively walk/build the trie and return the fingerprinted segments."""
        if not segs:
            return []

        seg, rest = segs[0], segs[1:]

        with self._lock:
            # Already wildcarded at this position — return wildcard immediately
            if node.get("_wildcard"):
                out_seg = _WILDCARD
            elif seg == "":
                # Empty string segments (leading / trailing slash) — keep as-is
                out_seg = seg
                if mutate:
                    child = node["_children"].setdefault(seg, {
                        "_children": {}, "_values": set(), "_wildcard": False
                    })
                else:
                    child = node["_children"].get(seg, {
                        "_children": {}, "_values": set(), "_wildcard": False
                    })
                return [out_seg] + self._walk(child, rest, mutate)
            elif _NUMERIC_SEG.match(seg) or _UUID_SEG.match(seg) or _HEX_ID_SEG.match(seg):
                # Clearly parametric — wildcard immediately without counting
                out_seg = _WILDCARD
                if mutate:
                    node["_wildcard"] = True
            else:
                # Register this value; wildcard when threshold exceeded
                if mutate:
                    node["_values"].add(seg)
                    if len(node["_values"]) >= self._threshold:
                        node["_wildcard"] = True
                        out_seg = _WILDCARD
                    else:
                        out_seg = seg
                else:
                    # Read-only: wildcard if the node is already past threshold
                    if len(node.get("_values", set())) >= self._threshold:
                        out_seg = _WILDCARD
                    else:
                        out_seg = seg

            if out_seg == _WILDCARD:
                # All concrete children collapse into the wildcard child
                if mutate:
                    child = node["_children"].setdefault(_WILDCARD, {
                        "_children": {}, "_values": set(), "_wildcard": False
                    })
                else:
                    child = node["_children"].get(_WILDCARD, {
                        "_children": {}, "_values": set(), "_wildcard": False
                    })
            else:
                if mutate:
                    child = node["_children"].setdefault(seg, {
                        "_children": {}, "_values": set(), "_wildcard": False
                    })
                else:
                    child = node["_children"].get(seg, {
                        "_children": {}, "_values": set(), "_wildcard": False
                    })

        return [out_seg] + self._walk(child, rest, mutate)


def _url_structural_fingerprint(url: str, trie: "PathTrie") -> str:
    """
    Return the structural fingerprint of `url` using `trie`.
    Strips query string and fragment before fingerprinting.
    """
    return trie.fingerprint(url)


# ── Netscape cookie jar loader ────────────────────────────────────────────────
# Parses the Netscape cookie file format exported by Burp Suite, curl,
# Firefox, Chrome (via EditThisCookie), and most HTTP tools.
# Each non-comment line is TAB-separated:
#   domain  flag  path  secure  expiry  name  value
#
# Returns a list of Playwright cookie dicts ready for ctx.add_cookies().

def load_cookie_jar(path: str) -> List[dict]:
    """
    Parse a Netscape-format cookie file and return Playwright cookie dicts.

    Handles:
    - Standard Netscape format (7 TAB-separated fields)
    - HTTP-only cookies prefixed with #HttpOnly-
    - Comment lines (# ...) and blank lines
    - Cookies with no value (name only)
    - Domain leading-dot normalization (.example.com -> example.com for Playwright)
    - Expiry = 0 or missing -> session cookie (no expires key set)

    Raises FileNotFoundError if path does not exist.
    Raises ValueError on a completely unparseable file (not a cookie jar).
    """
    cookies: List[dict] = []
    valid_lines = 0
    error_lines = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\r\n")

                # Strip HttpOnly prefix (used by curl's --cookie-jar)
                http_only = False
                if line.startswith("#HttpOnly-"):
                    line      = line[len("#HttpOnly-"):]
                    http_only = True

                # Skip comments and blanks
                if not line or line.startswith("#"):
                    continue

                parts = line.split("\t")
                if len(parts) < 6:
                    error_lines += 1
                    continue

                # Pad to 7 fields — some exporters omit the value column for
                # value-less cookies
                while len(parts) < 7:
                    parts.append("")

                domain_raw, _flag, path_val, secure_str, expiry_str, name, value = (
                    parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                )

                # Playwright requires domain WITHOUT a leading dot for host cookies,
                # but WITH a leading dot for domain cookies (subdomains).
                # We preserve the dot if present — Playwright handles both.
                domain = domain_raw.strip()
                if not domain:
                    error_lines += 1
                    continue

                name  = name.strip()
                value = value.strip()
                if not name:
                    error_lines += 1
                    continue

                secure = secure_str.strip().upper() == "TRUE"

                cookie: dict = {
                    "name":   name,
                    "value":  value,
                    "domain": domain,
                    "path":   path_val.strip() or "/",
                    "secure": secure,
                    "httpOnly": http_only,
                    "sameSite": "None" if secure else "Lax",
                }

                # Expiry — omit key for session cookies (expiry = 0 or blank)
                try:
                    exp = int(float(expiry_str.strip()))
                    if exp > 0:
                        cookie["expires"] = float(exp)
                except (ValueError, TypeError):
                    pass

                cookies.append(cookie)
                valid_lines += 1

    except FileNotFoundError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to parse cookie jar {path!r}: {e}") from e

    if valid_lines == 0 and error_lines > 0:
        raise ValueError(
            f"Cookie jar {path!r} contained {error_lines} lines but none were parseable. "
            "Is this a Netscape cookie file?"
        )

    logger.info(
        "Cookie jar loaded: %s — %d cookies parsed (%d lines skipped)",
        path, valid_lines, error_lines,
    )
    return cookies


# ── ResponseParser — extract URLs from every HTTP response body ───────────────
# Mirrors Katana's ResponseParser (engine/parser).
#
# Runs on EVERY response body the browser receives — HTML, JS, JSON, CSS.
# Extracts embedded URLs that the browser would never navigate to on its own
# but which may reveal hidden API endpoints, admin routes, or internal services.
#
# Extraction layers (in order of reliability):
#   1. HTML href/src/action attributes  (lxml-style regex — no DOM access needed)
#   2. JavaScript string URL literals   (fetch/axios/XMLHttpRequest call patterns)
#   3. JSON string values               (REST API pagination cursors, next-page links)
#   4. CSS url() references             (background images hosted on app server)
#   5. Source map references            (sourceMappingURL comment / header)
#   6. Generic URL pattern sweep        (last resort — catches anything the above miss)

# Pre-compiled patterns — compiled once at import time for speed.

# HTML attribute URLs
_RP_HTML_ATTRS = _re.compile(
    r'''(?:href|src|action|data-src|data-href|data-url|data-endpoint|content)\s*=\s*["']([^"'#\s]{4,400})["']''',
    _re.IGNORECASE,
)

# JS string literals — URLs passed to common HTTP call patterns
_RP_JS_CALLS = _re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request)|'XMLHttpRequest'|xhr\.open|'\.ajax'|'\$\.get'|'\$\.post')\s*\(\s*["'`]([^"'`\s]{4,400})["'`]''',
    _re.IGNORECASE,
)

# JS string literals — bare URL strings (path or full URL) — broader pattern
_RP_JS_STRINGS = _re.compile(
    r'''["'`](/(?:[a-zA-Z0-9_\-./~!$&'()*+,;=:@%?#]){1,300})["'`]'''
)

# JSON string values that look like paths or full URLs
_RP_JSON_URLS = _re.compile(
    r'"(?:url|href|endpoint|path|next|prev|link|action|redirect|location|uri|src|source)"\s*:\s*"([^"]{4,400})"',
    _re.IGNORECASE,
)

# CSS url() references
_RP_CSS_URLS = _re.compile(r'''url\(\s*["']?([^"')#\s]{4,400})["']?\s*\)''', _re.IGNORECASE)

# Source map references (inline comment + X-SourceMap header)
_RP_SOURCEMAP = _re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
    _re.IGNORECASE,
)

# Generic absolute/relative URL sweep — catches anything above missed
_RP_GENERIC_PATH = _re.compile(
    r'''["'`\s]((?:https?://[^\s"'`<>]{8,400}|/[a-zA-Z0-9_\-./~!$&'()*+,;=:@%]{2,300}))["'`\s<>]'''
)

# File extensions to skip — static assets with no endpoint value
_RP_SKIP_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".ogg", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz",
})

# Domains that are always third-party noise
_RP_SKIP_DOMAINS = frozenset({
    "google-analytics.com", "googletagmanager.com", "googleapis.com",
    "gstatic.com", "doubleclick.net", "facebook.net", "facebook.com",
    "twitter.com", "linkedin.com", "hotjar.com", "mixpanel.com",
    "segment.io", "amplitude.com", "fullstory.com", "intercom.io",
    "sentry.io", "bugsnag.com", "logrocket.com", "datadog-browser-agent.com",
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
})

# Max response body size to parse (8 MB) — avoids OOM on huge bundles
_RP_MAX_BODY_BYTES = 8 * 1024 * 1024


class ResponseParser:
    """
    Parses HTTP response bodies for embedded URLs.

    Designed to be called from HeadlessEngine._handle_response() for every
    non-blocked response, and also from a dedicated Playwright context-level
    response handler that captures responses the browser would normally not
    navigate to (XHR/fetch responses, JSON API responses, etc.)

    All extraction is done with pre-compiled regexes — no DOM access, no
    external dependencies.  Safe to call from any thread.

    Usage::

        parser = ResponseParser(target_origin="https://example.com")
        urls   = parser.extract(response_url, content_type, body_bytes)
        # urls is a list of absolute URL strings within the target origin
    """

    def __init__(self, target_origin: str) -> None:
        """
        target_origin: scheme + netloc of the crawl target, e.g. "https://example.com".
        Only URLs that resolve to this origin (or are relative paths) are returned.
        """
        parsed = urlparse(target_origin)
        self._origin  = f"{parsed.scheme}://{parsed.netloc}"
        self._netloc  = parsed.netloc.lower()

    # ── public ────────────────────────────────────────────────────────────────

    def extract(self, response_url: str, content_type: str, body: bytes) -> List[str]:
        """
        Extract embedded URLs from a response body.

        Returns a deduplicated list of absolute URLs that:
        - Belong to the same origin as target_origin, OR are relative paths
        - Are not obviously static assets (.png, .woff, etc.)
        - Are not third-party analytics/CDN domains
        - Are at least 4 characters long

        Body is silently truncated to _RP_MAX_BODY_BYTES before parsing.
        All exceptions are caught — never raises.
        """
        try:
            if not body:
                return []
            # Truncate large bodies to avoid OOM / slow regex on 50MB bundles
            if len(body) > _RP_MAX_BODY_BYTES:
                body = body[:_RP_MAX_BODY_BYTES]

            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                return []

            ct_lower = (content_type or "").lower()
            found: Set[str] = set()

            # Choose extraction strategy based on content type
            if "html" in ct_lower:
                found.update(self._extract_html(text))
                found.update(self._extract_js_strings(text))
            elif "javascript" in ct_lower or "ecmascript" in ct_lower or self._is_js_url(response_url):
                found.update(self._extract_js_calls(text))
                found.update(self._extract_js_strings(text))
                found.update(self._extract_sourcemaps(text, response_url))
            elif "json" in ct_lower:
                found.update(self._extract_json_urls(text))
            elif "css" in ct_lower:
                found.update(self._extract_css_urls(text))
            else:
                # Unknown type — run all extractors
                found.update(self._extract_html(text))
                found.update(self._extract_js_strings(text))
                found.update(self._extract_json_urls(text))

            # Always run generic sweep — catches anything above missed
            found.update(self._extract_generic(text))

            # Normalize + filter
            return self._normalize_and_filter(found, response_url)

        except Exception as e:
            logger.debug("ResponseParser.extract error for %s: %s", response_url, e)
            return []

    # ── extraction layers ─────────────────────────────────────────────────────

    def _extract_html(self, text: str) -> Set[str]:
        return set(_RP_HTML_ATTRS.findall(text))

    def _extract_js_calls(self, text: str) -> Set[str]:
        return set(_RP_JS_CALLS.findall(text))

    def _extract_js_strings(self, text: str) -> Set[str]:
        return set(_RP_JS_STRINGS.findall(text))

    def _extract_json_urls(self, text: str) -> Set[str]:
        return set(_RP_JSON_URLS.findall(text))

    def _extract_css_urls(self, text: str) -> Set[str]:
        return set(_RP_CSS_URLS.findall(text))

    def _extract_sourcemaps(self, text: str, response_url: str) -> Set[str]:
        """Extract sourceMappingURL references and resolve them to absolute URLs."""
        refs: Set[str] = set()
        for match in _RP_SOURCEMAP.finditer(text):
            ref = match.group(1).strip()
            if ref.startswith("data:"):
                continue  # inline source map — no URL to follow
            refs.add(ref)
        return refs

    def _extract_generic(self, text: str) -> Set[str]:
        return set(_RP_GENERIC_PATH.findall(text))

    # ── normalization + filtering ─────────────────────────────────────────────

    def _normalize_and_filter(self, raw: Set[str], base_url: str) -> List[str]:
        """Resolve relative URLs, drop static assets and third-party domains."""
        result: List[str] = []
        seen: Set[str] = set()

        for candidate in raw:
            candidate = candidate.strip()
            if not candidate or len(candidate) < 4:
                continue
            # Skip data URIs and JavaScript protocol
            if candidate.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
                continue

            try:
                # Resolve relative URLs against the response URL
                absolute = urljoin(base_url, candidate)
                parsed   = urlparse(absolute)
            except Exception:
                continue

            # Must be http or https
            if parsed.scheme not in ("http", "https"):
                continue

            netloc_lower = parsed.netloc.lower()

            # Skip third-party noise domains
            skip = False
            for skip_domain in _RP_SKIP_DOMAINS:
                if netloc_lower == skip_domain or netloc_lower.endswith("." + skip_domain):
                    skip = True
                    break
            if skip:
                continue

            # Must belong to our target origin
            if netloc_lower != self._netloc:
                # Allow subdomains of the target — e.g. api.example.com for example.com
                target_base = self._netloc.lstrip("www.")
                if not (netloc_lower == target_base or
                        netloc_lower.endswith("." + target_base)):
                    continue

            # Skip static asset extensions
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in _RP_SKIP_EXTS):
                continue

            # Normalize: drop query + fragment for dedup
            norm = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            if norm in seen:
                continue
            seen.add(norm)
            result.append(norm)

        return result

    @staticmethod
    def _is_js_url(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))


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

    Three-layer detection — layered so fast checks run first:
    1. URL path keyword match (fast, no DOM access)
    2. Standard CSS selector match (type=password, autocomplete, form action)
    3. DIT-style heuristic scan — handles obfuscated field names, React forms
       with hashed attribute values, and input elements that lack type="password"
       but carry password-related name/id/placeholder attributes.

    This mirrors Katana's tryAutoLogin / DIT classifier approach.
    """
    try:
        if _is_login_url(page.url):
            return True

        # Layer 2: standard selectors
        for sel in _LOGIN_DOM_PATTERNS:
            try:
                if page.query_selector(sel):
                    return True
            except Exception:
                pass

        # Layer 3: DIT-style heuristic — scan all input elements for
        # password-related name/id/placeholder attributes (handles obfuscated
        # React/Vue forms where type="password" may be absent or minified).
        try:
            found = page.evaluate(r"""
                (function() {
                    var inputs = document.querySelectorAll('input, [role="textbox"]');
                    for (var i = 0; i < inputs.length; i++) {
                        var el = inputs[i];
                        var attrs = [
                            el.getAttribute('name')        || '',
                            el.getAttribute('id')          || '',
                            el.getAttribute('placeholder') || '',
                            el.getAttribute('aria-label')  || '',
                            el.getAttribute('data-field')  || '',
                            el.getAttribute('data-name')   || '',
                        ].join(' ').toLowerCase();
                        // password-like attribute on any input = auth page
                        if (/pass(w(or)?d?)?|psw|pwd|credential|secret/.test(attrs))
                            return true;
                    }
                    // Check page title / h1 for auth-page language
                    var t = (document.title + ' ' +
                             (document.querySelector('h1,h2') || {}).innerText || ''
                            ).toLowerCase();
                    if (/\b(log\s*in|sign\s*in|login|signin|authenticate)\b/.test(t) &&
                        document.querySelectorAll('input').length > 0)
                        return true;
                    return false;
                })()
            """)
            if found:
                return True
        except Exception:
            pass

    except Exception:
        pass
    return False


class BrowserPool:
    """
    Concurrency limiter + browser configuration store for Phase 2 parallel BFS.

    Playwright sync_api binds every object (browser, context, page) to the
    greenlet of the thread that created it.  Sharing a pre-created browser
    across threads causes "greenlet.error: Cannot switch to a different thread".

    The fix: each ThreadPoolExecutor worker thread owns its entire Playwright
    lifecycle — it calls _make_browser_for_thread() to create a fresh
    sync_playwright() context + browser + context + page, uses it for one URL
    visit, then tears it all down via _close_browser_for_thread().  No browser
    objects cross thread boundaries.

    BrowserPool only provides:
      - a Semaphore to cap concurrency at num_browsers parallel visits
      - stored config (browser args, ctx kwargs, cookies, init script, callbacks)
        so workers don't need to pass a long argument list themselves
      - acquire() / release() that gate on the semaphore only (no slot dict)
      - close_all() which is now a no-op (workers clean up themselves)

    Usage (inside each worker thread):
        _browser_pool.acquire()          # blocks if num_browsers slots busy
        try:
            slot = _browser_pool.make_thread_browser()
            try:
                slot["page"].goto(url)
                ...
            finally:
                _browser_pool.close_thread_browser(slot)
        finally:
            _browser_pool.release()
    """

    def __init__(self, num_browsers: int, browser_args: list,
                 ctx_kwargs: dict, cookies: list, init_script: str,
                 block_fn, response_fn,
                 cdp_request_fn=None, cdp_response_fn=None):
        self._num          = max(1, num_browsers)
        self._browser_args = browser_args
        self._ctx_kwargs   = ctx_kwargs
        self._cookies      = cookies
        self._init_script  = init_script
        self._block_fn     = block_fn
        self._response_fn  = response_fn
        self._cdp_request_fn  = cdp_request_fn
        self._cdp_response_fn = cdp_response_fn
        # Semaphore caps the number of parallel browser visits.
        self._sem = threading.Semaphore(self._num)

    def make_thread_browser(self) -> dict:
        """
        Create a complete Playwright stack owned by the calling thread.

        Must be called from the worker thread that will use the returned page —
        never from a different thread.  Returns a dict with keys:
          pw, browser, ctx, page, cdp, resp_queue
        Pass the whole dict to close_thread_browser() when done.

        Response draining MUST be done by the same thread that called this
        method (i.e. the Playwright-owning thread).  Never pass Playwright
        Response objects to another thread — greenlet affinity will cause
        "Cannot switch to a different thread" errors.  Use drain_thread_responses()
        on the owning thread after each goto/interact/before close.
        """
        from playwright.sync_api import sync_playwright as _sync_playwright

        pw      = _sync_playwright().start()
        browser = pw.chromium.launch(headless=True, args=self._browser_args)
        ctx     = browser.new_context(**self._ctx_kwargs)

        if self._cookies:
            try:
                ctx.add_cookies(self._cookies)
            except Exception:
                pass
        ctx.add_init_script(self._init_script)

        # Queue-based response collection — ctx.on("response") fires on
        # Playwright's event loop thread.  We do only a pure-Python queue.put
        # here (safe) and never call any Playwright method (response.body etc.)
        # from this callback.  The owning worker thread drains the queue
        # synchronously via drain_thread_responses() between navigation steps.
        resp_queue: queue.Queue = queue.Queue()

        ctx.on("response", lambda r: resp_queue.put(
            (r, r.frame.url if r.frame else r.url)
        ))
        def _route_handler_pool(route):
            # route.abort()/continue_() go through Playwright's sync→async bridge
            # which tries to switch greenlets across OS thread boundaries — fatal.
            # Instead, schedule the coroutine directly on the already-running event
            # loop (we ARE on the event loop thread inside this callback), bypassing
            # the sync bridge entirely.
            import asyncio as _asyncio
            if self._block_fn(route.request.url, route.request.resource_type):
                _asyncio.ensure_future(route._impl_obj.abort())
            else:
                _asyncio.ensure_future(route._impl_obj.continue_())

        ctx.route("**/*", _route_handler_pool)

        page = ctx.new_page()

        # Gap 6: Auto-dismiss JS dialogs so alert()/confirm() don't stall visits.
        page.on("dialog", lambda d: d.accept() if d.type in ("alert", "beforeunload") else d.dismiss())

        # Gap 2: CDP Fetch interception for raw traffic capture.
        cdp: Optional[object] = None
        if self._cdp_request_fn is not None or self._cdp_response_fn is not None:
            cdp = _attach_cdp_fetch_interception(
                page,
                on_request_body_fn  = self._cdp_request_fn,
                on_response_body_fn = self._cdp_response_fn,
                resource_patterns   = ["*"],
            )

        return {
            "pw":         pw,
            "browser":    browser,
            "ctx":        ctx,
            "page":       page,
            "cdp":        cdp,
            "resp_queue": resp_queue,
        }

    def drain_thread_responses(self, slot: dict) -> int:
        """
        Drain all pending responses from the queue on the OWNING worker thread.

        Must be called from the same thread that called make_thread_browser().
        Calls self._response_fn(r, src) for each queued response — safe because
        we are on the Playwright-owning thread, so response.body() has the
        correct greenlet affinity.

        Returns the number of responses processed.
        """
        processed = 0
        resp_queue = slot["resp_queue"]
        while True:
            try:
                r, src = resp_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._response_fn(r, src)
            except Exception:
                pass
            processed += 1
        return processed

    def close_thread_browser(self, slot: dict) -> None:
        """
        Tear down the Playwright stack created by make_thread_browser().
        Must be called from the same worker thread that created it.
        Drain responses (drain_thread_responses) BEFORE calling this so no
        pending response bodies are lost when ctx.close() invalidates them.
        """
        # Gap 2 cleanup
        _detach_cdp_session(slot.get("cdp"))
        try:
            slot["ctx"].close()
        except Exception:
            pass
        try:
            slot["browser"].close()
        except Exception:
            pass
        try:
            slot["pw"].stop()
        except Exception:
            pass

    def acquire(self) -> None:
        """Block until a concurrency slot is free."""
        self._sem.acquire()

    def release(self) -> None:
        """Release a concurrency slot."""
        self._sem.release()

    def close_all(self) -> None:
        """No-op — each worker thread tears down its own browser."""
        pass


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
        target_url:         str,
        scope,
        timeout:            int   = 30,
        stealth:            bool  = False,
        max_pages:          int   = 100,
        interact:           bool  = False,
        workers:            int   = 3,
        external_seen:      Set[str]   = None,
        cookies:            List[dict] = None,
        extra_headers:      dict       = None,
        seen_hashes:        Set[str]   = None,
        # ── Katana enhancements ─────────────────────────────────────────────
        max_failures:       int   = 10,    # MaxFailureCount: halt after N consecutive action failures
        max_crawl_duration: int   = 0,     # MaxCrawlDuration in seconds (0 = unlimited); starts AFTER auth
        enable_diagnostics: bool  = False, # DiagnosticsWriter: screenshots + action log
        slow_mo:            int   = 0,     # SlowMotion: ms to sleep between interactions (0 = off)
        captcha_handler     = None,        # Optional callable(page) -> bool; called when captcha detected
        cookie_consent_bypass: bool = True, # Auto-dismiss GDPR consent banners before crawling
        # New Katana enhancements (session 2)
        auth_steps:         Optional[List["LoginStep"]] = None,  # Recorded auth flow replay
        page_load_strategy: str   = "domcontentloaded",          # eager/domcontentloaded/load/networkidle
        hooks:              Optional["CrawlHooks"] = None,        # Lifecycle callback hooks
        # New Katana enhancements (session 3)
        cookie_jar_path:    Optional[str]  = None,   # Path to Netscape cookie file (Burp export)
        url_filter_similar: bool           = False,  # Enable URL structural dedup (PathTrie)
        url_filter_threshold: int          = 3,      # PathTrie wildcard threshold (default 3)
        response_body_extract: bool        = True,   # Parse response bodies for embedded URLs
        # New Katana enhancements (session 4)
        max_onclick_links:         int   = 50,   # Max a[onclick] links to simulate per page (0=disabled)
        capture_raw_traffic:       bool  = False, # Store raw HTTP req/resp bytes alongside api_calls
        content_similarity_threshold: float = 0.0, # Skip pages with >X% structural similarity (0=disabled)
        technology_detection:      bool  = False, # Enable per-response tech fingerprinting
        # Form interaction engine
        forms_mode:                bool  = False, # Enable Tier 2 form interaction (POST forms)
        # Browser pool
        num_browsers:              int   = 5,     # Parallel browser instances (default 5)
    ):
        self.target_url  = target_url
        self.scope       = scope
        self.timeout     = timeout
        self.stealth     = stealth
        self.max_pages   = max_pages
        self.interact    = interact
        self.num_workers = max(1, min(workers, 5))
        self.num_browsers = max(1, num_browsers)
        self.cookies       = cookies or []        # Playwright cookie dicts
        self.extra_headers = _parse_extra_headers(extra_headers)
        self.seen_hashes   = seen_hashes or set()

        # Katana enhancement params
        self.max_failures          = max(1, max_failures)
        self.max_crawl_duration    = max(0, max_crawl_duration)
        self.enable_diagnostics    = enable_diagnostics
        self.slow_mo               = max(0, slow_mo)
        self.captcha_handler       = captcha_handler
        self.cookie_consent_bypass = cookie_consent_bypass
        # Session 2 Katana enhancements
        self.auth_steps            = auth_steps or []
        self.page_load_strategy    = page_load_strategy or "domcontentloaded"
        self.hooks                 = hooks or CrawlHooks()
        self._logged_in:      bool = False   # loggedIn flag — avoids re-auth mid-crawl

        # Session 3 Katana enhancements
        self.cookie_jar_path       = cookie_jar_path
        self.url_filter_similar    = url_filter_similar
        self.url_filter_threshold  = max(1, url_filter_threshold)
        self.response_body_extract = response_body_extract

        # Session 4 Katana enhancements
        self.max_onclick_links        = max_onclick_links
        self.capture_raw_traffic      = capture_raw_traffic
        self.content_similarity_threshold = content_similarity_threshold
        self.technology_detection     = technology_detection
        # Form interaction engine (Tier 1 always on; Tier 2 when forms_mode=True)
        self.form_interactor = FormInteractor(tier2_enabled=forms_mode)
        # Raw traffic capture store
        self._raw_traffic: List[dict] = []
        self._raw_lock: threading.Lock = threading.Lock()
        # JS nav tracking
        self._js_nav_urls: List[str]  = []
        self._js_nav_lock: threading.Lock = threading.Lock()
        # Technology fingerprinting store {url -> [tech_names]}
        self._tech_detections: dict   = {}
        self._tech_lock: threading.Lock = threading.Lock()
        # Content similarity — simple seen-content fingerprint set
        self._content_hashes: Set[str] = set()

        # PathTrie — URL structural dedup (created only when enabled)
        self._path_trie: Optional[PathTrie] = (
            PathTrie(threshold=self.url_filter_threshold)
            if url_filter_similar else None
        )
        # PathTrie dedup tracking set — fingerprint -> bool (replaces URL seen check)
        self._trie_seen: Set[str] = set()

        # ResponseParser — parses every response body for embedded URLs
        # Instantiated once with the target origin and reused across all responses
        parsed_target = urlparse(target_url)
        _target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        self._response_parser: Optional[ResponseParser] = (
            ResponseParser(target_origin=_target_origin)
            if response_body_extract else None
        )
        # Lock-protected list of URLs discovered by the response parser that
        # haven't been fed to the BFS queue yet (drained in run())
        self._rp_discovered: List[str] = []
        self._rp_lock: threading.Lock  = threading.Lock()

        # Background JS fetch threads — _flush_page_intel() spawns daemon threads
        # to fetch <script src>, ES modules, workers, and service workers off the
        # Playwright thread.  We track every thread here so run() can join them all
        # after Phase 3 before taking the final js_files snapshot, preventing the
        # "0 JS" race where threads finish after the stats are already logged.
        self._bg_fetch_threads: List[threading.Thread] = []
        self._bg_fetch_lock:    threading.Lock          = threading.Lock()

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
        self.sse_urls:   List[str]     = []   # EventSource (SSE) endpoints
        self.nav_urls:   List[str]     = []   # history pushState/replaceState URLs
        self.routes:     Set[str]      = set()
        self.pages_visited: int        = 0
        # Total JS responses intercepted by the browser (before dedup).
        # js_files only counts NEW files not seen by the static crawler;
        # this counter tracks how many JS responses the browser actually
        # saw so the operator can distinguish "0 new" from "0 seen at all".
        self._js_intercepted_count: int = 0
        self.auth_result: Optional[dict] = None  # populated during run()
        self._seen_interact_states: Set[str] = set()  # DOM states already interacted with
        # Action queue — typed crawl actions for state-based exploration
        self._action_queue:   deque         = deque()
        self._seen_actions:   Set[str]      = set()

        # CrawlGraph — DAG of page states and action edges (Katana enhancement 1)
        self.crawl_graph: CrawlGraph = CrawlGraph()

        # DiagnosticsWriter — optional (Katana enhancement 11)
        self._diagnostics: Optional[DiagnosticsWriter] = (
            DiagnosticsWriter() if enable_diagnostics else None
        )

        # MaxCrawlDuration start time — set after auth completes (Katana enhancement 10)
        self._crawl_start_time: float = 0.0

        # Consecutive failure counter for MaxFailureCount guard (Katana enhancement 4)
        self._consecutive_failures: int = 0

        # Seed urls provided externally (from crawler/static analysis)
        self.seed_urls:  List[str]     = []
        self.external_seen = external_seen or set()

    # ── Katana enhancement helpers ────────────────────────────────────────────

    def _slow_mo_wait(self, page) -> None:
        """SlowMotion mode: inject a configurable delay between interactions.
        Only fires when slow_mo > 0. Used for visual debugging. (Enhancement 12)"""
        if self.slow_mo > 0:
            try:
                page.wait_for_timeout(self.slow_mo)
            except Exception:
                pass

    def _is_crawl_deadline_exceeded(self) -> bool:
        """MaxCrawlDuration: returns True if the crawl timer has expired.
        Timer starts after auth completes — not at run() entry. (Enhancement 10)"""
        if self.max_crawl_duration <= 0 or self._crawl_start_time == 0.0:
            return False
        return (time.monotonic() - self._crawl_start_time) >= self.max_crawl_duration

    def _dismiss_cookie_consent(self, page) -> bool:
        """Cookie consent bypass: try to click an accept/allow button on the
        page and return True if one was found and clicked. Uses a priority-ordered
        list of selectors covering OneTrust, Cookiebot, Quantcast, IAB TCF, and
        generic button text patterns. (Enhancement 8)"""
        if not self.cookie_consent_bypass:
            return False
        for sel in CONSENT_SELECTORS:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.click(timeout=1000)
                    logger.debug("Cookie consent dismissed via: %s", sel)
                    page.wait_for_timeout(400)
                    return True
            except Exception:
                continue
        return False

    def _is_captcha_page(self, page) -> bool:
        """Captcha detection: checks for known captcha widgets and challenge
        page text markers. Returns True if a captcha is detected. (Enhancement 9)"""
        try:
            for sel in _CAPTCHA_SELECTORS:
                try:
                    if page.query_selector(sel):
                        return True
                except Exception:
                    pass
            # Text-based check on page body (catches Cloudflare IUAM, etc.)
            body_text = ""
            try:
                body_text = (page.evaluate("() => document.body.innerText") or "").lower()
            except Exception:
                pass
            if body_text and any(m in body_text for m in _CAPTCHA_TEXT_MARKERS):
                return True
        except Exception:
            pass
        return False

    def _handle_captcha(self, page) -> bool:
        """Handle captcha: call the optional captcha_handler, or just log and
        return False if no handler is configured. (Enhancement 9)"""
        if not self._is_captcha_page(page):
            return False
        logger.warning("Captcha detected on %s", page.url)
        if self.captcha_handler is not None:
            try:
                solved = self.captcha_handler(page)
                if solved:
                    logger.info("Captcha solver returned success")
                    return True
                else:
                    logger.warning("Captcha solver returned failure")
            except Exception as e:
                logger.warning("Captcha handler raised: %s", e)
        return False

    def _capture_session_state(self, page) -> dict:
        """Session delta verification: snapshot cookies + localStorage keys
        at a point in time. Compare before/after to confirm auth succeeded.
        (Enhancement 6)"""
        snap = {"cookies": [], "storage_keys": []}
        try:
            snap["cookies"] = [c["name"] for c in page.context.cookies()]
        except Exception:
            pass
        try:
            snap["storage_keys"] = page.evaluate(
                "() => Object.keys(window.localStorage || {})"
            )
        except Exception:
            pass
        return snap

    def _session_state_changed(self, before: dict, after: dict) -> bool:
        """Return True if the session state changed (new cookies or storage keys
        appeared), which confirms an auth flow established a session. (Enhancement 6)"""
        before_cookies = set(before.get("cookies", []))
        after_cookies  = set(after.get("cookies",  []))
        before_storage = set(before.get("storage_keys", []))
        after_storage  = set(after.get("storage_keys",  []))
        return bool(
            (after_cookies  - before_cookies)  or
            (after_storage  - before_storage)
        )

    def _navigate_back_to_state_origin(
        self, page, action: CrawlAction, stabilizer
    ) -> bool:
        """navigateBackToStateOrigin: if the browser is not on the page that
        owns this action (by URL and origin_id), navigate back and verify
        the DOM state matches before returning True.  Returns False if
        restoration fails. (Enhancement 3)"""
        # If already on the right URL, check the DOM state
        if page.url == action.url or page.url.rstrip("/") == action.url.rstrip("/"):
            if not action.origin_id:
                return True  # no origin_id to verify — assume ok
            current_fp = self._dom_fingerprint(page)
            if current_fp and current_fp[:16] == action.origin_id:
                return True  # browser is on the correct state
            # Same URL but DOM changed — the SPA transitioned; navigate back
        # Navigate to the action's source URL
        try:
            page.goto(action.url, timeout=self.timeout * 1000,
                      wait_until="domcontentloaded")
            stabilizer.wait_for_framework(max_ms=2000)
        except Exception as e:
            logger.debug("navigateBackToStateOrigin: goto failed for %s: %s",
                         action.url, e)
            return False
        # Verify the DOM fingerprint if we have an origin_id
        if action.origin_id:
            fp = self._dom_fingerprint(page)
            if fp and fp[:16] != action.origin_id:
                logger.debug(
                    "navigateBackToStateOrigin: state mismatch after navigate "
                    "(expected %s, got %s) for %s",
                    action.origin_id, fp[:16], action.url,
                )
                # Mismatch is non-fatal: SPA state may differ — log and continue
        return True

    def _check_element_interactable(self, page, el) -> bool:
        """Interactability check: verify the element is not covered by an overlay
        (modal, cookie banner, spinner) before clicking it.  Mirrors Katana's
        CoveredError / interactability check. (Enhancement 5)

        Returns True if the element is safe to click.
        """
        try:
            box = el.bounding_box()
            if not box:
                return False
            # Sample the center point and check if elementFromPoint returns
            # the same element or a descendant, meaning no overlay is in the way.
            cx = box["x"] + box["width"]  / 2
            cy = box["y"] + box["height"] / 2
            covered = page.evaluate(
                """([cx, cy]) => {
                    var top = document.elementFromPoint(cx, cy);
                    if (!top) return true;  // no element = covered
                    // walk up to see if the hit target is the same element
                    var probe = top;
                    while (probe) {
                        if (probe === arguments[0]) return false;  // not covered
                        probe = probe.parentElement;
                    }
                    return true;  // covered by something else
                }""",
                [cx, cy],
            )
            return not covered
        except Exception:
            # If the check fails we fall back to attempting the click anyway
            return True

    # ── Session 2 Katana enhancement helpers ─────────────────────────────────

    def _scroll_into_view(self, page, el) -> None:
        """Universal ScrollIntoView — call before every click, not just Phase 3.
        Mirrors Katana's ScrollIntoView() call before every action.
        Falls back silently if the element is gone or raises. (Enhancement 6)"""
        try:
            el.scroll_into_view_if_needed(timeout=600)
        except Exception:
            try:
                # Fallback: use JS scrollIntoView in case Playwright can't do it
                page.evaluate("el => el.scrollIntoView({block:'center',behavior:'instant'})", el)
            except Exception:
                pass

    def _classify_click_error(self, e: Exception, page=None, el=None) -> Exception:
        """Classify a click failure into a typed error subclass so that the
        recovery path can be specific to the root cause.
        (Enhancement 3 — typed click error classification)

        Returns one of:
          ElementCoveredError        — overlay is in the way
          ElementInvisibleError      — element not visible / no bounding box
          ElementNoPointerEventsError — pointer-events:none
          the original exception     — anything else (network, timeout, etc.)
        """
        msg = str(e).lower()

        # Check pointer-events via computed style if we have element + page
        if el is not None and page is not None:
            try:
                pe = page.evaluate(
                    "el => window.getComputedStyle(el).pointerEvents", el
                )
                if pe == "none":
                    return ElementNoPointerEventsError(str(e))
            except Exception:
                pass

        # Check bounding box — zero-size means invisible
        if el is not None:
            try:
                box = el.bounding_box()
                if not box or (box["width"] == 0 and box["height"] == 0):
                    return ElementInvisibleError(str(e))
            except Exception:
                pass

        # Playwright error messages for covered / invisible
        if any(k in msg for k in ("covered", "intercept", "obscured", "overlapping",
                                   "blocked by", "other element")):
            return ElementCoveredError(str(e))

        if any(k in msg for k in ("not visible", "invisible", "hidden",
                                   "display: none", "visibility: hidden")):
            return ElementInvisibleError(str(e))

        if "pointer-events" in msg:
            return ElementNoPointerEventsError(str(e))

        return e

    def _has_terminal_visible_assertion(self, steps: List[LoginStep]) -> bool:
        """Return True if any step in the recorded flow is an assert_visible step.
        A terminal visible assertion is an explicit UI check that login succeeded
        (e.g. 'Welcome back' is visible). Mirrors HasTerminalVisibleAssertion in
        Katana. (Enhancement 5)"""
        return any(s.step_type == "assert_visible" for s in steps)

    def _run_recorded_auth_flow(self, page, stabilizer) -> bool:
        """Replay a recorded authentication flow (multi-step SSO/MFA).
        Mirrors Katana's auth.StepsFromFile + replay loop.

        Executes each LoginStep in order:
          navigate        — page.goto(url)
          fill            — locator(selector).fill(value)
          click           — locator(selector).click()
          wait            — page.wait_for_timeout(timeout_ms)
          assert_visible  — assert element/text is visible (terminal assertion)

        Returns True if the flow completed AND either:
          - A terminal visible assertion passed, OR
          - The session state changed (cookies / localStorage delta)
        Returns False on any step failure or assertion failure.
        (Enhancement 1 — Recorded auth flow replay)"""
        if not self.auth_steps:
            return False

        logger.info("Recorded auth flow: %d steps", len(self.auth_steps))
        session_before = self._capture_session_state(page)

        for i, step in enumerate(self.auth_steps):
            try:
                if step.step_type == "navigate":
                    target = step.url or self.target_url
                    page.goto(target, timeout=step.timeout_ms or self.timeout * 1000,
                              wait_until=self.page_load_strategy)
                    stabilizer.wait_for_framework(max_ms=1500)
                    logger.debug("Auth step %d navigate: %s", i, target)

                elif step.step_type == "fill":
                    page.locator(step.selector).fill(
                        step.value, timeout=step.timeout_ms
                    )
                    logger.debug("Auth step %d fill: %s", i, step.selector)

                elif step.step_type == "click":
                    loc = page.locator(step.selector)
                    loc.scroll_into_view_if_needed(timeout=500)
                    loc.click(timeout=step.timeout_ms)
                    stabilizer.wait_after_interaction(max_ms=1500)
                    logger.debug("Auth step %d click: %s", i, step.selector)

                elif step.step_type == "wait":
                    page.wait_for_timeout(step.timeout_ms)
                    logger.debug("Auth step %d wait: %dms", i, step.timeout_ms)

                elif step.step_type == "assert_visible":
                    # Terminal visible assertion — confirm login succeeded by
                    # checking that a success indicator is visible on-screen.
                    if step.assertion_text:
                        try:
                            page.get_by_text(step.assertion_text).wait_for(
                                state="visible", timeout=step.timeout_ms
                            )
                            logger.info(
                                "Auth step %d assert_visible PASSED: '%s'",
                                i, step.assertion_text,
                            )
                        except Exception as ae:
                            logger.warning(
                                "Auth step %d assert_visible FAILED: '%s' not visible — %s",
                                i, step.assertion_text, ae,
                            )
                            return False
                    elif step.selector:
                        try:
                            page.locator(step.selector).wait_for(
                                state="visible", timeout=step.timeout_ms
                            )
                            logger.info(
                                "Auth step %d assert_visible PASSED: selector '%s'",
                                i, step.selector,
                            )
                        except Exception as ae:
                            logger.warning(
                                "Auth step %d assert_visible FAILED: '%s' — %s",
                                i, step.selector, ae,
                            )
                            return False
                else:
                    logger.warning("Unknown auth step type '%s', skipping", step.step_type)

            except Exception as e:
                logger.warning("Auth step %d (%s) failed: %s", i, step.step_type, e)
                return False

        # Check session delta — did cookies / localStorage change?
        session_after = self._capture_session_state(page)
        delta = self._session_state_changed(session_before, session_after)

        # If the flow had a terminal visible assertion AND it passed (we didn't
        # return False above), the flow succeeded regardless of session delta.
        has_terminal = self._has_terminal_visible_assertion(self.auth_steps)

        if delta:
            logger.info("Recorded auth flow: session delta confirmed — authenticated")
            return True
        if has_terminal:
            logger.info("Recorded auth flow: terminal assertion passed — authenticated")
            return True

        logger.warning(
            "Recorded auth flow: completed but no session delta and no terminal "
            "assertion — assuming NOT authenticated"
        )
        return False

    def _submit_login_form(self, page) -> bool:
        """Find and click the submit button on a login form.
        Tries common submit selector patterns in priority order.
        Returns True if a submit button was clicked. (Enhancement 2 helper)"""
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Login")',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button:has-text("Submit")',
            'button:has-text("Continue")',
            '[data-testid*="submit"]',
            '[data-testid*="login"]',
            'form button',  # last resort: any button in a form
        ]
        for sel in submit_selectors:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible() and el.is_enabled():
                    el.scroll_into_view_if_needed(timeout=400)
                    el.click(timeout=1500)
                    logger.debug("_submit_login_form: clicked '%s'", sel)
                    return True
            except Exception:
                continue
        return False

    def _try_auto_login(self, page, stabilizer) -> bool:
        """DIT-style auto-login fallback — called when the recorded flow fails
        or no recorded flow exists but we land on a login page.

        Attempts to fill detected username/password fields and submit.
        Uses the same DIT classifier patterns as Katana's auto-login.
        Only attempted when we have a user:pass from an auth header or the
        caller injected credentials via a special auth_credentials dict.
        Returns True if a session delta confirms login. (Enhancement 2)"""
        # Require a stored credential pair — look for "Authorization: Basic"
        # header or an "auth_credentials" attribute set externally
        cred_pair = getattr(self, "auth_credentials", None)
        if not cred_pair:
            # Try extracting from extra_headers Basic auth
            for k, v in (self.extra_headers or {}).items():
                if k.lower() == "authorization" and v.lower().startswith("basic "):
                    import base64
                    try:
                        decoded = base64.b64decode(v[6:]).decode("utf-8", errors="replace")
                        if ":" in decoded:
                            u, p = decoded.split(":", 1)
                            cred_pair = {"username": u, "password": p}
                    except Exception:
                        pass
                    break
        if not cred_pair:
            logger.debug("_try_auto_login: no credentials available, skipping")
            return False

        username = cred_pair.get("username", "")
        password = cred_pair.get("password", "")
        if not username or not password:
            return False

        logger.info("Auto-login fallback: attempting on %s", page.url)
        session_before = self._capture_session_state(page)

        # Fill username
        user_selectors = [
            'input[type="email"]',
            'input[name="username"]',
            'input[name="email"]',
            'input[name="user"]',
            'input[id*="username"]',
            'input[id*="email"]',
            'input[placeholder*="username" i]',
            'input[placeholder*="email" i]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]',
        ]
        filled_user = False
        for sel in user_selectors:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.fill(username, timeout=1000)
                    filled_user = True
                    logger.debug("Auto-login: filled username via '%s'", sel)
                    break
            except Exception:
                continue

        if not filled_user:
            logger.debug("Auto-login: could not find username field")
            return False

        # Fill password
        pass_selectors = [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="pass"]',
            'input[id*="password"]',
            'input[autocomplete="current-password"]',
            'input[autocomplete="password"]',
        ]
        filled_pass = False
        for sel in pass_selectors:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.fill(password, timeout=1000)
                    filled_pass = True
                    logger.debug("Auto-login: filled password via '%s'", sel)
                    break
            except Exception:
                continue

        if not filled_pass:
            logger.debug("Auto-login: could not find password field")
            return False

        # Submit form
        submitted = self._submit_login_form(page)
        if not submitted:
            logger.debug("Auto-login: could not find submit button")
            return False

        # Wait for navigation / SPA transition
        try:
            stabilizer.wait_for_framework(max_ms=3000)
        except Exception:
            pass

        # Verify via session delta
        session_after = self._capture_session_state(page)
        if self._session_state_changed(session_before, session_after):
            logger.info("Auto-login: session delta confirmed — authenticated")
            return True

        logger.debug("Auto-login: no session delta — login may have failed")
        return False

    def _detect_sub_pages(self, ctx, stabilizer, source_url: str) -> None:
        """Register a listener on the browser context that captures new pages
        (popups, new tabs) opened by JavaScript (window.open, target=_blank links).
        For each sub-page that opens, we wait for it to load, flush its intel,
        and record it in the crawl graph.
        (Enhancement 10 — Sub-page detection)"""
        def _on_new_page(new_page):
            try:
                sub_stabilizer = PageStabilizer(new_page)
                sub_stabilizer.wait_for_framework(max_ms=3000)
                sub_url = new_page.url
                if not sub_url or sub_url in ("about:blank", ""):
                    return
                logger.debug("Sub-page detected: %s (from %s)", sub_url, source_url)
                # Scope check
                from ..safety.network import validate_url as _vurl
                safe, _ = _vurl(sub_url)
                if not safe or not self.scope.in_scope(sub_url):
                    return
                # Register URL
                if not self.registry.register_url(sub_url):
                    return  # already seen
                # Add route
                parsed_sub = urlparse(sub_url)
                route = parsed_sub.path or "/"
                self._add_route(route)
                # Flush intel from the sub-page
                try:
                    new_routes = self._flush_page_intel(new_page, sub_url)
                    for r in new_routes:
                        self._add_route(r)
                except Exception as e:
                    logger.debug("Sub-page intel flush error %s: %s", sub_url, e)
                # Register in CrawlGraph
                fp = self._dom_fingerprint(new_page)
                if fp:
                    self.crawl_graph.add_page_state(fp[:16], sub_url, depth=1)
                with self._lock:
                    self.pages_visited += 1
                # Fire on_navigation hook
                if self.hooks.on_navigation:
                    try:
                        self.hooks.on_navigation(sub_url)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug("Sub-page handler error: %s", e)
            finally:
                try:
                    new_page.close()
                except Exception:
                    pass

        try:
            ctx.on("page", _on_new_page)
            logger.debug("Sub-page detection listener registered")
        except Exception as e:
            logger.debug("Sub-page listener registration failed: %s", e)

    # ─────────────────────────────────────────────────────────────────────────

    def _add_js_file(self, js_file: JSFile) -> bool:
        """Thread-safe JS file registration."""
        if not self.registry.register_hash(js_file.sha256):
            return False
        with self._lock:
            self.js_files.append(js_file)
        return True

    def _add_route(self, route: str) -> bool:
        """Thread-safe route registration. Returns True if new.

        For routes with a query string, also registers the bare path so coverage
        stats count the path once — but only when the bare path differs from the
        full route, otherwise the two register_route() calls see the same string
        and the second always returns False, preventing anything from being added.
        """
        path_only = route.split("?")[0]
        # Register bare path for coverage stats ONLY when route has a query string.
        # If path_only == route (no query), skip this call — we do it below.
        if path_only != route:
            self.registry.register_route(path_only)
        # Register the full route (or bare path when no query) for dedup.
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
        Capture JS files and extract embedded URLs from every network response.

        Two responsibilities:
        1. ResponseParser — parse every response body for URLs not visible in the DOM
           (Katana enhancement: response body URL extraction). Discovered URLs are
           staged into self._rp_discovered and drained into the BFS queue in run().
        2. JS capture — three-layer detection, body dedup, JS file creation (existing).
        """
        try:
            url           = response.url
            ct            = response.headers.get("content-type", "")
            resource_type = response.request.resource_type

            # ── Shared response body fetch (ResponseParser + tech fingerprinting) ─
            # Fetched once and reused to avoid calling response.body() twice.
            _resp_body: Optional[bytes] = None
            if self._response_parser is not None or self.technology_detection or self.capture_raw_traffic:
                try:
                    _resp_body = response.body()
                except Exception:
                    _resp_body = None

            # ── ResponseParser: extract embedded URLs from every response ────────
            # Runs on ALL responses (HTML, JS, JSON, CSS) — before the JS-only
            # guard below — so we harvest routes that live in non-JS responses too.
            if self._response_parser is not None and _resp_body:
                try:
                    found = self._response_parser.extract(url, ct, _resp_body)
                    if found:
                        with self._rp_lock:
                            self._rp_discovered.extend(found)
                        logger.debug(
                            "ResponseParser: %d URLs from %s", len(found), url
                        )
                except Exception as rp_err:
                    logger.debug("ResponseParser error for %s: %s", url, rp_err)

            # Technology fingerprinting — Katana hybrid feature 6
            if self.technology_detection and _resp_body is not None:
                try:
                    techs = self._fingerprint_technologies(url, dict(response.headers), _resp_body)
                    if techs:
                        page_url = source_page or url
                        with self._tech_lock:
                            existing = self._tech_detections.get(page_url, [])
                            self._tech_detections[page_url] = list(set(existing + techs))
                except Exception as tech_err:
                    logger.debug("Technology detection error for %s: %s", url, tech_err)

            # Raw capture — store request+response bytes alongside api_call entries
            # Katana's FetchRequestStageResponse captures full wire-level traffic;
            # we approximate with Playwright's response object fields.
            if self.capture_raw_traffic and _resp_body is not None:
                try:
                    req  = response.request
                    resp = response
                    # Build raw request representation
                    req_headers = "\r\n".join(
                        f"{k}: {v}" for k, v in (req.headers or {}).items()
                    )
                    post_data = ""
                    try:
                        post_data = req.post_data or ""
                    except Exception:
                        pass
                    raw_req = (
                        f"{req.method} {req.url} HTTP/1.1\r\n"
                        f"{req_headers}\r\n\r\n"
                        f"{post_data}"
                    )
                    # Build raw response representation
                    resp_headers = "\r\n".join(
                        f"{k}: {v}" for k, v in (resp.headers or {}).items()
                    )
                    resp_body_str = _resp_body.decode("utf-8", errors="replace")[:4096] if _resp_body else ""
                    raw_resp = (
                        f"HTTP/1.1 {resp.status}\r\n"
                        f"{resp_headers}\r\n\r\n"
                        f"{resp_body_str}"
                    )
                    with self._raw_lock:
                        self._raw_traffic.append({
                            "url":          url,
                            "method":       req.method,
                            "status":       resp.status,
                            "raw_request":  raw_req,
                            "raw_response": raw_resp,
                            "source_page":  source_page,
                        })
                except Exception as raw_err:
                    logger.debug("Raw capture error for %s: %s", url, raw_err)

            # ── JS capture (original logic unchanged) ────────────────────────────
            if not self._is_js_response(url, ct, resource_type):
                return

            # Skip cross-origin JS that's outside our scope
            safe, _ = validate_url(url)
            if not safe or not self.scope.in_scope(url):
                return

            # Count every in-scope JS response the browser saw, before dedup.
            # This lets us distinguish "0 new (all already found by static
            # crawler)" from "0 seen at all", which is an important operator
            # signal.  Thread-safe: use the existing self._lock.
            with self._lock:
                self._js_intercepted_count += 1

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
        Checks visible text, href path segments, id, and class — same approach
        as Katana's isLogoutPage() which catches CSS-icon logout buttons whose
        visible text is empty but whose href is /logout or /signout.
        """
        try:
            text  = (element.inner_text() or "").lower().strip()
            href  = (element.get_attribute("href")  or "").lower()
            eid   = (element.get_attribute("id")    or "").lower()
            cls   = (element.get_attribute("class") or "").lower()
            # Check href path segments specifically — catches icon-only buttons
            href_path = urlparse(href).path if href.startswith("/") else href
            combined = f"{text} {href_path} {eid} {cls}"
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

    def _queue_action(self, action: CrawlAction) -> bool:
        """
        Queue a typed crawl action. Returns True if new, False if already seen.
        Thread-safe.
        """
        k = action.key()
        with self._lock:
            if k in self._seen_actions:
                return False
            self._seen_actions.add(k)
            self._action_queue.append(action)
        return True

    def _discover_form_actions(self, page, source_url: str) -> None:
        """
        Discover forms on the current page and queue them as FILL_FORM actions
        for dedicated follow-up crawling — same pattern Katana uses for FillForm
        action type. This ensures form-triggered API calls are captured even if
        the form wasn't visible during the main page visit.

        Sets origin_id from the current DOM fingerprint so Phase 3 can verify
        the browser is on the correct state before executing (OriginID pattern).
        """
        # Capture DOM fingerprint at discovery time — used as OriginID (Enhancement 2)
        origin_id = ""
        try:
            fp = self._dom_fingerprint(page)
            if fp:
                origin_id = fp[:16]
                self.crawl_graph.add_page_state(origin_id, source_url)
        except Exception:
            pass

        try:
            forms = page.evaluate("""
                (function() {
                    var results = [];
                    // Real <form> tags + div.form pseudo-forms (common on React/Vue apps)
                    var real   = Array.from(document.querySelectorAll('form'));
                    var pseudo = Array.from(document.querySelectorAll('div.form, [role="form"]'));
                    // Deduplicate - pseudo might overlap with real
                    var seen = new Set();
                    var all  = real.concat(pseudo.filter(function(el) { return !seen.has(el) && !seen.add(el); }));
                    all.forEach(function(f, i) {
                        var action = f.getAttribute('action') || '';
                        var id     = f.getAttribute('id')     || '';
                        var cls    = f.getAttribute('class')  || '';
                        var ctx    = (action + id + cls).toLowerCase();
                        results.push({
                            idx:    i,
                            action: action,
                            id:     id,
                            cls:    cls,
                            ctx:    ctx,
                            pseudo: f.tagName !== 'FORM',
                        });
                    });
                    return results;
                })()
            """) or []
        except Exception:
            return

        skip_kws = SKIP_FORM_CONTEXTS
        for f in forms:
            ctx = f.get("ctx", "")
            if any(kw in ctx for kw in skip_kws):
                continue
            # pseudo-forms (div.form, role=form) use a different selector
            if f.get("pseudo"):
                fid = f.get("id", "")
                if fid:
                    selector = f"#{fid}"
                else:
                    selector = f"div.form:nth-of-type({f['idx'] + 1})"
            else:
                selector = f"form:nth-of-type({f['idx'] + 1})"
            action = CrawlAction(
                action_type=ActionType.FILL_FORM,
                url=source_url,
                selector=selector,
                parent_url=source_url,
                origin_id=origin_id,
            )
            if self._queue_action(action):
                self.crawl_graph.add_edge(action)  # register in CrawlGraph

    def _discover_click_actions(self, page, source_url: str) -> None:
        """
        Discover clickable elements and queue them as LEFT_CLICK actions.

        Two sources:
        1. Static DOM scan - buttons/roles/onclick/data-action attributes
        2. __bundlespy_listeners - elements that only have JS addEventListener
           registrations and no visible HTML attribute (the majority of elements
           on modern React/Vue/Angular apps)
        """
        # Capture DOM fingerprint at discovery time - used as OriginID
        origin_id = ""
        try:
            fp = self._dom_fingerprint(page)
            if fp:
                origin_id = fp[:16]
                self.crawl_graph.add_page_state(origin_id, source_url)
        except Exception:
            pass

        # ── Source 1: static DOM scan ─────────────────────────────────────────
        static_elements = []
        try:
            static_elements = page.evaluate("""
                (function() {
                    var results = [];
                    var seen    = new Set();
                    var sels    = [
                        'button:not([type="submit"]):not([form])',
                        '[role="button"]:not(a)',
                        '[data-action]',
                        '[data-target]',
                        '[onclick]',
                    ];
                    sels.forEach(function(sel) {
                        try {
                            document.querySelectorAll(sel).forEach(function(el, i) {
                                var txt = (el.innerText || '').trim().toLowerCase();
                                var id  = el.getAttribute('id')    || '';
                                var cls = el.getAttribute('class') || '';
                                var key = txt + '|' + id + '|' + cls;
                                if (seen.has(key) || !txt) return;
                                seen.add(key);
                                results.push({
                                    cssSelector: sel + ':nth-of-type(' + (i + 1) + ')',
                                    text:        txt,
                                });
                            });
                        } catch(e) {}
                    });
                    return results.slice(0, 30);
                })()
            """) or []
        except Exception:
            pass

        # ── Source 2: dynamically registered event listener targets ───────────
        # These are elements discovered by the addEventListener hook injected at
        # page load. They only exist as JS listener targets - no HTML marker.
        listener_elements = []
        try:
            raw = page.evaluate("window.__bundlespy_listeners || []") or []
            seen_css = set()
            for rec in raw:
                if not isinstance(rec, dict):
                    continue
                css = rec.get("cssSelector", "")
                if not css or css in seen_css:
                    continue
                txt = (rec.get("textContent") or "").strip().lower()
                # Skip elements with no text and no id - too ambiguous to target
                if not txt and not rec.get("id"):
                    continue
                seen_css.add(css)
                listener_elements.append({
                    "cssSelector": css,
                    "text":        txt,
                })
        except Exception:
            pass

        # ── Merge, deduplicate, and queue ─────────────────────────────────────
        seen_selectors: Set[str] = set()
        all_candidates = static_elements + listener_elements

        for el in all_candidates:
            selector = el.get("cssSelector", "")
            text     = el.get("text", "")
            if not selector or selector in seen_selectors:
                continue
            seen_selectors.add(selector)

            if any(kw in text for kw in DESTRUCTIVE_KEYWORDS):
                continue
            if any(kw in text for kw in LOGOUT_KEYWORDS):
                continue

            action = CrawlAction(
                action_type=ActionType.LEFT_CLICK,
                url=source_url,
                selector=selector,
                parent_url=source_url,
                origin_id=origin_id,
            )
            if self._queue_action(action):
                self.crawl_graph.add_edge(action)

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

    def _extract_sse_urls(self, page) -> List[str]:
        """Extract EventSource (SSE) endpoint URLs captured at page load."""
        try:
            r = page.evaluate("window.__bundlespy_sse || []")
            return [x["url"] for x in r if isinstance(x, dict) and "url" in x]
        except Exception:
            return []

    def _extract_nav_urls(self, page) -> List[str]:
        """Extract client-side route URLs from history.pushState / replaceState calls."""
        try:
            r = page.evaluate("window.__bundlespy_nav || []")
            return [x["url"] for x in r if isinstance(x, dict) and "url" in x]
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
        Form interaction engine — delegates to FormInteractor (Tier 1 + Tier 2).

        Tier 1 (always active):
          - GET forms only
          - Search / filter / query fields only
          - Safe dummy values — never real PII
          - Submits via keyboard Enter to capture GET navigation URLs, then
            navigates back so the crawl continues on the original page

        Tier 2 (active when --forms flag was passed, i.e. engine.form_interactor.tier2_enabled):
          - POST forms included, after intent classification
          - Safe intents only: search, contact, newsletter, login, registration
          - Never touches payment / checkout / delete / transfer forms
          - Never fills destructive or sensitive fields (password only in login flows,
            never card/cvv/amount/ssn/pin)
          - Fills fields to trigger JS reactions — does NOT submit POST forms

        Any new routes found via GET form submission are fed back into the BFS queue.
        """
        source_url = page.url
        # Block form.reset() during fill - prevent JS from wiping our values
        try:
            page.evaluate("window.__bundlespy_prevent_reset = true;")
        except Exception:
            pass
        try:
            page_report = self.form_interactor.interact_page(
                page, stabilizer, source_url=source_url,
            )
        except Exception as e:
            logger.debug("form_interactor.interact_page error: %s", e)
            return
        finally:
            try:
                page.evaluate("window.__bundlespy_prevent_reset = false;")
            except Exception:
                pass

        # Feed discovered GET-form routes back into the BFS queue
        for route in page_report.new_routes:
            self._add_route(route)

        if page_report.forms_interacted > 0:
            logger.debug(
                "forms: %d found, %d interacted, %d skipped, %d new routes — %s",
                page_report.forms_found,
                page_report.forms_interacted,
                page_report.forms_skipped,
                len(page_report.new_routes),
                source_url,
            )

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
            sse_urls    = self._extract_sse_urls(page)
            nav_urls    = self._extract_nav_urls(page)
            worker_urls = self._extract_worker_urls(page)
            iframe_urls = self._extract_iframe_urls(page)

            with self._lock:
                self.api_calls.extend(api_calls)
                self.ws_urls.extend(ws_urls)
                self.sse_urls.extend(sse_urls)
                self.nav_urls.extend(nav_urls)

            # SSE and nav paths become routes
            parsed_tgt = urlparse(self.target_url)
            tgt_origin  = f"{parsed_tgt.scheme}://{parsed_tgt.netloc}"
            for raw_url in sse_urls + nav_urls:
                try:
                    if raw_url.startswith(tgt_origin):
                        _p = urlparse(raw_url)
                        new_routes.add((_p.path or "/") + (("?" + _p.query) if _p.query else ""))
                    elif raw_url.startswith("/"):
                        new_routes.add(raw_url)
                except Exception:
                    pass

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
        """Convert routes to full URLs, sorted by priority. Filters parametric routes.

        Routes may be bare paths (/about), paths with query strings
        (/projects?category=foo), or absolute URLs (https://...).
        Query strings are preserved — they represent distinct filterable
        pages that differ in content (Katana gap fix).
        """
        parsed = urlparse(self.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        urls   = []
        for route in routes:
            # _is_parametric_route only checks path segments — strip query first
            path_only = route.split("?")[0]
            # Skip framework-level route definitions — they're not real URLs
            if self._is_parametric_route(path_only):
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
            "session_delta":        False,  # True if cookies/storage changed (Enhancement 6)
        }

        if not result["credentials_supplied"]:
            # Anonymous scan — skip verification entirely
            return result

        # Session delta: snapshot state before navigation (Enhancement 6)
        session_before = self._capture_session_state(page)

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

            # Session delta: compare after navigation — confirms auth established (Enhancement 6)
            session_after = self._capture_session_state(page)
            result["session_delta"] = self._session_state_changed(session_before, session_after)
            if result["session_delta"]:
                logger.debug("Session delta confirmed: cookies/storage changed after auth navigation")

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
        Structural DOM fingerprint — hashes tag structure, not content.

        Two SPA pages with the same layout (same component) but different data
        (different product IDs) get the same hash and are treated as duplicates.
        This is the same principle as Katana's SimhashOracle.

        Structure signature: pathname + sorted tag-depth pairs from first 80
        elements + form count + input count. Ignores text content so product
        listing pages at /products/1 and /products/2 hash identically.
        """
        try:
            sig = page.evaluate("""
                (function() {
                    var path = window.location.pathname || '/';
                    // Structural walk — tag names + nesting depth, no text
                    var tags = [];
                    var walker = document.createTreeWalker(
                        document.body || document.documentElement,
                        NodeFilter.SHOW_ELEMENT,
                        null
                    );
                    var depth = 0;
                    var node  = walker.nextNode();
                    var count = 0;
                    while (node && count < 80) {
                        tags.push(node.tagName.toLowerCase());
                        node = walker.nextNode();
                        count++;
                    }
                    var forms  = document.querySelectorAll('form').length;
                    var inputs = document.querySelectorAll('input,select,textarea').length;
                    // Sort tags so order-independent structural equivalence is detected
                    var struct = tags.slice().sort().join(',');
                    return path + '|' + struct + '|f' + forms + '|i' + inputs;
                })()
            """)
            return hashlib.sha256((sig or "").encode()).hexdigest()[:16]
        except Exception:
            return ""

    def _simulate_onclick_links(self, page, source_url: str, max_links: int = 50) -> list:
        """
        Click every a[onclick] element and record URL changes — Katana hybrid approach.

        Standard crawlers miss JS redirects anchored to onclick handlers:
            <a href="#" onclick="window.location='/admin/dashboard'">Admin</a>

        Katana's navigateRequest() clicks each a[onclick] individually, records
        the URL drift after click, then navigates back. We do the same:
        1. Collect all a[onclick] selectors before clicking anything
        2. For each: click -> measure URL drift -> navigate back
        3. Return list of new URLs found (deduped, in-scope only)
        """
        new_urls = []
        try:
            # Collect href+onclick attrs without clicking yet
            onclick_links = page.evaluate("""
                () => {
                    var links = Array.from(document.querySelectorAll('a[onclick]'));
                    return links.slice(0, """ + str(max_links) + """).map(function(el, idx) {
                        return {
                            idx: idx,
                            href: el.href || '',
                            onclick: el.getAttribute('onclick') || '',
                            text: (el.textContent || '').trim().slice(0, 60)
                        };
                    });
                }
            """)
            if not onclick_links:
                return []

            parsed = urlparse(self.target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            pre_url = page.url

            for link_info in onclick_links:
                if self.pages_visited >= self.max_pages:
                    break
                idx = link_info.get("idx", 0)
                try:
                    # Re-query by index each time (DOM may have changed)
                    elements = page.query_selector_all("a[onclick]")
                    if idx >= len(elements):
                        continue
                    el = elements[idx]
                    if not el.is_visible():
                        continue
                    pre_click_url = page.url
                    # Click and briefly wait for any navigation
                    try:
                        el.click(timeout=500)
                    except Exception:
                        # click() may throw if it triggers navigation — that's fine
                        pass
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=1500)
                    except Exception:
                        pass
                    post_url = page.url
                    # URL drift — JS redirected us somewhere new
                    if post_url != pre_click_url and post_url != pre_url:
                        parsed_post = urlparse(post_url)
                        if parsed_post.netloc == parsed.netloc:
                            if self.scope.in_scope(post_url) and not self.registry.seen_url(post_url):
                                new_urls.append(post_url)
                                logger.debug(
                                    "onclick drift: %s -> %s",
                                    pre_click_url, post_url,
                                )
                    # Navigate back to source regardless of drift
                    if page.url != source_url:
                        try:
                            page.goto(source_url, timeout=self.timeout * 1000,
                                     wait_until="domcontentloaded")
                            page.wait_for_load_state("domcontentloaded", timeout=2000)
                        except Exception:
                            try:
                                page.go_back(timeout=3000)
                            except Exception:
                                pass
                except Exception as link_err:
                    logger.debug("onclick link %d error: %s", idx, link_err)
                    # Try to recover back to source
                    try:
                        if page.url != source_url:
                            page.goto(source_url, timeout=self.timeout * 1000,
                                     wait_until="domcontentloaded")
                    except Exception:
                        pass
        except Exception as e:
            logger.debug("onclick simulation error for %s: %s", source_url, e)
        return new_urls

    def _fingerprint_technologies(self, url: str, headers: dict, body_bytes: bytes) -> list:
        """
        Lightweight inline Wappalyzer-style technology fingerprinting.

        Checks response headers and body against signature patterns for common
        technologies. No external service — all patterns are inline regexes.
        Returns a list of detected technology names for this response.

        Katana runs Wappalyzer per-response in hybrid/crawl.go; we do the same
        with a curated inline fingerprint database covering the most common stacks.
        """
        import re as _re
        detected = []
        try:
            h = {k.lower(): v for k, v in (headers or {}).items()}
            body = ""
            try:
                body = body_bytes.decode("utf-8", errors="ignore")[:8192] if body_bytes else ""
            except Exception:
                pass

            _FINGERPRINTS = [
                # (tech_name, [(source, pattern)])
                # source: "header:<name>", "body"
                ("Django",        [("header:x-frame-options", r"SAMEORIGIN"),
                                  ("header:server",          r"WSGIServer|gunicorn"),
                                  ("body",                   r"csrfmiddlewaretoken|django")]),
                ("Rails",         [("header:x-powered-by",   r"Phusion Passenger"),
                                  ("header:server",          r"nginx|puma|thin"),
                                  ("body",                   r"csrf-token.*Rails|data-turbolinks")]),
                ("Laravel",       [("header:set-cookie",      r"laravel_session"),
                                  ("body",                   r"Laravel|Illuminate\\\\")]),
                ("WordPress",     [("body",                   r"/wp-content/|/wp-includes/|wp-json")]),
                ("Drupal",        [("header:x-generator",     r"Drupal"),
                                  ("body",                   r"Drupal\.settings|/sites/default/files/")]),
                ("Joomla",        [("body",                   r"/components/com_|Joomla!")]),
                ("Next.js",       [("header:x-powered-by",   r"Next\.js"),
                                  ("body",                   r"__NEXT_DATA__|/_next/static/")]),
                ("Nuxt.js",       [("body",                   r"__NUXT__|/_nuxt/")]),
                ("React",         [("body",                   r"react\.development\.js|react\.production\.min|__reactFiber|ReactDOM")]),
                ("Vue.js",        [("body",                   r"Vue\.js|vue\.min\.js|__vue__|v-bind:|v-on:")]),
                ("Angular",       [("body",                   r"ng-version=|angular\.min\.js|ng-app|ng-controller")]),
                ("Svelte",        [("body",                   r"__svelte|svelte/internal")]),
                ("jQuery",        [("body",                   r"jquery\.min\.js|jQuery v[0-9]|jquery-[0-9]")]),
                ("Bootstrap",     [("body",                   r"bootstrap\.min\.css|bootstrap\.bundle|getbootstrap\.com")]),
                ("GraphQL",       [("body",                   r'"__typename"|"query":\s*"query |graphql')]),
                ("Nginx",         [("header:server",          r"nginx")]),
                ("Apache",        [("header:server",          r"Apache")]),
                ("Express",       [("header:x-powered-by",   r"Express")]),
                ("ASP.NET",       [("header:x-powered-by",   r"ASP\.NET"),
                                  ("header:x-aspnet-version", r".")]),
                ("PHP",           [("header:x-powered-by",   r"PHP/"),
                                  ("body",                   r"\.php\?|PHPSESSID")]),
                ("Cloudflare",    [("header:cf-ray",          r".")]),
                ("Fastly",        [("header:x-served-by",     r"cache-")]),
                ("AWS CloudFront",[("header:x-amz-cf-id",     r".")]),
                ("Shopify",       [("header:x-shopify-stage", r"."),
                                  ("body",                   r"Shopify\.theme|cdn\.shopify\.com")]),
                ("Stripe",        [("body",                   r"stripe\.com/v3|Stripe\(")]),
                ("Google Analytics",[("body",                 r"gtag\(|ga\('create'|google-analytics\.com/analytics")]),
            ]
            for tech_name, patterns in _FINGERPRINTS:
                for source, pattern in patterns:
                    try:
                        if source.startswith("header:"):
                            hname = source[7:]
                            hval  = h.get(hname, "")
                            if hval and _re.search(pattern, hval, _re.IGNORECASE):
                                detected.append(tech_name)
                                break
                        elif source == "body":
                            if body and _re.search(pattern, body, _re.IGNORECASE):
                                detected.append(tech_name)
                                break
                    except Exception:
                        pass
        except Exception as e:
            logger.debug("Tech fingerprint error for %s: %s", url, e)
        return detected

    def _is_similar_content(self, page) -> bool:
        """
        Structural content similarity gate — skip near-duplicate pages.

        Uses a lightweight structural fingerprint (tag sequence + form count +
        link count) and checks Hamming distance against previously seen fingerprints.
        Threshold 0.0 = disabled. Threshold 0.85 = skip if 85%+ structurally similar.

        Katana's SimhashOracle uses simhash with configurable threshold; we use
        a simpler but effective structural hash approach that doesn't require
        external dependencies.
        """
        if self.content_similarity_threshold <= 0.0:
            return False
        try:
            sig = page.evaluate("""
                () => {
                    var tags = Array.from(document.querySelectorAll('*'))
                        .slice(0, 200)
                        .map(function(el) { return el.tagName.toLowerCase(); });
                    var forms  = document.querySelectorAll('form').length;
                    var links  = document.querySelectorAll('a').length;
                    var inputs = document.querySelectorAll('input').length;
                    var sorted = tags.slice().sort().join(',');
                    return sorted + '|f' + forms + '|l' + links + '|i' + inputs;
                }
            """)
            if not sig:
                return False
            # Convert to a 64-bit simhash-style fingerprint using character n-grams
            # Hamming distance check: count differing bits between fingerprints
            h = hashlib.sha256(sig.encode()).digest()
            # Convert first 8 bytes to integer for bit comparison
            new_fp_int = int.from_bytes(h[:8], "big")
            threshold_bits = int((1.0 - self.content_similarity_threshold) * 64)
            for seen_fp in self._content_hashes:
                seen_int = int(seen_fp, 16)
                xor = new_fp_int ^ seen_int
                hamming = bin(xor).count("1")
                if hamming <= threshold_bits:
                    return True  # Too similar to a seen page
            # Not a duplicate — register this fingerprint
            self._content_hashes.add(format(new_fp_int, "016x"))
            return False
        except Exception as e:
            logger.debug("Content similarity check error: %s", e)
            return False

    def _extract_shadow_dom_routes(self, page) -> set:
        """
        Extract routes from shadow DOM using CDP DOMGetDocument with pierce=True.

        Playwright's page.content() and querySelectorAll() only see the light DOM.
        Web Components hide entire navigation trees inside shadow roots that are
        invisible to standard scraping. CDP with pierce=True crosses every shadow
        boundary in a single call, returning the full composed tree.

        Katana does the same in hybrid/crawl.go: dom.GetDocument with depth=-1,
        pierce=True, then walks nodes collecting href/action attributes.
        """
        found = set()
        cdp = None
        try:
            cdp = page.context.new_cdp_session(page)
            doc = cdp.send("DOM.getDocument", {"depth": -1, "pierce": True})
            root = doc.get("root", {})

            parsed = urlparse(self.target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            def _walk(node):
                if not isinstance(node, dict):
                    return
                # nodeType 1 = ELEMENT_NODE
                if node.get("nodeType") != 1:
                    for child in node.get("children", []):
                        _walk(child)
                    return
                tag = (node.get("localName") or "").lower()
                attrs = {}
                raw_attrs = node.get("attributes", [])
                # CDP returns attributes as flat [name, value, name, value...] list
                for i in range(0, len(raw_attrs) - 1, 2):
                    attrs[raw_attrs[i].lower()] = raw_attrs[i + 1]

                if tag in ("a", "link"):
                    href = attrs.get("href", "")
                    if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        if href.startswith("/"):
                            found.add(href)
                        elif href.startswith(origin):
                            found.add(urlparse(href).path or "/")
                elif tag == "form":
                    action = attrs.get("action", "")
                    if action and not action.startswith(("javascript:", "mailto:")):
                        if action.startswith("/"):
                            found.add(action)
                        elif action.startswith(origin):
                            found.add(urlparse(action).path or "/")

                for child in node.get("children", []):
                    _walk(child)
                # Pierce shadow roots
                for shadow in node.get("shadowRoots", []):
                    _walk(shadow)

            _walk(root)
        except Exception as e:
            logger.debug("CDP shadow DOM error: %s", e)
        finally:
            if cdp is not None:
                try:
                    cdp.detach()
                except Exception:
                    pass
        return found

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

        # API / WS / SSE / nav intercepts
        try:
            api_calls   = self._extract_api_calls(page)
            ws_urls     = self._extract_ws_urls(page)
            ws_messages = self._extract_ws_messages(page)
            sse_urls    = self._extract_sse_urls(page)
            nav_urls    = self._extract_nav_urls(page)
            with self._lock:
                self.api_calls.extend(api_calls)
                self.ws_urls.extend(ws_urls)
                self.ws_messages.extend(ws_messages)
                self.sse_urls.extend(sse_urls)
                self.nav_urls.extend(nav_urls)
            # SSE and nav URLs that look like same-origin paths become routes
            parsed_tgt = urlparse(self.target_url)
            tgt_origin  = f"{parsed_tgt.scheme}://{parsed_tgt.netloc}"
            for raw_url in sse_urls + nav_urls:
                try:
                    if raw_url.startswith(tgt_origin):
                        _p = urlparse(raw_url)
                        new_routes.add((_p.path or "/") + (("?" + _p.query) if _p.query else ""))
                    elif raw_url.startswith("/"):
                        new_routes.add(raw_url)
                except Exception:
                    pass
        except Exception as e:
            logger.debug("API/WS/SSE/nav extraction error %s: %s", source_url, e)

        # WebWorkers + Service Workers (item 6)
        try:
            worker_urls = self._extract_worker_urls(page)
            sw_urls     = self._extract_sw_urls(page)
            import threading as _t
            for w_url in worker_urls:
                _th = _t.Thread(target=self._fetch_worker_js, args=(w_url, source_url), daemon=True)
                _th.start()
                with self._bg_fetch_lock:
                    self._bg_fetch_threads.append(_th)
            for sw_url in sw_urls:
                _th = _t.Thread(target=self._fetch_service_worker, args=(sw_url, source_url), daemon=True)
                _th.start()
                with self._bg_fetch_lock:
                    self._bg_fetch_threads.append(_th)
        except Exception as e:
            logger.debug("Worker/SW extraction error %s: %s", source_url, e)

        # Iframes — add same-origin ones as routes (preserve query string)
        try:
            iframe_urls = self._extract_iframe_urls(page)
            parsed = urlparse(self.target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for iframe_url in iframe_urls:
                if iframe_url.startswith(origin):
                    _ip = urlparse(iframe_url)
                    new_routes.add((_ip.path or "/") + (("?" + _ip.query) if _ip.query else ""))
                elif iframe_url.startswith("/"):
                    new_routes.add(iframe_url)
        except Exception as e:
            logger.debug("Iframe extraction error %s: %s", source_url, e)

        # Shadow DOM traversal — extract routes hidden inside Web Components.
        # Playwright's page.content() only sees the light DOM; shadow roots require
        # CDP DOMGetDocument with pierce=True to pierce every shadow boundary.
        # Katana uses this same approach in hybrid/crawl.go navigateRequest().
        try:
            shadow_routes = self._extract_shadow_dom_routes(page)
            new_routes.update(shadow_routes)
        except Exception as e:
            logger.debug("Shadow DOM traversal error %s: %s", source_url, e)

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
                _th = _t.Thread(
                    target=self._fetch_dom_scripts,
                    args=(_dom_script_urls, source_url),
                    daemon=True,
                )
                _th.start()
                with self._bg_fetch_lock:
                    self._bg_fetch_threads.append(_th)
        except Exception as e:
            logger.debug("DOM scrape error %s: %s", source_url, e)

        # ES module entry points — collect <script type="module" src> URLs
        # in the Playwright thread, then fetch + recurse off-thread (item 8).
        try:
            _module_urls = self._collect_module_script_urls(page)
            if _module_urls:
                import threading as _t
                for _murl in _module_urls:
                    _th = _t.Thread(
                        target=self._fetch_es_module,
                        args=(_murl, source_url, 0),
                        daemon=True,
                    )
                    _th.start()
                    with self._bg_fetch_lock:
                        self._bg_fetch_threads.append(_th)
        except Exception as e:
            logger.debug("ES module collection error %s: %s", source_url, e)

        # Reset interceptor buffers for next page
        try:
            page.evaluate("""
                window.__bundlespy_requests    = [];
                window.__bundlespy_ws          = [];
                window.__bundlespy_ws_messages = [];
                window.__bundlespy_workers     = [];
                window.__bundlespy_sw          = [];
                window.__bundlespy_iframes     = [];
                window.__bundlespy_sse         = [];
                window.__bundlespy_nav         = [];
                window.__bundlespy_listeners   = [];
                window.__bspy_mutations        = 0;
                window.__bspy_requests         = 0;
                window.__bspy_last_active      = Date.now();
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
            # Gap 1: PageLoadStrategy — now includes "heuristic" mode.
            # For "heuristic", goto() uses "commit" (returns as soon as the
            # first byte arrives) and then _wait_heuristic() takes over:
            # it polls for URL changes (SPA router detection) then falls
            # back to network-idle + DOM stability. All other strategies
            # pass directly to Playwright's wait_until.
            # (Enhancement 9 — PageLoadStrategy)
            _resolved_strategy = (self.page_load_strategy or "domcontentloaded").lower()
            _use_heuristic     = (_resolved_strategy == "heuristic")
            _strategy_map = {
                "eager":            "domcontentloaded",
                "domcontentloaded": "domcontentloaded",
                "load":             "load",
                "networkidle":      "networkidle",
                "none":             "commit",
                "heuristic":        "commit",   # goto returns fast; heuristic runs after
            }
            _wait_until = _strategy_map.get(_resolved_strategy, "domcontentloaded")

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

            # Cookie jar pre-loading — merge Netscape cookie file into self.cookies
            # BEFORE context creation so they're available for the very first request.
            # Handles Burp Suite exports, curl cookie jars, Firefox/Chrome exports.
            if self.cookie_jar_path:
                try:
                    jar_cookies = load_cookie_jar(self.cookie_jar_path)
                    self.cookies = list(self.cookies) + jar_cookies
                    logger.info(
                        "Cookie jar loaded: %d cookies from %s",
                        len(jar_cookies), self.cookie_jar_path,
                    )
                except FileNotFoundError:
                    logger.warning(
                        "Cookie jar file not found: %s — skipping", self.cookie_jar_path
                    )
                except ValueError as e:
                    logger.warning(
                        "Cookie jar parse error (%s): %s — skipping",
                        self.cookie_jar_path, e,
                    )
                except Exception as e:
                    logger.warning(
                        "Cookie jar load failed (%s): %s — skipping",
                        self.cookie_jar_path, e,
                    )

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
            #
            # Queue-based pattern — ctx.on("response") fires on Playwright's
            # event loop thread.  We do only a pure-Python queue.put here (safe).
            # Never call response.body() or any Playwright method from this
            # callback — that would cross into a different greenlet and raise
            # "greenlet.error: Cannot switch to a different thread".
            #
            # Phase 1 runs on the main thread which owns this Playwright context,
            # so we drain the queue explicitly on the main thread (via
            # _drain_phase1_responses()) after each navigation / interaction.
            _resp_queue: queue.Queue = queue.Queue()

            def _on_response(r):
                try:
                    # frame.url is the page that triggered this request
                    source = r.frame.url if r.frame else r.url
                except Exception:
                    source = r.url
                _resp_queue.put((r, source))

            ctx.on("response", _on_response)

            def _drain_phase1_responses() -> int:
                """Drain queued responses on the main (Playwright-owning) thread."""
                processed = 0
                while True:
                    try:
                        r, src = _resp_queue.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        self._handle_response(r, src)
                    except Exception:
                        pass
                    processed += 1
                return processed

            def _route_handler_phase1(route):
                # route.abort()/continue_() go through Playwright's sync→async bridge
                # which tries to switch greenlets across OS thread boundaries — fatal.
                # Instead, schedule the coroutine directly on the already-running event
                # loop (we ARE on the event loop thread inside this callback), bypassing
                # the sync bridge entirely.
                import asyncio as _asyncio
                if self._should_block(route.request.url, route.request.resource_type):
                    _asyncio.ensure_future(route._impl_obj.abort())
                else:
                    _asyncio.ensure_future(route._impl_obj.continue_())

            ctx.route("**/*", _route_handler_phase1)

            # ── Single persistent page — reused across all navigation ─────────
            page = ctx.new_page()
            stabilizer = PageStabilizer(page)

            # JS navigation tracking — Katana's PageFrameNavigated approach.
            # page.on("framenavigated") fires for window.location=, meta-refresh,
            # history.pushState, and client-side router transitions that the
            # response handler misses because they don't produce a new HTTP response.
            def _on_frame_navigated(frame):
                try:
                    if frame != page.main_frame:
                        return  # Only track main frame navigations
                    nav_url = frame.url
                    if not nav_url or nav_url in ("about:blank", ""):
                        return
                    parsed_nav = urlparse(nav_url)
                    if parsed_nav.netloc and parsed_nav.netloc != urlparse(self.target_url).netloc:
                        return  # Cross-origin — not our target
                    if self.scope.in_scope(nav_url) and not self.registry.seen_url(nav_url):
                        with self._js_nav_lock:
                            self._js_nav_urls.append(nav_url)
                        logger.debug("JS nav detected: %s", nav_url)
                except Exception:
                    pass

            page.on("framenavigated", _on_frame_navigated)

            # ── Gap 2: CDP FetchRequestPaused interception (Phase 1 page) ────
            # Katana's FetchRequestStage/FetchResponseStage pipeline gives us
            # raw POST bodies and raw response bytes at the CDP level — things
            # Playwright's high-level response event can miss (cached hits,
            # service-worker intercepts, partial streaming bodies).
            _phase1_cdp: Optional[object] = None
            if self.capture_raw_traffic:
                def _cdp_request_handler(url: str, method: str, headers: dict,
                                         body_bytes: bytes) -> None:
                    """Store CDP-intercepted request bodies into raw traffic."""
                    if not body_bytes:
                        return
                    with self._raw_lock:
                        # Append a lightweight stub — response comes separately.
                        self._raw_traffic.append({
                            "url":          url,
                            "method":       method,
                            "status":       0,  # not known yet — response fills this
                            "raw_request":  (
                                f"{method} {url} HTTP/1.1\r\n"
                                + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
                                + f"\r\n\r\n{body_bytes.decode('utf-8', errors='replace')}"
                            ),
                            "raw_response": "",
                            "source_page":  page.url or self.target_url,
                            "via_cdp":      True,
                        })

                def _cdp_response_handler(url: str, status: int, headers: dict,
                                          body_bytes: bytes) -> None:
                    """Merge CDP-intercepted response bodies into raw traffic."""
                    # Build the raw HTTP response wire representation.
                    resp_headers_str = "\r\n".join(
                        f"{k}: {v}" for k, v in headers.items()
                    )
                    body_str = body_bytes.decode("utf-8", errors="replace")[:4096]
                    raw_resp = (
                        f"HTTP/1.1 {status}\r\n"
                        f"{resp_headers_str}\r\n\r\n"
                        f"{body_str}"
                    )
                    with self._raw_lock:
                        # Merge into an existing stub from the request phase if present.
                        for entry in reversed(self._raw_traffic):
                            if entry.get("url") == url and entry.get("via_cdp") and not entry.get("raw_response"):
                                entry["status"] = status
                                entry["raw_response"] = raw_resp
                                return
                        # No matching stub — add a standalone response entry.
                        self._raw_traffic.append({
                            "url":          url,
                            "method":       "GET",
                            "status":       status,
                            "raw_request":  "",
                            "raw_response": raw_resp,
                            "source_page":  page.url or self.target_url,
                            "via_cdp":      True,
                        })

                _phase1_cdp = _attach_cdp_fetch_interception(
                    page,
                    on_request_body_fn  = _cdp_request_handler,
                    on_response_body_fn = _cdp_response_handler,
                    # Intercept everything — our raw_traffic handler has its own
                    # size cap (body[:4096]) so cost is bounded.
                    resource_patterns   = ["*"],
                )

            # Sub-page detection — register popup/new-tab listener on context
            # (Enhancement 10 — must be set up before any navigation)
            self._detect_sub_pages(ctx, stabilizer, self.target_url)

            # ── Phase 1: Auth verification + root page ────────────────────────
            self.timer.start("phase1_root")

            # Recorded auth flow — replay before cookie-based auth or standard load
            # (Enhancement 1 — Recorded auth flow replay)
            if self.auth_steps:
                # Navigate to target first so recorded flow starts from the right page
                try:
                    page.goto(self.target_url, timeout=self.timeout * 1000,
                              wait_until=_wait_until)
                    if _use_heuristic:
                        _wait_heuristic(page, max_ms=self.timeout * 1000)
                    stabilizer.wait_for_framework(max_ms=2000)
                except Exception as e:
                    logger.debug("Phase 1: initial navigate for recorded flow failed: %s", e)

                flow_ok = self._run_recorded_auth_flow(page, stabilizer)
                if flow_ok:
                    self._logged_in = True
                    logger.info("Recorded auth flow succeeded — loggedIn=True")
                else:
                    # Auto-login fallback — DIT-style (Enhancement 2)
                    logger.warning(
                        "Recorded auth flow failed — attempting auto-login fallback"
                    )
                    # Re-navigate to target login in case flow left us elsewhere
                    try:
                        page.goto(self.target_url, timeout=self.timeout * 1000,
                                  wait_until=_wait_until)
                        if _use_heuristic:
                            _wait_heuristic(page, max_ms=self.timeout * 1000)
                        stabilizer.wait_for_framework(max_ms=2000)
                    except Exception:
                        pass
                    if _is_login_page(page):
                        # Fire on_login_detected hook (Enhancement 4)
                        if self.hooks.on_login_detected:
                            try:
                                self.hooks.on_login_detected(page)
                            except Exception:
                                pass
                        fallback_ok = self._try_auto_login(page, stabilizer)
                        if fallback_ok:
                            self._logged_in = True
                            logger.info("Auto-login fallback succeeded — loggedIn=True")
                        else:
                            logger.warning("Auto-login fallback also failed — crawling unauthenticated")

            if self.cookies or self.extra_headers:
                self.auth_result = self._verify_auth(page, self.target_url)
                logger.info(
                    "Auth: authenticated=%s final=%s status=%s session_delta=%s",
                    self.auth_result["authenticated"],
                    self.auth_result["final_url"],
                    self.auth_result["status"],
                    self.auth_result.get("session_delta", False),
                )
                if self.auth_result.get("authenticated"):
                    self._logged_in = True
                # Extra stability wait after auth — SPAs may still be mounting
                # their router after the framework detect fires in _verify_auth
                stabilizer.wait_for_framework(max_ms=2000)
                self.registry.register_url(self.target_url)
                with self._lock:
                    self.pages_visited += 1
                fp = self._dom_fingerprint(page)
                if fp:
                    _seen_dom_states.add(fp)
                    self.crawl_graph.add_page_state(fp[:16], self.target_url, depth=0)
                initial_routes = self._flush_page_intel(page, self.target_url)
                _drain_phase1_responses()
            else:
                try:
                    page.goto(self.target_url, timeout=self.timeout * 1000,
                              wait_until=_wait_until)
                    if _use_heuristic:
                        _wait_heuristic(page, max_ms=self.timeout * 1000)
                    with self._lock:
                        self.pages_visited += 1
                    stabilizer.wait_for_framework(max_ms=3000)
                except Exception as e:
                    logger.debug("Root page error: %s", e)
                self.registry.register_url(self.target_url)
                fp = self._dom_fingerprint(page)
                if fp:
                    _seen_dom_states.add(fp)
                    self.crawl_graph.add_page_state(fp[:16], self.target_url, depth=0)
                initial_routes = self._flush_page_intel(page, self.target_url)
                _drain_phase1_responses()

            # Cookie consent bypass — run on root page before crawl starts (Enhancement 8)
            if self.cookie_consent_bypass:
                dismissed = self._dismiss_cookie_consent(page)
                if dismissed:
                    # Re-flush after dismissal — banner may have been blocking JS rendering
                    for r in self._flush_page_intel(page, self.target_url):
                        initial_routes.add(r)
                    _drain_phase1_responses()

            # Captcha check on root page (Enhancement 9)
            if self._is_captcha_page(page):
                # Fire on_captcha_detected hook (Enhancement 4)
                if self.hooks.on_captcha_detected:
                    try:
                        self.hooks.on_captcha_detected(page)
                    except Exception:
                        pass
                self._handle_captcha(page)
                _drain_phase1_responses()

            # MaxCrawlDuration timer starts HERE — after auth completes (Enhancement 10)
            self._crawl_start_time = time.monotonic()
            if self.max_crawl_duration > 0:
                logger.info("MaxCrawlDuration: %ds (starts after auth)", self.max_crawl_duration)

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

            # ── Phase 2: BFS route exploration (parallel browser pool) ────────
            # Bug 19 fix: use a real BFS deque so routes discovered during the
            # loop are fed back into the queue immediately and visited in the
            # same run. The old code collected new_routes_found and only added
            # them after the loop ended — they were never visited.
            self.timer.start("phase2_routes")

            # Build the browser pool — N independent browser+context+page sets.
            # Phase 1 (auth) used the single browser above; the pool takes over
            # for Phase 2 parallel BFS. Each slot replicates the same context
            # config (UA, stealth flags, cookies, init script, routing rules).
            _pool_browser_args = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-web-security",
                "--disable-features=VizDisplayCompositor",
                "--blink-settings=imagesEnabled=false",
                "--disable-background-networking",
                "--disable-sync",
            ]

            def _pool_response_fn(r, source_url):
                try:
                    self._handle_response(r, source_url)
                except Exception:
                    pass

            # Gap 2: CDP-level raw traffic handlers for pool slots.
            # When capture_raw_traffic is on, each pool slot's page gets a CDP
            # Fetch interception session that captures POST bodies and response
            # bytes before the browser can consume them — the same data Katana
            # captures via FetchRequestStage/FetchResponseStage in browser.go.
            # The handlers are thread-safe (self._raw_lock guards the list).
            def _pool_cdp_request_fn(url: str, method: str, headers: dict,
                                     body_bytes: bytes) -> None:
                """Store CDP-intercepted pool-slot request bodies."""
                if not body_bytes:
                    return
                with self._raw_lock:
                    self._raw_traffic.append({
                        "url":          url,
                        "method":       method,
                        "status":       0,
                        "raw_request":  (
                            f"{method} {url} HTTP/1.1\r\n"
                            + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
                            + f"\r\n\r\n{body_bytes.decode('utf-8', errors='replace')}"
                        ),
                        "raw_response": "",
                        "source_page":  "",
                        "via_cdp":      True,
                    })

            def _pool_cdp_response_fn(url: str, status: int, headers: dict,
                                      body_bytes: bytes) -> None:
                """Merge CDP-intercepted pool-slot response bodies."""
                resp_headers_str = "\r\n".join(
                    f"{k}: {v}" for k, v in headers.items()
                )
                body_str = body_bytes.decode("utf-8", errors="replace")[:4096]
                raw_resp = (
                    f"HTTP/1.1 {status}\r\n"
                    f"{resp_headers_str}\r\n\r\n"
                    f"{body_str}"
                )
                with self._raw_lock:
                    for entry in reversed(self._raw_traffic):
                        if entry.get("url") == url and entry.get("via_cdp") and not entry.get("raw_response"):
                            entry["status"] = status
                            entry["raw_response"] = raw_resp
                            return
                    self._raw_traffic.append({
                        "url":          url,
                        "method":       "GET",
                        "status":       status,
                        "raw_request":  "",
                        "raw_response": raw_resp,
                        "source_page":  "",
                        "via_cdp":      True,
                    })

            _browser_pool = BrowserPool(
                num_browsers  = self.num_browsers,
                browser_args  = _pool_browser_args,
                ctx_kwargs    = kwargs,
                cookies       = self.cookies,
                init_script   = INTERCEPT_JS,
                block_fn      = self._should_block,
                response_fn   = _pool_response_fn,
                # Gap 2: wire up CDP handlers only when raw capture is on
                cdp_request_fn  = _pool_cdp_request_fn  if self.capture_raw_traffic else None,
                cdp_response_fn = _pool_cdp_response_fn if self.capture_raw_traffic else None,
            )
            logger.info(
                "BrowserPool ready: %d parallel browser slots", self.num_browsers
            )

            initial_urls = self._build_urls(self.routes)
            # Bug 11 fix: _build_urls already sorts by priority; don't sort again.
            bfs_queue: deque = deque(initial_urls)
            login_loop_count = 0
            bfs_depth: Dict[str, int] = {}  # url -> BFS depth for CrawlGraph

            # PathTrie dedup tracking counters
            _trie_filtered_count: int = 0
            _rp_added_count: int      = 0
            # Session 4 counters
            _js_nav_count: int        = 0
            _onclick_nav_count: int   = 0

            # Session-loss flag — set by any pool worker hitting a login wall
            _session_lost = threading.Event()

            def _visit_url_in_slot(url: str, depth: int):
                """
                Visit one URL using a thread-local Playwright browser.

                Each call creates its own sync_playwright() + browser + context +
                page, uses it, then tears it all down.  This is the only safe
                pattern with Playwright sync_api under threading: objects are
                greenlet-bound and cannot cross thread boundaries.

                Returns (new_urls, onclick_count, success, session_lost_flag).
                Called from a ThreadPoolExecutor worker thread.
                """
                # Gate on concurrency limit — blocks until a slot is available.
                _browser_pool.acquire()
                slot = None
                try:
                    # Build a fresh browser stack owned by this thread.
                    slot = _browser_pool.make_thread_browser()
                    slot_page       = slot["page"]
                    slot_stabilizer = PageStabilizer(slot_page)

                    slot_page.goto(
                        url,
                        timeout    = self.timeout * 1000,
                        wait_until = _wait_until,
                    )
                    if _use_heuristic:
                        _wait_heuristic(slot_page, max_ms=self.timeout * 1000)
                    # Drain responses after initial page load — owning thread only.
                    _browser_pool.drain_thread_responses(slot)
                    with self._lock:
                        self.pages_visited += 1

                    # on_navigation hook
                    if self.hooks.on_navigation:
                        try:
                            self.hooks.on_navigation(url)
                        except Exception:
                            pass

                    # Session-loss detection — only meaningful when we actually
                    # started authenticated (self._logged_in).  An unauthenticated
                    # scan hitting a login form is normal; flagging it as session
                    # loss would incorrectly stop the entire parallel BFS.
                    #
                    # Even when authenticated, _is_login_page() alone isn't proof
                    # of session loss — the page may embed a login modal, password-
                    # reset widget, or SPA auth overlay on a public route.  We set
                    # the flag only when we have a logged-in state to lose.
                    if self._logged_in and _is_login_page(slot_page) and not _is_login_url(url):
                        if self.hooks.on_login_detected:
                            try:
                                self.hooks.on_login_detected(slot_page)
                            except Exception:
                                pass
                        # Drain responses before bailing — don't skip collected data.
                        _browser_pool.drain_thread_responses(slot)
                        _session_lost.set()
                        return [], 0, False, True

                    # Cookie consent
                    if self.cookie_consent_bypass:
                        self._dismiss_cookie_consent(slot_page)

                    # Captcha
                    if self._is_captcha_page(slot_page):
                        self._handle_captcha(slot_page)

                    # DOM state dedup
                    slot_stabilizer.wait_for_framework(max_ms=2000)
                    fp = self._dom_fingerprint(slot_page)
                    if fp:
                        with self._lock:
                            if fp in _seen_dom_states:
                                return [], 0, True, False
                            _seen_dom_states.add(fp)
                        self.crawl_graph.add_page_state(fp[:16], url, depth=depth)
                        load_action = CrawlAction(
                            action_type = ActionType.LOAD_URL,
                            url         = url,
                            depth       = depth,
                            parent_url  = url,
                        )
                        self.crawl_graph.add_edge(load_action)

                    # Content similarity gate
                    if self.content_similarity_threshold > 0.0:
                        if self._is_similar_content(slot_page):
                            logger.debug("Content similarity gate: skipping %s", url)
                            return [], 0, True, False

                    if self.interact:
                        self._interact(slot_page, slot_stabilizer)
                        self._observe_forms(slot_page, slot_stabilizer)
                        # Drain any responses triggered by JS interactions.
                        _browser_pool.drain_thread_responses(slot)

                    new_routes = self._flush_page_intel(slot_page, url)
                    self._discover_form_actions(slot_page, url)
                    self._discover_click_actions(slot_page, url)

                    new_urls   = self._build_urls(new_routes)
                    _oc_count  = 0

                    if self.max_onclick_links > 0:
                        try:
                            onclick_new = self._simulate_onclick_links(
                                slot_page, url, max_links=self.max_onclick_links
                            )
                            for onclick_url in onclick_new:
                                if onclick_url not in new_urls:
                                    new_urls.append(onclick_url)
                                    _oc_count += 1
                        except Exception as e:
                            logger.debug("onclick simulation failed for %s: %s", url, e)

                    # Final drain before closing — captures any late-arriving
                    # responses (async resource loads, lazy fetches, etc.).
                    _browser_pool.drain_thread_responses(slot)
                    return new_urls, _oc_count, True, False

                except Exception as e:
                    logger.debug("Error visiting %s: %s", url, e)
                    return [], 0, False, False
                finally:
                    if slot is not None:
                        # Drain one last time before teardown so no pending
                        # response bodies are lost when ctx.close() runs.
                        try:
                            _browser_pool.drain_thread_responses(slot)
                        except Exception:
                            pass
                        _browser_pool.close_thread_browser(slot)
                    _browser_pool.release()

            # Use a ThreadPoolExecutor scoped to Phase 2 only.
            # We dispatch batches of up to num_browsers URLs at a time so the
            # BFS queue drains can still feed new URLs between batches.
            from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

            with ThreadPoolExecutor(max_workers=self.num_browsers) as _executor:
                while bfs_queue:
                    if self.pages_visited >= self.max_pages:
                        break

                    if _session_lost.is_set():
                        logger.warning(
                            "Session lost mid-crawl — login wall detected on "
                            "authenticated session; stopping BFS"
                        )
                        if self.auth_result is not None:
                            self.auth_result["authenticated"] = False
                            self.auth_result["reason"] = (
                                "Login wall detected mid-crawl on an "
                                "authenticated session — session may have expired"
                            )
                        self._logged_in = False
                        break

                    # Drain ResponseParser discoveries into the BFS queue.
                    if self._response_parser is not None:
                        with self._rp_lock:
                            pending_rp = self._rp_discovered[:]
                            self._rp_discovered.clear()
                        for rp_url in pending_rp:
                            if self.scope.in_scope(rp_url) and not self.registry.seen_url(rp_url):
                                if self._path_trie is not None:
                                    fp = self._path_trie.fingerprint(rp_url)
                                    if fp in self._trie_seen:
                                        _trie_filtered_count += 1
                                        continue
                                    self._trie_seen.add(fp)
                                _rp_parsed = urlparse(rp_url)
                                _rp_route  = (_rp_parsed.path or "/") + (
                                    ("?" + _rp_parsed.query) if _rp_parsed.query else ""
                                )
                                self._add_route(_rp_route)
                                bfs_queue.append(rp_url)
                                _rp_added_count += 1

                    # Drain JS navigation discoveries
                    with self._js_nav_lock:
                        pending_js_nav = self._js_nav_urls[:]
                        self._js_nav_urls.clear()
                    for js_nav_url in pending_js_nav:
                        if self.scope.in_scope(js_nav_url) and not self.registry.seen_url(js_nav_url):
                            if self._path_trie is not None:
                                js_fp = self._path_trie.fingerprint(js_nav_url)
                                if js_fp in self._trie_seen:
                                    _trie_filtered_count += 1
                                    continue
                                self._trie_seen.add(js_fp)
                            _jn_parsed = urlparse(js_nav_url)
                            _jn_route  = (_jn_parsed.path or "/") + (
                                ("?" + _jn_parsed.query) if _jn_parsed.query else ""
                            )
                            self._add_route(_jn_route)
                            bfs_queue.append(js_nav_url)
                            _js_nav_count += 1

                    # MaxCrawlDuration guard
                    if self._is_crawl_deadline_exceeded():
                        logger.info(
                            "MaxCrawlDuration (%ds) reached — stopping BFS",
                            self.max_crawl_duration,
                        )
                        break

                    # MaxFailureCount guard
                    if self._consecutive_failures >= self.max_failures:
                        logger.warning(
                            "MaxFailureCount (%d) reached — halting BFS",
                            self.max_failures,
                        )
                        break

                    # Collect a batch of URLs — up to num_browsers at once
                    _batch_items: List[tuple] = []
                    while bfs_queue and len(_batch_items) < self.num_browsers:
                        candidate = bfs_queue.popleft()
                        current_depth = bfs_depth.get(candidate, 1)

                        if not self.registry.register_url(candidate):
                            continue
                        safe_c, _ = validate_url(candidate)
                        if not safe_c or not self.scope.in_scope(candidate):
                            continue
                        _batch_items.append((candidate, current_depth))

                    if not _batch_items:
                        continue

                    # Dispatch batch in parallel
                    _futures = {
                        _executor.submit(_visit_url_in_slot, _burl, _bdepth): (_burl, _bdepth)
                        for _burl, _bdepth in _batch_items
                    }

                    for _fut in _as_completed(_futures):
                        _burl, _bdepth = _futures[_fut]
                        try:
                            new_urls, oc_count, success, sess_lost = _fut.result()
                        except Exception as _fe:
                            logger.debug("Future error for %s: %s", _burl, _fe)
                            self._consecutive_failures += 1
                            continue

                        if sess_lost:
                            continue  # session_lost event already set

                        if not success:
                            self._consecutive_failures += 1
                            continue

                        self._consecutive_failures = 0
                        _onclick_nav_count += oc_count

                        # Feed newly discovered URLs back into BFS queue
                        for new_url in new_urls:
                            if not self.registry.seen_url(new_url):
                                if self._path_trie is not None:
                                    new_fp = self._path_trie.fingerprint(new_url)
                                    if new_fp in self._trie_seen:
                                        _trie_filtered_count += 1
                                        continue
                                    self._trie_seen.add(new_fp)
                                _parsed_new = urlparse(new_url)
                                _route_key  = (_parsed_new.path or "/") + (
                                    ("?" + _parsed_new.query) if _parsed_new.query else ""
                                )
                                self._add_route(_route_key)
                                bfs_queue.append(new_url)
                                bfs_depth[new_url] = _bdepth + 1

            # Shut down all pool browsers — must happen inside sync_playwright ctx
            _browser_pool.close_all()
            logger.info("BrowserPool closed")

            self.timer.stop("phase2_routes")

            # ── Phase 3: Action queue — state-based crawl ─────────────────────
            # Process queued FILL_FORM and LEFT_CLICK actions discovered during
            # BFS. Each action navigates to its source URL and fires the action,
            # capturing any new API calls or routes the state transition reveals.
            self.timer.start("phase3_actions")
            _action_pages_visited = 0
            _MAX_ACTION_PAGES = min(20, max(0, self.max_pages - self.pages_visited))

            phase3_consecutive_failures = 0

            while self._action_queue and _action_pages_visited < _MAX_ACTION_PAGES:
                # MaxCrawlDuration guard in Phase 3 as well (Enhancement 10)
                if self._is_crawl_deadline_exceeded():
                    logger.info("MaxCrawlDuration reached — stopping Phase 3")
                    break

                # MaxFailureCount guard for Phase 3 (Enhancement 4)
                if phase3_consecutive_failures >= self.max_failures:
                    logger.warning(
                        "MaxFailureCount (%d) reached in Phase 3 — halting",
                        self.max_failures,
                    )
                    break

                action = self._action_queue.popleft()
                try:
                    # navigateBackToStateOrigin: verify browser is on the correct
                    # DOM state before executing the action (Enhancements 2 + 3)
                    self._recover_drift(page, action.url, stabilizer)
                    restored = self._navigate_back_to_state_origin(page, action, stabilizer)
                    if not restored:
                        phase3_consecutive_failures += 1
                        continue

                    # Diagnostics: record pre-action state (Enhancement 11)
                    if self._diagnostics:
                        self._diagnostics.record(page, action, note="pre-action")

                    # before_action hook (Enhancement 4)
                    if self.hooks.before_action:
                        try:
                            self.hooks.before_action(page, action)
                        except Exception:
                            pass

                    # SlowMotion delay before action (Enhancement 12)
                    self._slow_mo_wait(page)

                    if action.action_type == ActionType.FILL_FORM:
                        try:
                            form = page.query_selector("form")
                            if form and form.is_visible():
                                self._interact_forms(page, stabilizer)
                                new_routes = self._flush_page_intel(page, action.url)
                                for r in new_routes:
                                    if self._add_route(r):
                                        full = self._build_urls({r})
                                        for u in full:
                                            if not self.registry.seen_url(u):
                                                if self._path_trie is not None:
                                                    _fp = self._path_trie.fingerprint(u)
                                                    if _fp in self._trie_seen:
                                                        _trie_filtered_count += 1
                                                        continue
                                                    self._trie_seen.add(_fp)
                                                bfs_queue.append(u)
                                _action_pages_visited += 1
                                phase3_consecutive_failures = 0
                                # Diagnostics: record post-action state (Enhancement 11)
                                if self._diagnostics:
                                    self._diagnostics.record(page, action, note="post-fill_form")
                                # after_action hook (Enhancement 4)
                                if self.hooks.after_action:
                                    try:
                                        self.hooks.after_action(page, action)
                                    except Exception:
                                        pass
                        except Exception as e:
                            logger.debug("Action FILL_FORM failed %s: %s", action.url, e)
                            phase3_consecutive_failures += 1

                    elif action.action_type == ActionType.LEFT_CLICK:
                        try:
                            el = page.query_selector(action.selector)
                            if el and el.is_visible() and el.is_enabled():
                                # Universal ScrollIntoView before click (Enhancement 6)
                                self._scroll_into_view(page, el)
                                # Interactability check: verify no overlay covers
                                # the element before clicking (Enhancement 5)
                                if not self._check_element_interactable(page, el):
                                    logger.debug(
                                        "Element covered by overlay, skipping: %s on %s",
                                        action.selector, action.url,
                                    )
                                    # Try consent bypass — a cookie banner may be covering it
                                    if self.cookie_consent_bypass:
                                        self._dismiss_cookie_consent(page)
                                    phase3_consecutive_failures += 1
                                    continue
                                # SlowMotion delay before click (Enhancement 12)
                                self._slow_mo_wait(page)
                                try:
                                    el.click(timeout=800)
                                except Exception as click_err:
                                    # Typed error classification (Enhancement 3)
                                    typed_err = self._classify_click_error(click_err, page, el)
                                    if isinstance(typed_err, ElementCoveredError):
                                        logger.debug(
                                            "ElementCoveredError on %s — trying consent bypass",
                                            action.selector,
                                        )
                                        if self.cookie_consent_bypass:
                                            self._dismiss_cookie_consent(page)
                                        # Retry once after banner dismissal
                                        try:
                                            el.click(timeout=600)
                                        except Exception:
                                            phase3_consecutive_failures += 1
                                            continue
                                    elif isinstance(typed_err, ElementInvisibleError):
                                        logger.debug(
                                            "ElementInvisibleError on %s — skipping",
                                            action.selector,
                                        )
                                        phase3_consecutive_failures += 1
                                        continue
                                    elif isinstance(typed_err, ElementNoPointerEventsError):
                                        logger.debug(
                                            "ElementNoPointerEventsError on %s — JS click fallback",
                                            action.selector,
                                        )
                                        # JS click bypasses pointer-events:none
                                        try:
                                            page.evaluate("el => el.click()", el)
                                        except Exception:
                                            phase3_consecutive_failures += 1
                                            continue
                                    else:
                                        raise typed_err
                                stabilizer.wait_after_interaction(max_ms=1000)
                                new_routes = self._flush_page_intel(page, action.url)
                                for r in new_routes:
                                    if self._add_route(r):
                                        full = self._build_urls({r})
                                        for u in full:
                                            if not self.registry.seen_url(u):
                                                if self._path_trie is not None:
                                                    _fp = self._path_trie.fingerprint(u)
                                                    if _fp in self._trie_seen:
                                                        _trie_filtered_count += 1
                                                        continue
                                                    self._trie_seen.add(_fp)
                                                bfs_queue.append(u)
                                _action_pages_visited += 1
                                phase3_consecutive_failures = 0
                                # Diagnostics: record post-click state (Enhancement 11)
                                if self._diagnostics:
                                    self._diagnostics.record(page, action, note="post-left_click")
                                # after_action hook (Enhancement 4)
                                if self.hooks.after_action:
                                    try:
                                        self.hooks.after_action(page, action)
                                    except Exception:
                                        pass
                        except Exception as e:
                            logger.debug("Action LEFT_CLICK failed %s: %s", action.url, e)
                            phase3_consecutive_failures += 1

                except Exception as e:
                    logger.debug("Action processing error: %s", e)
                    phase3_consecutive_failures += 1

            self.timer.stop("phase3_actions")
            logger.info("Phase 3 done: %d action pages", _action_pages_visited)

            # Final ResponseParser drain — pick up anything discovered during
            # the last Phase 3 action (these URLs won't be BFS-visited this run
            # but are available in routes for the caller to use).
            if self._response_parser is not None:
                with self._rp_lock:
                    pending_rp_final = self._rp_discovered[:]
                    self._rp_discovered.clear()
                for rp_url in pending_rp_final:
                    if self.scope.in_scope(rp_url) and not self.registry.seen_url(rp_url):
                        self._add_route(urlparse(rp_url).path or "/")
                        _rp_added_count += 1
                if pending_rp_final:
                    logger.debug(
                        "ResponseParser final drain: %d URLs added to routes",
                        len(pending_rp_final),
                    )

            # Close DiagnosticsWriter (Enhancement 11)
            if self._diagnostics:
                # CrawlGraph DOT export — written alongside the diagnostics output
                # (Enhancement 8 — CrawlGraph DOT file export)
                dot_path = _os.path.join(self._diagnostics.dir, "crawl_graph.dot")
                self.crawl_graph.draw_dot(dot_path)
                self._diagnostics.close()

            # Join all background JS fetch threads before taking the stats
            # snapshot.  _flush_page_intel() fires daemon threads to fetch
            # <script src>, ES modules, workers, and service workers off the
            # Playwright thread.  Without this barrier those threads can still
            # be running when len(self.js_files) is read, producing "0 JS" in
            # the headless summary while the JS analysis stage sees all 5 files
            # ~300ms later.
            with self._bg_fetch_lock:
                _pending_threads = list(self._bg_fetch_threads)
            for _bgt in _pending_threads:
                try:
                    _bgt.join(timeout=15)
                except Exception:
                    pass
            logger.debug("Background JS fetch barrier: joined %d threads", len(_pending_threads))

            # Detach Phase 1 CDP session before closing the context
            _detach_cdp_session(_phase1_cdp)

            # Final drain of Phase 1 responses before closing ctx — any
            # late-arriving responses (async resources, lazy fetches) get
            # processed here while the context is still valid.
            _drain_phase1_responses()

            try:
                ctx.close()
            except Exception:
                pass
            browser.close()

        # ── Phase 4: Build endpoints ──────────────────────────────────────────
        self.timer.start("endpoint_build")
        self.endpoints = self._api_calls_to_endpoints()
        self.timer.stop("endpoint_build")
        self.timer.stop("total")

        timings = self.timer.summary()
        workers_found = [js for js in self.js_files if js.technology == "webworker"]

        sw_found      = [js for js in self.js_files if js.technology in ("service-worker", "service-worker-import")]
        es_mod_found  = [js for js in self.js_files if js.technology in ("es-module",)]
        shadow_found  = [js for js in self.js_files if "shadow-dom" in (js.technology or "")]

        crawl_graph_summary = self.crawl_graph.summary()

        stats = {
            "pages":              self.pages_visited,
            "js":                 len(self.js_files),
            # Total JS responses the browser intercepted before dedup.
            # When the static crawler already found all JS files, js==0 but
            # js_intercepted>0 — this tells the operator headless was working.
            "js_intercepted":     self._js_intercepted_count,
            "xhr":                sum(1 for c in self.api_calls if c.get("type") == "xhr"),
            "fetch":              sum(1 for c in self.api_calls if c.get("type") == "fetch"),
            "ws":                 len(self.ws_urls),
            "ws_messages":        len(self.ws_messages),
            "sse":                len(set(self.sse_urls)),
            "nav_pushstate":      len(self.nav_urls),
            "routes":             len(self.routes),
            "endpoints":          len(self.endpoints),
            "workers":            len(workers_found),
            "sw":                 len(sw_found),
            "es_modules":         len(es_mod_found),
            "shadow_dom":         len(shadow_found),
            "actions_queued":     len(self._seen_actions),
            "crawl_graph":        crawl_graph_summary,
            "timings":            timings,
            # Katana enhancements (session 3)
            "response_parser_urls": _rp_added_count,
            "trie_filtered":        _trie_filtered_count,
            # Katana enhancements (session 4)
            "onclick_navigations":  _onclick_nav_count,
            "js_nav_urls":          _js_nav_count,
            "technologies":         dict(self._tech_detections),
            "raw_traffic_captured": len(self._raw_traffic),
        }

        logger.info(
            "Headless done: %d pages, %d JS new (%d intercepted), %d routes, "
            "%d graph-nodes, %.1fs total",
            self.pages_visited, len(self.js_files), self._js_intercepted_count,
            len(self.routes), crawl_graph_summary["nodes"],
            timings.get("total", 0),
        )
        return {
            "js_files":    self.js_files,
            "endpoints":   self.endpoints,
            "routes":      list(self.routes),
            "api_calls":   self.api_calls,
            "ws_messages": self.ws_messages,
            "sse_urls":    list(set(self.sse_urls)),
            "nav_urls":    self.nav_urls,
            "stats":       stats,
            "timings":     timings,
            "auth_result": self.auth_result,
            "crawl_graph": crawl_graph_summary,
            "raw_traffic":    self._raw_traffic if self.capture_raw_traffic else [],
            "technologies":   self._tech_detections,
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
    url:                  str,
    scope,
    timeout:              int            = 30,
    stealth:              bool           = False,
    max_pages:            int            = 100,
    external_seen:        set            = None,
    seed_urls:            list           = None,
    interact:             bool           = False,
    workers:              int            = 3,
    cookies:              list           = None,
    extra_headers:        dict           = None,
    seen_hashes:          set            = None,
    # Katana enhancements (session 1)
    max_failures:         int            = 10,
    max_crawl_duration:   int            = 0,
    enable_diagnostics:   bool           = False,
    slow_mo:              int            = 0,
    captcha_handler       = None,
    cookie_consent_bypass: bool          = True,
    # Katana enhancements (session 2)
    auth_steps:           Optional[List[LoginStep]] = None,
    page_load_strategy:   str            = "domcontentloaded",
    hooks:                Optional[CrawlHooks] = None,
    auth_credentials:     Optional[dict] = None,
    # Katana enhancements (session 3)
    cookie_jar_path:      Optional[str]  = None,
    url_filter_similar:   bool           = False,
    url_filter_threshold: int            = 3,
    response_body_extract: bool          = True,
    # Katana enhancements (session 4)
    max_onclick_links:    int            = 50,
    capture_raw_traffic:  bool           = False,
    content_similarity_threshold: float  = 0.0,
    technology_detection: bool           = False,
    # Form interaction engine
    forms_mode:           bool           = False,
    # Browser pool
    num_browsers:         int            = 5,
) -> dict:
    """
    Full headless scan — all Katana enhancements exposed.

    seed_urls:             routes from static analysis to pre-seed the engine.
    workers:               concurrent page processing (default 3).
    interact:              enable tab/dropdown interaction (slower, more coverage).
    cookies:               Playwright cookie dicts injected before first navigation.
    extra_headers:         extra HTTP headers (non-Cookie) applied to every request.
    seen_hashes:           content SHA-256 hashes already seen by the crawler (for dedup).
    max_failures:          halt crawl after this many consecutive page/action failures (default 10).
    max_crawl_duration:    max crawl time in seconds, 0 = unlimited; timer starts after auth (default 0).
    enable_diagnostics:    write screenshots + action log + crawl_graph.dot to a temp dir (default False).
    slow_mo:               milliseconds to pause between interactions for visual debugging (default 0).
    captcha_handler:       optional callable(page) -> bool that tries to solve detected captchas.
    cookie_consent_bypass: auto-dismiss GDPR/cookie banners before crawling (default True).
    auth_steps:            recorded auth flow steps (LoginStep list) for multi-step SSO/MFA replay.
    page_load_strategy:    navigation wait strategy: eager/domcontentloaded/load/networkidle/none.
    hooks:                 CrawlHooks lifecycle callbacks (before_action, after_action, on_navigation, etc.).
    auth_credentials:      dict with 'username' and 'password' for auto-login fallback.
    cookie_jar_path:       path to a Netscape-format cookie file (Burp Suite export) to pre-load.
    url_filter_similar:    collapse structurally identical URLs (/item/1, /item/2 -> /item/*) to
                           avoid hammering parameterized routes (PathTrie dedup, default False).
    url_filter_threshold:  number of distinct values before a path segment is wildcarded (default 3).
    response_body_extract: parse every HTTP response body for embedded URLs not visible in the DOM
                           (JS fetch calls, JSON hrefs, CSS url(), sourcemaps — default True).
    num_browsers:          number of parallel browser instances in the pool for Phase 2 BFS
                           (default 5; lower to 1-2 when WAF rate-limiting is a concern).
    """
    engine = HeadlessEngine(
        target_url             = url,
        scope                  = scope,
        timeout                = timeout,
        stealth                = stealth,
        max_pages              = max_pages,
        interact               = interact,
        workers                = workers,
        external_seen          = external_seen or set(),
        cookies                = cookies or [],
        extra_headers          = extra_headers or {},
        seen_hashes            = seen_hashes or set(),
        max_failures           = max_failures,
        max_crawl_duration     = max_crawl_duration,
        enable_diagnostics     = enable_diagnostics,
        slow_mo                = slow_mo,
        captcha_handler        = captcha_handler,
        cookie_consent_bypass  = cookie_consent_bypass,
        auth_steps             = auth_steps or [],
        page_load_strategy     = page_load_strategy,
        hooks                  = hooks,
        cookie_jar_path        = cookie_jar_path,
        url_filter_similar     = url_filter_similar,
        url_filter_threshold   = url_filter_threshold,
        response_body_extract  = response_body_extract,
        max_onclick_links      = max_onclick_links,
        capture_raw_traffic    = capture_raw_traffic,
        content_similarity_threshold = content_similarity_threshold,
        technology_detection   = technology_detection,
        forms_mode             = forms_mode,
        num_browsers           = num_browsers,
    )
    if seed_urls:
        engine.seed_urls = list(seed_urls)
    if auth_credentials:
        engine.auth_credentials = auth_credentials
    return engine.run()
