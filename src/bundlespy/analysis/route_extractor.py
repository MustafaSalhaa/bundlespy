"""
Frontend Route Extractor for BundleSpy.

Extracts page routes (not API endpoints) defined in frontend router configs
and navigation calls across every major framework. Works on minified and
unminified JS alike.

Covers:
- React Router v4/v5/v6 (Route, Routes, createBrowserRouter, useNavigate, Link)
- Vue Router v3/v4 (routes array, router.push, router.addRoute, <router-link>)
- Angular Router (RouterModule.forRoot, { path: '...', component: ... })
- Next.js (router.push, next/link href, getServerSideProps redirects)
- SvelteKit (goto, <a href=...>, $page.url, load function redirects)
- Nuxt (navigateTo, useRouter().push, definePageMeta({ path: ... }))
- Reach Router, Wouter, Tanstack Router, Solid Router
- Generic: history.pushState, location.href, window.location.pathname =
- Express/Koa server-side HTML routes (not just API routes)
- Named route constants and route map objects

Design constraints:
- Never makes network calls
- Fails silently on any exception
- Hard time limit via caller (inherits from extract_all_endpoints)
- Works on minified code
- Returns Endpoint objects with category="ROUTE" and confidence scores
"""

import re
import logging
from typing import List, Set, Optional
from urllib.parse import urlparse

from ..storage.models import Endpoint

logger = logging.getLogger("bundlespy.analysis.route_extractor")

# Confidence levels
CONF_HIGH   = 0.9
CONF_MEDIUM = 0.82
CONF_LOW    = 0.72

# Minimum path length to be considered a valid route
MIN_PATH_LEN = 2

# Extensions that are assets, not routes
_SKIP_EXTS = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".css", ".scss", ".less",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".json", ".xml", ".map", ".pdf", ".zip", ".mp4", ".mp3",
)

# URL scheme prefixes that indicate non-routes
_SKIP_PREFIXES = (
    "http://", "https://", "ws://", "wss://", "//",
    "javascript:", "mailto:", "tel:", "data:", "blob:", "#",
)

# Exact values to skip
_SKIP_VALUES = frozenset({
    "", "*", "**", ".", "/", "..", "./", "../",
    "/favicon.ico", "/index.html", "//", "/*",
    "null", "undefined", "none", "true", "false",
})

# Substrings that indicate noise / CDN / template expressions
_SKIP_CONTAINS = frozenset({
    "${", "<%", "%>",
    "cdn.", "cdnjs.", "unpkg.com", "jsdelivr.net",
    "googletagmanager.com", "google-analytics.com",
    "twitter.com", "facebook.net", "linkedin.com",
})

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# React Router v4/v5/v6: <Route path="/foo" ...>
RE_JSX_ROUTE = re.compile(
    r'<Route[^>]+\bpath\s*=\s*[{]?\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$+,;]+)["\x27`]',
    re.IGNORECASE,
)

# createBrowserRouter / route objects: path: "/foo"
RE_CREATE_BROWSER_ROUTER = re.compile(
    r'\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$+,;]+)["\x27`]',
    re.IGNORECASE,
)

# Generic navigation: navigate("/foo"), push("/foo"), replace("/foo")
RE_NAVIGATE = re.compile(
    r'\b(?:navigate|navigateTo|push|replace)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# React Router <Link to="/foo"> / <Link href="/foo">
RE_LINK_TO = re.compile(
    r'<Link[^>]+\b(?:to|href)\s*=\s*[{]?\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# React Router v5 <Redirect to="/foo">
RE_REDIRECT_TO = re.compile(
    r'<Redirect[^>]+\bto\s*=\s*[{]?\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# history.push/replace/go("/foo")
RE_HISTORY = re.compile(
    r'\bhistory\s*\.\s*(?:push|replace|go)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# Route object with path key: { ..., path: "/foo", ... }
RE_ROUTE_OBJECT_PATH = re.compile(
    r'\{[^}]{0,500}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$]+)["\x27`][^}]{0,200}\}',
    re.IGNORECASE | re.DOTALL,
)

# Vue Router v3/v4 route array entry: { path: '/foo', component: Foo }
RE_VUE_ROUTE_ARRAY = re.compile(
    r'\{\s*(?:["\x27]?path["\x27]?\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$+,;]+)["\x27`])',
    re.IGNORECASE,
)

# Vue router.push("/foo")
RE_VUE_PUSH = re.compile(
    r'\brouter\s*\.\s*(?:push|replace|go|navigate)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# Vue router.push({ path: "/foo" })
RE_VUE_PUSH_OBJ = re.compile(
    r'\brouter\s*\.\s*(?:push|replace)\s*\(\s*\{[^}]{0,200}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Vue router.addRoute / beforeEach / afterEach
RE_VUE_ADD_ROUTE = re.compile(
    r'\b(?:addRoute|beforeEach|afterEach)\s*\([^)]{0,200}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# Vue <router-link to="/foo">
RE_ROUTER_LINK = re.compile(
    r'<router-link[^>]+\bto\s*=\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Angular [routerLink]="/foo"
RE_ANGULAR_ROUTERLINK = re.compile(
    r'\brouterLink\s*=\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Angular this.router.navigate(['/foo'])
RE_ANGULAR_NAVIGATE = re.compile(
    r'\bthis\s*\.\s*router\s*\.\s*navigate\s*\(\s*\[\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Angular this.router.navigateByUrl('/foo')
RE_ANGULAR_NAVIGATE_URL = re.compile(
    r'\bnavigateByUrl\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Angular redirectTo: '/foo'
RE_ANGULAR_REDIRECT_TO = re.compile(
    r'\bredirectTo\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Next.js redirect destination: "/foo"
RE_NEXTJS_REDIRECT_DEST = re.compile(
    r'\bdestination\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Next.js redirect() / permanentRedirect()
RE_NEXTJS_REDIRECT_CALL = re.compile(
    r'\b(?:redirect|permanentRedirect)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Next.js rewrite source: '/foo'
RE_NEXTJS_REWRITE = re.compile(
    r'\bsource\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!:*]+)["\x27`]',
    re.IGNORECASE,
)

# SvelteKit goto('/foo')
RE_SVELTE_GOTO = re.compile(
    r'\bgoto\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Nuxt definePageMeta({ path: '/foo' })
RE_NUXT_PAGE_META = re.compile(
    r'\bdefinePageMeta\s*\([^)]{0,300}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Tanstack Router createRoute / createFileRoute / createRootRoute / createLazyRoute
RE_TANSTACK_ROUTE = re.compile(
    r'\bcreate(?:Route|FileRoute|RootRoute|LazyRoute)\s*\([^)]{0,300}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!*$]+)["\x27`]',
    re.IGNORECASE,
)

# window.location.href = "/foo" / location.assign("/foo")
RE_LOCATION_ASSIGN = re.compile(
    r'(?:window\s*\.\s*)?location\s*(?:\.\s*(?:href|pathname|assign|replace))?\s*[=\(]\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# history.pushState({}, "", "/foo")
RE_HISTORY_PUSHSTATE = re.compile(
    r'\bhistory\s*\.\s*(?:pushState|replaceState)\s*\([^,)]*,[^,)]*,\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Backbone routes: { "/foo": "handler" }
RE_BACKBONE_ROUTES = re.compile(
    r'\broutes\s*:\s*\{([^}]{0,2000})\}',
    re.DOTALL,
)
RE_BACKBONE_ROUTE_ENTRY = re.compile(
    r'["\x27](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!]+)["\x27]\s*:',
)

# Named route constants: ROUTES.HOME = "/home" / PATHS["LOGIN"] = "/login"
RE_ROUTE_CONST = re.compile(
    r'\b(?:ROUTE|ROUTES|PATHS|PATH|URL|URLS|NAV|NAVIGATION|LINKS|PAGES)\s*(?:\.\s*[A-Z_][A-Z0-9_]{0,40}|\[["\x27][A-Z_][A-Z0-9_]{0,40}["\x27]\])\s*=\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Route map objects: ROUTES = { HOME: "/home", ... }
RE_ROUTE_OBJECT = re.compile(
    r'\b(?:ROUTE|ROUTES|PATHS|PATH|URL|URLS|NAV|NAVIGATION|LINKS|PAGES)\s*=\s*(?:Object\.freeze\s*\()?\s*\{([^}]{0,3000})\}',
    re.IGNORECASE | re.DOTALL,
)
RE_OBJECT_STRING_VALUE = re.compile(
    r'["\x27]?[A-Za-z_$][A-Za-z0-9_$]{0,60}["\x27]?\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
)

# JSX href="/foo"
RE_JSX_HREF = re.compile(
    r'\bhref\s*[=:]\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Express/Koa server-side HTML routes: app.get("/foo", ...) / router.get("/foo")
RE_SERVER_HTML_ROUTE = re.compile(
    r'\b(?:app|router|server)\s*\.\s*get\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}:*[\]@!]+)["\x27`]',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _clean_route(path: str) -> str:
    """Normalize route path - convert :param and [param] to {param}."""
    if not path:
        return path
    # :param -> {param}
    path = re.sub(r':([A-Za-z_][A-Za-z0-9_]{0,30})', r'{\1}', path)
    # [[...param]] or [...param] -> {...param}
    path = re.sub(r'\[\[?\.\.\.[A-Za-z_][A-Za-z0-9_]*\]?\]', '{...param}', path)
    # [param] -> {param}
    path = re.sub(r'\[([A-Za-z_][A-Za-z0-9_]*)\]', r'{\1}', path)
    # Strip trailing slash (but not root /)
    if len(path) > 1:
        path = path.rstrip('/')
    return path


def _is_valid_route(path: str) -> bool:
    """Return True if path looks like a real frontend route."""
    if not path or len(path) < MIN_PATH_LEN:
        return False

    # Skip known noise prefixes
    for prefix in _SKIP_PREFIXES:
        if path.startswith(prefix):
            return False

    # Skip exact noise values
    if path.lower() in _SKIP_VALUES:
        return False

    # Skip by extension
    lower = path.lower()
    for ext in _SKIP_EXTS:
        if lower.endswith(ext):
            return False

    # Skip by substring noise
    for s in _SKIP_CONTAINS:
        if s in lower:
            return False

    # Must start with / (at least 3 chars) or look like a word path
    if path.startswith('/') and len(path) < 3:
        return False

    if not path.startswith('/'):
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_/-]{1,80}$', path):
            return False

    # Pure param placeholder like {id} alone is not a route
    if re.match(r'^\{[^}]+\}$', path):
        return False

    # Single JS identifier without slash (e.g. "home" could be ambiguous)
    if '/' not in path:
        if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', path) and len(path) < 3:
            return False

    return True


def _get_line(content: str, pos: int) -> int:
    """Return 1-based line number for character position."""
    return content[:pos].count('\n') + 1


def _evidence(content: str, pos: int, length: int = 100) -> str:
    """Return a short evidence snippet around the match."""
    start = max(0, pos - 10)
    end   = min(len(content), pos + length)
    return content[start:end].replace('\n', ' ').strip()[:200]


def _make_endpoint(path: str, file_url: str, line: int, confidence: float,
                   evidence: str, method: str = "GET") -> Optional[Endpoint]:
    """Build a Route-category Endpoint object."""
    if not _is_valid_route(path):
        return None
    cleaned = _clean_route(path)
    if not cleaned or not _is_valid_route(cleaned):
        return None
    try:
        ep = Endpoint(
            url=cleaned,
            path=cleaned,
            method=method,
            category="ROUTE",
            source_file=file_url,
            line_number=line,
            confidence=confidence,
            evidence=evidence,
        )
        try:
            ep.source_type = "static"
        except Exception:
            pass
        return ep
    except Exception:
        return None


def extract_routes(content: str, file_url: str) -> List[Endpoint]:
    """
    Extract all frontend route paths from JS content.

    Returns a list of Endpoint objects with category="ROUTE".
    Never raises; returns [] on any error.
    """
    if not content:
        return []

    results: List[Endpoint] = []
    seen: Set[str] = set()

    def _add(path: str, confidence: float, line: int, evidence: str,
             method: str = "GET") -> None:
        ep = _make_endpoint(path, file_url, line, confidence, evidence, method)
        if ep is None:
            return
        key = ep.url.rstrip("/").lower().split("?")[0]
        if key in seen:
            return
        seen.add(key)
        results.append(ep)

    try:
        _run_patterns(content, file_url, _add)
    except Exception as exc:
        logger.debug("Route extraction failed for %s: %s", file_url, exc)

    return results


def _run_patterns(content: str, file_url: str, _add) -> None:
    """Run all pattern groups. Called inside a try/except by extract_routes."""

    # React Router JSX <Route path="/foo">
    for m in RE_JSX_ROUTE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # createBrowserRouter path: "/foo" - filter API/graphql paths
    for m in RE_CREATE_BROWSER_ROUTER.finditer(content):
        path = m.group(1)
        line = _get_line(content, m.start())
        ev   = _evidence(content, m.start())
        if path.startswith('/api/') or '/graphql' in path.lower():
            _add(path, 0.7, line, ev)
        else:
            _add(path, CONF_HIGH, line, ev)

    # React Router <Link to="/foo">
    for m in RE_LINK_TO.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # React Router <Redirect to="/foo">
    for m in RE_REDIRECT_TO.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Generic navigate/push/replace
    for m in RE_NAVIGATE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # history.push/replace/go
    for m in RE_HISTORY.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Vue Router route array
    for m in RE_VUE_ROUTE_ARRAY.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Vue router.push("/foo")
    for m in RE_VUE_PUSH.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Vue router.push({ path: "/foo" })
    for m in RE_VUE_PUSH_OBJ.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Vue addRoute / beforeEach / afterEach
    for m in RE_VUE_ADD_ROUTE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Vue <router-link to="/foo">
    for m in RE_ROUTER_LINK.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Angular [routerLink]
    for m in RE_ANGULAR_ROUTERLINK.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Angular this.router.navigate(['/foo'])
    for m in RE_ANGULAR_NAVIGATE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Angular navigateByUrl
    for m in RE_ANGULAR_NAVIGATE_URL.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Angular redirectTo
    for m in RE_ANGULAR_REDIRECT_TO.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Next.js redirect destination
    for m in RE_NEXTJS_REDIRECT_DEST.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Next.js redirect() / permanentRedirect()
    for m in RE_NEXTJS_REDIRECT_CALL.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Next.js rewrite source
    for m in RE_NEXTJS_REWRITE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # SvelteKit goto
    for m in RE_SVELTE_GOTO.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Nuxt definePageMeta
    for m in RE_NUXT_PAGE_META.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Tanstack Router createRoute / createFileRoute etc.
    for m in RE_TANSTACK_ROUTE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Route map objects: ROUTES = { HOME: "/home", ... }
    for m in RE_ROUTE_OBJECT.finditer(content):
        body      = m.group(1)
        line_base = _get_line(content, m.start())
        for inner in RE_OBJECT_STRING_VALUE.finditer(body):
            _add(inner.group(1), CONF_HIGH, line_base,
                 _evidence(content, m.start()))

    # Named route constants: ROUTES.HOME = "/home"
    for m in RE_ROUTE_CONST.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Backbone routes
    for m in RE_BACKBONE_ROUTES.finditer(content):
        body      = m.group(1)
        line_base = _get_line(content, m.start())
        for inner in RE_BACKBONE_ROUTE_ENTRY.finditer(body):
            _add(inner.group(1), CONF_HIGH, line_base,
                 _evidence(content, m.start()))

    # history.pushState
    for m in RE_HISTORY_PUSHSTATE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # location.href / location.assign
    for m in RE_LOCATION_ASSIGN.finditer(content):
        _add(m.group(1), CONF_LOW, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # JSX href="/foo"
    for m in RE_JSX_HREF.finditer(content):
        _add(m.group(1), CONF_LOW, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # Express/Koa server-side HTML routes
    for m in RE_SERVER_HTML_ROUTE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))
