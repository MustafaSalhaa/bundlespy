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

# ── Confidence levels ─────────────────────────────────────────────────────────

CONF_HIGH   = 0.90  # explicit router config, createBrowserRouter, RouterModule
CONF_MEDIUM = 0.82  # router.push, navigate(), goto() - likely frontend nav
CONF_LOW    = 0.72  # history.pushState, location.href - may be redirect logic

# ── Minimum path length (filter out "/" and single-char noise) ────────────────

MIN_PATH_LEN = 2

# ── Skip patterns - these are NOT page routes ─────────────────────────────────

_SKIP_EXTS = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".css", ".scss", ".less",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".json", ".xml", ".map",
    ".pdf", ".zip", ".mp4", ".mp3",
)

_SKIP_PREFIXES = (
    "http://", "https://", "ws://", "wss://",
    "//", "javascript:", "mailto:", "tel:", "data:", "blob:",
    "#",
)

_SKIP_VALUES = {
    "", "/", "/*", "//", "*", "**",
    "./", "../", ".",
    "undefined", "null", "true", "false", "none",
    "/index.html", "/favicon.ico",
}

_SKIP_CONTAINS = {
    "google-analytics.com", "googletagmanager.com",
    "facebook.net", "twitter.com", "linkedin.com",
    "cdn.", "cdnjs.", "unpkg.com", "jsdelivr.net",
    "${", "<%", "%>",
}


# ── React Router patterns ─────────────────────────────────────────────────────

# <Route path="/admin" ... /> or <Route path='/admin/users'>
RE_JSX_ROUTE = re.compile(
    r'<Route[^>]+\bpath\s*=\s*[{]?\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$+,;]+)["\x27`]',
    re.IGNORECASE,
)

# createBrowserRouter([{ path: "/admin", ... }]) - React Router v6
RE_CREATE_BROWSER_ROUTER = re.compile(
    r'\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$+,;]+)["\x27`]',
    re.IGNORECASE,
)

# useNavigate / navigate() / router.push() / router.replace() / navigateTo() (Nuxt)
RE_NAVIGATE = re.compile(
    r'\b(?:navigate|navigateTo|push|replace)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# <Link to="/dashboard"> or <Link href="/about">
RE_LINK_TO = re.compile(
    r'<Link[^>]+\b(?:to|href)\s*=\s*[{]?\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Redirect to="/login" (React Router v5)
RE_REDIRECT_TO = re.compile(
    r'<Redirect[^>]+\bto\s*=\s*[{]?\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# history.push('/path') history.replace('/path')
RE_HISTORY = re.compile(
    r'\bhistory\s*\.\s*(?:push|replace|go)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# Switch/Routes children - catch path="" assignments in React Router objects
RE_ROUTE_OBJECT_PATH = re.compile(
    r'\{[^}]{0,500}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$]+)["\x27`][^}]{0,200}\}',
    re.IGNORECASE | re.DOTALL,
)


# ── Vue Router patterns ───────────────────────────────────────────────────────

# routes: [ { path: '/home', component: Home } ]
# Also catches Angular, Nuxt route arrays
RE_VUE_ROUTE_ARRAY = re.compile(
    r'\{\s*(?:["\x27]?path["\x27]?\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!$+,;]+)["\x27`])',
    re.IGNORECASE,
)

# router.push('/path') router.replace('/path') - Vue Router
RE_VUE_PUSH = re.compile(
    r'\brouter\s*\.\s*(?:push|replace|go|navigate)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# router.push({ path: '/admin' }) - Vue Router object form
RE_VUE_PUSH_OBJ = re.compile(
    r'\brouter\s*\.\s*(?:push|replace)\s*\(\s*\{[^}]{0,200}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# router.addRoute({ path: '/new-route', ... })
RE_VUE_ADD_ROUTE = re.compile(
    r'\b(?:addRoute|beforeEach|afterEach)\s*\([^)]{0,200}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]]+)["\x27`]',
    re.IGNORECASE,
)

# <router-link to="/about"> in template strings or SSR
RE_ROUTER_LINK = re.compile(
    r'<router-link[^>]+\bto\s*=\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)


# ── Angular Router patterns ───────────────────────────────────────────────────

# RouterModule.forRoot(routes) / RouterModule.forChild(routes)
# Angular route objects: { path: 'admin', component: ... }
# Already covered by RE_VUE_ROUTE_ARRAY (same syntax)

# routerLink="/path" attribute (Angular template in JS string)
RE_ANGULAR_ROUTERLINK = re.compile(
    r'\brouterLink\s*=\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# this.router.navigate(['/admin', userId]) - Angular
RE_ANGULAR_NAVIGATE = re.compile(
    r'\bthis\s*\.\s*router\s*\.\s*navigate\s*\(\s*\[\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# router.navigateByUrl('/path') - Angular
RE_ANGULAR_NAVIGATE_URL = re.compile(
    r'\bnavigateByUrl\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# canActivate / canLoad - Angular guards often reveal protected routes
RE_ANGULAR_REDIRECT_TO = re.compile(
    r'\bredirectTo\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)


# ── Next.js patterns ──────────────────────────────────────────────────────────

# router.push('/checkout') - next/router useRouter()
# already covered by RE_NAVIGATE

# next/link <Link href="/about"> - already covered by RE_LINK_TO

# getServerSideProps redirect: { destination: '/login' }
RE_NEXTJS_REDIRECT_DEST = re.compile(
    r'\bdestination\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Next.js App Router - redirect('/login'), notFound() path, permanentRedirect
RE_NEXTJS_REDIRECT_CALL = re.compile(
    r'\b(?:redirect|permanentRedirect)\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Next.js API route handlers (route.ts files compiled in) - export GET/POST
RE_NEXTJS_REWRITE = re.compile(
    r'\bsource\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!:*]+)["\x27`]',
    re.IGNORECASE,
)


# ── SvelteKit patterns ────────────────────────────────────────────────────────

# goto('/dashboard') - SvelteKit
RE_SVELTE_GOTO = re.compile(
    r'\bgoto\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# $app/navigation: afterNavigate, beforeNavigate callbacks expose route.id
# definePageMeta - Nuxt
RE_NUXT_PAGE_META = re.compile(
    r'\bdefinePageMeta\s*\([^)]{0,300}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)


# ── Tanstack Router / Wouter / Solid Router ───────────────────────────────────

# createRoute({ path: '/about', ... }) - Tanstack Router
RE_TANSTACK_ROUTE = re.compile(
    r'\bcreate(?:Route|FileRoute|RootRoute|LazyRoute)\s*\([^)]{0,300}\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!*$]+)["\x27`]',
    re.IGNORECASE,
)

# <Route path="/about"> - Wouter (same syntax as React Router)
# Already covered by RE_JSX_ROUTE


# ── Generic navigation patterns ───────────────────────────────────────────────

# window.location.href = '/path'
# window.location.pathname = '/path'
# location.href = '/path'
RE_LOCATION_ASSIGN = re.compile(
    r'(?:window\s*\.\s*)?location\s*(?:\.\s*(?:href|pathname|assign|replace))?'
    r'\s*[=\(]\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# history.pushState(state, title, '/path')
RE_HISTORY_PUSHSTATE = re.compile(
    r'\bhistory\s*\.\s*(?:pushState|replaceState)\s*\([^,)]*,[^,)]*,\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Backbone Router routes object: { "users/:id": "showUser" }
RE_BACKBONE_ROUTES = re.compile(
    r'\broutes\s*:\s*\{([^}]{0,2000})\}',
    re.DOTALL,
)
RE_BACKBONE_ROUTE_ENTRY = re.compile(
    r'["\x27](/?[A-Za-z0-9/_\-.:*?=&%#{}[\]@!]+)["\x27]\s*:',
)

# Named route constant assignments: ROUTES.HOME = '/home', routes.admin = '/admin'
RE_ROUTE_CONST = re.compile(
    r'\b(?:ROUTE|ROUTES|PATHS|PATH|URL|URLS|NAV|NAVIGATION|LINKS|PAGES)\s*'
    r'(?:\.\s*[A-Z_][A-Z0-9_]{0,40}|\[["\x27][A-Z_][A-Z0-9_]{0,40}["\x27]\])\s*'
    r'=\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Route constant object: const ROUTES = { HOME: '/home', ADMIN: '/admin' }
RE_ROUTE_OBJECT = re.compile(
    r'\b(?:ROUTE|ROUTES|PATHS|PATH|URL|URLS|NAV|NAVIGATION|LINKS|PAGES)\s*'
    r'=\s*(?:Object\.freeze\s*\()?\s*\{([^}]{0,3000})\}',
    re.IGNORECASE | re.DOTALL,
)
RE_OBJECT_STRING_VALUE = re.compile(
    r'["\x27]?[A-Za-z_$][A-Za-z0-9_$]{0,60}["\x27]?\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]'
)

# href attributes in JSX template strings (compiled SSR)
RE_JSX_HREF = re.compile(
    r'\bhref\s*[=:]\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}[\]@!]+)["\x27`]',
    re.IGNORECASE,
)

# Express/server HTML routes (app.get('/page', renderFn) - server-side HTML routes)
RE_SERVER_HTML_ROUTE = re.compile(
    r'\b(?:app|router|server)\s*\.\s*get\s*\(\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}:*[\]@!]+)["\x27`]',
    re.IGNORECASE,
)


# ── Helper functions ──────────────────────────────────────────────────────────

def _clean_route(path: str) -> str:
    """Normalize route path - convert :param and [param] to {param}."""
    if not path:
        return path
    # Express :param style
    path = re.sub(r':([A-Za-z_][A-Za-z0-9_]{0,30})', r'{\1}', path)
    # Next.js [param] and [[...param]] style
    path = re.sub(r'\[\[?\.\.\.[A-Za-z_][A-Za-z0-9_]*\]?\]', '{...param}', path)
    path = re.sub(r'\[([A-Za-z_][A-Za-z0-9_]*)\]', r'{\1}', path)
    # Angular :id style already handled above
    # Strip trailing slash unless root
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _is_valid_route(path: str) -> bool:
    """Return True if path looks like a real frontend route."""
    if not path or len(path) < MIN_PATH_LEN:
        return False

    # Skip anything that starts with a known non-route prefix
    for prefix in _SKIP_PREFIXES:
        if path.startswith(prefix):
            return False

    # Skip known junk values
    if path.lower() in _SKIP_VALUES:
        return False

    # Skip files (assets, scripts, etc.)
    lower = path.lower()
    for ext in _SKIP_EXTS:
        if lower.endswith(ext):
            return False

    # Skip anything containing suspicious substrings
    for s in _SKIP_CONTAINS:
        if s in lower:
            return False

    # Must start with / or be a relative word-path (at least 2 chars for relative)
    if path.startswith("/") and len(path) < 3:
        return False
    if not path.startswith("/") and not re.match(r'^[a-zA-Z][a-zA-Z0-9_/-]{1,80}$', path):
        return False

    # Reject pure template placeholders like {param} with no leading slash
    if re.match(r'^\{[^}]+\}$', path):
        return False

    # Reject things that look like variable names only (no slash)
    if "/" not in path and re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', path) and len(path) < 3:
        return False

    return True


def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _evidence(content: str, pos: int, length: int = 100) -> str:
    start = max(0, pos - 10)
    end   = min(len(content), pos + length)
    return content[start:end].replace("\n", " ").strip()[:200]


def _make_endpoint(path: str, file_url: str, line: int,
                   confidence: float, evidence: str, method: str = "GET") -> Optional[Endpoint]:
    """Build a Route-category Endpoint object."""
    if not _is_valid_route(path):
        return None
    cleaned = _clean_route(path)
    if not cleaned or not _is_valid_route(cleaned):
        return None

    ep = Endpoint(
        url         = cleaned,
        path        = cleaned,
        method      = method,
        category    = "ROUTE",
        source_file = file_url,
        line_number = line,
        confidence  = confidence,
        evidence    = evidence,
    )
    try:
        ep.source_type = "static"
    except Exception:
        pass
    return ep


# ── Main extractor ────────────────────────────────────────────────────────────

def extract_routes(content: str, file_url: str) -> List[Endpoint]:
    """
    Extract all frontend route paths from JavaScript content.

    Covers React Router, Vue Router, Angular Router, Next.js, SvelteKit,
    Nuxt, Tanstack Router, Wouter, Backbone, and generic navigation APIs.

    Returns a list of Endpoint objects with category="ROUTE".
    Fails silently - never raises.
    """
    if not content:
        return []

    results: List[Endpoint] = []
    seen: Set[str] = set()

    def _add(path: str, confidence: float, line: int, evidence: str,
             method: str = "GET") -> None:
        if not path:
            return
        normalized = _clean_route(path.strip())
        if not normalized:
            return
        key = normalized.lower()
        # Deduplicate - same path seen from multiple patterns is one route
        if key in seen:
            return
        seen.add(key)
        ep = _make_endpoint(normalized, file_url, line, confidence, evidence, method)
        if ep:
            results.append(ep)

    try:
        _run_patterns(content, file_url, _add)
    except Exception as exc:
        logger.debug("Route extraction failed for %s: %s", file_url, exc)

    return results


def _run_patterns(content: str, file_url: str, _add) -> None:
    """Run all pattern groups. Called inside a try/except by extract_routes."""

    # ── React Router JSX <Route path="..."> ──────────────────────────────────
    for m in RE_JSX_ROUTE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── React Router / generic path: "..." in route objects ──────────────────
    for m in RE_CREATE_BROWSER_ROUTER.finditer(content):
        path = m.group(1)
        # Skip if this is inside a known API assignment (don't steal from endpoint extractor)
        line = _get_line(content, m.start())
        ev   = _evidence(content, m.start())
        # Give lower confidence if ambiguous - could be API
        if path.startswith("/api/") or "/graphql" in path.lower():
            _add(path, 0.70, line, ev)
        else:
            _add(path, CONF_HIGH, line, ev)

    # ── <Link to=...> / <Link href=...> ──────────────────────────────────────
    for m in RE_LINK_TO.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── <Redirect to=...> ────────────────────────────────────────────────────
    for m in RE_REDIRECT_TO.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── navigate() / push() / replace() ──────────────────────────────────────
    for m in RE_NAVIGATE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── history.push('/path') ─────────────────────────────────────────────────
    for m in RE_HISTORY.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Vue Router: routes array path ────────────────────────────────────────
    for m in RE_VUE_ROUTE_ARRAY.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── router.push('/path') ──────────────────────────────────────────────────
    for m in RE_VUE_PUSH.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── router.push({ path: '/admin' }) ──────────────────────────────────────
    for m in RE_VUE_PUSH_OBJ.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── router.addRoute / beforeEach ─────────────────────────────────────────
    for m in RE_VUE_ADD_ROUTE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── <router-link to="..."> ────────────────────────────────────────────────
    for m in RE_ROUTER_LINK.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Angular routerLink ────────────────────────────────────────────────────
    for m in RE_ANGULAR_ROUTERLINK.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Angular this.router.navigate(['/path']) ───────────────────────────────
    for m in RE_ANGULAR_NAVIGATE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Angular navigateByUrl ─────────────────────────────────────────────────
    for m in RE_ANGULAR_NAVIGATE_URL.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Angular redirectTo ────────────────────────────────────────────────────
    for m in RE_ANGULAR_REDIRECT_TO.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Next.js: destination in redirect ─────────────────────────────────────
    for m in RE_NEXTJS_REDIRECT_DEST.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Next.js: redirect('/login') App Router ────────────────────────────────
    for m in RE_NEXTJS_REDIRECT_CALL.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Next.js: rewrites source ──────────────────────────────────────────────
    for m in RE_NEXTJS_REWRITE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── SvelteKit: goto('/path') ──────────────────────────────────────────────
    for m in RE_SVELTE_GOTO.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Nuxt: definePageMeta path ─────────────────────────────────────────────
    for m in RE_NUXT_PAGE_META.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Tanstack Router createRoute({ path }) ─────────────────────────────────
    for m in RE_TANSTACK_ROUTE.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Route constant objects: const ROUTES = { HOME: '/home', ... } ────────
    for m in RE_ROUTE_OBJECT.finditer(content):
        body = m.group(1)
        line_base = _get_line(content, m.start())
        for inner in RE_OBJECT_STRING_VALUE.finditer(body):
            _add(inner.group(1), CONF_HIGH, line_base, _evidence(content, m.start()))

    # ── Named route constant assignments: ROUTES.ADMIN = '/admin' ────────────
    for m in RE_ROUTE_CONST.finditer(content):
        _add(m.group(1), CONF_HIGH, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Backbone Router routes object ─────────────────────────────────────────
    for m in RE_BACKBONE_ROUTES.finditer(content):
        body = m.group(1)
        line_base = _get_line(content, m.start())
        for inner in RE_BACKBONE_ROUTE_ENTRY.finditer(body):
            path = inner.group(1)
            if not path.startswith("http"):
                if not path.startswith("/"):
                    path = "/" + path
                _add(path, CONF_HIGH, line_base, _evidence(content, m.start()))

    # ── history.pushState(state, title, '/path') ──────────────────────────────
    for m in RE_HISTORY_PUSHSTATE.finditer(content):
        _add(m.group(1), CONF_MEDIUM, _get_line(content, m.start()),
             _evidence(content, m.start()))

    # ── Generic location.href = '/path' ──────────────────────────────────────
    for m in RE_LOCATION_ASSIGN.finditer(content):
        path = m.group(1)
        if path.startswith("/") and len(path) > 1:
            _add(path, CONF_LOW, _get_line(content, m.start()),
                 _evidence(content, m.start()))

    # ── href="/path" in JSX/template strings (SSR bundles) ───────────────────
    # Lower confidence - very noisy
    for m in RE_JSX_HREF.finditer(content):
        path = m.group(1)
        # Only take paths that look like real pages - at least one more segment
        if path.startswith("/") and len(path) > 2 and "/" in path[1:]:
            _add(path, CONF_LOW, _get_line(content, m.start()),
                 _evidence(content, m.start()))

    # ── Server-side HTML routes: app.get('/page', handler) ───────────────────
    for m in RE_SERVER_HTML_ROUTE.finditer(content):
        path = m.group(1)
        # Only include if it doesn't look like a pure API path
        if not path.startswith("/api/") and "/graphql" not in path.lower():
            _add(path, CONF_MEDIUM, _get_line(content, m.start()),
                 _evidence(content, m.start()))
