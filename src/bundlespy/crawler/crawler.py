"""
BundleSpy crawler - maximum attack-surface coverage.

Discovery layers (all applied, fully modular):
  1. robots.txt             — Disallow/Allow routes + sitemap hints + JS paths
  2. sitemap.xml            — recursive sitemap index, <loc> extraction
  3. Asset manifests        — CRA, Vite, Next.js, Laravel Mix, generic
  4. Common page probes     — 200+ high-value paths probed directly
  5. Common JS probes       — 80+ known JS bundle paths
  6. HTML crawl             — script tags, preload, import maps, data-src, SW
  7. Deep JS route extract  — React/Vue/Angular/Next/Nuxt/Svelte/custom routers
  8. Dynamic imports        — import(), webpack chunks, Vite chunks, preload refs
  9. Hash / SPA routing     — /#/route, #!/route, hash-based navigation
 10. HTML form discovery    — <form action>, buttons, relative action resolution
 11. Historical URLs        — optional Wayback Machine CDX (marked 'historical')
 12. Inline script dedup    — content-hash based dedup
 13. Service worker         — precached asset lists
 14. Link headers           — preload/modulepreload links

Every discovered URL/route carries a DiscoveryRecord with full provenance:
  url, source, source_file, line, column, evidence, confidence,
  is_historical, is_runtime, is_static, parent_url
"""

import re
import json
import hashlib
import logging
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from typing import Set, List, Tuple, Optional, Dict
from datetime import datetime
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse

from .fetcher import Fetcher
from .scope import ScopeChecker
from ..discovery.html import extract_js_urls, extract_links, extract_inline_scripts
from ..storage.models import JSFile
from ..analysis.html_scanner import scan_html

logger = logging.getLogger("bundlespy.crawler")


# ── Discovery record — every found URL carries this ──────────────────────────

@dataclass
class DiscoveryRecord:
    """Full provenance record for a discovered URL or route."""
    url:          str
    source:       str            # robots | sitemap | dom | js_route | form | hash | historical | manifest | probe | source_map | chunk | browser_runtime
    source_file:  str = ""       # which JS / HTML page it came from
    line:         int = 0
    column:       int = 0
    evidence:     str = ""       # the raw string that triggered discovery
    confidence:   float = 1.0   # 0.0 - 1.0
    is_historical: bool = False  # from Wayback / CDX
    is_runtime:   bool = False   # found at runtime (headless)
    is_static:    bool = True    # found in static analysis
    parent_url:   str = ""       # which page led here
    occurrences:  List[str] = field(default_factory=list)  # all source files that found this


# ── Probe paths ───────────────────────────────────────────────────────────────

# Every important application path worth probing directly.
# Covers: auth, admin, API, docs, user flows, DevOps endpoints, CMS, cloud,
#         framework-specific paths, mobile API paths, payment, debug endpoints.
COMMON_PAGE_PATHS = [
    # ── Authentication ────────────────────────────────────────────────────────
    "/login", "/signin", "/sign-in", "/log-in",
    "/logout", "/signout", "/sign-out", "/log-out",
    "/register", "/signup", "/sign-up", "/join", "/create-account",
    "/forgot-password", "/forgot_password", "/reset-password", "/reset_password",
    "/password-reset", "/password_reset", "/change-password", "/change_password",
    "/auth", "/auth/login", "/auth/signin", "/auth/register", "/auth/logout",
    "/auth/callback", "/auth/refresh", "/auth/token", "/auth/verify",
    "/oauth", "/oauth/authorize", "/oauth/token", "/oauth/callback",
    "/oauth2/authorize", "/oauth2/token", "/oauth2/callback",
    "/sso", "/sso/login", "/saml/login", "/saml/callback", "/oidc/login",
    "/session", "/sessions", "/session/new", "/sessions/new",
    "/verify", "/verify-email", "/confirm", "/confirm-email",
    "/mfa", "/2fa", "/two-factor", "/totp", "/otp",
    "/unlock", "/invitation", "/invitations",

    # ── Admin / Management ────────────────────────────────────────────────────
    "/admin", "/admin/login", "/admin/dashboard", "/admin/users",
    "/admin/settings", "/admin/config", "/admin/panel",
    "/administrator", "/administration",
    "/management", "/manage", "/manager",
    "/console", "/control", "/control-panel",
    "/dashboard", "/dashboards",
    "/panel", "/cp", "/wp-admin",
    "/cms", "/cms/admin", "/cms/login",
    "/backend", "/back-office", "/backoffice",
    "/site-admin", "/superadmin", "/superuser",
    "/manager/login", "/master",

    # ── User / Account ────────────────────────────────────────────────────────
    "/account", "/my-account", "/myaccount",
    "/profile", "/profiles", "/me",
    "/user", "/users", "/user/profile",
    "/settings", "/preferences", "/notifications",
    "/home", "/start", "/welcome",
    "/onboarding",
    "/subscription", "/subscriptions", "/billing", "/billing/manage",
    "/plan", "/plans", "/upgrade", "/downgrade",

    # ── API ───────────────────────────────────────────────────────────────────
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/v1/users", "/api/v1/auth", "/api/v1/health", "/api/v1/status",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/graphiql", "/graphql/console",
    "/gql",
    "/api/graphql", "/api/rest",
    "/api/admin", "/api/internal",

    # ── API Documentation ─────────────────────────────────────────────────────
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/swagger/v1", "/swagger/v2",
    "/api-docs", "/api/docs", "/api/documentation",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/redoc", "/docs", "/documentation",
    "/spec", "/api/spec",
    "/apidoc", "/apidocs",

    # ── DevOps / Health / Debug ───────────────────────────────────────────────
    "/health", "/healthcheck", "/health-check", "/health/live", "/health/ready",
    "/ping", "/status", "/ready", "/live",
    "/metrics", "/prometheus", "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/metrics", "/actuator/beans",
    "/debug", "/debug/vars", "/debug/pprof",
    "/info", "/_info",
    "/version", "/_version",
    "/env", "/environment",
    "/__status", "/__health",
    "/.well-known/health",

    # ── Framework-specific ────────────────────────────────────────────────────
    # Next.js
    "/_next", "/_next/data",
    # Nuxt
    "/_nuxt",
    # SvelteKit
    "/__svelte",
    # Django
    "/django-admin", "/django-admin/login",
    # Rails
    "/rails/info", "/rails/mailers",
    # Laravel
    "/telescope", "/horizon",
    # Spring Boot
    "/spring", "/actuator",
    # .NET
    "/hangfire", "/miniprofiler",

    # ── Search ────────────────────────────────────────────────────────────────
    "/search", "/find", "/query", "/results",
    "/api/search", "/api/v1/search",

    # ── Content / CMS ─────────────────────────────────────────────────────────
    "/blog", "/news", "/articles", "/posts", "/press",
    "/about", "/about-us",
    "/contact", "/contact-us",
    "/help", "/help-center", "/support", "/faq",
    "/sitemap", "/sitemap.html",
    "/privacy", "/privacy-policy", "/terms", "/terms-of-service",
    "/legal",

    # ── E-commerce ────────────────────────────────────────────────────────────
    "/products", "/catalog", "/shop", "/store",
    "/cart", "/basket", "/checkout",
    "/orders", "/order", "/order-history",
    "/wishlist",
    "/payment", "/payments", "/pay",
    "/invoice", "/invoices",
    "/shipping",

    # ── Files / Media / Upload ────────────────────────────────────────────────
    "/upload", "/uploads", "/uploader",
    "/download", "/downloads",
    "/files", "/file", "/attachments",
    "/media", "/images", "/assets", "/static",
    "/export", "/import",
    "/share", "/shared",
    "/documents",

    # ── Reporting ─────────────────────────────────────────────────────────────
    "/reports", "/report", "/analytics", "/statistics", "/stats",
    "/logs", "/audit", "/audit-log",

    # ── Notifications / Messaging ─────────────────────────────────────────────
    "/notifications", "/messages", "/inbox", "/chat",
    "/alerts", "/feed",
    "/webhooks", "/webhook",

    # ── Organization / Team ───────────────────────────────────────────────────
    "/team", "/teams", "/members", "/organization", "/org",
    "/groups", "/group", "/roles", "/permissions",
    "/projects", "/workspaces",

    # ── Mobile / App API ──────────────────────────────────────────────────────
    "/mobile", "/app", "/apps",
    "/api/mobile", "/mobile/api",
    "/ios", "/android",
    "/push", "/push-notifications",

    # ── Security / Auth well-known ────────────────────────────────────────────
    "/.well-known", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/oauth-authorization-server",
    "/.well-known/webfinger",

    # ── Public discovery files ────────────────────────────────────────────────
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/humans.txt", "/security.txt", "/security",
    "/.env", "/.env.example", "/.git/config",
    "/CHANGELOG.md", "/CHANGELOG",
    "/package.json", "/composer.json",
    "/phpinfo.php", "/info.php",
    "/crossdomain.xml", "/clientaccesspolicy.xml",

    # ── Developer / Internal ─────────────────────────────────────────────────
    "/internal", "/dev", "/develop", "/development",
    "/staging", "/test", "/testing",
    "/preview", "/demo",
    "/feature", "/labs",
    "/beta",
    "/config", "/configuration",
    "/setup", "/install", "/installer",
    "/.config",

    # ── Integration / Webhooks ────────────────────────────────────────────────
    "/integrations", "/integration", "/connect",
    "/plugins", "/extensions", "/addons",
    "/marketplace",
    "/apps/manage",

    # ── Feeds ─────────────────────────────────────────────────────────────────
    "/feed", "/feeds", "/rss", "/atom",
    "/api/feed",

    # ── Misc high-value ───────────────────────────────────────────────────────
    "/token", "/tokens",
    "/key", "/keys", "/apikey", "/api-key",
    "/secret", "/secrets",
    "/credentials",
    "/error", "/errors", "/404", "/500", "/403",
    "/maintenance",
    "/cron", "/jobs", "/queue",
    "/cache", "/flush",
    "/migrate", "/migrations",
    "/proxy", "/forward",
    "/redirect",
    "/cors", "/options",
]

# Common JS asset paths to probe directly.
COMMON_JS_PATHS = [
    # ── Root / generic ────────────────────────────────────────────────────────
    "/app.js", "/main.js", "/bundle.js", "/index.js", "/runtime.js",
    "/vendor.js", "/common.js", "/chunk.js", "/polyfills.js",
    "/app.min.js", "/main.min.js", "/bundle.min.js",
    "/application.js", "/application.min.js",
    "/init.js", "/core.js", "/utils.js", "/helpers.js",
    "/config.js", "/settings.js", "/env.js",
    "/bootstrap.js",

    # ── /static/js/ ──────────────────────────────────────────────────────────
    "/static/js/app.js", "/static/js/main.js", "/static/js/bundle.js",
    "/static/js/runtime.js", "/static/js/vendor.js", "/static/js/index.js",
    "/static/js/common.js", "/static/js/chunk.js", "/static/js/polyfills.js",
    "/static/js/application.js",

    # ── /assets/ ─────────────────────────────────────────────────────────────
    "/assets/app.js", "/assets/main.js", "/assets/index.js",
    "/assets/bundle.js", "/assets/vendor.js", "/assets/runtime.js",
    "/assets/js/app.js", "/assets/js/main.js", "/assets/js/bundle.js",

    # ── /js/ ─────────────────────────────────────────────────────────────────
    "/js/app.js", "/js/main.js", "/js/bundle.js", "/js/vendor.js",
    "/js/common.js", "/js/index.js", "/js/application.js",
    "/js/runtime.js", "/js/chunk.js", "/js/core.js",

    # ── /dist/ ───────────────────────────────────────────────────────────────
    "/dist/app.js", "/dist/main.js", "/dist/bundle.js", "/dist/vendor.js",
    "/dist/index.js", "/dist/runtime.js",
    "/dist/js/app.js", "/dist/js/main.js",

    # ── /build/ ──────────────────────────────────────────────────────────────
    "/build/app.js", "/build/main.js", "/build/bundle.js",
    "/build/static/js/main.js", "/build/static/js/bundle.js",

    # ── /public/ ─────────────────────────────────────────────────────────────
    "/public/js/app.js", "/public/js/main.js", "/public/js/bundle.js",
    "/public/app.js", "/public/main.js",

    # ── Framework-specific ────────────────────────────────────────────────────
    # Next.js
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/pages/index.js",
    # Nuxt
    "/_nuxt/app.js",
    "/_nuxt/vendor.js",
    "/_nuxt/manifest.js",
    # SvelteKit
    "/_app/immutable/start.js",
    "/_app/start.js",
    # Angular
    "/main.js", "/polyfills.js", "/runtime.js",
    # CRA
    "/static/js/main.chunk.js",
    "/static/js/vendors~main.chunk.js",
    # Vite
    "/assets/index.js",
    "/@vite/client",
    # Service workers
    "/sw.js", "/service-worker.js", "/serviceworker.js",
    "/workbox-sw.js", "/firebase-messaging-sw.js",

    # ── Laravel / PHP ─────────────────────────────────────────────────────────
    "/js/app.js",
    "/public/js/app.js",

    # ── Rails / Ruby ──────────────────────────────────────────────────────────
    "/assets/application.js",
    "/assets/application-*.js",

    # ── WordPress ─────────────────────────────────────────────────────────────
    "/wp-includes/js/jquery/jquery.min.js",
    "/wp-content/themes/",
    "/wp-content/plugins/",
]

# Asset manifest paths checked by all major build tools
ASSET_MANIFEST_PATHS = [
    "/asset-manifest.json",
    "/static/asset-manifest.json",
    "/.vite/manifest.json",
    "/manifest.json",
    "/build/asset-manifest.json",
    "/_next/static/chunks/webpack.js",
    "/webpack-manifest.json",
    "/mix-manifest.json",
    "/rev-manifest.json",
    "/assets/manifest.json",
    "/static/manifest.json",
    "/public/mix-manifest.json",
    "/.nuxt/dist/client/manifest.json",
    "/dist/manifest.json",
]

# Technology fingerprints
TECH_PATTERNS = {
    "React":     ["react.development.js", "__REACT_DEVTOOLS", "React.createElement", "_jsx("],
    "Vue":       ["Vue.config", "__vue_router__", "createApp(", "__VUE__"],
    "Angular":   ["ng-version", "platformBrowserDynamic", "NgModule", "ɵɵdefineComponent"],
    "Next.js":   ["__NEXT_DATA__", "/_next/static", "__NEXT_ROUTER"],
    "Nuxt":      ["__NUXT__", "_nuxt", "nuxt.config"],
    "SvelteKit": ["__sveltekit", "_app/immutable", "sveltekit:navigation"],
    "Webpack":   ["__webpack_require__", "webpackBootstrap", "__webpack_modules__"],
    "Vite":      ["/@vite/", "import.meta.hot", "/@fs/"],
}

# ── JS route extraction patterns ──────────────────────────────────────────────

# React Router, Vue Router, Angular, Next.js, Nuxt, custom
JS_ROUTE_PATTERNS = [
    # path: "/route"
    re.compile(r'''path\s*:\s*["'`](/[^"'`]{0,200})["'`]'''),
    # to: "/route"
    re.compile(r'''to\s*:\s*["'`](/[^"'`]{0,200})["'`]'''),
    # routes = ["/path", "/path2"]
    re.compile(r'''routes\s*=\s*\[([^\]]{0,2000})\]''', re.DOTALL),
    # router.addRoute("/path")
    re.compile(r'''\.addRoute\s*\(\s*["'`](/[^"'`]{0,200})["'`]'''),
    # navigate("/path") / history.push("/path")
    re.compile(r'''(?:navigate|push|replace|go)\s*\(\s*["'`](/[^"'`]{0,200})["'`]'''),
    # <Route path="/foo">
    re.compile(r'''<Route\s+[^>]*path=["'`]([^"'`]+)["'`]''', re.IGNORECASE),
    # RouterModule.forRoot([{path:'admin'}])
    re.compile(r'''\{[^{}]*path\s*:\s*["'`]([^"'`/][^"'`]{0,200})["'`][^{}]*\}'''),
    # Next.js pages: getStaticPaths, getServerSideProps route hints
    re.compile(r'''"pages"\s*:\s*\{([^}]{0,5000})\}''', re.DOTALL),
    # Nuxt routes
    re.compile(r'''__nuxt_routes__\s*=\s*(\[[^\]]{0,5000}\])''', re.DOTALL),
    # SvelteKit routes
    re.compile(r'''routes\s*:\s*(\[[^\]]{0,5000}\])''', re.DOTALL),
    # hash routes
    re.compile(r'''["'`](#/[^"'`]{1,200})["'`]'''),
    # hashbang routes
    re.compile(r'''["'`](#!/[^"'`]{1,200})["'`]'''),
    # parameterized routes (/users/:id, /posts/{id})
    re.compile(r'''["'`](/[a-zA-Z0-9_\-/:.{}*]{2,200})["'`]'''),
]

# Strings that disqualify a JS "route" candidate
JS_ROUTE_FP = {
    "http", ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico",
    ".woff", ".ttf", ".eot", ".map", "data:", "//", "__webpack",
    "function(", "=>", "import", "require", "module", ".prototype",
    "undefined", "null", "true", "false", "Object", "Array",
}

# Dynamic import patterns
DYNAMIC_IMPORT_PATTERNS = [
    # import("./module")
    re.compile(r'''import\s*\(\s*["'`]([^"'`]+)["'`]\s*\)'''),
    # require("./module")
    re.compile(r'''require\s*\(\s*["'`]([^"'`]+)["'`]\s*\)'''),
    # webpackChunkName comments
    re.compile(r'''webpackChunkName\s*:\s*["'`]([^"'`]+)["'`]'''),
    # /* webpackPrefetch: true */
    re.compile(r'''webpackPrefetch\s*:\s*true'''),
    # <link rel="modulepreload" href="...">
    re.compile(r'''rel=["']modulepreload["'][^>]*href=["']([^"']+)["']''', re.IGNORECASE),
    # <link rel="preload" as="script" href="...">
    re.compile(r'''rel=["']preload["'][^>]*as=["']script["'][^>]*href=["']([^"']+)["']''', re.IGNORECASE),
]

# Hash routing patterns
HASH_ROUTE_PATTERNS = [
    re.compile(r'''["'`](#/[a-zA-Z0-9_\-/.]{1,200})["'`]'''),
    re.compile(r'''["'`](#!/[a-zA-Z0-9_\-/.]{1,200})["'`]'''),
    re.compile(r'''href=["'](#/[^"']{1,200})["']''', re.IGNORECASE),
    re.compile(r'''href=["'](#!/[^"']{1,200})["']''', re.IGNORECASE),
    re.compile(r'''window\.location\.hash\s*=\s*["'`](#[^"'`]{1,200})["'`]'''),
]

# Sitemap namespaces
SITEMAP_NS = {
    "sm":    "http://www.sitemaps.org/schemas/sitemap/0.9",
    "image": "http://www.google.com/schemas/sitemap-image/1.1",
    "news":  "http://www.google.com/schemas/sitemap-news/0.9",
    "video": "http://www.google.com/schemas/sitemap-video/1.1",
}

# Wayback Machine CDX
CDX_WAYBACK     = "https://web.archive.org/cdx/search/cdx"
WAYBACK_TIMEOUT = 15
WAYBACK_LIMIT   = 500


# ── Helpers ───────────────────────────────────────────────────────────────────

def fingerprint_tech(content: str) -> str:
    for tech, patterns in TECH_PATTERNS.items():
        if any(p in content for p in patterns):
            return tech
    return ""


def _normalize_js_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    except Exception:
        return url


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _is_js_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))


def _is_html_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return (
        path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp", "/"))
        or "/" in path[-1:]
        or "." not in path.split("/")[-1]
    )


def _extract_js_from_manifest(content: str, base_url: str) -> List[str]:
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


def _parse_robots_txt(content: str, base_url: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Parse robots.txt.
    Returns: (js_paths, route_paths, sitemap_urls)

    route_paths includes ALL Disallow/Allow paths — every one is a potential
    application route even if it's not a JS file.
    js_paths is the subset that look like JS files.
    sitemap_urls are Sitemap: directives.
    """
    parsed    = urlparse(base_url)
    base      = f"{parsed.scheme}://{parsed.netloc}"
    js_paths  = []
    routes    = []
    sitemaps  = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        lower = line.lower()

        if lower.startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            if sitemap_url:
                # Ensure absolute URL
                if not sitemap_url.startswith("http"):
                    sitemap_url = base + sitemap_url
                sitemaps.append(sitemap_url)

        elif lower.startswith(("disallow:", "allow:")):
            path = line.split(":", 1)[1].strip()
            if not path or path == "/" or path == "*":
                continue
            # Strip wildcard suffix for route extraction
            clean_path = path.split("*")[0].rstrip("$")
            if not clean_path or clean_path == "/":
                continue
            # Record every path as a potential route
            routes.append(base + clean_path)
            # Separate subset: actual JS files
            if _is_js_url(clean_path):
                js_paths.append(base + clean_path)

    return js_paths, routes, sitemaps


def _extract_js_from_link_headers(headers: dict, base_url: str) -> List[str]:
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
    urls = []
    base = sw_url.rsplit("/", 1)[0] + "/"
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
                p = urlparse(sw_url)
                urls.append(f"{p.scheme}://{p.netloc}{raw}")
            else:
                urls.append(urljoin(base, raw))
    return list(set(urls))


def _extract_data_src_js(html: str, base_url: str) -> List[str]:
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
    urls = []
    m = re.search(
        r'<script[^>]+type=["\']importmap["\'][^>]*>(.*?)</script>',
        html, re.IGNORECASE | re.DOTALL
    )
    if not m:
        return urls
    try:
        data    = json.loads(m.group(1))
        imports = data.get("imports", {})
        for v in imports.values():
            if isinstance(v, str) and _is_js_url(v):
                urls.append(urljoin(base_url, v))
    except Exception:
        pass
    return urls


def _extract_js_routes_from_content(content: str, source_url: str) -> List[DiscoveryRecord]:
    """
    Deep JS route extraction — scan JS content for route definitions
    using all known router patterns. Returns DiscoveryRecords with evidence.
    """
    records   = []
    seen      = set()
    lines     = content.split("\n")

    def _add(path: str, pattern_name: str, evidence: str, line_no: int):
        path = path.strip().strip("\"'`").split("?")[0].split("#")[0]
        if not path or path in seen:
            return
        # Must start with / or # or #!
        if not (path.startswith("/") or path.startswith("#")):
            return
        # Length sanity
        if len(path) < 2 or len(path) > 250:
            return
        # Must not look like a file extension
        last_seg = path.rsplit("/", 1)[-1]
        if "." in last_seg and not any(
            last_seg.endswith(e) for e in [":id", ":slug", ":uuid", ":name"]
        ):
            ext = last_seg.rsplit(".", 1)[-1].lower()
            if ext not in ("html", "php", "asp", "aspx", "jsp"):
                return
        # Reject obvious FPs
        if any(fp in path for fp in JS_ROUTE_FP):
            return
        seen.add(path)
        records.append(DiscoveryRecord(
            url=path,
            source="js_route",
            source_file=source_url,
            line=line_no,
            evidence=evidence[:120],
            confidence=0.8,
        ))

    for pat in JS_ROUTE_PATTERNS:
        for m in pat.finditer(content):
            # Compute approximate line number
            line_no = content[:m.start()].count("\n") + 1
            raw = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            if not raw:
                continue
            # Handle array matches — split on commas and quotes
            if raw.startswith("[") or ("," in raw and '"' in raw):
                for sub in re.findall(r'''["'`](/[^"'`]{1,200})["'`]''', raw):
                    _add(sub, pat.pattern[:40], sub, line_no)
            else:
                _add(raw, pat.pattern[:40], m.group(0)[:80], line_no)

    return records


def _extract_dynamic_imports(content: str, base_url: str) -> List[str]:
    """Extract dynamic import() / require() paths and resolve them."""
    urls = []
    seen = set()
    base_dir = base_url.rsplit("/", 1)[0] + "/"
    p = urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"

    for pat in DYNAMIC_IMPORT_PATTERNS:
        for m in pat.finditer(content):
            if not m.lastindex:
                continue
            raw = m.group(1).strip("\"'`")
            if not raw or raw in seen:
                continue
            seen.add(raw)
            # Resolve to absolute URL
            if raw.startswith("http"):
                url = raw
            elif raw.startswith("/"):
                url = origin + raw
            elif raw.startswith("./") or raw.startswith("../"):
                url = urljoin(base_dir, raw)
            else:
                url = urljoin(base_dir, raw)
            if _is_js_url(url):
                urls.append(url)

    return list(set(urls))


def _extract_forms(html: str, base_url: str) -> List[DiscoveryRecord]:
    """
    Extract <form> actions and related navigation targets.
    Returns DiscoveryRecords with form evidence.
    """
    records = []
    seen    = set()
    p       = urlparse(base_url)
    origin  = f"{p.scheme}://{p.netloc}"

    # <form action="/path" method="POST">
    form_pattern = re.compile(
        r'<form[^>]+action=["\'`]([^"\'`]+)["\'`][^>]*>',
        re.IGNORECASE
    )
    for m in form_pattern.finditer(html):
        action = m.group(1).strip()
        if not action or action.startswith(("javascript:", "mailto:", "#")):
            continue
        # Resolve relative actions
        if action.startswith("http"):
            url = action
        elif action.startswith("/"):
            url = origin + action
        else:
            url = urljoin(base_url, action)
        path = urlparse(url).path
        if path and path not in seen:
            seen.add(path)
            records.append(DiscoveryRecord(
                url=path,
                source="form",
                source_file=base_url,
                evidence=m.group(0)[:120],
                confidence=0.9,
                parent_url=base_url,
            ))

    # Also pick up <button formaction="...">
    btn_pattern = re.compile(
        r'<button[^>]+formaction=["\'`]([^"\'`]+)["\'`]',
        re.IGNORECASE
    )
    for m in btn_pattern.finditer(html):
        action = m.group(1).strip()
        if not action or action.startswith("javascript:"):
            continue
        url  = urljoin(base_url, action)
        path = urlparse(url).path
        if path and path not in seen:
            seen.add(path)
            records.append(DiscoveryRecord(
                url=path,
                source="form",
                source_file=base_url,
                evidence=m.group(0)[:120],
                confidence=0.85,
                parent_url=base_url,
            ))

    return records


def _extract_hash_routes(html_or_js: str, base_url: str) -> List[DiscoveryRecord]:
    """Extract hash-based SPA routes from HTML or JS content."""
    records = []
    seen    = set()

    for pat in HASH_ROUTE_PATTERNS:
        for m in pat.finditer(html_or_js):
            raw = m.group(1).strip()
            if not raw or raw in seen:
                continue
            seen.add(raw)
            records.append(DiscoveryRecord(
                url=raw,
                source="hash_route",
                source_file=base_url,
                evidence=m.group(0)[:80],
                confidence=0.75,
            ))

    return records


def _parse_sitemap(content: str, base_url: str, fetcher: Fetcher,
                   scope: ScopeChecker, depth: int = 0,
                   max_depth: int = 3, seen: Set[str] = None) -> List[DiscoveryRecord]:
    """
    Parse sitemap XML (sitemap or sitemap index) recursively.
    Returns DiscoveryRecords for all discovered URLs.
    depth / max_depth prevent infinite recursion.
    """
    if seen is None:
        seen = set()
    if depth > max_depth:
        return []

    records = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    tag = root.tag.lower()
    ns_match = re.match(r'\{([^}]+)\}', root.tag)
    ns = ns_match.group(1) if ns_match else ""
    ns_prefix = f"{{{ns}}}" if ns else ""

    # Sitemap index — recurse into child sitemaps
    if "sitemapindex" in tag:
        for sitemap_el in root.findall(f".//{ns_prefix}sitemap"):
            loc_el = sitemap_el.find(f"{ns_prefix}loc")
            if loc_el is None or not loc_el.text:
                continue
            child_url = loc_el.text.strip()
            if child_url in seen:
                continue
            seen.add(child_url)
            if not scope.in_scope(child_url):
                continue
            child_content, child_status, _, _ = fetcher.get(child_url)
            if child_content and child_status == 200:
                records.extend(_parse_sitemap(
                    child_content, child_url, fetcher, scope,
                    depth=depth + 1, max_depth=max_depth, seen=seen,
                ))
    else:
        # URL set — extract <loc> entries
        for url_el in root.findall(f".//{ns_prefix}url"):
            loc_el = url_el.find(f"{ns_prefix}loc")
            if loc_el is None or not loc_el.text:
                continue
            url = loc_el.text.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            if not scope.in_scope(url):
                continue
            records.append(DiscoveryRecord(
                url=url,
                source="sitemap",
                source_file=base_url,
                evidence=url,
                confidence=1.0,
                is_static=True,
            ))

    return records


def _query_wayback(domain: str, limit: int = WAYBACK_LIMIT) -> List[DiscoveryRecord]:
    """
    Query Wayback Machine CDX for historical URLs (all types, not just JS).
    Returns DiscoveryRecords marked is_historical=True.
    """
    try:
        import requests as _req
        params = {
            "url":       f"*.{domain}/*",
            "matchType": "domain",
            "output":    "json",
            "fl":        "original,statuscode,timestamp",
            "filter":    "statuscode:200",
            "collapse":  "urlkey",
            "limit":     str(limit),
        }
        resp = _req.get(
            CDX_WAYBACK, params=params,
            timeout=WAYBACK_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; BundleSpy/1.0)"},
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        if not data or len(data) < 2:
            return []
        records = []
        for row in data[1:]:
            if not row or not row[0]:
                continue
            url = row[0]
            # Skip pure JS/CSS/asset URLs — we want page routes
            path = urlparse(url).path.lower()
            if any(path.endswith(e) for e in [
                ".js", ".css", ".png", ".jpg", ".gif",
                ".ico", ".woff", ".ttf", ".eot", ".svg", ".map",
            ]):
                continue
            records.append(DiscoveryRecord(
                url=url,
                source="historical",
                source_file="wayback://cdx",
                evidence=f"CDX timestamp={row[2] if len(row) > 2 else '?'}",
                confidence=0.6,
                is_historical=True,
                is_static=False,
            ))
        logger.info("Wayback CDX: %d historical URLs for %s", len(records), domain)
        return records
    except Exception as e:
        logger.debug("Wayback query failed for %s: %s", domain, e)
        return []


# ── Canonical route registry ──────────────────────────────────────────────────

class RouteRegistry:
    """
    Central deduplicated route/URL store.
    Merges provenance — multiple discovery sources for the same route are
    tracked together, never lost.
    """
    def __init__(self):
        self._routes: Dict[str, DiscoveryRecord] = {}

    def _key(self, url: str) -> str:
        try:
            p = urlparse(url)
            path = p.path.rstrip("/") or "/"
            # Treat hash routes as separate entries
            if p.fragment:
                return f"{p.scheme}://{p.netloc}{path}#{p.fragment}".lower()
            return f"{p.scheme}://{p.netloc}{path}".lower()
        except Exception:
            return url.lower()

    def register(self, record: DiscoveryRecord) -> bool:
        """
        Register a discovery record. Returns True if new, False if merged.
        When merged, all source files are accumulated in occurrences.
        """
        key = self._key(record.url)
        if key in self._routes:
            existing = self._routes[key]
            # Merge provenance
            if record.source_file and record.source_file not in existing.occurrences:
                existing.occurrences.append(record.source_file)
            # Highest confidence wins
            if record.confidence > existing.confidence:
                existing.confidence = record.confidence
            # If any source finds it non-historical, it's confirmed live
            if not record.is_historical:
                existing.is_historical = False
            return False
        record.occurrences = [record.source_file] if record.source_file else []
        self._routes[key] = record
        return True

    def get_all(self) -> List[DiscoveryRecord]:
        return list(self._routes.values())

    def has(self, url: str) -> bool:
        return self._key(url) in self._routes

    def __len__(self) -> int:
        return len(self._routes)


# ── Main Crawler ──────────────────────────────────────────────────────────────

class Crawler:
    def __init__(
        self,
        target_url:      str,
        fetcher:         Fetcher,
        scope:           ScopeChecker,
        max_depth:       int  = 2,
        max_pages:       int  = 100,
        max_js_files:    int  = 1000,
        common_paths:    bool = False,
        wayback:         bool = False,
        max_sitemap_depth: int = 3,
        status_cb        = None,   # callable(str) — UI status line hook
    ):
        self.target_url        = target_url
        self.fetcher           = fetcher
        self.scope             = scope
        self.max_depth         = max_depth
        self.max_pages         = max_pages
        self.max_js_files      = max_js_files
        self.common_paths      = common_paths
        self.wayback           = wayback
        self.max_sitemap_depth = max_sitemap_depth
        self._status_cb        = status_cb  # called with a short status string each phase

        # Core dedup sets
        self.visited_pages:      Set[str] = set()
        self.visited_js:         Set[str] = set()
        self.seen_js_hashes:     Set[str] = set()
        self.seen_inline_hashes: Set[str] = set()

        # Output
        self.js_files:           List[JSFile]         = []
        self.inline_scripts:     List[Tuple[str, str]] = []
        self.html_findings:      List                  = []
        self.errors:             List[str]             = []
        self.pages_crawled:      int                   = 0

        # Discovery registry
        self.route_registry     = RouteRegistry()
        self.discovery_records:  List[DiscoveryRecord] = []

        # robots.txt discovered sitemaps (for cross-referencing)
        self._robots_sitemaps:   List[str] = []

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _status(self, msg: str) -> None:
        """Emit a sub-phase status line via the UI callback (if wired up)."""
        if self._status_cb:
            try:
                self._status_cb(msg)
            except Exception:
                pass

    def _register(self, record: DiscoveryRecord) -> bool:
        is_new = self.route_registry.register(record)
        if is_new:
            self.discovery_records.append(record)
        return is_new

    def _base_url(self) -> str:
        p = urlparse(self.target_url)
        return f"{p.scheme}://{p.netloc}"

    # ── Main crawl pipeline ───────────────────────────────────────────────────

    def crawl(self) -> None:
        base = self._base_url()

        # Phase 1: robots.txt — routes, JS paths, sitemap hints
        self._status("Reading robots.txt")
        self._discover_from_robots(base)

        # Phase 2: sitemaps — recursive, unified with robots-discovered sitemaps
        self._status("Parsing sitemaps")
        self._discover_from_sitemaps(base)

        # Phase 3: asset manifests — all major build tools
        self._status("Checking asset manifests")
        self._discover_from_manifests(base)

        # Phase 4: optional Wayback historical URLs
        if self.wayback:
            self._discover_from_wayback(base)

        # Phase 5: common JS probes (--common-paths flag extends the list;
        #           basic JS probing always runs via _probe_common_pages)
        if self.common_paths:
            self._status(f"Probing {len(COMMON_JS_PATHS)} common JS paths")
            import time as _time
            import requests as _req
            _js_probe_start = _time.monotonic()
            MAX_JS_PROBE_SECONDS = 45
            for path in COMMON_JS_PATHS:
                if _time.monotonic() - _js_probe_start > MAX_JS_PROBE_SECONDS:
                    break
                url = base + path
                norm = _normalize_js_url(url)
                if norm in self.visited_js:
                    continue
                try:
                    r = _req.head(url, timeout=3, verify=False, allow_redirects=True,
                                  headers={"User-Agent": self.fetcher.user_agent})
                    if r.status_code in range(200, 300):
                        self._fetch_js(url, self.target_url)
                except Exception:
                    pass

        # Phase 6: common page probes — always runs, HEAD-based, 60s budget
        queue: deque = deque()
        queue.append((self.target_url, 0))
        self.visited_pages.add(self.target_url)

        self._status(f"Probing {len(COMMON_PAGE_PATHS)} common routes")
        self._probe_common_pages(base, queue)
        probed_live = len([r for r in self.discovery_records if r.source == "probe"])
        self._status(f"Probes complete  {probed_live} live routes found")

        # Phase 7: sitemap-discovered pages → queue
        sitemap_count = len([r for r in self.discovery_records if r.source == "sitemap"])
        if sitemap_count:
            self._status(f"Queuing {sitemap_count} sitemap URLs")
        for record in self.discovery_records:
            if record.source == "sitemap" and not record.is_historical:
                url = record.url
                if url not in self.visited_pages and self.scope.in_scope(url):
                    self.visited_pages.add(url)
                    queue.append((url, 1))

        # Phase 8: main crawl
        self._status(f"Crawling pages (depth {self.max_depth}, max {self.max_pages})")
        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            self._crawl_page(url, depth, queue)

        # Phase 9: validate historical URLs against live site (optional, lightweight)
        if self.wayback:
            self._status("Validating historical URLs")
            self._validate_historical()

        logger.info(
            "Crawl complete: %d pages, %d JS files, %d discovered routes",
            self.pages_crawled, len(self.js_files), len(self.route_registry),
        )

    def _probe_common_pages(self, base: str, queue: deque) -> None:
        """
        Probe common page paths using HEAD requests (fast, no body).
        Falls back to GET only when HEAD returns 405.
        Hard time budget: max 60 seconds total across all probes.
        Always runs by default. --common-paths flag has no effect on this method;
        the flag only controls the extended JS probe list.
        """

        import time as _time
        budget_start = _time.monotonic()
        MAX_PROBE_SECONDS = 60   # never spend more than 60s probing

        for path in COMMON_PAGE_PATHS:
            # Hard time budget — bail out, let main crawl take over
            if _time.monotonic() - budget_start > MAX_PROBE_SECONDS:
                logger.debug("Probe time budget exhausted, stopping common page probes")
                break

            probe_url = base + path
            if probe_url in self.visited_pages:
                continue

            # Use HEAD first — 10x faster, no body transfer
            try:
                import requests as _req
                resp = _req.head(
                    probe_url,
                    timeout=3,       # short timeout for probes only
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": self.fetcher.user_agent},
                )
                status = resp.status_code
                ct     = resp.headers.get("Content-Type", "")
                # Some servers don't support HEAD — fall back to GET
                if status == 405:
                    content, status, ct, _ = self.fetcher.get(probe_url)
                elif status not in range(200, 300):
                    continue
                else:
                    content = True   # HEAD success — we don't need the body here
            except Exception:
                continue

            if content and status in range(200, 300):
                ct_low = (ct or "").lower()
                if "html" in ct_low or "text" in ct_low or not ct:
                    self.visited_pages.add(probe_url)
                    queue.append((probe_url, 1))
                    self._register(DiscoveryRecord(
                        url=probe_url,
                        source="probe",
                        source_file="probe://common_paths",
                        evidence=f"HTTP {status}",
                        confidence=1.0,
                        parent_url=self.target_url,
                    ))

    # ── robots.txt ────────────────────────────────────────────────────────────

    def _discover_from_robots(self, base: str) -> None:
        robots_url = base + "/robots.txt"
        content, status, _, _ = self.fetcher.get(robots_url)
        if not content or status != 200:
            return

        js_paths, route_paths, sitemap_urls = _parse_robots_txt(content, base)

        # Fetch JS paths found in robots.txt
        for path in js_paths:
            if self.scope.in_scope(path):
                self._fetch_js(path, robots_url)

        # Register all Disallow/Allow routes
        for url in route_paths:
            if self.scope.in_scope(url):
                self._register(DiscoveryRecord(
                    url=url,
                    source="robots",
                    source_file=robots_url,
                    evidence=f"Disallow/Allow: {urlparse(url).path}",
                    confidence=0.85,
                ))

        # Store sitemap URLs for unified sitemap phase
        self._robots_sitemaps = sitemap_urls
        logger.info(
            "robots.txt: %d JS paths, %d routes, %d sitemaps",
            len(js_paths), len(route_paths), len(sitemap_urls),
        )

    # ── Sitemaps ──────────────────────────────────────────────────────────────

    def _discover_from_sitemaps(self, base: str) -> None:
        seen_sitemaps: Set[str] = set()
        # Well-known sitemap locations
        sitemap_paths = [
            "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
            "/wp-sitemap.xml", "/sitemaps/sitemap.xml",
            "/sitemap/sitemap.xml", "/news-sitemap.xml",
            "/product-sitemap.xml", "/page-sitemap.xml",
        ]
        all_sitemap_urls = [base + p for p in sitemap_paths] + self._robots_sitemaps

        for sitemap_url in all_sitemap_urls:
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)
            content, status, _, _ = self.fetcher.get(sitemap_url)
            if not content or status != 200:
                continue
            records = _parse_sitemap(
                content, sitemap_url, self.fetcher, self.scope,
                depth=0, max_depth=self.max_sitemap_depth, seen=seen_sitemaps,
            )
            for r in records:
                self._register(r)
            if records:
                logger.info("Sitemap %s: %d URLs", sitemap_url, len(records))

    # ── Asset manifests ───────────────────────────────────────────────────────

    def _discover_from_manifests(self, base: str) -> None:
        for path in ASSET_MANIFEST_PATHS:
            url = base + path
            content, status, ct, _ = self.fetcher.get(url)
            if not content or status != 200:
                continue
            ct_lower = ct.lower() if ct else ""
            if ct and not any(t in ct_lower for t in [
                "json", "javascript", "text"
            ]):
                continue
            js_urls = _extract_js_from_manifest(content, base)
            if js_urls:
                logger.info("Manifest %s: %d JS files", path, len(js_urls))
                for js_url in js_urls:
                    if self.scope.in_scope(js_url):
                        self._fetch_js(js_url, url)

    # ── Wayback historical ────────────────────────────────────────────────────

    def _discover_from_wayback(self, base: str) -> None:
        domain = urlparse(base).hostname or ""
        if not domain:
            return
        records = _query_wayback(domain)
        for r in records:
            if self.scope.in_scope(r.url):
                self._register(r)

    def _validate_historical(self) -> None:
        """
        Probe historical-only URLs to see if they're still live.
        Only probes URLs not already seen in the live crawl.
        Strict limit — historical validation is best-effort.
        """
        MAX_HIST_PROBES = 50
        count = 0
        for record in self.discovery_records:
            if not record.is_historical:
                continue
            if count >= MAX_HIST_PROBES:
                break
            if not self.scope.in_scope(record.url):
                continue
            _, status, _, _ = self.fetcher.get(record.url)
            if status in range(200, 300):
                record.is_historical = False   # confirmed still live
                record.confidence    = 0.9
                logger.debug("Historical URL still live: %s", record.url)
            count += 1

    # ── HTML page crawl ───────────────────────────────────────────────────────

    def _crawl_page(self, url: str, depth: int, queue: deque) -> None:
        logger.debug("Crawling: %s (depth %d)", url, depth)
        content, status, content_type, _ = self.fetcher.get(url)
        if not content or status not in range(200, 300):
            return

        ct_lower = (content_type or "").lower()

        if "json" in ct_lower:
            for m in re.finditer(r'["\'`]([^"\'`]*\.js)["\'`]', content):
                raw = m.group(1)
                if raw.startswith("/") or raw.startswith("http"):
                    js_url = urljoin(url, raw)
                    if self.scope.in_scope(js_url) and _is_js_url(js_url):
                        self._fetch_js(js_url, url)
            return

        if "html" not in ct_lower and "text" not in ct_lower:
            return

        self.pages_crawled += 1

        # Scan HTML for secrets
        html_findings = scan_html(content, url)
        if html_findings:
            self.html_findings.extend(html_findings)

        # Extract form routes
        for record in _extract_forms(content, url):
            self._register(record)

        # Extract hash routes from HTML
        for record in _extract_hash_routes(content, url):
            self._register(record)

        # Extract all JS from this page
        js_urls = self._extract_all_js_from_html(content, url)
        for js_url in js_urls:
            if len(self.js_files) >= self.max_js_files:
                break
            self._fetch_js(js_url, url)

        # Inline scripts — deduplicated
        for script in extract_inline_scripts(content):
            script = script.strip()
            if not script or len(script) < 10:
                continue
            h = _content_hash(script)
            if h not in self.seen_inline_hashes:
                self.seen_inline_hashes.add(h)
                self.inline_scripts.append((script, url))
                # Scan inline scripts for routes too
                for record in _extract_js_routes_from_content(script, url):
                    self._register(record)
                for record in _extract_hash_routes(script, url):
                    self._register(record)

        # Queue new pages
        if depth < self.max_depth:
            links = extract_links(content, url)
            for link in links:
                link_norm = link.rstrip("/")
                if link_norm not in self.visited_pages and self.scope.in_scope(link):
                    self.visited_pages.add(link_norm)
                    queue.append((link, depth + 1))

    def _extract_all_js_from_html(self, html: str, base_url: str) -> List[str]:
        urls: Set[str] = set()

        # Standard script tags and preload links
        for url in extract_js_urls(html, base_url):
            urls.add(url)

        # Import maps
        for url in _extract_import_map(html, base_url):
            urls.add(url)

        # data-src lazy loaders
        for url in _extract_data_src_js(html, base_url):
            urls.add(url)

        # Protocol-relative URLs
        for m in re.finditer(r'["\']//([a-zA-Z0-9][^"\']*\.js)["\']', html):
            raw = m.group(1)
            parsed = urlparse(base_url)
            urls.add(f"{parsed.scheme}://{raw}")

        # <link rel="modulepreload"> and <link rel="preload" as="script">
        for pat in DYNAMIC_IMPORT_PATTERNS[3:]:  # the link-based ones
            for m in pat.finditer(html):
                if m.lastindex:
                    raw = m.group(1)
                    url = urljoin(base_url, raw)
                    if _is_js_url(url):
                        urls.add(url)

        # Service worker
        sw_m = re.search(
            r'registerServiceWorker\s*\(\s*["\']([^"\']+)["\']|'
            r'serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if sw_m:
            sw_path    = sw_m.group(1) or sw_m.group(2)
            sw_url     = urljoin(base_url, sw_path)
            sw_content, sw_status, _, _ = self.fetcher.get(sw_url)
            if sw_content and sw_status == 200:
                for u in _extract_js_from_service_worker(sw_content, sw_url):
                    if self.scope.in_scope(u):
                        urls.add(u)

        result = []
        for url in urls:
            try:
                if self.scope.in_scope(url) and _is_js_url(url):
                    result.append(url)
            except Exception:
                pass
        return result

    # ── JS file fetcher + route extractor ─────────────────────────────────────

    def _fetch_js(self, url: str, source_page: str, retry: bool = True) -> None:
        norm_url = _normalize_js_url(url)
        if norm_url in self.visited_js:
            return
        self.visited_js.add(norm_url)

        if len(self.js_files) >= self.max_js_files:
            return

        content, status, content_type, sha256 = self.fetcher.get(url)

        if status in (500, 502, 503, 504) and retry:
            import time
            time.sleep(1)
            content, status, content_type, sha256 = self.fetcher.get(url)

        if not content or status not in range(200, 300):
            if status not in (404, 403) and status != 0:
                self.errors.append(f"Failed {url} (HTTP {status})")
            return

        ct_lower = (content_type or "").lower()
        if content_type and not any(t in ct_lower for t in [
            "javascript", "text/plain", "application/", "text/html",
            "text/javascript", "application/json", "text/typescript",
        ]):
            return

        content_h = _content_hash(content)
        if content_h in self.seen_js_hashes:
            return
        self.seen_js_hashes.add(content_h)

        tech = fingerprint_tech(content)

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

        # ── Deep route extraction from this JS file ────────────────────────
        for record in _extract_js_routes_from_content(content, url):
            self._register(record)

        # ── Hash route extraction ──────────────────────────────────────────
        for record in _extract_hash_routes(content, url):
            self._register(record)

        # ── Dynamic imports (chunk discovery) ─────────────────────────────
        chunk_urls = _extract_dynamic_imports(content, url)
        for chunk_url in chunk_urls:
            if self.scope.in_scope(chunk_url):
                self._fetch_js(chunk_url, url)  # recursive, dedup prevents loops

        logger.debug(
            "Fetched JS: %s (%d bytes, %s)",
            url, js_file.size_bytes, tech or "unknown",
        )
