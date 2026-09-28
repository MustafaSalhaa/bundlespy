"""
Endpoint Classifier - intelligent scoring system for route/endpoint candidates.

Every string extracted by endpoints.py and route_extractor.py passes through
here before it reaches the final output. The classifier assigns a score based
on structural, contextual, and semantic signals. Low-scoring strings (noise,
chart tokens, config keys) get dropped; high-scoring ones are promoted.

Score thresholds:
  < 40  -> DROP  (not shown at all)
  40-59 -> LOW_CONFIDENCE (shown only with --verbose / -v)
  60+   -> CONFIRMED endpoint (normal output)

Verification:
  For path-only candidates that score >= 60 and the target host is known,
  an optional lightweight HTTP probe (HEAD then GET) is run.
  Result is stored in the candidate's ValidationStatus field.

Design constraints:
  - Never makes network calls on its own; caller passes an optional fetcher
  - Fails silently on any exception, returning the candidate unchanged
  - No external dependencies beyond the stdlib and bundlespy models
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from ..storage.models import Endpoint, ValidationStatus

logger = logging.getLogger("bundlespy.analysis.endpoint_classifier")

# ---------------------------------------------------------------------------
# Score thresholds
# ---------------------------------------------------------------------------

SCORE_DROP         = 40    # below this -> discard completely
SCORE_LOW_CONF     = 60    # below this -> LOW_CONFIDENCE (verbose only)
# >= SCORE_LOW_CONF -> confirmed endpoint

# ---------------------------------------------------------------------------
# Positive structural signals
# ---------------------------------------------------------------------------

# Starts with a slash - strongest path signal
RE_STARTS_SLASH      = re.compile(r'^/')

# Has at least one internal slash separator (not just leading /)
RE_HAS_SEPARATOR     = re.compile(r'(?<=/)[a-zA-Z0-9_\-{}]+.*/')

# Classic API path prefixes
RE_API_PREFIX        = re.compile(
    r'^/(?:api|v\d+|rest|graphql|ws|socket|rpc|trpc|admin|auth|oauth|login|logout'
    r'|signup|register|password|token|session|upload|download|export|import|internal'
    r'|webhook|callback|health|status|ping|metrics|openapi|swagger|docs/api)(?:/|$)',
    re.IGNORECASE,
)

# Full URL (http/https/ws/wss)
RE_FULL_URL          = re.compile(r'^(?:https?|wss?|ws)://', re.IGNORECASE)

# HTTP method words in surrounding context (50 chars either side)
RE_HTTP_METHOD       = re.compile(
    r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b',
    re.IGNORECASE,
)

# Fetch/XHR/axios keyword in surrounding context
RE_HTTP_CLIENT       = re.compile(
    r'\b(?:fetch|axios|XMLHttpRequest|\.get\(|\.post\(|\.put\(|\.delete\(|\.patch\('
    r'|\.request\(|superagent|ky\.get|ky\.post|http\.get|http\.post'
    r'|angular.*HttpClient|urql|apollo\.query|apollo\.mutate)\b',
    re.IGNORECASE,
)

# URL construction context
RE_URL_CONTEXT       = re.compile(
    r'\b(?:url|endpoint|baseUrl|baseURL|apiUrl|apiURL|href|action|src|path'
    r'|route|location|redirect|returnUrl|callbackUrl)\s*[=:+]',
    re.IGNORECASE,
)

# Template literal / concatenation hints
RE_TEMPLATE_URL      = re.compile(r'`[^`]*\$\{[^}]+\}[^`]*/[^`]*`')

# Path parameter patterns - strong API signal
RE_PATH_PARAM        = re.compile(r'[/{](?:id|uuid|slug|userId|orgId|token|[a-z]+Id)[}/]',
                                  re.IGNORECASE)

# Dynamic segment patterns: /users/{id} or /users/:id
RE_DYNAMIC_SEGMENT   = re.compile(r'/\{[^}]+\}|/:[a-zA-Z_][a-zA-Z0-9_]*')

# ---------------------------------------------------------------------------
# Negative signals - things that indicate this is NOT an endpoint
# ---------------------------------------------------------------------------

# Pure single English word with no path structure
RE_BARE_WORD         = re.compile(r'^[a-zA-Z][a-zA-Z]*$')

# camelCase identifier without slashes (chart option names etc.)
RE_CAMEL_NO_SLASH    = re.compile(r'^[a-z][a-zA-Z0-9]+$')

# ALL_CAPS_CONSTANT (enum/config key, not a path)
RE_CAPS_CONST        = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')

# Looks like a CSS class or color
RE_CSS_VALUE         = re.compile(r'^(?:#[0-9a-fA-F]{3,8}|rgba?\(|hsla?\(|var\(--)')

# Known chart/viz library token patterns (ApexCharts, Chart.js, Recharts)
_CHART_TOKENS = frozenset({
    # ApexCharts series names and option keys
    "secure", "series", "unequal", "minimum", "median", "maximum",
    "open", "high", "low", "close", "volume",
    # Generic chart noise
    "xaxis", "yaxis", "legend", "tooltip", "plotOptions", "dataLabels",
    "fill", "stroke", "markers", "grid", "annotations",
    # Chart.js labels that leak as paths
    "borderWidth", "pointRadius", "lineTension",
    # Recharts
    "ComposedChart", "BarChart", "LineChart", "AreaChart",
})

# Known JS library internals that leak into path extraction
_LIB_TOKENS = frozenset({
    # Lodash / underscore
    "chunk", "compact", "concat", "difference", "drop", "fill",
    "filter", "find", "flatten", "flow", "group", "head", "includes",
    "indexOf", "intersection", "join", "keys", "last", "map", "merge",
    "omit", "orderBy", "pick", "reduce", "reject", "rest", "reverse",
    "set", "slice", "some", "sort", "sortBy", "split", "tail", "take",
    "union", "unique", "uniq", "values", "zip",
    # Moment.js / date-fns tokens
    "format", "parse", "utc", "local", "duration", "locale",
    # i18n
    "namespace", "language", "fallback",
})

# Context keywords that suggest this is inside a chart/viz block
RE_CHART_CONTEXT     = re.compile(
    r'\b(?:series|chart|plot|apex|recharts|chartjs|d3|echarts'
    r'|xaxis|yaxis|legend|tooltip|stroke|fill|marker|annotation)\s*[=:{,]',
    re.IGNORECASE,
)

# Config object keys that are definitely not paths
RE_CONFIG_KEY_CTX    = re.compile(
    r'\b(?:type|color|size|weight|width|height|margin|padding|opacity'
    r'|duration|delay|easing|threshold|step|interval|timeout|retries)\s*[=:]',
    re.IGNORECASE,
)

# Webpack/bundler internal pseudo-paths
RE_WEBPACK_INTERNAL  = re.compile(
    r'^(?:webpack(?:/|$)|__webpack_|externals?|node_modules?|webpack-internal)',
    re.IGNORECASE,
)

# Pure file extension without path (e.g. ".js", ".png")
RE_BARE_EXT          = re.compile(r'^\.[a-z]{2,5}$')

# UUID / hash standalone strings (not endpoints)
RE_PURE_HASH         = re.compile(r'^[0-9a-f]{32,}$', re.IGNORECASE)

# Version strings like "1.2.3" or "v1.2.3"
RE_VERSION_STRING    = re.compile(r'^v?\d+\.\d+(?:\.\d+)?(?:-[a-z0-9.]+)?$', re.IGNORECASE)

# Known skip domains (CDN, social, doc sites)
_SKIP_DOMAINS = frozenset({
    "reactjs.org", "w3.org", "github.com", "developer.mozilla.org",
    "tc39.es", "schema.org", "example.com", "example.org",
    "twitter.com", "x.com", "linkedin.com", "facebook.com",
    "instagram.com", "youtube.com", "google.com", "googleapis.com",
    "googletagmanager.com", "google-analytics.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "npmjs.com", "webpack.js.org", "babeljs.io", "vuejs.org", "angular.io",
})

# Asset file extensions that are not endpoints
_ASSET_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".css", ".scss", ".less",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".tar", ".gz",
    ".mp4", ".mp3", ".avi", ".webm", ".ogg",
    ".map",    # source maps are not endpoints
})

# Path prefixes that are always static assets, never API endpoints
_STATIC_PATH_PREFIXES = (
    "/images/", "/img/", "/fonts/", "/icons/", "/static/images/",
    "/assets/images/", "/assets/fonts/", "/media/",
)


# ---------------------------------------------------------------------------
# RouteCandidate
# ---------------------------------------------------------------------------

@dataclass
class RouteCandidate:
    """
    A scored endpoint candidate. Wraps an Endpoint with scoring metadata.
    """
    endpoint:        Endpoint
    raw_score:       int   = 0
    signals_hit:     List[str] = field(default_factory=list)
    signals_missed:  List[str] = field(default_factory=list)
    confidence_band: str   = "DROP"    # DROP | LOW | HIGH
    verified_status: str   = ValidationStatus.NOT_ATTEMPTED
    verified_code:   Optional[int] = None

    @property
    def url(self) -> str:
        return self.endpoint.url

    @property
    def category(self) -> str:
        return self.endpoint.category

    def is_confirmed(self) -> bool:
        return self.confidence_band == "HIGH"

    def is_low_confidence(self) -> bool:
        return self.confidence_band == "LOW"

    def is_dropped(self) -> bool:
        return self.confidence_band == "DROP"


# ---------------------------------------------------------------------------
# Core scoring function
# ---------------------------------------------------------------------------

def score_endpoint(url: str, surrounding_context: str = "") -> Tuple[int, List[str], List[str]]:
    """
    Compute a score for a single URL/path candidate.

    Returns:
        (score, positive_signals, negative_signals)

    Scoring guide:
        > 0  positive signal hit
        < 0  negative signal hit
        Each rule has a weight; weights are additive.
    """
    score      = 0
    positive   = []
    negative   = []
    ctx        = surrounding_context.lower()
    url_lower  = url.lower()

    # ---- Early hard rejects (score to -1000 so they always DROP) -----------

    # Skip domains
    try:
        parsed = urlparse(url if "://" in url else "x://" + url)
        host   = (parsed.hostname or "").lower().lstrip("www.")
        if host in _SKIP_DOMAINS or any(host.endswith("." + d) for d in _SKIP_DOMAINS):
            return -1000, [], ["skip_domain"]
    except Exception:
        pass

    # Asset extensions
    path_lower = (urlparse(url).path if "://" in url else url).lower().split("?")[0]
    for ext in _ASSET_EXTS:
        if path_lower.endswith(ext):
            return -1000, [], [f"asset_ext:{ext}"]

    # Static asset path prefixes
    for prefix in _STATIC_PATH_PREFIXES:
        if prefix in path_lower:
            return -1000, [], [f"static_prefix:{prefix}"]

    # Webpack internal pseudo-paths
    if RE_WEBPACK_INTERNAL.search(url):
        return -1000, [], ["webpack_internal"]

    # Pure hash / UUID string
    if RE_PURE_HASH.match(url.strip("/")):
        return -1000, [], ["pure_hash"]

    # Version string
    if RE_VERSION_STRING.match(url.strip("/")):
        return -1000, [], ["version_string"]

    # Bare file extension like ".js"
    if RE_BARE_EXT.match(url):
        return -1000, [], ["bare_ext"]

    # CSS / color value
    if RE_CSS_VALUE.match(url):
        return -1000, [], ["css_value"]

    # ---- Structural signals ------------------------------------------------

    # Starts with slash
    if RE_STARTS_SLASH.match(url):
        score += 25
        positive.append("starts_slash(+25)")
    elif RE_FULL_URL.match(url):
        score += 30
        positive.append("full_url(+30)")
    else:
        score -= 20
        negative.append("no_leading_slash(-20)")

    # Has internal path separator
    if RE_HAS_SEPARATOR.search(url):
        score += 20
        positive.append("has_separator(+20)")

    # Matches a known API prefix pattern
    if RE_API_PREFIX.match(url):
        score += 40
        positive.append("api_prefix(+40)")

    # Has path parameters
    if RE_PATH_PARAM.search(url):
        score += 15
        positive.append("path_param(+15)")

    if RE_DYNAMIC_SEGMENT.search(url):
        score += 10
        positive.append("dynamic_segment(+10)")

    # ---- Context signals ---------------------------------------------------

    # HTTP method keyword in context
    if RE_HTTP_METHOD.search(surrounding_context):
        score += 20
        positive.append("http_method_ctx(+20)")

    # HTTP client (fetch/axios/XHR) in context
    if RE_HTTP_CLIENT.search(surrounding_context):
        score += 25
        positive.append("http_client_ctx(+25)")

    # URL variable name in context
    if RE_URL_CONTEXT.search(surrounding_context):
        score += 15
        positive.append("url_var_ctx(+15)")

    # Template literal URL construction
    if RE_TEMPLATE_URL.search(surrounding_context):
        score += 10
        positive.append("template_literal_ctx(+10)")

    # ---- Negative structural signals ---------------------------------------

    # Pure single word, no slashes
    if RE_BARE_WORD.match(url) and "/" not in url:
        score -= 40
        negative.append("bare_word(-40)")

    # camelCase without slashes (chart option name)
    if RE_CAMEL_NO_SLASH.match(url) and "/" not in url:
        score -= 35
        negative.append("camel_no_slash(-35)")

    # ALL_CAPS constant
    if RE_CAPS_CONST.match(url) and "/" not in url:
        score -= 30
        negative.append("caps_const(-30)")

    # Known chart token
    stripped = url.strip("/").lower()
    if stripped in _CHART_TOKENS:
        score -= 50
        negative.append("chart_token(-50)")

    # Known library utility token
    if stripped in _LIB_TOKENS:
        score -= 40
        negative.append("lib_token(-40)")

    # ---- Negative context signals -----------------------------------------

    # Inside a chart/viz block
    if RE_CHART_CONTEXT.search(ctx):
        score -= 30
        negative.append("chart_context(-30)")

    # Inside a CSS/config key block
    if RE_CONFIG_KEY_CTX.search(ctx):
        score -= 15
        negative.append("config_key_ctx(-15)")

    # Very short path with no meaningful segment (e.g. "/a")
    segments = [s for s in path_lower.split("/") if s]
    if len(segments) == 1 and len(segments[0]) <= 2:
        score -= 25
        negative.append("too_short_path(-25)")

    # Long paths that look like minified code rather than paths (> 8 segments)
    if len(segments) > 8:
        score -= 20
        negative.append("too_many_segments(-20)")

    return score, positive, negative


# ---------------------------------------------------------------------------
# Classifier entry point
# ---------------------------------------------------------------------------

def classify_endpoint(
    endpoint: Endpoint,
    surrounding_context: str = "",
) -> RouteCandidate:
    """
    Score an Endpoint and return a RouteCandidate.
    Always returns a candidate - caller checks .is_dropped().

    Incorporates the Endpoint's existing category and confidence
    as additional scoring inputs - these come from the extractors that
    already applied framework-specific pattern matching.
    """
    try:
        score, pos, neg = score_endpoint(endpoint.url, surrounding_context)
    except Exception as exc:
        logger.debug("Scoring failed for %s: %s", endpoint.url, exc)
        score, pos, neg = 0, [], ["scoring_error"]

    # ---- Bonus from existing extractor classification ----------------------
    # The route_extractor and endpoint_intel already applied precise patterns.
    # Trust their category labels to lift candidates that passed those patterns.

    cat = getattr(endpoint, "category", "") or ""
    if cat == "ROUTE":
        # Came from route_extractor - framework-specific patterns (React Router,
        # Vue, Angular, etc.) are much more precise than our regexes above.
        score += 25
        pos = pos + ["extractor_route(+25)"]
    elif cat in ("API", "AUTH", "ADMIN", "GRAPHQL", "WEBSOCKET"):
        score += 20
        pos = pos + [f"extractor_{cat.lower()}(+20)"]

    # Existing confidence (0.72-0.9 from extractors) also adds signal
    conf = getattr(endpoint, "confidence", 0.5) or 0.5
    if conf >= 0.85:
        score += 10
        pos = pos + ["high_conf_extractor(+10)"]
    elif conf >= 0.72:
        score += 5
        pos = pos + ["med_conf_extractor(+5)"]

    if score >= SCORE_LOW_CONF:
        band = "HIGH"
    elif score >= SCORE_DROP:
        band = "LOW"
    else:
        band = "DROP"

    candidate = RouteCandidate(
        endpoint        = endpoint,
        raw_score       = score,
        signals_hit     = pos,
        signals_missed  = neg,
        confidence_band = band,
    )
    return candidate


def classify_endpoints(
    endpoints: List[Endpoint],
    context_map: Optional[dict] = None,
) -> List[RouteCandidate]:
    """
    Classify a list of Endpoint objects.

    context_map: optional dict {url -> surrounding_context_string}
                 for per-endpoint context lookup.

    Returns all candidates - callers filter by is_dropped() / is_confirmed().
    """
    results = []
    ctx_map = context_map or {}
    for ep in endpoints:
        ctx = ctx_map.get(ep.url, "")
        candidate = classify_endpoint(ep, ctx)
        results.append(candidate)
    return results


# ---------------------------------------------------------------------------
# Optional HTTP verification
# ---------------------------------------------------------------------------

def verify_candidates(
    candidates:  List[RouteCandidate],
    base_url:    str,
    fetcher,
    max_verify:  int = 50,
    timeout_s:   float = 5.0,
) -> List[RouteCandidate]:
    """
    Run lightweight HTTP HEAD probes against confirmed candidates.
    Only probes path-only endpoints (not full URLs from external domains).
    Mutates each candidate's verified_status / verified_code in place.

    Args:
        candidates:  list of RouteCandidate objects (scored already)
        base_url:    target origin e.g. "https://example.com"
        fetcher:     bundlespy fetcher with a .get(url) method
        max_verify:  cap on total probes (avoid hammering the server)
        timeout_s:   not directly used here; fetcher has its own timeout
    """
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    probed = 0

    for cand in candidates:
        if cand.is_dropped():
            continue
        if probed >= max_verify:
            break

        url = cand.url

        # Only probe relative paths against the target origin
        if url.startswith("/"):
            probe_url = base_origin + url
        elif url.startswith(("http://", "https://")):
            probe_url_parsed = urlparse(url)
            probe_host = (probe_url_parsed.hostname or "").lower()
            base_host  = (parsed_base.hostname or "").lower()
            if probe_host != base_host:
                # Don't probe external URLs
                continue
            probe_url = url
        else:
            continue

        try:
            content, status, _ct, _sha = fetcher.get(probe_url)
            cand.verified_code = status
            probed += 1

            if status in range(200, 400):
                cand.verified_status = ValidationStatus.CONFIRMED
                cand.endpoint.confidence = min(1.0, cand.endpoint.confidence + 0.1)
                cand.raw_score += 20      # reward verified endpoints
                if cand.confidence_band == "LOW":
                    cand.confidence_band = "HIGH"  # promote on successful probe
                logger.debug(
                    "VERIFIED %s -> HTTP %d (score now %d)",
                    probe_url, status, cand.raw_score,
                )
            elif status == 401 or status == 403:
                # 401/403 means the endpoint EXISTS but is protected - still real
                cand.verified_status = ValidationStatus.CONFIRMED
                cand.endpoint.confidence = min(1.0, cand.endpoint.confidence + 0.05)
                cand.raw_score += 15
                if cand.confidence_band == "LOW":
                    cand.confidence_band = "HIGH"
                logger.debug(
                    "PROTECTED %s -> HTTP %d (score now %d)",
                    probe_url, status, cand.raw_score,
                )
            elif status == 404:
                cand.verified_status = ValidationStatus.UNREACHABLE
                # Small penalty - might be a valid route not yet deployed
                cand.raw_score -= 5
                logger.debug("NOT FOUND %s -> HTTP 404", probe_url)
            elif status >= 500:
                # 5xx means the server saw it and errored - endpoint is real
                cand.verified_status = ValidationStatus.CONFIRMED
                cand.raw_score += 10
                logger.debug("SERVER ERROR %s -> HTTP %d (counts as real)", probe_url, status)
            else:
                cand.verified_status = ValidationStatus.PROBED

        except Exception as exc:
            logger.debug("Probe failed for %s: %s", probe_url, exc)
            cand.verified_status = ValidationStatus.UNREACHABLE

    return candidates


# ---------------------------------------------------------------------------
# Filter helpers for callers
# ---------------------------------------------------------------------------

def confirmed_only(candidates: List[RouteCandidate]) -> List[Endpoint]:
    """Return Endpoint objects for candidates that scored HIGH."""
    return [c.endpoint for c in candidates if c.is_confirmed()]


def verbose_output(candidates: List[RouteCandidate]) -> List[Endpoint]:
    """Return Endpoint objects for HIGH + LOW confidence candidates."""
    return [c.endpoint for c in candidates if not c.is_dropped()]


def debug_dump(candidates: List[RouteCandidate]) -> str:
    """
    Human-readable scoring breakdown - useful for -vv mode and debugging.
    """
    lines = []
    for c in sorted(candidates, key=lambda x: -x.raw_score):
        band_icon = {"HIGH": "[+]", "LOW": "[~]", "DROP": "[-]"}[c.confidence_band]
        lines.append(
            f"{band_icon} score={c.raw_score:+4d}  {c.url[:80]}"
        )
        if c.signals_hit:
            lines.append(f"      pos: {', '.join(c.signals_hit)}")
        if c.signals_missed:
            lines.append(f"      neg: {', '.join(c.signals_missed)}")
        if c.verified_code:
            lines.append(f"      http: {c.verified_code} ({c.verified_status})")
    return "\n".join(lines)
