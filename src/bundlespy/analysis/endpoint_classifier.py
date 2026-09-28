"""
Endpoint Classifier - intelligent scoring system for route/endpoint candidates.

Every string extracted by endpoints.py and route_extractor.py passes through
here before it reaches the final output. The classifier assigns a score based
on structural, contextual, and semantic signals. Low-scoring strings (noise,
chart tokens, config keys, CSS utilities, i18n keys, etc.) get dropped;
high-scoring ones are promoted.

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
from typing import List, Optional, Tuple, Dict, Set
from urllib.parse import urlparse

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

# Classic API path prefixes (optional leading slash for relative paths)
RE_API_PREFIX        = re.compile(
    r'^/?(?:api|v\d+|rest|graphql|gql|ws|socket|rpc|trpc|grpc'
    r'|admin|auth|oauth|oauth2|login|logout|signin|signout'
    r'|signup|register|password|token|refresh|session|me'
    r'|upload|download|export|import|internal|private'
    r'|webhook|webhooks|callback|callbacks'
    r'|health|healthz|status|ping|ready|liveness'
    r'|metrics|telemetry|openapi|swagger|docs/api|api-docs'
    r'|users|accounts|orders|payments|products|inventory|catalog'
    r'|search|notifications|messages|feeds|timeline|events'
    r'|billing|subscriptions|checkout|cart|wishlist'
    r'|reports|analytics|dashboard|settings|config|configuration'
    r'|files|media|images|videos|documents|attachments'
    r'|comments|reviews|ratings|likes|follows|shares'
    r'|teams|organizations|workspaces|projects|tasks'
    r'|roles|permissions|policies|audit|logs'
    r'|email|sms|push|notifications|alerts'
    r'|integrations|connections|providers|sources|destinations)(?:/|$)',
    re.IGNORECASE,
)

# Relative path that has at least one internal slash (no leading slash)
# e.g. "api/users", "v1/tokens", "auth/login", "users/profile"
RE_RELATIVE_PATH     = re.compile(
    r'^[a-zA-Z][a-zA-Z0-9_\-]*/[a-zA-Z0-9_\-/{}:?=&%#.]+$'
)

# Full URL (http/https/ws/wss)
RE_FULL_URL          = re.compile(r'^(?:https?|wss?|ws)://', re.IGNORECASE)

# HTTP method words in surrounding context
RE_HTTP_METHOD       = re.compile(
    r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b',
    re.IGNORECASE,
)

# Fetch/XHR/axios keyword in surrounding context
RE_HTTP_CLIENT       = re.compile(
    r'\b(?:fetch\s*\(|axios\s*[.(]|XMLHttpRequest|'
    r'\.get\s*\(|\.post\s*\(|\.put\s*\(|\.delete\s*\(|\.patch\s*\(|'
    r'\.request\s*\(|superagent|ky\s*\.\s*(?:get|post|put|delete|patch)|'
    r'http\s*\.\s*(?:get|post|put|delete|patch)|'
    r'HttpClient|urql|apollo(?:Client)?\.(?:query|mutate)|'
    r'useSWR|useQuery|useMutation|createApi|rtk\.query|'
    r'\.interceptors\.|baseURL|withCredentials|responseType)\b',
    re.IGNORECASE,
)

# URL construction context variable names
RE_URL_CONTEXT       = re.compile(
    r'\b(?:url|endpoint|endpointUrl|baseUrl|baseURL|apiUrl|apiURL|'
    r'href|action|src|path|route|location|redirect|returnUrl|callbackUrl|'
    r'requestUrl|targetUrl|proxyUrl|serviceUrl|remoteUrl|apiEndpoint|'
    r'resourceUrl|fetchUrl|queryUrl|postUrl|putUrl|deleteUrl)\s*[=:+]',
    re.IGNORECASE,
)

# Template literal URL construction with variable substitution
RE_TEMPLATE_URL      = re.compile(r'`[^`]*\$\{[^}]+\}[^`]*/[^`]*`')

# Path parameter patterns in the URL itself
RE_PATH_PARAM        = re.compile(
    r'[/{](?:id|uuid|slug|userId|orgId|teamId|projectId|token|'
    r'[a-z]+Id|[a-z]+Uuid|[a-z]+Slug)[}/]',
    re.IGNORECASE,
)

# Dynamic segment patterns: /users/{id} or /users/:id or /users/[id]
RE_DYNAMIC_SEGMENT   = re.compile(r'/\{[^}]+\}|/:[a-zA-Z_][a-zA-Z0-9_]*|/\[[^\]]+\]')

# Express/Fastify/Hapi route registration (server-side patterns in bundled SSR)
RE_SERVER_ROUTE      = re.compile(
    r'\b(?:app|router|server|fastify|hapi)\s*\.\s*(?:get|post|put|delete|patch|all|route|use)\s*\('
    r'\s*[`"\']([^`"\']+)[`"\']',
    re.IGNORECASE,
)

# Query string parameters are positive signal
RE_HAS_QUERY         = re.compile(r'\?[a-zA-Z_][a-zA-Z0-9_]*=')

# ---------------------------------------------------------------------------
# Negative signals - hard rejects first, then scored penalties
# ---------------------------------------------------------------------------

# Pure single English word with no path structure
RE_BARE_WORD         = re.compile(r'^[a-zA-Z][a-zA-Z]*$')

# camelCase identifier without slashes (chart option names, config keys)
RE_CAMEL_NO_SLASH    = re.compile(r'^[a-z][a-zA-Z0-9]+$')

# SCREAMING_SNAKE_CASE constant (enum/config key, not a path)
RE_CAPS_CONST        = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')

# PascalCase (component names, class names)
RE_PASCAL_CASE       = re.compile(r'^[A-Z][a-z][a-zA-Z0-9]+$')

# Looks like a CSS color / function value
RE_CSS_VALUE         = re.compile(
    r'^(?:#[0-9a-fA-F]{3,8}|rgba?\s*\(|hsla?\s*\(|var\s*\(--|'
    r'linear-gradient|radial-gradient|conic-gradient|inherit|initial|unset)'
)

# Tailwind utility class patterns (has slash but is not an endpoint)
# e.g. "hover:text-red-500", "dark:bg-gray-800", "lg:flex", "w-1/2"
RE_TAILWIND_CLASS    = re.compile(
    r'^(?:(?:hover|focus|active|disabled|group-hover|dark|light|'
    r'sm|md|lg|xl|2xl|print|motion-safe|motion-reduce|'
    r'first|last|odd|even|visited|checked|required|valid|invalid|'
    r'placeholder|before|after|selection|file|marker|prose|'
    r'peer|peer-hover|peer-focus|peer-checked):)+[a-z]'
    r'|^(?:text|bg|border|ring|shadow|p|m|w|h|min|max|flex|grid|'
    r'col|row|gap|space|divide|place|self|items|justify|content|'
    r'rounded|opacity|scale|rotate|translate|skew|transform|'
    r'transition|duration|ease|delay|animate|cursor|pointer|'
    r'select|overflow|truncate|whitespace|break|font|leading|'
    r'tracking|decoration|list|align|float|clear|object|'
    r'inset|top|right|bottom|left|z|order|sr|not|aspect|'
    r'columns|basis|grow|shrink|invisible|visible|static|fixed|'
    r'relative|absolute|sticky)-',
    re.IGNORECASE,
)

# Tailwind fraction class like "w-1/2", "h-2/3" - looks like path but isn't
RE_TAILWIND_FRACTION = re.compile(r'^[whp]-\d+/\d+$', re.IGNORECASE)

# i18n translation key patterns (dot-separated, no slashes)
# e.g. "common.errors.notFound", "validation.email.invalid"
RE_I18N_KEY          = re.compile(r'^[a-z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*){1,8}$')

# Relative file path (import path, not URL path)
# e.g. "./components/Button", "../utils/api", "../../shared/types"
RE_FILE_PATH         = re.compile(r'^\.\.?/')

# Node module path (no leading ./ but looks like module specifier)
RE_MODULE_PATH       = re.compile(
    r'^(?:@[a-z][a-z0-9\-]*/[a-z0-9\-/]+|'
    r'[a-z][a-z0-9\-]*/(?:dist|src|lib|esm|cjs|umd|bundle)/)',
    re.IGNORECASE,
)

# Environment variable placeholder strings
RE_ENV_VAR           = re.compile(
    r'process\.env\.[A-Z_]+|'
    r'\$\{?(?:process\.env\.)?[A-Z_][A-Z0-9_]+\}?|'
    r'import\.meta\.env\.[A-Z_]+'
)

# Regex pattern that leaked as a string (contains char classes or anchors)
RE_REGEX_PATTERN     = re.compile(r'[\[\]()\\^$*+?{,}|].*[\[\]()\\^$*+?{,}|]')

# CSS selector patterns (.class, #id, element[attr])
RE_CSS_SELECTOR      = re.compile(r'^(?:\.[a-zA-Z_\-]|\#[a-zA-Z_\-]|[a-z]+\[)')

# Contains spaces (URL paths never have spaces - this is prose or a label)
RE_HAS_SPACES        = re.compile(r'\s')

# Webpack/bundler internal pseudo-paths
RE_WEBPACK_INTERNAL  = re.compile(
    r'^(?:webpack(?:/|$)|__webpack_|externals?/|node_modules/|'
    r'webpack-internal://|data:application/)',
    re.IGNORECASE,
)

# Pure file extension like ".js", ".css"
RE_BARE_EXT          = re.compile(r'^\.[a-z]{2,5}$')

# UUID / hex hash standalone string (not an endpoint)
RE_PURE_HASH         = re.compile(r'^[0-9a-f]{24,}$', re.IGNORECASE)

# Base64 blob (contains = padding and long alphanum runs)
RE_BASE64_BLOB       = re.compile(r'^[A-Za-z0-9+/]{32,}={0,2}$')

# Version strings like "1.2.3", "v1.2.3", "v1.2.3-beta.1"
RE_VERSION_STRING    = re.compile(
    r'^v?\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?$',
    re.IGNORECASE,
)

# Looks like a semver constraint or range
RE_SEMVER_RANGE      = re.compile(r'^[~^><]?\d+\.\d+|^\*$')

# Timestamp or date-like string
RE_TIMESTAMP         = re.compile(
    r'^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2})?|'
    r'^\d{10,13}$',
)

# Looks like a MIME type (must start with a known MIME category and have a proper subtype)
# "application/json", "text/html", "image/png" - but NOT "api/users", "auth/login"
RE_MIME_TYPE         = re.compile(
    r'^(?:application|text|image|audio|video|font|model|multipart|message)'
    r'/[a-z][a-z0-9][a-z0-9.+\-]{2,}$',
    re.IGNORECASE,
)

# Looks like a SQL query fragment
RE_SQL_FRAGMENT      = re.compile(
    r'\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|GROUP BY|ORDER BY|HAVING)\b',
    re.IGNORECASE,
)

# Data URIs
RE_DATA_URI          = re.compile(r'^data:[a-z]+/[a-z+]+;base64,', re.IGNORECASE)

# Blob URLs
RE_BLOB_URL          = re.compile(r'^blob:', re.IGNORECASE)

# JavaScript protocol
RE_JS_PROTO          = re.compile(r'^javascript:', re.IGNORECASE)

# mailto / tel / sms
RE_NON_HTTP_PROTO    = re.compile(r'^(?:mailto|tel|sms|ftp|file|ssh|git|svn):', re.IGNORECASE)

# Looks like a URL pattern used in path-to-regexp (complex nested params)
# that leaks from route tables but is actually the pattern string, not a real URL
RE_COMPLEX_PATTERN   = re.compile(r'\([^)]{20,}\)|\[[^\]]{20,}\]')

# Strings that contain newlines (multi-line strings are not URL paths)
RE_MULTILINE         = re.compile(r'[\n\r]')

# Known CDN / documentation domains to skip
_SKIP_DOMAINS: Set[str] = {
    # Documentation
    "reactjs.org", "react.dev", "w3.org", "w3schools.com",
    "developer.mozilla.org", "mdn.io", "devdocs.io",
    "tc39.es", "ecma-international.org",
    "schema.org", "json-schema.org", "jsonapi.org",
    "openapi.org", "swagger.io",
    "example.com", "example.org", "example.net",
    "localhost",
    # Social
    "twitter.com", "x.com", "t.co",
    "linkedin.com", "facebook.com", "fb.com",
    "instagram.com", "tiktok.com", "snapchat.com",
    "youtube.com", "youtu.be", "vimeo.com",
    "pinterest.com", "reddit.com", "discord.com", "discord.gg",
    "telegram.org", "t.me", "slack.com",
    # Google ecosystem
    "google.com", "googleapis.com", "gstatic.com",
    "googletagmanager.com", "google-analytics.com",
    "googleadservices.com", "doubleclick.net",
    "maps.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    # Analytics / tracking
    "segment.io", "segment.com",
    "mixpanel.com", "amplitude.com",
    "hotjar.com", "fullstory.com",
    "intercom.com", "intercom.io",
    "zendesk.com", "freshdesk.com",
    "hubspot.com", "hubapi.com",
    "sentry.io", "bugsnag.com", "rollbar.com",
    "datadog.com", "newrelic.com", "dynatrace.com",
    "logrocket.com", "instana.com",
    # CDN / package delivery
    "cloudflare.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net", "skypack.dev",
    "esm.sh", "cdn.esm.sh",
    "staticfile.org", "bootcss.com",
    # Package registries
    "npmjs.com", "npm.im", "yarnpkg.com",
    "pypi.org", "crates.io", "pkg.go.dev",
    # Build tools
    "webpack.js.org", "vitejs.dev", "rollupjs.org",
    "babeljs.io", "swc.rs", "esbuild.github.io",
    # Frameworks (their own domains are not API endpoints)
    "vuejs.org", "angular.io", "svelte.dev", "solidjs.com",
    "nextjs.org", "nuxtjs.org", "remix.run", "astro.build",
    # Type definitions
    "typescriptlang.org", "definitelytyped.org",
    # GitHub / code hosting
    "github.com", "raw.githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "gist.github.com",
    # CI/CD
    "travis-ci.com", "circleci.com", "codecov.io",
    # Auth providers (their public docs pages, not API endpoints)
    "auth0.com", "okta.com", "cognito.amazonaws.com",
    "accounts.google.com", "login.microsoftonline.com",
    # AWS SDK base URLs that are not the target's own endpoints
    "amazonaws.com", "aws.amazon.com",
    # Polyfill / compatibility
    "polyfill.io", "polyfills.io",
}

# Asset file extensions (not endpoints)
_ASSET_EXTS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp",
    ".css", ".scss", ".sass", ".less", ".styl",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".mp4", ".mp3", ".avi", ".webm", ".ogg", ".mov", ".mkv", ".flac", ".wav",
    ".map",       # source maps
    ".LICENSE",
    ".txt",       # plain text files referenced in bundles
}

# Path prefixes that are always static assets, never API endpoints
_STATIC_PATH_PREFIXES: Tuple[str, ...] = (
    "/images/", "/img/", "/fonts/", "/icons/", "/static/images/",
    "/assets/images/", "/assets/fonts/", "/public/", "/media/images/",
    "/_next/image/", "/_next/static/", "/_nuxt/",
    "/wp-content/uploads/", "/wp-content/themes/", "/wp-content/plugins/",
)

# ---------------------------------------------------------------------------
# Massive token blocklists - strings that look like paths but aren't
# ---------------------------------------------------------------------------

# Chart / data-visualization library tokens
_CHART_TOKENS: Set[str] = {
    # OHLCV financial data labels (ApexCharts, TradingView, Highcharts, etc.)
    "open", "high", "low", "close", "volume", "vwap",
    "bid", "ask", "spread", "tick",
    # Generic chart series/option keys
    "series", "dataset", "datasets", "datapoint", "datapoints",
    "xaxis", "yaxis", "zaxis", "x-axis", "y-axis",
    "legend", "tooltip", "popup", "crosshair",
    "plotOptions", "chartOptions", "chartData", "chartConfig",
    "annotations", "markers", "marker", "stroke", "fill", "shadow",
    "borderWidth", "borderColor", "borderRadius",
    "pointRadius", "pointStyle", "pointBackgroundColor",
    "lineTension", "cubicInterpolationMode",
    "backgroundImage", "backgroundOpacity",
    "segmentColors", "slices",
    # Axis configuration
    "categories", "tickAmount", "tickPlacement", "tickInterval",
    "gridLines", "gridDashArray",
    "labelStyle", "labelFormat", "labelFormatter",
    "opposite", "reversed", "logarithmic",
    # ApexCharts specific
    "apex", "apexchart", "apexcharts",
    "sparkline", "radialBar", "polarArea", "heatmap", "treemap",
    "candlestick", "boxplot", "rangeBar",
    "distributed", "stacked", "horizontal",
    "noClick", "zoomEnabled", "panEnabled",
    # Recharts / Chart.js / D3 specific
    "ComposedChart", "BarChart", "LineChart", "AreaChart",
    "PieChart", "RadarChart", "ScatterChart", "Treemap",
    "Brush", "CartesianGrid", "ReferenceLine", "ReferenceArea",
    "ResponsiveContainer", "Legend", "Tooltip", "Cell",
    "XAxis", "YAxis", "ZAxis",
    # Vega / Vega-Lite
    "encoding", "mark", "spec", "transform", "aggregate",
    "condition", "bin", "timeUnit", "bandSize",
    # Generic viz
    "minimum", "maximum", "median", "mean", "stddev", "variance",
    "quartile", "percentile", "outlier", "anomaly",
    "projection", "topojson", "geojson",
    # Chart.js scale types
    "linear", "logarithmic", "radial", "timeseries", "category",
    "monotone", "stepped", "bezier",
    # Plotly
    "scatter", "scattergl", "bar", "histogram", "heatmap", "surface",
    "contour", "choropleth", "waterfall", "funnel",
    "mode", "textposition", "textinfo", "hoverinfo",
    "colorscale", "showscale", "colorbar", "coloraxis",
    # Financial chart
    "candlestick", "ohlc", "renko", "kagi",
    "resistance", "support", "fibonacci", "bollinger",
    "rsi", "macd", "stochastic", "momentum", "oscillator",
    "movingaverage", "ema", "sma", "wma",
    # Secure but in chart context
    "secure", "unsecure",
    "unequal", "equal",
}

# Lodash / Underscore / Ramda utility method names
_LODASH_TOKENS: Set[str] = {
    "chunk", "compact", "concat", "difference", "drop", "dropRight", "fill",
    "filter", "find", "findIndex", "findLast", "flatten", "flattenDeep",
    "flow", "flowRight", "fromPairs", "groupBy", "head", "includes",
    "indexOf", "initial", "intersection", "invoke", "isArray", "isBoolean",
    "isDate", "isEmpty", "isEqual", "isFinite", "isFunction", "isInteger",
    "isNaN", "isNil", "isNull", "isNumber", "isObject", "isPlainObject",
    "isRegExp", "isString", "isSymbol", "isUndefined", "join", "keyBy",
    "keys", "last", "lastIndexOf", "map", "mapKeys", "mapValues", "max",
    "maxBy", "mean", "meanBy", "merge", "mergeWith", "min", "minBy",
    "mixin", "noop", "now", "nth", "omit", "omitBy", "once", "orderBy",
    "over", "overArgs", "pad", "padEnd", "padStart", "partition", "pick",
    "pickBy", "pull", "pullAll", "range", "rangeRight", "reduce", "reject",
    "remove", "rest", "reverse", "sample", "set", "setWith", "shuffle",
    "size", "slice", "some", "sortBy", "split", "tail", "take", "takeRight",
    "tap", "throttle", "times", "toArray", "toCamelCase", "toKebabCase",
    "toPairs", "toPath", "toSnakeCase", "toString", "trim", "trimEnd",
    "trimStart", "truncate", "union", "unionBy", "unionWith", "unique",
    "uniq", "uniqBy", "values", "valuesIn", "without", "xor", "zip",
    "zipObject", "zipWith",
}

# Date library tokens (moment.js, date-fns, dayjs, luxon)
_DATE_TOKENS: Set[str] = {
    "format", "parse", "utc", "local", "duration", "locale",
    "subtract", "add", "startOf", "endOf", "isBefore", "isAfter",
    "isSame", "isSameOrBefore", "isSameOrAfter", "isBetween",
    "fromNow", "toNow", "calendar", "humanize", "diff",
    "toDate", "toISOString", "toJSON", "toLocaleString",
    "valueOf", "unix", "isValid", "isLeapYear",
    "month", "year", "date", "day", "hour", "minute", "second",
    "millisecond", "quarter", "week", "weekday", "weekYear",
    "daysInMonth", "weeksInYear",
    "DateTimeImmutable", "CarbonImmutable",
}

# i18n / internationalization library tokens
_I18N_TOKENS: Set[str] = {
    "namespace", "language", "fallback", "fallbackLng", "lng",
    "interpolation", "escapeValue", "formatSeparator",
    "keySeparator", "nsSeparator", "pluralSeparator",
    "defaultNS", "ns", "resources", "translation",
    "detect", "detection", "cacheUserLanguage",
    "initImmediate", "debug", "react", "useSuspense",
    "load", "backend", "loadPath", "addPath",
    "t", "i18n", "Trans", "useTranslation",
}

# React / Vue / Angular component/lifecycle names that leak as paths
_FRAMEWORK_TOKENS: Set[str] = {
    # React lifecycle
    "componentDidMount", "componentDidUpdate", "componentWillUnmount",
    "componentDidCatch", "getDerivedStateFromProps", "getSnapshotBeforeUpdate",
    "shouldComponentUpdate", "componentWillReceiveProps",
    # React hooks
    "useState", "useEffect", "useContext", "useReducer", "useCallback",
    "useMemo", "useRef", "useImperativeHandle", "useLayoutEffect",
    "useDebugValue", "useDeferredValue", "useTransition", "useId",
    "useInsertionEffect", "useSyncExternalStore",
    # React router specific (path templates, not real URL paths we want)
    "Outlet", "Navigate", "Route", "Routes", "Link", "NavLink",
    "useNavigate", "useParams", "useLocation", "useMatch",
    "useSearchParams", "useRouteError",
    # Vue lifecycle
    "created", "mounted", "beforeMount", "updated", "beforeUpdate",
    "destroyed", "beforeDestroy", "activated", "deactivated",
    "beforeCreate", "beforeUnmount", "unmounted",
    # Vue composition
    "setup", "defineComponent", "defineProps", "defineEmits",
    "defineExpose", "defineAsyncComponent",
    "ref", "reactive", "computed", "watch", "watchEffect",
    "provide", "inject", "nextTick", "toRef", "toRefs", "unref",
    # Angular decorators / lifecycle (leak as strings in minified bundles)
    "ngOnInit", "ngOnDestroy", "ngOnChanges", "ngAfterViewInit",
    "ngAfterViewChecked", "ngAfterContentInit", "ngAfterContentChecked",
    "ngDoCheck",
    # Svelte
    "onMount", "onDestroy", "beforeUpdate", "afterUpdate", "tick",
    # Generic component tokens
    "render", "hydrate", "mount", "unmount", "destroy",
    "forceUpdate", "setState", "getState", "dispatch",
    "subscribe", "unsubscribe", "emit", "off", "on", "once",
}

# CSS framework utility class segment heads (Tailwind, Bootstrap, Material-UI tokens)
_CSS_UTILITY_TOKENS: Set[str] = {
    # Bootstrap components
    "container", "row", "col", "navbar", "nav", "dropdown", "modal",
    "carousel", "accordion", "collapse", "offcanvas", "popover",
    "scrollspy", "toast", "tab", "badge", "breadcrumb", "btn", "btn-primary",
    "btn-secondary", "card", "form", "input-group", "jumbotron",
    "pagination", "progress", "spinner", "table",
    # Material-UI / Material Design class names that leak
    "MuiButton", "MuiTextField", "MuiSelect", "MuiDialog",
    "MuiDrawer", "MuiAppBar", "MuiToolbar", "MuiTypography",
    "makeStyles", "withStyles", "createTheme",
    # CSS property values that sneak in
    "block", "inline", "flex", "grid", "none", "hidden", "visible",
    "relative", "absolute", "fixed", "sticky",
    "auto", "inherit", "initial", "unset", "revert",
    "transparent", "currentColor",
    "normal", "bold", "italic", "underline", "line-through",
    "uppercase", "lowercase", "capitalize",
    "nowrap", "wrap", "ellipsis", "clip",
    "pointer", "default", "not-allowed", "grab", "zoom-in",
    "ease", "linear", "ease-in", "ease-out", "ease-in-out",
}

# GraphQL / schema definition tokens (not API paths)
_GRAPHQL_TOKENS: Set[str] = {
    "Query", "Mutation", "Subscription", "Fragment",
    "String", "Int", "Float", "Boolean", "ID",
    "type", "interface", "union", "enum", "input", "scalar", "schema",
    "implements", "directive", "on", "repeatable", "extend",
    "__typename", "__schema", "__type", "__field",
    "introspectionQuery", "buildSchema", "printSchema",
}

# Redux / state management tokens
_STATE_TOKENS: Set[str] = {
    "createSlice", "createReducer", "createAction", "createSelector",
    "createStore", "configureStore", "combineReducers", "applyMiddleware",
    "compose", "bindActionCreators",
    "getState", "dispatch", "subscribe",
    "initialState", "reducers", "extraReducers", "builder",
    "pending", "fulfilled", "rejected", "idle",
    "loading", "success", "error", "idle",
    "payload", "type", "meta", "error",
}

# Testing library tokens that appear in bundles with test code included
_TEST_TOKENS: Set[str] = {
    "describe", "it", "test", "expect", "beforeEach", "afterEach",
    "beforeAll", "afterAll", "jest", "jasmine", "mocha", "chai",
    "cy", "Cypress", "playwright", "puppeteer",
    "render", "screen", "fireEvent", "waitFor", "userEvent",
    "getByText", "getByRole", "getByLabel", "queryBy", "findBy",
    "toBe", "toEqual", "toStrictEqual", "toMatchObject",
    "toHaveBeenCalled", "toHaveBeenCalledWith", "toReturn",
    "mockImplementation", "mockReturnValue", "mockResolvedValue",
    "spyOn", "mock", "fn", "spy",
}

# All library token sets combined for O(1) lookup
_ALL_LIB_TOKENS: Set[str] = (
    _LODASH_TOKENS |
    _DATE_TOKENS |
    _I18N_TOKENS |
    _FRAMEWORK_TOKENS |
    _CSS_UTILITY_TOKENS |
    _GRAPHQL_TOKENS |
    _STATE_TOKENS |
    _TEST_TOKENS
)

# Context signals that indicate we're inside a non-HTTP library block
RE_LIB_CONTEXT       = re.compile(
    r'\b(?:moment\(|dayjs\(|DateTime\.|'
    r'i18n\.|t\("|t\(\'|useTranslation|'
    r'lodash\.|_\.|R\.|ramda\.|'
    r'styled\.|css`|createGlobalStyle|'
    r'jest\.|describe\(|it\(|test\(|expect\(|'
    r'createSlice|createStore|configureStore|'
    r'withRouter|connect\(|mapState|mapDispatch)\b',
    re.IGNORECASE,
)

# Chart context keywords
RE_CHART_CONTEXT     = re.compile(
    r'\b(?:series|chart|plot|apex|recharts|chartjs|d3|echarts|highcharts|'
    r'xaxis|yaxis|legend|tooltip|stroke|fill|marker|annotation|'
    r'dataLabels|plotOptions|sparkline|candlestick|heatmap|treemap|'
    r'Recharts|ApexChart|Highcharts|Chart\.js|nivo|visx|victory)\s*[=:{,\[]',
    re.IGNORECASE,
)

# Config/styling context (these strings are style options, not paths)
RE_CONFIG_KEY_CTX    = re.compile(
    r'\b(?:backgroundColor|color|fontSize|fontWeight|fontFamily|'
    r'padding|margin|width|height|maxWidth|minWidth|maxHeight|minHeight|'
    r'borderRadius|borderWidth|borderColor|borderStyle|'
    r'boxShadow|textShadow|opacity|visibility|display|position|'
    r'overflow|zIndex|cursor|transition|animation|transform|'
    r'theme\s*[:=]|palette\s*[:=]|typography\s*[:=]|breakpoints\s*[:=]|'
    r'spacing\s*[:=]|shadows\s*[:=]|components\s*[:=])\s*[=:{]',
    re.IGNORECASE,
)

# CSS-in-JS context
RE_CSS_IN_JS         = re.compile(
    r'\b(?:styled\.[a-z]+`|css`|createGlobalStyle`|keyframes`|'
    r'StyleSheet\.create|useStyles|makeStyles|createUseStyles|'
    r'injectGlobal|createStitches|globalStyle|style\s*=\s*\{)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Semantic path segment analysis
# ---------------------------------------------------------------------------

# Real REST resource words (these give bonus if they appear as path segments)
_REAL_RESOURCE_WORDS: Set[str] = {
    "users", "user", "accounts", "account", "orders", "order",
    "products", "product", "items", "item", "cart", "checkout",
    "payments", "payment", "invoices", "invoice",
    "messages", "message", "notifications", "notification",
    "search", "results", "feeds", "feed", "timeline",
    "comments", "comment", "reviews", "review", "ratings", "rating",
    "likes", "follows", "followers", "following", "shares",
    "files", "file", "uploads", "upload", "downloads", "download",
    "media", "images", "image", "videos", "video", "documents", "document",
    "attachments", "attachment", "assets", "asset",
    "reports", "report", "analytics", "metrics", "stats",
    "settings", "config", "preferences", "profile",
    "teams", "team", "organizations", "organization", "workspaces", "workspace",
    "projects", "project", "tasks", "task", "issues", "issue",
    "roles", "role", "permissions", "permission",
    "webhooks", "webhook", "events", "event", "callbacks", "callback",
    "health", "status", "ping", "ready", "liveness",
    "ws", "wss", "socket", "sockets", "live", "realtime", "stream", "streams",
    "sse", "poll", "polling", "longpoll",
    "login", "logout", "signup", "register", "verify", "confirm",
    "password", "reset", "forgot", "auth", "oauth", "token", "refresh",
    "session", "sessions", "keys", "key", "secrets", "secret",
    "emails", "email", "sms", "push",
    "categories", "category", "tags", "tag", "labels", "label",
    "collections", "collection", "lists", "list",
    "transactions", "transaction", "transfers", "transfer",
    "addresses", "address", "locations", "location",
    "subscriptions", "subscription", "plans", "plan",
    "departments", "department", "branches", "branch",
    "logs", "log", "audit", "history",
    "integrations", "integration", "connections", "connection",
    "export", "imports", "import",
    "data", "api", "v1", "v2", "v3",
    "graphql", "rest", "rpc", "grpc", "trpc",
    "internal", "external", "public", "private",
    "admin", "management", "dashboard",
    "me", "self", "current",
}

# Words that commonly appear in non-URL strings and are NOT REST resources
_NON_RESOURCE_WORDS: Set[str] = {
    # Color words
    "red", "blue", "green", "yellow", "orange", "purple", "pink",
    "white", "black", "gray", "grey", "brown", "cyan", "magenta",
    # Size words
    "small", "medium", "large", "tiny", "huge", "mini", "micro",
    "xs", "sm", "md", "lg", "xl",
    # Direction words
    "top", "bottom", "left", "right", "center", "middle",
    # Boolean-like words
    "true", "false", "yes", "no", "on", "off", "enabled", "disabled",
    # Generic words that appear in configs but not REST resources
    "new", "old", "next", "prev", "previous", "back", "forward",
    "first", "last", "more", "less",
    "all", "none", "any", "every", "each",
    "main", "secondary", "primary", "default",
    "info", "warning", "danger", "success", "error",
    # UI element words
    "button", "input", "select", "textarea", "checkbox", "radio",
    "form", "label", "title", "header", "footer", "sidebar",
    "menu", "item", "link", "icon", "badge", "chip",
    "dialog", "modal", "drawer", "panel", "card", "table",
    "row", "column", "cell", "tab", "page", "section",
    "container", "wrapper", "layout", "grid", "flex",
    "block", "inline", "hidden", "visible",
    # Programming words
    "function", "class", "object", "array", "string", "number",
    "boolean", "null", "undefined", "void", "this", "self", "super",
    "return", "export", "import", "const", "let", "var",
    "async", "await", "promise", "callback", "handler",
    "index", "value", "key", "name", "type", "id",
}


def _analyze_path_segments(url: str) -> Tuple[int, List[str], List[str]]:
    """
    Semantic analysis of individual path segments.

    Returns (score_delta, positive_signals, negative_signals).
    """
    score = 0
    pos: List[str] = []
    neg: List[str] = []

    # Strip query string and fragment
    path = url.split("?")[0].split("#")[0]

    # Get clean segments
    segments = [s.lower() for s in path.strip("/").split("/") if s]

    if not segments:
        return 0, pos, neg

    resource_matches = 0
    non_resource_matches = 0
    param_segments = 0

    for seg in segments:
        # Remove common parameter wrappers for analysis
        clean_seg = seg.strip("{}[]:")
        clean_seg = re.sub(r'^\$\{?|\}?$', '', clean_seg)

        # Dynamic/parameter segment
        if (seg.startswith(":") or
                (seg.startswith("{") and seg.endswith("}")) or
                (seg.startswith("[") and seg.endswith("]")) or
                "${" in seg):
            param_segments += 1
            continue

        # Pure numeric segment (like /users/123) - weak positive
        if re.match(r'^\d+$', clean_seg):
            score += 3
            pos.append(f"numeric_segment(+3):{clean_seg}")
            continue

        if clean_seg in _REAL_RESOURCE_WORDS:
            resource_matches += 1
        elif clean_seg in _NON_RESOURCE_WORDS:
            non_resource_matches += 1
        elif clean_seg in _CHART_TOKENS or clean_seg in _ALL_LIB_TOKENS:
            non_resource_matches += 2  # stronger penalty for known bad tokens

    if resource_matches > 0:
        bonus = resource_matches * 15
        score += bonus
        pos.append(f"resource_words(+{bonus}):{resource_matches}_matches")

    if param_segments > 0:
        bonus = param_segments * 8
        score += bonus
        pos.append(f"param_segments(+{bonus}):{param_segments}")

    if non_resource_matches > 0:
        penalty = non_resource_matches * 10
        score -= penalty
        neg.append(f"non_resource_words(-{penalty}):{non_resource_matches}_matches")

    # Check if ALL segments are non-resource - strong penalty
    total_meaningful = resource_matches + non_resource_matches
    if total_meaningful > 0 and resource_matches == 0 and non_resource_matches > 0:
        score -= 20
        neg.append("all_non_resource_segments(-20)")

    return score, pos, neg


# ---------------------------------------------------------------------------
# RouteCandidate
# ---------------------------------------------------------------------------

@dataclass
class RouteCandidate:
    """A scored endpoint candidate. Wraps an Endpoint with scoring metadata."""
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
    """
    score    = 0
    positive: List[str] = []
    negative: List[str] = []
    ctx      = surrounding_context

    # ---- Immediate hard rejects (score -1000 -> always DROP) ----------------

    # Spaces in a URL path -> not a URL
    if RE_HAS_SPACES.search(url):
        return -1000, [], ["has_spaces"]

    # Newlines in the string
    if RE_MULTILINE.search(url):
        return -1000, [], ["multiline"]

    # Data URI
    if RE_DATA_URI.match(url):
        return -1000, [], ["data_uri"]

    # Blob URL
    if RE_BLOB_URL.match(url):
        return -1000, [], ["blob_url"]

    # JavaScript pseudo-protocol
    if RE_JS_PROTO.match(url):
        return -1000, [], ["js_proto"]

    # Non-HTTP protocol (mailto, tel, etc.)
    if RE_NON_HTTP_PROTO.match(url):
        return -1000, [], ["non_http_proto"]

    # CSS color / function value
    if RE_CSS_VALUE.match(url):
        return -1000, [], ["css_value"]

    # CSS selector
    if RE_CSS_SELECTOR.match(url):
        return -1000, [], ["css_selector"]

    # Webpack internal
    if RE_WEBPACK_INTERNAL.search(url):
        return -1000, [], ["webpack_internal"]

    # Pure hex hash / UUID
    if RE_PURE_HASH.match(url.strip("/")):
        return -1000, [], ["pure_hash"]

    # Base64 blob
    if RE_BASE64_BLOB.match(url.strip("/")):
        return -1000, [], ["base64_blob"]

    # Version string
    if RE_VERSION_STRING.match(url.strip("/")):
        return -1000, [], ["version_string"]

    # Semver range
    if RE_SEMVER_RANGE.match(url.strip("/")):
        return -1000, [], ["semver_range"]

    # Timestamp / date
    if RE_TIMESTAMP.match(url.strip("/")):
        return -1000, [], ["timestamp"]

    # MIME type - but don't reject paths that match API prefixes
    if (RE_MIME_TYPE.match(url.strip("/"))
            and "/" in url and url.count("/") == 1
            and not RE_API_PREFIX.match(url)):
        return -1000, [], ["mime_type"]

    # Bare file extension
    if RE_BARE_EXT.match(url):
        return -1000, [], ["bare_ext"]

    # Relative file import path (./foo, ../bar)
    if RE_FILE_PATH.match(url):
        return -1000, [], ["relative_file_path"]

    # Node module path (e.g. "@scope/package/dist/...")
    if RE_MODULE_PATH.match(url):
        return -1000, [], ["node_module_path"]

    # Tailwind fraction class (w-1/2, h-2/3)
    if RE_TAILWIND_FRACTION.match(url):
        return -1000, [], ["tailwind_fraction"]

    # Tailwind utility class pattern
    if RE_TAILWIND_CLASS.match(url):
        return -1000, [], ["tailwind_class"]

    # i18n key (dot-separated, no slashes at all)
    if RE_I18N_KEY.match(url) and "/" not in url:
        return -1000, [], ["i18n_key"]

    # SQL fragment
    if RE_SQL_FRAGMENT.search(url):
        return -1000, [], ["sql_fragment"]

    # Regex pattern string
    if RE_REGEX_PATTERN.search(url) and not url.startswith("/api"):
        return -1000, [], ["regex_pattern"]

    # Very complex nested patterns (path-to-regexp artifacts)
    if RE_COMPLEX_PATTERN.search(url) and len(url) > 50:
        return -1000, [], ["complex_pattern"]

    # Domain-based hard rejects
    try:
        parsed = urlparse(url if "://" in url else "x://" + url)
        host   = (parsed.hostname or "").lower().lstrip("www.")
        if host:
            if host in _SKIP_DOMAINS or any(host.endswith("." + d) for d in _SKIP_DOMAINS):
                return -1000, [], ["skip_domain"]
    except Exception:
        pass

    # Asset extension hard reject
    path_lower = (urlparse(url).path if "://" in url else url).lower().split("?")[0]
    for ext in _ASSET_EXTS:
        if path_lower.endswith(ext):
            return -1000, [], [f"asset_ext:{ext}"]

    # Static asset path prefix hard reject
    for prefix in _STATIC_PATH_PREFIXES:
        if prefix in path_lower:
            return -1000, [], [f"static_prefix:{prefix}"]

    # Environment variable placeholder in URL - not a real URL
    if RE_ENV_VAR.search(url):
        return -1000, [], ["env_var_placeholder"]

    # Strip query for further analysis
    url_base    = url.split("?")[0].split("#")[0]
    url_lower   = url_base.lower()
    stripped    = url_lower.strip("/")

    # Chart token hard reject (bare token or with common wrappers)
    if stripped in _CHART_TOKENS and "/" not in stripped:
        return -1000, [], ["chart_token_bare"]

    # ---- Structural signals ------------------------------------------------

    if RE_STARTS_SLASH.match(url):
        score += 25
        positive.append("starts_slash(+25)")
    elif RE_FULL_URL.match(url):
        score += 30
        positive.append("full_url(+30)")
        # WebSocket URLs are always real endpoints
        if url_lower.startswith(("ws://", "wss://")):
            score += 20
            positive.append("websocket_url(+20)")
    elif RE_RELATIVE_PATH.match(url):
        # Relative path with internal slash - "api/users", "v1/tokens"
        score += 10
        positive.append("relative_path(+10)")
    else:
        # No leading slash, no protocol, no internal slash
        score -= 20
        negative.append("no_path_structure(-20)")

    # Internal path separator (multi-segment path)
    if RE_HAS_SEPARATOR.search(url):
        score += 20
        positive.append("has_separator(+20)")

    # Known API prefix
    if RE_API_PREFIX.match(url):
        score += 40
        positive.append("api_prefix(+40)")

    # Path parameters (strong API signal)
    if RE_PATH_PARAM.search(url):
        score += 15
        positive.append("path_param(+15)")

    # Dynamic segments like /users/{id} or /users/:id
    if RE_DYNAMIC_SEGMENT.search(url):
        score += 10
        positive.append("dynamic_segment(+10)")

    # Has query string parameters
    if RE_HAS_QUERY.search(url):
        score += 8
        positive.append("has_query_params(+8)")

    # ---- Context signals ---------------------------------------------------

    # HTTP method in surrounding context (strongest context signal)
    if RE_HTTP_METHOD.search(ctx):
        score += 20
        positive.append("http_method_ctx(+20)")

    # HTTP client library in context
    if RE_HTTP_CLIENT.search(ctx):
        score += 25
        positive.append("http_client_ctx(+25)")

    # URL variable assignment context
    if RE_URL_CONTEXT.search(ctx):
        score += 15
        positive.append("url_var_ctx(+15)")

    # Template literal URL construction in context
    if RE_TEMPLATE_URL.search(ctx):
        score += 10
        positive.append("template_literal_ctx(+10)")

    # Server-side route registration pattern in context
    if RE_SERVER_ROUTE.search(ctx):
        score += 20
        positive.append("server_route_ctx(+20)")

    # ---- Negative structural signals ---------------------------------------

    # Bare single word (no slashes at all)
    if RE_BARE_WORD.match(url) and "/" not in url:
        score -= 40
        negative.append("bare_word(-40)")

    # camelCase without slashes (config option, not a path)
    if RE_CAMEL_NO_SLASH.match(url) and "/" not in url:
        score -= 35
        negative.append("camel_no_slash(-35)")

    # SCREAMING_SNAKE_CASE (constant, not a path)
    if RE_CAPS_CONST.match(url) and "/" not in url:
        score -= 30
        negative.append("caps_const(-30)")

    # PascalCase (component/class name, not a path)
    if RE_PASCAL_CASE.match(url) and "/" not in url:
        score -= 30
        negative.append("pascal_case(-30)")

    # Known chart token (with surrounding context check)
    if stripped in _CHART_TOKENS:
        score -= 50
        negative.append("chart_token(-50)")
    elif stripped in _ALL_LIB_TOKENS:
        score -= 40
        negative.append("lib_token(-40)")

    # ---- Negative context signals -----------------------------------------

    # Inside a chart/viz block
    if RE_CHART_CONTEXT.search(ctx):
        score -= 30
        negative.append("chart_context(-30)")

    # Inside a CSS-in-JS block
    if RE_CSS_IN_JS.search(ctx):
        score -= 25
        negative.append("css_in_js_context(-25)")

    # Inside a config/styling block
    if RE_CONFIG_KEY_CTX.search(ctx):
        score -= 15
        negative.append("config_key_ctx(-15)")

    # Inside a library/framework block (lodash, moment, i18n, etc.)
    if RE_LIB_CONTEXT.search(ctx):
        score -= 20
        negative.append("lib_context(-20)")

    # ---- Path quality signals ---------------------------------------------

    # Very short path with no meaningful segment (e.g. "/a" or "/ab")
    segments = [s for s in url_lower.split("/") if s]
    if len(segments) == 1 and len(segments[0]) <= 2 and not segments[0].isdigit():
        score -= 25
        negative.append("too_short_path(-25)")

    # Too many segments (> 8) suggests minified code artifact or config key
    if len(segments) > 8:
        score -= 20
        negative.append("too_many_segments(-20)")

    # ---- Semantic segment analysis ----------------------------------------
    seg_score, seg_pos, seg_neg = _analyze_path_segments(url_base)
    score    += seg_score
    positive += seg_pos
    negative += seg_neg

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
    """
    try:
        score, pos, neg = score_endpoint(endpoint.url, surrounding_context)
    except Exception as exc:
        logger.debug("Scoring failed for %s: %s", endpoint.url, exc)
        score, pos, neg = 0, [], ["scoring_error"]

    # ---- Bonus from extractor classification ------------------------------
    # route_extractor and endpoint_intel already applied precise patterns.
    # Trust their category labels.

    cat = getattr(endpoint, "category", "") or ""
    if cat == "ROUTE":
        # Came from route_extractor - framework-specific patterns are precise
        score += 25
        pos = pos + ["extractor_route(+25)"]
    elif cat in ("API", "AUTH", "ADMIN", "GRAPHQL", "WEBSOCKET"):
        score += 20
        pos = pos + [f"extractor_{cat.lower()}(+20)"]

    # Existing confidence (0.72-0.9 from extractors) adds signal
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

    return RouteCandidate(
        endpoint        = endpoint,
        raw_score       = score,
        signals_hit     = pos,
        signals_missed  = neg,
        confidence_band = band,
    )


def classify_endpoints(
    endpoints: List[Endpoint],
    context_map: Optional[Dict[str, str]] = None,
) -> List[RouteCandidate]:
    """
    Classify a list of Endpoint objects.

    context_map: optional {url -> surrounding_context_string}

    Returns all candidates - callers filter by is_dropped() / is_confirmed().
    """
    results  = []
    ctx_map  = context_map or {}
    for ep in endpoints:
        ctx       = ctx_map.get(ep.url, "")
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
    max_verify:  int   = 50,
    timeout_s:   float = 5.0,
) -> List[RouteCandidate]:
    """
    Run lightweight HTTP HEAD probes against confirmed + low-confidence candidates.
    Only probes path-only endpoints (not full URLs from external domains).
    Mutates each candidate's verified_status / verified_code in place.
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

        if url.startswith("/"):
            probe_url = base_origin + url
        elif url.startswith(("http://", "https://")):
            probe_url_parsed = urlparse(url)
            probe_host = (probe_url_parsed.hostname or "").lower()
            base_host  = (parsed_base.hostname or "").lower()
            if probe_host != base_host:
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
                cand.raw_score += 20
                if cand.confidence_band == "LOW":
                    cand.confidence_band = "HIGH"
                logger.debug("VERIFIED %s -> HTTP %d (score now %d)",
                             probe_url, status, cand.raw_score)
            elif status in (401, 403):
                # Protected endpoint -> still real
                cand.verified_status = ValidationStatus.CONFIRMED
                cand.endpoint.confidence = min(1.0, cand.endpoint.confidence + 0.05)
                cand.raw_score += 15
                if cand.confidence_band == "LOW":
                    cand.confidence_band = "HIGH"
                logger.debug("PROTECTED %s -> HTTP %d (score now %d)",
                             probe_url, status, cand.raw_score)
            elif status == 404:
                cand.verified_status = ValidationStatus.UNREACHABLE
                cand.raw_score -= 5
                logger.debug("NOT FOUND %s -> HTTP 404", probe_url)
            elif status >= 500:
                # Server saw it and errored - endpoint is real
                cand.verified_status = ValidationStatus.CONFIRMED
                cand.raw_score += 10
                logger.debug("SERVER ERROR %s -> HTTP %d (counts as real)",
                             probe_url, status)
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
    """Human-readable scoring breakdown for -vv/--debug mode."""
    lines = []
    for c in sorted(candidates, key=lambda x: -x.raw_score):
        band_icon = {"HIGH": "[+]", "LOW": "[~]", "DROP": "[-]"}[c.confidence_band]
        lines.append(f"{band_icon} score={c.raw_score:+4d}  {c.url[:80]}")
        if c.signals_hit:
            lines.append(f"      pos: {', '.join(c.signals_hit)}")
        if c.signals_missed:
            lines.append(f"      neg: {', '.join(c.signals_missed)}")
        if c.verified_code:
            lines.append(f"      http: {c.verified_code} ({c.verified_status})")
    return "\n".join(lines)
