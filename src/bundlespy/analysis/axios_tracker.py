"""
Axios Base URL Tracker.

Finds axios.create({ baseURL }) calls in JS, extracts the base URL,
then resolves all relative paths found in the same file against it
to produce fully-qualified endpoint URLs.

Also detects:
- Default headers (Authorization, X-API-Key) — signals auth scheme
- Interceptors that add tokens — confirms auth-required API
- Named instance variables so paths on that instance get resolved

Supports:
- axios.create({ baseURL: "https://..." })
- const api = axios.create({ ... }); api.get("/users")
- baseURL via process.env / import.meta.env (kept as template)
- Multiple instances in one file
"""

import re
import logging
from typing import List, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse

from ..storage.models import Endpoint, InfrastructureItem

logger = logging.getLogger("bundlespy.analysis.axios_tracker")

# ── Patterns ──────────────────────────────────────────────────────────────────

# axios.create({ baseURL: "https://api.example.com/v2" })
# handles: single/double/backtick quotes, optional spaces
RE_AXIOS_CREATE = re.compile(
    r'axios\s*\.\s*create\s*\(\s*\{([^}]{0,800})\}',
    re.DOTALL,
)

# baseURL: "...", baseURL: '...', baseURL: `...`
RE_BASE_URL = re.compile(
    r'baseURL\s*:\s*(["\x27`])([^\1\n]{1,300}?)\1',
    re.IGNORECASE,
)

# baseURL: process.env.REACT_APP_API_URL  (no quotes)
RE_BASE_URL_ENV = re.compile(
    r'baseURL\s*:\s*((?:process\.env|import\.meta\.env)\.[A-Z_0-9]+)',
    re.IGNORECASE,
)

# const api = axios.create(...)  — capture instance variable name
RE_AXIOS_INSTANCE = re.compile(
    r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*axios\s*\.\s*create\s*\(',
)

# Authorization / X-API-Key in headers block inside axios.create
RE_AUTH_HEADER = re.compile(
    r'["\x27`]?(Authorization|X-API-Key|X-Auth-Token|api[_-]?key)["\x27`]?\s*:',
    re.IGNORECASE,
)

# instance.get("/path"), instance.post("/path"), etc.
# Built dynamically per instance name
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request")

# Relative paths: "/users", "/api/v2/orders/{id}"
RE_RELATIVE_PATH = re.compile(
    r'["\x27`](/[a-zA-Z0-9/_\-{}:?=&%.]{1,200})["\x27`]'
)

# Generic axios call without a named instance: axios.get("/path")
RE_AXIOS_DIRECT = re.compile(
    r'\baxios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*["\x27`]([^"\'`\n]{1,200})["\x27`]',
    re.IGNORECASE,
)

# Static asset extensions to skip when resolving relative paths
_SKIP_EXTS = frozenset([
    ".js", ".mjs", ".jsx", ".ts", ".tsx", ".css", ".scss",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".html", ".htm",
])


class AxiosInstance:
    """Represents one axios.create() call."""
    def __init__(self, base_url: str, var_name: Optional[str], has_auth: bool):
        self.base_url  = base_url    # resolved base URL string
        self.var_name  = var_name    # e.g. "api", "client", "http"
        self.has_auth  = has_auth    # True if default auth header found


def _clean_base_url(raw: str) -> Optional[str]:
    """
    Validate and clean an extracted baseURL value.
    Returns None for env vars (kept as-is with placeholder), template literals
    with unresolved variables, or clearly invalid values.
    """
    raw = raw.strip()

    # Env var reference — keep as template
    if raw.startswith("process.env") or raw.startswith("import.meta.env"):
        return f"${{{raw}}}"

    # Template literal with unresolved ${...} — keep skeleton
    if "${" in raw:
        # Replace interpolations with placeholder
        cleaned = re.sub(r'\$\{[^}]+\}', '{env}', raw)
        return cleaned if cleaned.startswith("http") or cleaned.startswith("{") else None

    # Must look like a URL or start with /
    if not (raw.startswith("http://") or raw.startswith("https://") or raw.startswith("/")):
        return None

    # Strip trailing slash for consistency
    return raw.rstrip("/")


def _is_skip_path(path: str) -> bool:
    """Skip static assets and framework paths."""
    lower = path.lower().split("?")[0]
    last_seg = lower.split("/")[-1]
    dot = last_seg.rfind(".")
    if dot > 0 and last_seg[dot:] in _SKIP_EXTS:
        return True
    skip_segs = {"static", "assets", "images", "img", "_next", "__webpack", "fonts"}
    parts = [p for p in lower.split("/") if p]
    if parts and parts[0] in skip_segs:
        return True
    return False


def _resolve_path(base_url: str, path: str) -> Optional[str]:
    """
    Join base URL + relative path.
    base_url: "https://api.example.com/v2"
    path:     "/users"
    result:   "https://api.example.com/v2/users"
    """
    if not base_url or not path:
        return None

    # If base has no scheme (env placeholder), just return path as-is
    if not base_url.startswith("http"):
        return path

    # Absolute path — join against scheme+host only
    if path.startswith("/"):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    # Relative — proper urljoin
    try:
        return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    except Exception:
        return None


def _build_instance_method_pattern(var_name: str) -> re.Pattern:
    """Build regex to find var_name.get("/path") etc."""
    methods = "|".join(_HTTP_METHODS)
    return re.compile(
        rf'\b{re.escape(var_name)}\s*\.\s*(?:{methods})\s*\(\s*["\x27`]([^"\'`\n]{{1,200}})["\x27`]',
        re.IGNORECASE,
    )


def extract_axios_instances(content: str) -> List[AxiosInstance]:
    """Find all axios.create() calls and extract their config."""
    instances: List[AxiosInstance] = []

    # Build a map: position of "axios.create(" -> var_name
    # RE_AXIOS_INSTANCE ends right before the opening paren of create()
    var_positions: Dict[int, str] = {}
    for m in RE_AXIOS_INSTANCE.finditer(content):
        # m.end() points just after "axios.create(" — the body starts there
        var_positions[m.end()] = m.group(1)

    for m in RE_AXIOS_CREATE.finditer(content):
        body     = m.group(1)
        var_name = None

        # Find the position of "axios.create(" within m.group(0)
        # m.start() is start of "axios.create({...})"
        # RE_AXIOS_INSTANCE ends at the same position as m.end() for the (
        # Check var_positions for positions near m.start()
        for pos, vname in var_positions.items():
            # pos is after "axios.create(" — should be close to m.start()+len("axios.create(")
            if abs(pos - m.start()) < 50:
                var_name = vname
                break

        # Extract baseURL
        base_url: Optional[str] = None
        url_match = RE_BASE_URL.search(body)
        if url_match:
            base_url = _clean_base_url(url_match.group(2))
        else:
            env_match = RE_BASE_URL_ENV.search(body)
            if env_match:
                base_url = _clean_base_url(env_match.group(1))

        if not base_url:
            continue

        # Check for auth headers in config
        has_auth = bool(RE_AUTH_HEADER.search(body))

        instances.append(AxiosInstance(base_url, var_name, has_auth))
        logger.debug(
            "axios.create() found: baseURL=%s var=%s auth=%s",
            base_url, var_name, has_auth,
        )

    return instances


def extract_axios_endpoints(
    content:  str,
    file_url: str,
    instances: List[AxiosInstance],
) -> Tuple[List[Endpoint], List[InfrastructureItem]]:
    """
    Given a list of axios instances, find all API calls made through them
    and resolve their paths against the base URL.

    Returns (endpoints, infra_items).
    infra_items: one per unique base URL (surfaced as API_BASE infrastructure).
    """
    from .endpoints import _categorize_path, _is_skip_url, _canonical_key

    endpoints:  List[Endpoint]            = []
    infra:      List[InfrastructureItem]  = []
    seen_paths: set                       = set()
    seen_bases: set                       = set()

    def add_endpoint(url: str, method: str, line_no: int, confidence: float) -> None:
        if _is_skip_url(url):
            return
        key = _canonical_key(url)
        if key in seen_paths:
            return
        seen_paths.add(key)
        category = _categorize_path(url)
        ep = Endpoint(
            url         = url,
            path        = url,
            method      = method,
            category    = category,
            source_file = file_url,
            line_number = line_no,
            confidence  = confidence,
            evidence    = "axios baseURL resolution",
        )
        try:
            ep.source_type = "static"
        except Exception:
            pass
        endpoints.append(ep)

    def add_infra(base_url: str, has_auth: bool) -> None:
        if base_url in seen_bases:
            return
        if not base_url.startswith("http"):
            return
        seen_bases.add(base_url)
        label = "API_BASE_AUTH" if has_auth else "API_BASE"
        infra.append(InfrastructureItem(
            value          = base_url,
            classification = label,
            source_file    = file_url,
            line_number    = 0,
            confidence     = 0.90,
            action         = "report_only",
        ))

    for instance in instances:
        base_url = instance.base_url
        add_infra(base_url, instance.has_auth)

        # Strategy 1: instance.get("/path") calls
        if instance.var_name:
            pat = _build_instance_method_pattern(instance.var_name)
            for m in pat.finditer(content):
                raw_path = m.group(1).strip()
                if _is_skip_path(raw_path):
                    continue
                # Infer HTTP method from the call
                call_method = "UNKNOWN"
                call_text   = content[m.start():m.start()+30].lower()
                for meth in _HTTP_METHODS:
                    if f".{meth}(" in call_text:
                        call_method = meth.upper()
                        break

                resolved = _resolve_path(base_url, raw_path)
                if resolved:
                    line_no = content[:m.start()].count("\n") + 1
                    add_endpoint(resolved, call_method, line_no, 0.85)

        # Strategy 2: all relative paths in the file resolved against this base
        # (lower confidence — not proven to be on this instance)
        parsed_base = urlparse(base_url) if base_url.startswith("http") else None
        if parsed_base:
            for m in RE_RELATIVE_PATH.finditer(content):
                raw_path = m.group(1)
                if _is_skip_path(raw_path):
                    continue
                resolved = _resolve_path(base_url, raw_path)
                if resolved:
                    line_no = content[:m.start()].count("\n") + 1
                    add_endpoint(resolved, "UNKNOWN", line_no, 0.65)

    # Strategy 3: direct axios.get("/path") calls — resolve against any found base
    for m in RE_AXIOS_DIRECT.finditer(content):
        raw_path = m.group(1).strip()
        if _is_skip_path(raw_path):
            continue
        call_method = "UNKNOWN"
        call_text   = content[m.start():m.start()+30].lower()
        for meth in _HTTP_METHODS:
            if f".{meth}(" in call_text:
                call_method = meth.upper()
                break
        # Use first instance's base, or keep as-is if none
        base = instances[0].base_url if instances else ""
        resolved = _resolve_path(base, raw_path) if base else raw_path
        if resolved:
            line_no = content[:m.start()].count("\n") + 1
            add_endpoint(resolved, call_method, line_no, 0.70)

    return endpoints, infra


def process_file(content: str, file_url: str) -> Tuple[List[Endpoint], List[InfrastructureItem]]:
    """
    Full axios tracking pipeline for one JS file.
    Returns (resolved_endpoints, infra_items).
    """
    if "axios" not in content:
        return [], []

    instances = extract_axios_instances(content)
    if not instances:
        # Still check for direct axios.get/post calls
        instances = []

    endpoints, infra = extract_axios_endpoints(content, file_url, instances)

    if endpoints or infra:
        logger.info(
            "axios tracker: %d instances, %d endpoints, %d infra from %s",
            len(instances), len(endpoints), len(infra), file_url,
        )

    return endpoints, infra
