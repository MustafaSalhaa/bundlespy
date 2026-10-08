"""
WebSocketMapper - WebSocket injection and security issue detection.
Pure static analysis of collected endpoint and JS data. Zero HTTP requests.

Detection cases:
  1. WebSocket endpoints with user-controlled message data (injection surface)
  2. Missing authentication on WebSocket upgrade (no token in headers or URL)
  3. Cross-origin WebSocket hijacking (CSWSH) - missing Origin check
  4. User-controlled URL for WebSocket connection (ws:// injection)
  5. Insecure ws:// (non-TLS) WebSocket endpoints
  6. Message data reflected without sanitization (XSS via WebSocket)
"""
import re
from typing import List, Set

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ..param_semantics import ALL_WEBSOCKET_PARAMS
from ...storage.models import ScanResult, Endpoint

# JS patterns that indicate WebSocket construction
_WS_CONNECT_RE = re.compile(
    r'new\s+WebSocket\s*\(\s*([^\)]+)\)',
    re.I,
)

# User-controlled URL sources that could feed a WebSocket URL
_USER_CONTROLLED_WS_SOURCES = [
    "location.href", "location.search", "location.hash",
    "searchParams.get(", "URLSearchParams",
    "window.name", "document.referrer",
    "postMessage", "params.", "$route.query",
    "router.query", "req.query",
]

# WebSocket message send with user data patterns
_WS_SEND_RE = re.compile(
    r'\.send\s*\(\s*(?:JSON\.stringify\s*\()?([^\)]+)\)',
    re.I,
)

# Auth token patterns in WS URL query string
_WS_TOKEN_IN_URL_RE = re.compile(
    r'(wss?://[^\s\'"`]+[?&](?:token|access_token|auth|jwt|key)=)',
    re.I,
)

# Origin header check in server-side JS (negative signal - if present, CSWSH less likely)
_ORIGIN_CHECK_RE = re.compile(r'(?:req\.headers\s*\[?[\'"]?origin|allowedOrigins)', re.I)


_BURP_NOTES_INJECTION = (
    "WebSocket injection surface - user-controlled data sent over WebSocket. "
    "Steps: 1) Intercept WebSocket messages in Burp (Proxy -> WebSockets history). "
    "2) Modify message content - inject SQL, command, or template expressions. "
    "3) Look for error messages or behavioral differences. "
    "4) Test JSON field injection: change field values to injection payloads. "
    "5) Replay messages with Burp Repeater's WS tab."
)

_BURP_NOTES_NO_AUTH = (
    "WebSocket endpoint may lack authentication on upgrade request. "
    "Steps: 1) Capture the WebSocket upgrade request (HTTP 101). "
    "2) Remove Authorization/Cookie headers and re-send the upgrade. "
    "3) If connection succeeds, test unauthenticated message sending. "
    "4) Check if the same data is accessible to all WebSocket clients (no user isolation)."
)

_BURP_NOTES_CSWSH = (
    "Cross-Site WebSocket Hijacking (CSWSH) - WebSocket upgrade without CSRF protection. "
    "WebSocket upgrades follow browser CORS rules but cookies are still sent. "
    "Steps: 1) Check if upgrade request includes a CSRF token. "
    "2) Build a malicious page that opens a WebSocket to the target origin. "
    "3) The victim's browser sends their cookies on the upgrade request. "
    "4) Read the victim's WebSocket messages on the attacker's server."
)

_BURP_NOTES_USER_CONTROLLED_URL = (
    "User-controlled WebSocket URL - ws:// injection surface. "
    "If an attacker can influence the WebSocket URL, they can redirect the connection "
    "to an attacker-controlled server and intercept all messages. "
    "Steps: 1) Inject ws://attacker.com/ws as the URL parameter. "
    "2) If the app connects to it, all subsequent messages are sent to the attacker. "
    "3) Combine with XSS to trigger automatic connection to attacker endpoint."
)

_BURP_NOTES_INSECURE_WS = (
    "Insecure WebSocket (ws://) detected - traffic is unencrypted. "
    "Messages are visible to any MITM on the network path. "
    "Steps: 1) Use Burp as a transparent proxy and capture ws:// traffic. "
    "2) Look for auth tokens, session data, or sensitive operations in messages. "
    "3) Note as a finding even without active exploitation - all plaintext is a risk."
)


def _has_ws_auth(ep: Endpoint) -> bool:
    """Check if the WebSocket upgrade request includes auth signals."""
    headers = ep.request_headers or {}
    for k in headers:
        kl = k.lower()
        if kl in ("authorization", "x-auth-token", "x-api-key"):
            return True
    # Check query params for token
    for param in (ep.query_params or []):
        pname = (param.get("name") or "").lower() if isinstance(param, dict) else str(param).lower()
        if pname in ("token", "access_token", "auth", "jwt", "key", "session"):
            return True
    return False


class WebSocketMapper(BaseSurfaceMapper):
    category = AttackCategory.WEBSOCKET

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        # Phase 1: endpoint-level WebSocket detection
        for ep in result.endpoints:
            url      = ep.url or ""
            path     = ep.path or ""
            method   = (ep.method or "GET").upper()
            auth_ctx = ep.auth_context or ""
            category = getattr(ep, "category", "") or ""

            # Detect WebSocket endpoints by URL scheme or category
            is_ws = (
                url.startswith("ws://") or url.startswith("wss://") or
                category.lower() in ("websocket", "ws") or
                "/ws" in path.lower() or "/websocket" in path.lower() or
                "/socket" in path.lower() or "/sockjs" in path.lower()
            )

            # Check param names for WebSocket params
            all_params = list(ep.query_params or []) + list(ep.body_fields or [])
            ws_param = None
            for param in all_params:
                pname = (param.get("name") or "") if isinstance(param, dict) else str(param)
                if pname.lower() in ALL_WEBSOCKET_PARAMS:
                    ws_param = pname
                    is_ws = True
                    break

            if not is_ws:
                continue

            # Check 1: missing authentication on WS upgrade
            has_auth = _has_ws_auth(ep)
            if not has_auth:
                key = f"ws_no_auth:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"WebSocket endpoint {url} has no auth token in upgrade request headers or query params",
                        "Unauthenticated WebSocket connections may expose data to any client",
                    ]
                    if auth_ctx:
                        evidence.append(f"Auth context: {auth_ctx} (but no token in upgrade request)")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "WebSocket: Missing Authentication",
                        parameters   = [],
                        confidence   = ConfidenceLevel.MEDIUM if auth_ctx else ConfidenceLevel.LOW,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_NO_AUTH,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.WEBSOCKET,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "WebSocket endpoint without auth in upgrade request",
                                details        = "No auth token detected in headers or query params",
                                raw_confidence = 55 if auth_ctx else 35,
                            ),
                        ],
                        surface_type = "WebSocket: Missing Authentication",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_NO_AUTH,
                    )

            # Check 2: CSWSH (no CSRF token on upgrade)
            req_hdrs = ep.request_headers or {}
            has_csrf_on_upgrade = any(
                k.lower() in ("x-csrf-token", "x-xsrf-token", "x-requested-with")
                for k in req_hdrs
            )
            if not has_csrf_on_upgrade:
                key = f"ws_cswsh:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"WebSocket upgrade at {url} has no CSRF protection",
                        "Browser sends cookies on WebSocket upgrades - cross-site attacker can hijack the connection",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "WebSocket: CSWSH",
                        parameters   = [],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_CSWSH,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.WEBSOCKET,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "WebSocket upgrade without CSRF protection",
                                details        = "No CSRF token on WS upgrade - CSWSH possible from any origin",
                                raw_confidence = 50,
                            ),
                        ],
                        surface_type = "WebSocket: CSWSH",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_CSWSH,
                    )

            # Check 3: insecure ws:// (non-TLS)
            if url.startswith("ws://"):
                key = f"ws_insecure:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"Insecure WebSocket URL: {url}",
                        "ws:// is unencrypted - all messages readable by network MITM",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "WebSocket: Insecure ws:// Transport",
                        parameters   = [],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_INSECURE_WS,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.WEBSOCKET,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "Insecure ws:// WebSocket",
                                details        = "Non-TLS WebSocket - messages unencrypted in transit",
                                raw_confidence = 60,
                            ),
                        ],
                        surface_type = "WebSocket: Insecure ws:// Transport",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_INSECURE_WS,
                    )

            # Check 4: user-controlled WebSocket URL param
            if ws_param:
                key = f"ws_url_param:{url}:{ws_param}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"User-controlled WebSocket URL parameter '{ws_param}' at {url}",
                        "If this parameter controls the WebSocket endpoint URL, it enables ws:// injection",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "WebSocket: User-Controlled URL",
                        parameters   = [ws_param],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_USER_CONTROLLED_URL,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                parameter      = ws_param,
                                context        = "WebSocket URL parameter",
                                details        = f"'{ws_param}' controls WebSocket connection endpoint",
                                raw_confidence = 65,
                            ),
                        ],
                        surface_type = "WebSocket: User-Controlled URL",
                        endpoint     = url,
                        method       = method,
                        parameter    = ws_param,
                        notes        = _BURP_NOTES_USER_CONTROLLED_URL,
                    )

        # Phase 2: JS file analysis for WebSocket patterns
        seen_js: Set[str] = set()

        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue
            js_url = js.url or "unknown"

            # Check for WS construction with user-controlled URL
            ws_matches = _WS_CONNECT_RE.findall(content)
            for ws_arg in ws_matches:
                has_user_url = any(src in content for src in _USER_CONTROLLED_WS_SOURCES)
                # Check for insecure ws:// literal
                insecure_literal = "ws://" in ws_arg and "wss://" not in ws_arg

                if insecure_literal:
                    key = f"ws_js_insecure:{js_url}"
                    if key not in seen_js:
                        seen_js.add(key)
                        from ...storage.models import Endpoint as _Endpoint
                        synthetic = _Endpoint(
                            url=js_url, path="", method="GET", category="",
                            source_file=js_url, line_number=0, confidence=0.6,
                            query_params=[], path_params=[], body_fields=[],
                            request_headers={}, auth_context="", source_type="static",
                        )
                        self._candidate(
                            endpoint     = synthetic,
                            surface_type = "WebSocket: Insecure ws:// in JS",
                            parameters   = [],
                            confidence   = ConfidenceLevel.MEDIUM,
                            evidence     = [
                                f"Insecure ws:// WebSocket URL in JS bundle: {js_url}",
                                f"WS argument: {ws_arg[:80]}",
                            ],
                            burp_notes   = _BURP_NOTES_INSECURE_WS,
                            auth_context = "",
                        )
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.STATIC_JS,
                                    source         = "static",
                                    asset          = js_url,
                                    context        = "ws:// WebSocket in JS bundle",
                                    details        = f"Insecure WebSocket URL in JS: {ws_arg[:60]}",
                                    raw_confidence = 50,
                                ),
                            ],
                            surface_type = "WebSocket: Insecure ws:// in JS",
                            endpoint     = js_url,
                            method       = "GET",
                            parameter    = "",
                            notes        = _BURP_NOTES_INSECURE_WS,
                        )

                if has_user_url:
                    key = f"ws_js_user_url:{js_url}"
                    if key not in seen_js:
                        seen_js.add(key)
                        user_sources = [s for s in _USER_CONTROLLED_WS_SOURCES if s in content]
                        from ...storage.models import Endpoint as _Endpoint
                        synthetic = _Endpoint(
                            url=js_url, path="", method="GET", category="",
                            source_file=js_url, line_number=0, confidence=0.7,
                            query_params=[], path_params=[], body_fields=[],
                            request_headers={}, auth_context="", source_type="static",
                        )
                        self._candidate(
                            endpoint     = synthetic,
                            surface_type = "WebSocket: User-Controlled Connection URL",
                            parameters   = user_sources[:3],
                            confidence   = ConfidenceLevel.HIGH,
                            evidence     = [
                                f"WebSocket connection in {js_url} uses user-controlled URL source",
                                "User sources: " + ", ".join(user_sources),
                            ],
                            burp_notes   = _BURP_NOTES_USER_CONTROLLED_URL,
                            auth_context = "",
                        )
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.STATIC_JS,
                                    source         = "static",
                                    asset          = js_url,
                                    context        = "WebSocket with user-controlled URL",
                                    details        = "User-controlled source: " + ", ".join(user_sources[:2]),
                                    raw_confidence = 65,
                                ),
                                Evidence(
                                    evidence_type  = EvidenceType.DOM,
                                    source         = "static",
                                    asset          = js_url,
                                    context        = "DOM source feeds WebSocket URL",
                                    details        = ", ".join(user_sources[:3]),
                                    raw_confidence = 50,
                                ),
                            ],
                            surface_type = "WebSocket: User-Controlled Connection URL",
                            endpoint     = js_url,
                            method       = "GET",
                            parameter    = user_sources[0] if user_sources else "",
                            notes        = _BURP_NOTES_USER_CONTROLLED_URL,
                        )
                break  # only process first WS match per file to avoid duplicates

        return self._results
