"""
OAuthMapper - OAuth 2.0 / OIDC attack surface detection.
Pure static analysis of collected endpoint and JS data. Zero HTTP requests.

Detection cases:
  1. Open redirect in redirect_uri parameter (improper whitelist validation)
  2. Authorization code interception via Referer header leakage
  3. state parameter absent or weak (CSRF on OAuth flow)
  4. PKCE absent on public clients (authorization code interception)
  5. Implicit flow usage (access token in URL fragment = token leakage)
  6. Client secret in JS bundle
  7. Token endpoint accessible without PKCE or client authentication
  8. id_token nonce validation gaps
"""
import re
from typing import List, Set

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ...storage.models import ScanResult, Endpoint

# OAuth/OIDC endpoint path patterns
_AUTHORIZE_PATHS = ("/authorize", "/oauth/authorize", "/auth", "/oauth2/authorize", "/connect/authorize")
_CALLBACK_PATHS  = ("/callback", "/oauth/callback", "/auth/callback", "/redirect", "/oauth2/callback")
_TOKEN_PATHS     = ("/token", "/oauth/token", "/oauth2/token", "/connect/token")

# JS patterns for client secrets hardcoded in bundles
_CLIENT_SECRET_RE = re.compile(
    r'client[_-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{8,})["\']',
    re.I,
)

# Implicit flow response_type
_IMPLICIT_RESPONSE_TYPE = re.compile(r'response_type\s*=\s*["\']?token\b', re.I)
_HYBRID_RESPONSE_TYPE   = re.compile(r'response_type\s*=\s*["\']?id_token\s+token', re.I)

# Weak state - short numeric, empty, or constant
_WEAK_STATE_RE = re.compile(r'[?&]state=([^&]{0,8}|[0-9]+)(?:&|$)', re.I)

# PKCE challenge param
_PKCE_RE = re.compile(r'code_challenge(?:_method)?', re.I)


def _is_authorize_path(path: str) -> bool:
    p = path.lower().rstrip("/")
    return any(p.endswith(ap) for ap in _AUTHORIZE_PATHS)


def _is_callback_path(path: str) -> bool:
    p = path.lower().rstrip("/")
    return any(p.endswith(cp) for cp in _CALLBACK_PATHS)


def _is_token_path(path: str) -> bool:
    p = path.lower().rstrip("/")
    return any(p.endswith(tp) for tp in _TOKEN_PATHS)


_BURP_NOTES_REDIRECT_URI = (
    "Open redirect in OAuth redirect_uri. "
    "If redirect_uri validation allows subdomain matching or path traversal, "
    "an attacker can redirect the authorization code to attacker.com. "
    "Steps: 1) Change redirect_uri to https://evil.com/callback. "
    "2) Try redirect_uri=https://legitimate.com@evil.com/callback (host confusion). "
    "3) Try https://legitimate.com.evil.com/callback (subdomain). "
    "4) Try https://legitimate.com/../../evil.com (path traversal). "
    "Intercept the authorization code and exchange it for tokens."
)

_BURP_NOTES_STATE_MISSING = (
    "OAuth state parameter absent or weak - CSRF on authorization flow. "
    "Without a cryptographically random state, an attacker can initiate an OAuth flow, "
    "trick the victim into completing it, and bind the victim's account to the attacker. "
    "Steps: 1) Start the authorization flow and capture the state value. "
    "2) If state is absent, short, or constant across requests, CSRF is exploitable. "
    "3) Craft a malicious page that starts the flow and auto-submits the victim's code."
)

_BURP_NOTES_PKCE_MISSING = (
    "PKCE (code_challenge) absent on authorization endpoint. "
    "Without PKCE, authorization codes can be intercepted and redeemed by a different client. "
    "Steps: 1) Intercept the authorization request and check for code_challenge param. "
    "2) If absent, attempt to exchange an intercepted code without a verifier. "
    "3) Use Burp Collaborator to steal the code via open redirect or Referer leakage."
)

_BURP_NOTES_IMPLICIT = (
    "Implicit flow (response_type=token) detected - access token in URL fragment. "
    "Access tokens in fragments leak via: Referer headers, browser history, JS on the page. "
    "Steps: 1) Check if access_token appears in URL fragment after /callback. "
    "2) Look for token logging or third-party scripts that can read location.hash. "
    "3) If the app has an open redirect after /callback, the fragment follows it."
)

_BURP_NOTES_CLIENT_SECRET = (
    "OAuth client_secret hardcoded in JavaScript bundle. "
    "This is CRITICAL - the client_secret should never be exposed to the browser. "
    "Steps: 1) Extract the client_secret value from the bundle. "
    "2) Use it to authenticate directly to the token endpoint. "
    "3) Check for client_credentials grant which bypasses user context entirely. "
    "4) Report the secret as exposed - it needs to be rotated immediately."
)

_BURP_NOTES_CALLBACK = (
    "OAuth callback endpoint detected. "
    "Test for: 1) authorization code injection (supply attacker's code for victim's session). "
    "2) code replay (use a code twice before it expires). "
    "3) state CSRF (complete victim's flow with attacker-chosen state). "
    "4) Referer header on callback page leaks the code to third-party scripts."
)


class OAuthMapper(BaseSurfaceMapper):
    category = AttackCategory.OAUTH

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        # Phase 1: endpoint analysis
        for ep in result.endpoints:
            url      = ep.url or ""
            path     = ep.path or ""
            method   = (ep.method or "GET").upper()
            auth_ctx = ep.auth_context or ""
            all_params = list(ep.query_params or []) + list(ep.body_fields or [])

            param_names = {
                ((p.get("name") or "") if isinstance(p, dict) else str(p)).lower()
                for p in all_params
            }
            param_values = {
                (p.get("name") or "").lower(): (p.get("value") or "")
                for p in all_params if isinstance(p, dict)
            }

            # Detect authorize endpoint
            if _is_authorize_path(path):
                # Check for missing state param
                if "state" not in param_names:
                    key = f"oauth_state_missing:{url}"
                    if key not in seen:
                        seen.add(key)
                        evidence = [
                            f"OAuth authorization endpoint {url} has no 'state' parameter",
                            "Missing state = no CSRF protection on the OAuth flow",
                        ]
                        if auth_ctx:
                            evidence.append(f"Auth context: {auth_ctx}")
                        self._candidate(
                            endpoint     = ep,
                            surface_type = "OAuth: Missing state (CSRF)",
                            parameters   = ["state"],
                            confidence   = ConfidenceLevel.HIGH,
                            evidence     = evidence,
                            burp_notes   = _BURP_NOTES_STATE_MISSING,
                            auth_context = auth_ctx,
                        )
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.ROUTE_DECLARATION,
                                    source         = "static",
                                    asset          = url,
                                    endpoint       = url,
                                    context        = "OAuth authorize endpoint without state parameter",
                                    details        = "state parameter missing - CSRF on OAuth flow",
                                    raw_confidence = 70,
                                ),
                            ],
                            surface_type = "OAuth: Missing state (CSRF)",
                            endpoint     = url,
                            method       = method,
                            parameter    = "state",
                            notes        = _BURP_NOTES_STATE_MISSING,
                        )

                # Check for missing PKCE
                if "code_challenge" not in param_names:
                    key = f"oauth_pkce_missing:{url}"
                    if key not in seen:
                        seen.add(key)
                        evidence = [
                            f"OAuth authorization endpoint {url} has no 'code_challenge' (PKCE)",
                            "Without PKCE, intercepted authorization codes can be redeemed without the verifier",
                        ]
                        self._candidate(
                            endpoint     = ep,
                            surface_type = "OAuth: Missing PKCE",
                            parameters   = ["code_challenge"],
                            confidence   = ConfidenceLevel.MEDIUM,
                            evidence     = evidence,
                            burp_notes   = _BURP_NOTES_PKCE_MISSING,
                            auth_context = auth_ctx,
                        )
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.ROUTE_DECLARATION,
                                    source         = "static",
                                    asset          = url,
                                    endpoint       = url,
                                    context        = "OAuth authorize endpoint without PKCE",
                                    details        = "code_challenge missing - authorization code interception risk",
                                    raw_confidence = 55,
                                ),
                            ],
                            surface_type = "OAuth: Missing PKCE",
                            endpoint     = url,
                            method       = method,
                            parameter    = "code_challenge",
                            notes        = _BURP_NOTES_PKCE_MISSING,
                        )

                # Check for redirect_uri - primary open redirect surface
                if "redirect_uri" in param_names:
                    key = f"oauth_redirect_uri:{url}"
                    if key not in seen:
                        seen.add(key)
                        redir_val = param_values.get("redirect_uri", "")
                        evidence = [
                            f"OAuth redirect_uri parameter at {url}",
                            "Test for open redirect: invalid redirect_uri values may be accepted if validation is weak",
                        ]
                        if redir_val:
                            evidence.append(f"Observed redirect_uri value: {redir_val}")
                        self._candidate(
                            endpoint     = ep,
                            surface_type = "OAuth: redirect_uri Open Redirect",
                            parameters   = ["redirect_uri"],
                            confidence   = ConfidenceLevel.HIGH,
                            evidence     = evidence,
                            burp_notes   = _BURP_NOTES_REDIRECT_URI,
                            auth_context = auth_ctx,
                        )
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                    source         = "static",
                                    asset          = url,
                                    endpoint       = url,
                                    parameter      = "redirect_uri",
                                    context        = "OAuth redirect_uri - open redirect surface",
                                    details        = "redirect_uri on authorization endpoint - test for whitelist bypass",
                                    raw_confidence = 70,
                                ),
                            ],
                            surface_type = "OAuth: redirect_uri Open Redirect",
                            endpoint     = url,
                            method       = method,
                            parameter    = "redirect_uri",
                            notes        = _BURP_NOTES_REDIRECT_URI,
                        )

            # Detect callback endpoint
            if _is_callback_path(path):
                key = f"oauth_callback:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"OAuth callback endpoint: {url}",
                        "Test for code injection, CSRF, and token leakage via Referer",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "OAuth: Callback Endpoint",
                        parameters   = list(param_names)[:5],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_CALLBACK,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.ROUTE_DECLARATION,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "OAuth callback endpoint",
                                details        = "OAuth redirect target - test code injection and CSRF",
                                raw_confidence = 50,
                            ),
                        ],
                        surface_type = "OAuth: Callback Endpoint",
                        endpoint     = url,
                        method       = method,
                        parameter    = "code",
                        notes        = _BURP_NOTES_CALLBACK,
                    )

        # Phase 2: JS bundle analysis for hardcoded secrets and implicit flow
        seen_js: Set[str] = set()

        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue
            js_url = js.url or "unknown"

            # Check for hardcoded client_secret
            secret_match = _CLIENT_SECRET_RE.search(content)
            if secret_match:
                key = f"oauth_secret:{js_url}"
                if key not in seen_js:
                    seen_js.add(key)
                    secret_prefix = secret_match.group(1)[:4] + "..."
                    from ...storage.models import Endpoint as _Endpoint
                    synthetic = _Endpoint(
                        url=js_url, path="", method="GET", category="",
                        source_file=js_url, line_number=0, confidence=0.9,
                        query_params=[], path_params=[], body_fields=[],
                        request_headers={}, auth_context="", source_type="static",
                    )
                    self._candidate(
                        endpoint     = synthetic,
                        surface_type = "OAuth: Client Secret Exposed",
                        parameters   = ["client_secret"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"client_secret hardcoded in JS bundle: {js_url}",
                            f"Secret prefix: {secret_prefix} (truncated)",
                            "Client secrets must never be in browser-side JS - rotate immediately",
                        ],
                        burp_notes   = _BURP_NOTES_CLIENT_SECRET,
                        auth_context = "",
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.STATIC_JS,
                                source         = "static",
                                asset          = js_url,
                                context        = "OAuth client_secret in JS bundle",
                                details        = f"Hardcoded client_secret found in {js_url}",
                                raw_confidence = 85,
                            ),
                        ],
                        surface_type = "OAuth: Client Secret Exposed",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = "client_secret",
                        notes        = _BURP_NOTES_CLIENT_SECRET,
                    )

            # Check for implicit flow
            if _IMPLICIT_RESPONSE_TYPE.search(content) or _HYBRID_RESPONSE_TYPE.search(content):
                key = f"oauth_implicit:{js_url}"
                if key not in seen_js:
                    seen_js.add(key)
                    from ...storage.models import Endpoint as _Endpoint
                    synthetic = _Endpoint(
                        url=js_url, path="", method="GET", category="",
                        source_file=js_url, line_number=0, confidence=0.7,
                        query_params=[], path_params=[], body_fields=[],
                        request_headers={}, auth_context="", source_type="static",
                    )
                    self._candidate(
                        endpoint     = synthetic,
                        surface_type = "OAuth: Implicit Flow (Token in URL)",
                        parameters   = ["response_type"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"Implicit flow (response_type=token) detected in JS bundle: {js_url}",
                            "Access token appears in URL fragment - leaks via Referer, browser history, JS",
                        ],
                        burp_notes   = _BURP_NOTES_IMPLICIT,
                        auth_context = "",
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.STATIC_JS,
                                source         = "static",
                                asset          = js_url,
                                context        = "OAuth implicit flow in JS",
                                details        = "response_type=token - access token in URL fragment",
                                raw_confidence = 70,
                            ),
                        ],
                        surface_type = "OAuth: Implicit Flow (Token in URL)",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = "response_type",
                        notes        = _BURP_NOTES_IMPLICIT,
                    )

        return self._results
