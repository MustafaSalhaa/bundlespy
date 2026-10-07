"""
Endpoint Validation Module.

Safely probes discovered endpoints with GET/HEAD requests only.
Reports status codes, content-types, response sizes, CORS issues,
cookie flag problems, sensitive response fields, and response body structure.
Never makes state-changing requests. Never follows redirects off-scope.
Respects rate limits and scope enforcement.
"""

import json
import time
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

import requests
import urllib3

from ..storage.models import Endpoint
from ..safety.network import validate_url
from ..utils.stealth import random_ua

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.analysis.endpoint_validator")

MAX_RESPONSE_SIZE = 512 * 1024  # 512 KB cap


# ── Sensitive field names found in JSON responses ─────────────────────────────

_SENSITIVE_RESP_FIELDS: Set[str] = {
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "id_token", "idtoken", "api_key", "apikey", "secret", "password",
    "passwd", "credentials", "credential", "private_key", "privatekey",
    "session", "session_token", "sessiontoken", "auth", "authorization",
    "role", "roles", "isadmin", "is_admin", "admin", "permissions",
    "permission", "privilege", "privileges", "scope", "grants",
    "ssn", "social_security", "dob", "date_of_birth", "credit_card",
    "card_number", "cvv", "pin", "bank_account",
}

# Field names that hint the response contains auth material even without exact match
_SENSITIVE_RESP_PREFIXES = ("token", "secret", "key", "auth", "cred", "pass")


@dataclass
class ValidationResult:
    endpoint:               str
    method:                 str
    status_code:            int
    content_type:           str
    response_size:          int
    redirect_url:           str
    server:                 str
    interesting:            bool
    notes:                  List[str] = field(default_factory=list)
    error:                  Optional[str] = None
    # ── enriched fields ──────────────────────────────────────────────────────
    # JSON field names from the response body (top-level + 1 level nested)
    response_body_fields:   List[str]          = field(default_factory=list)
    # CORS findings: e.g. "CORS wildcard on credentialed endpoint"
    cors_issues:            List[str]          = field(default_factory=list)
    # Cookie flag issues: e.g. "Set-Cookie 'session' missing HttpOnly"
    cookie_issues:          List[str]          = field(default_factory=list)
    # Sensitive field names found in the body: e.g. ["token", "role"]
    sensitive_response_fields: List[str]       = field(default_factory=list)
    # Promoted by validator: CANDIDATE | VALIDATED
    validation_status:      str                = "CANDIDATE"
    # Raw response headers for downstream consumers
    response_headers:       Dict[str, str]     = field(default_factory=dict)


INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405}
SKIP_EXTENSIONS   = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
}

# Endpoint exists regardless of what the server did with the request
_EXISTENCE_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


def _should_skip(url: str) -> bool:
    """Skip static/non-API URLs to cut noise."""
    lower = url.lower()
    return any(lower.endswith(ext) for ext in SKIP_EXTENSIONS)


# ── Header analysis helpers ───────────────────────────────────────────────────

def _analyze_cors(headers: Dict[str, str], url: str, notes: List[str], cors_issues: List[str]) -> None:
    """
    Check for CORS misconfigurations in response headers.
    Flags wildcard origin + credentials and reflected origin patterns.
    """
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if not acao:
        return

    if acao == "*":
        if acac == "true":
            # Browsers block this combination but some fetch polyfills don't
            msg = "CORS wildcard (Access-Control-Allow-Origin: *) combined with Allow-Credentials: true - invalid but may bypass polyfills"
            cors_issues.append(msg)
            notes.append("CORS misconfiguration: wildcard + credentials")
        else:
            notes.append("CORS wildcard - public cross-origin read allowed")
    else:
        # Reflected origin: server echoed back whatever Origin header was sent.
        # We can't test this statically, but we flag non-standard origin values
        # that look dynamic (not a static hostname).
        if acao not in ("null",) and not acao.startswith("http"):
            pass  # not actionable without a live Origin test
        elif acao == "null":
            # null origin is exploitable from sandboxed iframes / file:// pages
            msg = "CORS allows null origin - exploitable from sandboxed iframe or file:// context"
            cors_issues.append(msg)
            notes.append("CORS: null origin allowed")

    acam = headers.get("access-control-allow-methods", "")
    if acam and any(m in acam.upper() for m in ("DELETE", "PUT", "PATCH")):
        notes.append(f"CORS exposes mutating methods: {acam}")


def _analyze_cookies(headers: Dict[str, str], url: str, notes: List[str], cookie_issues: List[str]) -> None:
    """
    Check Set-Cookie headers for missing security flags.
    Flags: missing HttpOnly, missing Secure on HTTPS endpoints, missing SameSite.
    """
    is_https = url.lower().startswith("https://")

    # requests lowercases header names; multiple Set-Cookie values may appear
    # under the same key (requests collapses them with a comma)
    raw = headers.get("set-cookie", "")
    if not raw:
        return

    # Split on ", " but only at positions that start a new cookie directive
    # (naive split is fine for security flag detection - we just need directives)
    cookies = [c.strip() for c in raw.split(",") if "=" in c or c.strip().lower() in ("httponly", "secure")]

    for cookie in cookies:
        parts = [p.strip().lower() for p in cookie.split(";")]
        if not parts:
            continue

        # Cookie name is the part before the first =
        name_part = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0]
        directives = set(parts[1:])

        missing: List[str] = []
        if "httponly" not in directives:
            missing.append("HttpOnly")
        if is_https and "secure" not in directives:
            missing.append("Secure")
        if not any(d.startswith("samesite") for d in directives):
            missing.append("SameSite")

        if missing:
            msg = f"Set-Cookie '{name_part}' missing: {', '.join(missing)}"
            cookie_issues.append(msg)
            notes.append(f"Cookie flag issue: {msg}")


# ── Response body analysis ─────────────────────────────────────────────────────

def _extract_json_fields(body: bytes, content_type: str) -> List[str]:
    """
    Parse up to one level of JSON nesting and return field names.
    Handles both root-level objects and arrays of objects.
    Returns empty list on parse failure or non-JSON content.
    """
    if "json" not in content_type.lower():
        # Attempt parse anyway for endpoints with wrong content-type headers
        if not body.lstrip()[:1] in (b"{", b"["):
            return []

    try:
        decoded = body.decode("utf-8", errors="replace")
        parsed = json.loads(decoded)
    except (json.JSONDecodeError, ValueError):
        return []

    fields: List[str] = []

    def _collect(obj: Any, depth: int) -> None:
        if depth > 1:
            return
        if isinstance(obj, dict):
            for k in obj:
                if isinstance(k, str):
                    fields.append(k)
                    _collect(obj[k], depth + 1)
        elif isinstance(obj, list):
            for item in obj[:3]:  # sample first 3 items
                _collect(item, depth)

    _collect(parsed, 0)

    # Deduplicate while preserving order
    seen: Set[str] = set()
    unique: List[str] = []
    for f in fields:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    return unique


def _find_sensitive_fields(fields: List[str]) -> List[str]:
    """
    Check extracted response field names against known-sensitive names.
    Also catches prefix matches like 'tokenExpiry' or 'authHeader'.
    """
    found: List[str] = []
    for f in fields:
        fl = f.lower().replace("_", "").replace("-", "")
        if fl in _SENSITIVE_RESP_FIELDS:
            found.append(f)
        elif any(fl.startswith(pfx) for pfx in _SENSITIVE_RESP_PREFIXES):
            found.append(f)
    return found


# ── Core probe logic ──────────────────────────────────────────────────────────

def validate_endpoint(
    url:        str,
    base_url:   str,
    scope,
    timeout:    int   = 8,
    stealth:    bool  = False,
    delay:      float = 0.5,
) -> Optional[ValidationResult]:
    """
    Probe a single endpoint safely.
    Uses HEAD first, falls back to GET if HEAD is not allowed.
    GET response body is parsed for JSON structure and security signals.
    Never sends a body. Never makes POST/PUT/DELETE.
    """
    if _should_skip(url):
        return None

    safe, reason = validate_url(url, check_dns=True)
    if not safe:
        logger.debug("Skipping unsafe endpoint: %s (%s)", url, reason)
        return None

    if not scope.in_scope(url):
        logger.debug("Endpoint out of scope: %s", url)
        return None

    time.sleep(delay)

    headers = {
        "User-Agent": random_ua() if stealth else "BundleSpy/1.0.0 (authorized security assessment)",
        "Accept":     "application/json,text/html,*/*",
        "Referer":    base_url,
    }

    result = ValidationResult(
        endpoint="", method="", status_code=0, content_type="",
        response_size=0, redirect_url="", server="", interesting=False,
    )
    result.endpoint = url

    body: bytes = b""
    resp_headers: Dict[str, str] = {}

    # ── HEAD probe ────────────────────────────────────────────────────────────
    head_failed = False
    try:
        resp = requests.head(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            stream=False,
        )
        resp_headers                = dict(resp.headers.lower_items())
        result.method               = "HEAD"
        result.status_code          = resp.status_code
        result.content_type         = resp.headers.get("Content-Type", "")
        result.server               = resp.headers.get("Server", "")
        result.redirect_url         = resp.headers.get("Location", "")

        if resp.status_code in (405, 501):
            head_failed = True

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        head_failed = True

    except Exception as e:
        result.error = str(e)
        return result

    # ── GET fallback ──────────────────────────────────────────────────────────
    if head_failed:
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                stream=True,
            )
            resp_headers                = dict(resp.headers.lower_items())
            result.method               = "GET"
            result.status_code          = resp.status_code
            result.content_type         = resp.headers.get("Content-Type", "")
            result.server               = resp.headers.get("Server", "")
            result.redirect_url         = resp.headers.get("Location", "")

            for chunk in resp.iter_content(8192):
                body += chunk
                if len(body) >= MAX_RESPONSE_SIZE:
                    break
            result.response_size = len(body)

        except Exception as e:
            result.error = str(e)
            return result

    elif result.method == "HEAD" and result.status_code not in (405, 501):
        # HEAD succeeded - do a separate GET for body analysis only on JSON responses
        ct = result.content_type.lower()
        if "json" in ct or result.status_code == 200:
            try:
                resp_get = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                    stream=True,
                )
                for chunk in resp_get.iter_content(8192):
                    body += chunk
                    if len(body) >= MAX_RESPONSE_SIZE:
                        break
                result.response_size = len(body)
                # Prefer GET headers for CORS/cookie analysis (HEAD often omits them)
                resp_headers = dict(resp_get.headers.lower_items())
            except Exception:
                pass  # non-fatal - we already have status from HEAD

    result.response_headers = resp_headers

    # ── Security header analysis ──────────────────────────────────────────────
    _analyze_cors(resp_headers, url, result.notes, result.cors_issues)
    _analyze_cookies(resp_headers, url, result.notes, result.cookie_issues)

    # ── JSON body analysis ────────────────────────────────────────────────────
    if body:
        result.response_body_fields = _extract_json_fields(body, result.content_type)
        if result.response_body_fields:
            result.sensitive_response_fields = _find_sensitive_fields(result.response_body_fields)
            if result.sensitive_response_fields:
                result.notes.append(
                    "Sensitive fields in response: " + ", ".join(result.sensitive_response_fields)
                )
                result.interesting = True

    # ── Status-based classification ───────────────────────────────────────────
    result.interesting = result.interesting or (result.status_code in INTERESTING_CODES)

    # Endpoint existence is confirmed for any of these codes
    if result.status_code in _EXISTENCE_CODES:
        result.validation_status = "VALIDATED"

    if result.status_code == 200:
        result.notes.append("Publicly accessible")
    elif result.status_code == 401:
        result.notes.append("Authentication required - endpoint exists")
    elif result.status_code == 403:
        result.notes.append("Forbidden - endpoint exists, access denied")
    elif result.status_code in (301, 302, 307, 308):
        result.notes.append(f"Redirects to: {result.redirect_url}")
    elif result.status_code == 405:
        result.notes.append(
            "LIKELY_POST - server rejected GET/HEAD with 405 Method Not Allowed; "
            "retry manually with POST/PUT/PATCH and appropriate Content-Type"
        )
        result.interesting = True

    if "json" in result.content_type.lower():
        result.notes.append("Returns JSON")
    if "graphql" in url.lower():
        result.notes.append("Potential GraphQL endpoint")
    if any(k in url.lower() for k in ("/admin", "/management", "/internal")):
        result.notes.append("Administrative path")

    if result.cors_issues:
        result.interesting = True
    if result.cookie_issues:
        result.interesting = True

    return result


def validate_endpoints(
    endpoints:     List[Endpoint],
    base_url:      str,
    scope,
    timeout:       int   = 8,
    stealth:       bool  = False,
    rate:          float = 1.0,
    max_endpoints: int   = 100,
) -> List[ValidationResult]:
    """
    Validate a list of discovered endpoints.
    Returns results sorted by interest level (interesting first, then status code).
    """
    results: List[ValidationResult] = []
    delay   = 1.0 / max(rate, 0.1)
    count   = 0

    for ep in endpoints:
        if count >= max_endpoints:
            logger.warning("Endpoint validation limit reached (%d)", max_endpoints)
            break

        url = ep.url
        if not url.startswith(("http://", "https://")):
            continue

        result = validate_endpoint(
            url, base_url, scope,
            timeout=timeout, stealth=stealth, delay=delay,
        )
        if result:
            results.append(result)
            count += 1
            if result.interesting:
                extra = ""
                if result.cors_issues:
                    extra += f" | CORS: {result.cors_issues[0]}"
                if result.sensitive_response_fields:
                    extra += f" | Sensitive fields: {', '.join(result.sensitive_response_fields)}"
                logger.info(
                    "Interesting endpoint: %s [%d] %s%s",
                    result.endpoint, result.status_code,
                    " | ".join(result.notes[:3]),
                    extra,
                )

    results.sort(key=lambda r: (not r.interesting, r.status_code))
    return results


def validation_results_by_url(results: List[ValidationResult]) -> Dict[str, "ValidationResult"]:
    """
    Build a URL-keyed lookup dict from a list of ValidationResult objects.
    Used by attack_surface.py to promote CANDIDATE items to VALIDATED.
    """
    return {r.endpoint: r for r in results}
