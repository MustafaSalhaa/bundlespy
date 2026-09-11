"""
JWT detection and local analysis.
Detects JWT structures, decodes header/payload locally,
and reports algorithm, claims, and expiry without sending
tokens anywhere or attempting to forge/brute-force them.
"""

import re
import json
import base64
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger("bundlespy.analysis.jwt")

RE_JWT = re.compile(
    r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*'
)


def _b64_decode(s: str) -> Optional[bytes]:
    """Decode base64url-encoded string with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s)
    except Exception:
        return None


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT locally without validation.
    Returns a dict with header, payload, and metadata.
    Never attempts to verify the signature or contact any service.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_raw   = _b64_decode(parts[0])
    payload_raw  = _b64_decode(parts[1])

    if not header_raw or not payload_raw:
        return None

    try:
        header  = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    result: Dict[str, Any] = {
        "algorithm": header.get("alg", "unknown"),
        "type":      header.get("typ", "unknown"),
        "kid":       header.get("kid"),
        "issuer":    payload.get("iss"),
        "subject":   payload.get("sub"),
        "audience":  payload.get("aud"),
        "issued_at": None,
        "expires":   None,
        "is_expired": None,
        "claims":    {k: v for k, v in payload.items()
                      if k not in ("iss", "sub", "aud", "exp", "iat", "nbf")},
    }

    now = datetime.utcnow().timestamp()

    if "iat" in payload:
        try:
            result["issued_at"] = datetime.utcfromtimestamp(payload["iat"]).isoformat()
        except Exception:
            pass

    if "exp" in payload:
        try:
            exp_ts = payload["exp"]
            result["expires"]    = datetime.utcfromtimestamp(exp_ts).isoformat()
            result["is_expired"] = now > exp_ts
        except Exception:
            pass

    # Flag dangerous algorithms
    alg = result["algorithm"].lower()
    if alg == "none":
        result["algorithm_risk"] = "CRITICAL - alg:none allows unsigned tokens"
    elif alg.startswith("hs"):
        result["algorithm_risk"] = "MEDIUM - symmetric algorithm, key may be brute-forceable"
    else:
        result["algorithm_risk"] = "LOW"

    return result


def find_jwts(content: str) -> list:
    """Find all JWT-like strings in content and decode them."""
    results = []
    seen    = set()

    for match in RE_JWT.finditer(content):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)

        decoded = decode_jwt(token)
        if decoded:
            line_no = content[:match.start()].count("\n") + 1
            results.append({
                "token":      token,
                "line":       line_no,
                "decoded":    decoded,
            })

    return results
