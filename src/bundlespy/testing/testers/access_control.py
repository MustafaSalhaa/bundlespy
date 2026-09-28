"""
AccessControlMapper - IDOR/BOLA surface candidate identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
import re
from typing import List
from urllib.parse import urlparse

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Regex patterns that indicate an object identifier in the path
_NUMERIC_ID_RE  = re.compile(r'/(\d{1,12})(?=/|$|\?)')
_UUID_RE        = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
    re.I,
)

# Query/body param names that suggest object identifiers
_IDOR_PARAM_NAMES = {
    "id", "user_id", "account_id", "order_id", "item_id",
    "product_id", "report_id", "doc_id", "document_id",
    "file_id", "message_id", "record_id", "object_id",
    "uid", "user", "account", "record",
}

_BURP_NOTES = (
    "Test adjacent IDs (±1, ±10). Try unauthenticated. "
    "Try other user session. Check if response differs."
)


def _path_pattern(path: str) -> str:
    """Normalize a path to its structural pattern, stripping actual ID values."""
    # Use lookahead so the trailing / is not consumed
    p = re.sub(r'/(\d{1,12})(?=/|$|\?)', r'/{numeric_id}', path)
    p = re.sub(
        r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
        r'/{uuid}', p, flags=re.I,
    )
    return p


class AccessControlMapper(BaseSurfaceMapper):
    category = AttackCategory.ACCESS_CONTROL

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Dedup by path pattern so /user/1 and /user/2 produce one candidate
        seen_patterns: set = set()

        for ep in result.endpoints:
            path = ep.path or urlparse(ep.url).path or ""
            method = (ep.method or "GET").upper()

            params_found = []
            confidence   = ConfidenceLevel.LOW
            evidence     = []

            # 1. Numeric IDs in path
            if _NUMERIC_ID_RE.search(path):
                params_found.append("path:numeric_id")
                evidence.append(f"Numeric ID in path: {path}")
                confidence = ConfidenceLevel.HIGH if ep.auth_context and ep.auth_context.lower() not in ("", "none") else ConfidenceLevel.MEDIUM

            # 2. UUID in path
            if _UUID_RE.search(path):
                params_found.append("path:uuid")
                evidence.append(f"UUID in path: {path}")
                confidence = ConfidenceLevel.HIGH if ep.auth_context and ep.auth_context.lower() not in ("", "none") else ConfidenceLevel.MEDIUM

            # 3. Path params named like IDs
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name in _IDOR_PARAM_NAMES:
                    params_found.append(f"path_param:{name}")
                    evidence.append(f"Path parameter '{name}' matches object ID naming")
                    if ep.auth_context and ep.auth_context.lower() not in ("", "none"):
                        confidence = ConfidenceLevel.HIGH

            # 4. Query params named like IDs
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name in _IDOR_PARAM_NAMES:
                    params_found.append(f"query:{name}")
                    evidence.append(f"Query parameter '{name}' matches object ID naming")
                    if confidence != ConfidenceLevel.HIGH:
                        confidence = ConfidenceLevel.MEDIUM

            if not params_found:
                continue

            # Dedup by structural path pattern
            pat = _path_pattern(path)
            dedup_key = f"{method}:{pat}:{','.join(sorted(params_found))}"
            if dedup_key in seen_patterns:
                continue
            seen_patterns.add(dedup_key)

            auth_ctx = ep.auth_context or ""
            if auth_ctx and auth_ctx.lower() not in ("", "none"):
                evidence.append(f"Auth context: {auth_ctx} (auth-gated resource)")

            self._candidate(
                endpoint     = ep,
                surface_type = "IDOR/BOLA",
                parameters   = params_found,
                confidence   = confidence,
                evidence     = evidence,
                burp_notes   = _BURP_NOTES,
                auth_context = auth_ctx,
            )

        return self._results
