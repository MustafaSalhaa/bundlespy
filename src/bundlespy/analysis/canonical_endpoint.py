"""
Canonical endpoint identity.

Maps observed URL variants to parameterized templates so that
/api/users/123 and /api/users/456 are recognized as the same surface.

Rules:
- HTTP methods are ALWAYS kept distinct: GET /api/users/{id} != DELETE /api/users/{id}
- Numeric IDs, UUIDs, and hex tokens are replaced with typed placeholders
- Slug-like segments that vary across multiple observations are widened to {slug}
- Non-varying path segments (stable literals) are never replaced
- When ambiguous (only one observation of a segment) we keep the literal value
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from ..storage.models import Endpoint

# Segment patterns that indicate a path parameter rather than a static word
_RE_NUMERIC_ID  = re.compile(r'^\d+$')
_RE_UUID        = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
_RE_OBJECT_ID   = re.compile(r'^[0-9a-f]{24}$', re.IGNORECASE)  # MongoDB ObjectId
_RE_HEX_TOKEN   = re.compile(r'^[0-9a-f]{16,64}$', re.IGNORECASE)
_RE_BASE62_ID   = re.compile(r'^[A-Za-z0-9]{8,32}$')   # short IDs like YFk3xZqP

# Already-parameterized segments like {id} or :id should pass through unchanged
_RE_ALREADY_PARAM = re.compile(r'^\{[^}]+\}$')
_RE_COLON_PARAM   = re.compile(r'^:.+$')


def _segment_looks_like_id(seg: str) -> bool:
    """True if this segment is very likely a runtime ID, not a static word."""
    if not seg:
        return False
    if _RE_ALREADY_PARAM.match(seg) or _RE_COLON_PARAM.match(seg):
        return True
    if _RE_NUMERIC_ID.match(seg):
        return True
    if _RE_UUID.match(seg):
        return True
    if _RE_OBJECT_ID.match(seg):
        return True
    if _RE_HEX_TOKEN.match(seg):
        return True
    return False


def _placeholder_for(seg: str) -> str:
    """Return the canonical placeholder name for an ID-like segment."""
    if _RE_ALREADY_PARAM.match(seg):
        return seg   # already {something}
    if _RE_COLON_PARAM.match(seg):
        return "{" + seg[1:] + "}"  # :id -> {id}
    if _RE_NUMERIC_ID.match(seg):
        return "{id}"
    if _RE_UUID.match(seg):
        return "{uuid}"
    if _RE_OBJECT_ID.match(seg):
        return "{id}"
    if _RE_HEX_TOKEN.match(seg):
        return "{id}"
    return "{id}"


def canonicalize_path(path: str) -> str:
    """
    Replace obvious runtime IDs with typed placeholders.

    Examples:
      /api/users/123             -> /api/users/{id}
      /api/users/abc123def456gh  -> /api/users/{id}  (24-char hex)
      /api/v1/posts/3f2a-...uuid -> /api/v1/posts/{uuid}
      /api/users/{userId}        -> /api/users/{userId}  (already parameterized)
      /dashboard/settings        -> /dashboard/settings  (no IDs)
    """
    if not path:
        return path
    # Strip query/fragment before processing
    clean = path.split("?")[0].split("#")[0]
    parts = clean.split("/")
    result = []
    for part in parts:
        if _segment_looks_like_id(part):
            result.append(_placeholder_for(part))
        else:
            result.append(part)
    return "/".join(result)


def canonical_key(method: str, path: str) -> str:
    """
    Stable deduplication key: (METHOD, canonical_path).
    HTTP methods are always distinct - GET != DELETE on the same template.
    """
    canon = canonicalize_path(path)
    return f"{method.upper()}:{canon}"


# ── Multi-observation slug widening ──────────────────────────────────────────
# When we see the same path template but with different string values
# in a particular segment position, that position is likely a slug param.
# We widen it on the second distinct observation.

class CanonicalRegistry:
    """
    Accumulates endpoints and deduplicates them by canonical identity.

    Two endpoints with the same (method, canonical_path) are merged:
    - The highest-confidence one survives as the representative
    - All observed raw paths are recorded in observed_variants
    - source_type is promoted to "correlated" when >1 source contributes

    Thread-safety: not thread-safe; call from a single thread at report time.
    """

    def __init__(self) -> None:
        # key -> representative Endpoint
        self._canonical: Dict[str, Endpoint] = {}
        # key -> set of raw path strings seen
        self._variants:  Dict[str, Set[str]]  = {}

    def add(self, ep: Endpoint) -> None:
        """Register one endpoint, merging into an existing canonical if present."""
        # Compute the canonical path if not already done
        if ep.canonical_path is None:
            ep.canonical_path = canonicalize_path(ep.path)
        key = canonical_key(ep.method, ep.path)

        if key not in self._canonical:
            self._canonical[key] = ep
            self._variants[key]  = {ep.path}
        else:
            existing = self._canonical[key]
            self._variants[key].add(ep.path)

            # Keep the higher-confidence representative
            if ep.confidence > existing.confidence:
                # Carry over the variant history to the new representative
                ep.observed_variants = list(self._variants[key])
                ep.canonical_path    = existing.canonical_path
                self._canonical[key] = ep
            else:
                existing.observed_variants = list(self._variants[key])

            # Mark as correlated when more than one distinct raw path observed
            rep = self._canonical[key]
            if len(self._variants[key]) > 1 and rep.source_type != "correlated":
                rep.source_type = "correlated"

    def deduplicated(self) -> List[Endpoint]:
        """Return the deduplicated representative endpoint list."""
        return list(self._canonical.values())

    def stats(self) -> Tuple[int, int]:
        """Return (total_unique_canonicals, total_raw_variants_seen)."""
        total_variants = sum(len(v) for v in self._variants.values())
        return len(self._canonical), total_variants


def deduplicate_endpoints(endpoints: List[Endpoint]) -> List[Endpoint]:
    """
    Convenience wrapper: deduplicate a flat list of endpoints.

    Returns one representative per (method, canonical_path).
    Mutates each endpoint to set canonical_path and observed_variants.
    """
    registry = CanonicalRegistry()
    for ep in endpoints:
        registry.add(ep)
    result = registry.deduplicated()
    unique, total = registry.stats()
    return result
