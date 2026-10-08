"""
Fingerprint and deduplication for SurfaceFinding.

Fingerprint = SHA256(method + normalized_endpoint + parameter + surface_type + subtype)

Normalization strips dynamic segments so these share a fingerprint:
  GET /api/users/123
  GET /api/users/456
  GET /api/users/789
  → GET /api/users/{id}

But these are kept distinct (method changes the surface):
  GET  /api/users/{id}  →  GET::/api/users/{id}::id::BOLA::
  PATCH /api/users/{id} →  PATCH::/api/users/{id}::id::BOLA::
"""
from __future__ import annotations

import hashlib
import re
from typing import List

from .evidence import SurfaceFinding


# ── Normalization ──────────────────────────────────────────────────────────────

_UUID_RE   = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_NUMERIC_RE = re.compile(r"/\d+(?=/|$)")
_HEX_RE     = re.compile(r"/[0-9a-f]{16,}(?=/|$)", re.I)

# Query string and fragment stripped before normalization
_QS_RE      = re.compile(r"[?#].*$")


def normalize_endpoint(url: str) -> str:
    """
    Normalize a URL to its structural pattern.

    Strips scheme, host, query string, fragment.
    Replaces numeric IDs, UUIDs, and long hex strings with placeholders.
    Collapses double slashes. Strips trailing slash.

    Examples:
      https://example.com/api/users/123?foo=bar  →  /api/users/{id}
      /api/orders/3fa85f64-5717-4562-b3fc-2c963f66afa6  →  /api/orders/{uuid}
      /build/assets/app-BmnQm7Ty.js  →  /build/assets/app-BmnQm7Ty.js  (no change)
    """
    if not url:
        return ""

    # Strip scheme + host
    path = re.sub(r"^https?://[^/]+", "", url)

    # Strip query string and fragment
    path = _QS_RE.sub("", path)

    # UUID → {uuid}
    path = _UUID_RE.sub("{uuid}", path)

    # Long hex tokens (e.g. /abc123def456abc1/) → {id}
    path = _HEX_RE.sub("/{id}", path)

    # Numeric path segments → {id}
    path = _NUMERIC_RE.sub("/{id}", path)

    # Collapse double slashes
    path = re.sub(r"/{2,}", "/", path)

    # Strip trailing slash (but keep root /)
    if len(path) > 1:
        path = path.rstrip("/")

    return path or "/"


def make_fingerprint(
    method:       str,
    endpoint:     str,
    parameter:    str,
    surface_type: str,
    subtype:      str = "",
) -> str:
    """
    Produce a stable SHA256 fingerprint for a surface.

    Inputs are normalized:
      method       → uppercase
      endpoint     → normalize_endpoint()
      parameter    → lowercase strip
      surface_type → lowercase strip
      subtype      → lowercase strip

    Returns first 16 hex chars (64 bits) — collision risk negligible for typical scan sizes.
    """
    norm_endpoint = normalize_endpoint(endpoint)
    raw = "::".join([
        (method or "GET").upper(),
        norm_endpoint,
        (parameter or "").lower().strip(),
        (surface_type or "").lower().strip(),
        (subtype or "").lower().strip(),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Deduplication ──────────────────────────────────────────────────────────────

def deduplicate(findings: List[SurfaceFinding]) -> List[SurfaceFinding]:
    """
    Collapse findings that share a fingerprint into a single finding.

    The finding with the highest confidence score is kept as the base.
    Evidence lists are merged (preserving order, no duplicates by evidence id).
    relationships list is updated to record which fingerprints were merged.
    """
    if not findings:
        return []

    # Group by fingerprint
    groups: dict = {}
    for f in findings:
        groups.setdefault(f.fingerprint, []).append(f)

    result: List[SurfaceFinding] = []
    for fp, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Keep highest-confidence as base
        base = max(group, key=lambda x: x.confidence)

        # Merge evidence from all others into base
        seen_ids = {ev.id for ev in base.evidence}
        for other in group:
            if other is base:
                continue
            for ev in other.evidence:
                if ev.id not in seen_ids:
                    base.evidence.append(ev)
                    seen_ids.add(ev.id)

        # Record that multiple findings were collapsed
        merged_fps = [o.fingerprint for o in group if o is not base]
        for mfp in merged_fps:
            if mfp not in base.relationships:
                base.relationships.append(mfp)

        result.append(base)

    return result
