"""
Centralized provenance-aware URL registry for BundleSpy discovery.

Implements the "Unified discovery model" (spec section 6).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredURL:
    url: str
    source: str                  # static | chunk | source-map | headless | interaction | runtime | worker | iframe
    parent: str = ""             # URL that led to this discovery
    source_file: str = ""
    line: int = 0
    column: int = 0
    route: str = ""              # frontend route if applicable
    frame_context: str = ""      # frame/worker context
    runtime_context: str = ""    # runtime context
    occurrences: int = 1
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# URL normalisation helpers
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
}


def _normalize_url(url: str) -> str:
    """
    Normalise a URL for deduplication:
      - lowercase scheme and host
      - remove default ports (80 for http, 443 for https)
      - normalise path (no trailing slash unless root "/")
      - drop fragment
      - sort query parameters
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    # netloc = host[:port] but we need to handle port removal
    port = parsed.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None

    if port is not None:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    # Preserve userinfo if present
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    # Normalise path — strip trailing slash unless root
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if not path:
        path = "/"

    # Sort query params for stable comparison
    query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_pairs)

    # Drop fragment
    normalised = urlunparse((scheme, netloc, path, parsed.params, query, ""))
    return normalised


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class DiscoveryRegistry:
    """
    Thread-safe, provenance-aware registry of discovered URLs.

    Every URL is stored with full provenance metadata. Duplicate registrations
    increment the occurrence counter but do not overwrite the original provenance.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: Dict[str, DiscoveredURL] = {}  # key = normalised URL

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def register(
        self,
        url: str,
        source: str,
        parent: str = "",
        source_file: str = "",
        line: int = 0,
        column: int = 0,
        route: str = "",
        frame_context: str = "",
        runtime_context: str = "",
        confidence: float = 1.0,
    ) -> bool:
        """
        Register a discovered URL.

        Returns True if this is a NEW URL (first time seen).
        Returns False if duplicate (occurrence counter incremented, provenance preserved).
        """
        key = _normalize_url(url)

        with self._lock:
            if key in self._store:
                self._store[key].occurrences += 1
                return False

            self._store[key] = DiscoveredURL(
                url=key,
                source=source,
                parent=parent,
                source_file=source_file,
                line=line,
                column=column,
                route=route,
                frame_context=frame_context,
                runtime_context=runtime_context,
                occurrences=1,
                confidence=confidence,
            )
            return True

    def get(self, url: str) -> Optional[DiscoveredURL]:
        """Return the DiscoveredURL for *url*, or None if not registered."""
        key = _normalize_url(url)
        with self._lock:
            return self._store.get(key)

    def all(self) -> List[DiscoveredURL]:
        """Return all registered DiscoveredURL objects."""
        with self._lock:
            return list(self._store.values())

    def by_source(self, source: str) -> List[DiscoveredURL]:
        """Return all DiscoveredURL objects matching the given source type."""
        with self._lock:
            return [entry for entry in self._store.values() if entry.source == source]

    def deduplicated(self) -> List[DiscoveredURL]:
        """Return all entries sorted by confidence descending."""
        with self._lock:
            entries = list(self._store.values())
        return sorted(entries, key=lambda e: e.confidence, reverse=True)

    def merge(self, other: "DiscoveryRegistry") -> None:
        """
        Merge another registry into this one.

        For URLs already present: sum occurrence counts.
        For new URLs: copy the entry verbatim (preserving provenance).
        """
        with other._lock:
            other_entries = list(other._store.values())

        with self._lock:
            for entry in other_entries:
                key = _normalize_url(entry.url)
                if key in self._store:
                    self._store[key].occurrences += entry.occurrences
                else:
                    # Deep-copy the dataclass to avoid shared state
                    import copy
                    new_entry = copy.copy(entry)
                    new_entry.url = key
                    self._store[key] = new_entry

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict_list(self) -> List[dict]:
        """Export all entries as a list of dicts suitable for JSON serialisation."""
        with self._lock:
            return [asdict(entry) for entry in self._store.values()]

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def __repr__(self) -> str:
        return f"<DiscoveryRegistry urls={len(self)}>"
