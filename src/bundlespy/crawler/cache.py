"""
On-disk HTTP response cache for BundleSpy.

Design
------
- Cache dir: ~/.cache/bundlespy/http/  (overridable via BUNDLESPY_CACHE_DIR)
- Each entry is stored as two files:
    <sha256_of_url>.meta.json   -- URL, ETag, Last-Modified, content-type, timestamp
    <sha256_of_url>.body        -- raw bytes of the response body
- On a cache HIT the fetcher sends a conditional GET (If-None-Match / If-Modified-Since).
  If the server returns 304 Not Modified, the cached body is returned directly -- zero
  bandwidth used.  If the server returns 200, the new body replaces the old entry.
- On a cache MISS the response is stored after the first successful fetch.
- Content is keyed by the SHA256 of the URL so filenames are always safe on all OSes.
- The cache is per-user (not per-scan), so the second scan against the same target is
  dramatically faster even if run days later.

Thread safety
-------------
Each write is atomic: body is written to a .tmp file then renamed into place so a
crashed process never leaves a corrupt entry.

Cache invalidation
------------------
- Entries expire after MAX_AGE_SECONDS (default 7 days).  Stale entries are ignored on
  read and overwritten on the next fetch.
- Callers can pass cache=False to bypass for a single request.
- The --no-cache CLI flag disables cache reads (writes still happen so the next run
  benefits).
- The --clear-cache CLI flag deletes all entries on startup.

Statistics
----------
FetchCache.stats() returns {"hits": int, "misses": int, "revalidated": int, "saved_bytes": int}
which is printed in the scan summary and included in the JSON/HTML reports.
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("bundlespy.cache")

# Default cache location - respects XDG
_DEFAULT_CACHE_DIR = Path(os.environ.get(
    "BUNDLESPY_CACHE_DIR",
    Path.home() / ".cache" / "bundlespy" / "http",
))

# 7 days
MAX_AGE_SECONDS = int(os.environ.get("BUNDLESPY_CACHE_TTL", 7 * 24 * 3600))


@dataclass
class CacheStats:
    hits:        int = 0
    misses:      int = 0
    revalidated: int = 0   # 304 Not Modified responses
    saved_bytes: int = 0   # bytes NOT downloaded due to cache hits


@dataclass
class CacheEntry:
    url:          str
    etag:         Optional[str]
    last_modified: Optional[str]
    content_type: str
    sha256:       str          # SHA256 of the response body
    size:         int          # byte size of the response body
    stored_at:    float        # Unix timestamp


class FetchCache:
    """
    Thread-safe on-disk HTTP cache.

    Usage
    -----
    cache = FetchCache()                      # default dir
    cache = FetchCache(disabled=True)         # reads disabled (writes still happen)
    cache = FetchCache(path="/tmp/mydir")     # custom dir

    hit, content, meta = cache.get(url)
    if hit:
        # use content and meta["etag"] / meta["last_modified"] for conditional GET
        ...

    cache.put(url, body_bytes, status_code, response_headers)
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        disabled: bool = False,
        max_age: int = MAX_AGE_SECONDS,
    ):
        self.disabled = disabled
        self.max_age  = max_age
        self.stats    = CacheStats()
        self._dir     = Path(path) if path else _DEFAULT_CACHE_DIR
        if not disabled:
            try:
                self._dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning("Cannot create cache dir %s: %s - cache disabled", self._dir, e)
                self.disabled = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url_key(self, url: str) -> str:
        """Stable 64-char hex key derived from the URL."""
        return hashlib.sha256(url.encode()).hexdigest()

    def _meta_path(self, key: str) -> Path:
        return self._
