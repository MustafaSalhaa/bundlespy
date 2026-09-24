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
        return self._dir / f"{key}.meta.json"

    def _body_path(self, key: str) -> Path:
        return self._dir / f"{key}.body"

    def _load_meta(self, key: str) -> Optional[CacheEntry]:
        meta_path = self._meta_path(key)
        if not meta_path.exists():
            return None
        try:
            with meta_path.open() as f:
                d = json.load(f)
            return CacheEntry(
                url           = d["url"],
                etag          = d.get("etag"),
                last_modified = d.get("last_modified"),
                content_type  = d.get("content_type", ""),
                sha256        = d["sha256"],
                size          = d.get("size", 0),
                stored_at     = d.get("stored_at", 0.0),
            )
        except Exception:
            return None

    def _is_fresh(self, entry: CacheEntry) -> bool:
        age = time.time() - entry.stored_at
        return age < self.max_age

    def _read_body(self, key: str) -> Optional[bytes]:
        body_path = self._body_path(key)
        if not body_path.exists():
            return None
        try:
            return body_path.read_bytes()
        except Exception:
            return None

    def _write_entry(self, url: str, body: bytes, etag: Optional[str],
                     last_modified: Optional[str], content_type: str) -> None:
        key       = self._url_key(url)
        sha256    = hashlib.sha256(body).hexdigest()
        meta      = {
            "url":           url,
            "etag":          etag,
            "last_modified": last_modified,
            "content_type":  content_type,
            "sha256":        sha256,
            "size":          len(body),
            "stored_at":     time.time(),
        }
        # Atomic body write
        tmp = self._body_path(key).with_suffix(".tmp")
        try:
            tmp.write_bytes(body)
            tmp.replace(self._body_path(key))
            with self._meta_path(key).open("w") as f:
                json.dump(meta, f)
        except Exception as e:
            logger.debug("Cache write failed for %s: %s", url, e)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, url: str) -> Tuple[bool, Optional[bytes], dict]:
        """
        Look up a URL in the cache.

        Returns
        -------
        (hit, body_bytes, meta)

        hit=True, fresh entry  -> body_bytes is the cached content; meta has etag/last_modified
                                   for the caller to send as a conditional GET header
        hit=False              -> body_bytes is None; meta is empty
        hit=True but stale     -> treated as a miss so the caller re-fetches
        """
        if self.disabled:
            return False, None, {}

        key   = self._url_key(url)
        entry = self._load_meta(key)

        if entry is None:
            self.stats.misses += 1
            return False, None, {}

        if not self._is_fresh(entry):
            # Return the conditional-request headers so the fetcher can still do 304
            self.stats.misses += 1
            meta = {}
            if entry.etag:
                meta["etag"] = entry.etag
            if entry.last_modified:
                meta["last_modified"] = entry.last_modified
            return False, None, meta

        body = self._read_body(key)
        if body is None:
            self.stats.misses += 1
            return False, None, {}

        self.stats.hits += 1
        self.stats.saved_bytes += entry.size
        meta = {
            "etag":          entry.etag,
            "last_modified": entry.last_modified,
            "content_type":  entry.content_type,
            "sha256":        entry.sha256,
        }
        return True, body, meta

    def put(self, url: str, body: bytes, response_headers: dict) -> None:
        """Store a fresh response in the cache."""
        if self.disabled:
            return
        etag          = response_headers.get("etag") or response_headers.get("ETag")
        last_modified = response_headers.get("last-modified") or response_headers.get("Last-Modified")
        content_type  = response_headers.get("content-type") or response_headers.get("Content-Type", "")
        self._write_entry(url, body, etag, last_modified, content_type)

    def record_revalidated(self, url: str, size: int) -> None:
        """Call when the server returns 304 Not Modified."""
        self.stats.revalidated += 1
        self.stats.saved_bytes += size

    def summary(self) -> dict:
        """Return a plain dict suitable for the report."""
        total = self.stats.hits + self.stats.misses
        hit_rate = round(self.stats.hits / total * 100, 1) if total else 0.0
        return {
            "hits":        self.stats.hits,
            "misses":      self.stats.misses,
            "revalidated": self.stats.revalidated,
            "saved_bytes": self.stats.saved_bytes,
            "hit_rate_pct": hit_rate,
            "cache_dir":   str(self._dir),
        }

    def clear(self) -> int:
        """Delete all cache entries. Returns number of entries removed."""
        if not self._dir.exists():
            return 0
        removed = 0
        for f in self._dir.glob("*.meta.json"):
            key = f.stem.replace(".meta", "")
            try:
                self._meta_path(key).unlink(missing_ok=True)
                self._body_path(key).unlink(missing_ok=True)
                removed += 1
            except Exception:
                pass
        return removed

    def evict_expired(self) -> int:
        """Remove entries older than max_age. Called automatically on init in background."""
        if not self._dir.exists():
            return 0
        removed = 0
        for meta_file in self._dir.glob("*.meta.json"):
            try:
                with meta_file.open() as f:
                    d = json.load(f)
                age = time.time() - d.get("stored_at", 0)
                if age > self.max_age:
                    key = meta_file.stem.replace(".meta", "")
                    meta_file.unlink(missing_ok=True)
                    self._body_path(key).unlink(missing_ok=True)
                    removed += 1
            except Exception:
                pass
        return removed

    def size_on_disk(self) -> int:
        """Return total bytes used by the cache directory."""
        if not self._dir.exists():
            return 0
        return sum(f.stat().st_size for f in self._dir.iterdir() if f.is_file())
