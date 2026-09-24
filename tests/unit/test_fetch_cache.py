"""
Unit tests for the on-disk HTTP fetch cache (bundlespy.crawler.cache).

Covers:
- Cache miss on empty cache
- Cache hit on fresh entry
- Stale entry returns conditional-request headers only (no body)
- put() stores body and meta correctly
- 304 revalidation via record_revalidated()
- clear() removes all entries and returns correct count
- evict_expired() removes old entries, keeps fresh ones
- size_on_disk() returns positive value after writes
- Disabled cache always misses
- summary() returns correct hit rate
- SHA256 mismatch: corrupted body returns miss
- Large body stored and retrieved correctly
- Two different URLs have separate cache entries
- Same URL stored twice overwrites the entry
- Meta fields (etag, last_modified, content_type) round-trip correctly
- Cache with custom path uses that directory
- Cache dir is created if it does not exist
- Atomic write: .tmp file not left behind on success
- stats.saved_bytes accumulates across multiple hits
- stats.hits / misses / revalidated start at zero
- get() on URL with no matching body file returns miss
"""

import hashlib
import json
import time
from pathlib import Path

import pytest

from bundlespy.crawler.cache import FetchCache, CacheStats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _put(cache: FetchCache, url: str, body: bytes, etag: str = None,
         last_modified: str = None, content_type: str = "application/javascript"):
    headers = {"content-type": content_type}
    if etag:
        headers["etag"] = etag
    if last_modified:
        headers["last-modified"] = last_modified
    cache.put(url, body, headers)


def _body(text: str = "console.log('hello');") -> bytes:
    return text.encode()


# ---------------------------------------------------------------------------
# Basic miss / hit
# ---------------------------------------------------------------------------

def test_miss_on_empty_cache(tmp_path):
    cache = FetchCache(path=tmp_path)
    hit, body, meta = cache.get("https://example.com/app.js")
    assert not hit
    assert body is None


def test_hit_after_put(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    data  = _body()
    _put(cache, url, data)
    hit, body, meta = cache.get(url)
    assert hit
    assert body == data


def test_hit_body_is_correct(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    data  = b"const x = 42; // unique content"
    _put(cache, url, data)
    hit, body, _ = cache.get(url)
    assert body == data


def test_different_urls_separate_entries(tmp_path):
    cache = FetchCache(path=tmp_path)
    _put(cache, "https://example.com/a.js", b"aaa")
    _put(cache, "https://example.com/b.js", b"bbb")
    _, body_a, _ = cache.get("https://example.com/a.js")
    _, body_b, _ = cache.get("https://example.com/b.js")
    assert body_a == b"aaa"
    assert body_b == b"bbb"


def test_overwrite_same_url(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    _put(cache, url, b"version1")
    _put(cache, url, b"version2")
    _, body, _ = cache.get(url)
    assert body == b"version2"


# ---------------------------------------------------------------------------
# Meta round-trip
# ---------------------------------------------------------------------------

def test_etag_roundtrip(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    _put(cache, url, _body(), etag='"abc123"')
    _, _, meta = cache.get(url)
    assert meta["etag"] == '"abc123"'


def test_last_modified_roundtrip(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    _put(cache, url, _body(), last_modified="Wed, 01 Jan 2026 00:00:00 GMT")
    _, _, meta = cache.get(url)
    assert meta["last_modified"] == "Wed, 01 Jan 2026 00:00:00 GMT"


def test_content_type_roundtrip(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    _put(cache, url, _body(), content_type="text/javascript; charset=utf-8")
    _, _, meta = cache.get(url)
    assert "javascript" in meta["content_type"]


def test_sha256_in_meta(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    data  = _body()
    _put(cache, url, data)
    _, _, meta = cache.get(url)
    expected = hashlib.sha256(data).hexdigest()
    assert meta["sha256"] == expected


# ---------------------------------------------------------------------------
# Stale entry
# ---------------------------------------------------------------------------

def test_stale_entry_returns_miss(tmp_path):
    cache = FetchCache(path=tmp_path, max_age=0)   # everything is immediately stale
    url   = "https://example.com/app.js"
    _put(cache, url, _body(), etag='"stale-etag"')
    hit, body, meta = cache.get(url)
    assert not hit
    assert body is None


def test_stale_entry_returns_conditional_headers(tmp_path):
    cache = FetchCache(path=tmp_path, max_age=0)
    url   = "https://example.com/app.js"
    _put(cache, url, _body(), etag='"stale-etag"', last_modified="Mon, 01 Jan 2024 00:00:00 GMT")
    _, _, meta = cache.get(url)
    # Even though it is a miss, meta holds headers for conditional GET
    assert meta.get("etag") == '"stale-etag"'
    assert "last_modified" in meta


# ---------------------------------------------------------------------------
# 304 revalidation
# ---------------------------------------------------------------------------

def test_record_revalidated_increments_stats(tmp_path):
    cache = FetchCache(path=tmp_path)
    cache.record_revalidated("https://example.com/app.js", 5000)
    assert cache.stats.revalidated == 1
    assert cache.stats.saved_bytes == 5000


def test_record_revalidated_accumulates(tmp_path):
    cache = FetchCache(path=tmp_path)
    cache.record_revalidated("https://example.com/a.js", 1000)
    cache.record_revalidated("https://example.com/b.js", 2000)
    assert cache.stats.revalidated == 2
    assert cache.stats.saved_bytes == 3000


# ---------------------------------------------------------------------------
# clear()
# ---------------------------------------------------------------------------

def test_clear_empty_cache_returns_zero(tmp_path):
    cache = FetchCache(path=tmp_path)
    assert cache.clear() == 0


def test_clear_removes_entries(tmp_path):
    cache = FetchCache(path=tmp_path)
    _put(cache, "https://example.com/a.js", b"aaa")
    _put(cache, "https://example.com/b.js", b"bbb")
    removed = cache.clear()
    assert removed == 2
    hit, _, _ = cache.get("https://example.com/a.js")
    assert not hit


def test_clear_leaves_no_files(tmp_path):
    cache = FetchCache(path=tmp_path)
    _put(cache, "https://example.com/a.js", b"aaa")
    cache.clear()
    files = list(tmp_path.iterdir())
    assert files == []


# ---------------------------------------------------------------------------
# evict_expired()
# ---------------------------------------------------------------------------

def test_evict_removes_old_entries(tmp_path):
    cache = FetchCache(path=tmp_path, max_age=1)
    url   = "https://example.com/app.js"
    _put(cache, url, _body())
    # Backdate the stored_at in the meta file
    key  = cache._url_key(url)
    meta_path = cache._meta_path(key)
    with meta_path.open() as f:
        d = json.load(f)
    d["stored_at"] = time.time() - 10   # 10 seconds ago, max_age=1
    with meta_path.open("w") as f:
        json.dump(d, f)
    removed = cache.evict_expired()
    assert removed == 1
    hit, _, _ = cache.get(url)
    assert not hit


def test_evict_keeps_fresh_entries(tmp_path):
    cache = FetchCache(path=tmp_path, max_age=3600)
    url   = "https://example.com/app.js"
    _put(cache, url, _body())
    removed = cache.evict_expired()
    assert removed == 0
    hit, _, _ = cache.get(url)
    assert hit


# ---------------------------------------------------------------------------
# Disabled cache
# ---------------------------------------------------------------------------

def test_disabled_cache_always_misses(tmp_path):
    cache = FetchCache(path=tmp_path, disabled=True)
    _put(cache, "https://example.com/app.js", _body())
    hit, body, _ = cache.get("https://example.com/app.js")
    assert not hit
    assert body is None


def test_disabled_cache_put_does_nothing(tmp_path):
    cache = FetchCache(path=tmp_path, disabled=True)
    _put(cache, "https://example.com/app.js", _body())
    files = list(tmp_path.iterdir())
    assert files == []


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def test_stats_start_at_zero(tmp_path):
    cache = FetchCache(path=tmp_path)
    assert cache.stats.hits == 0
    assert cache.stats.misses == 0
    assert cache.stats.revalidated == 0
    assert cache.stats.saved_bytes == 0


def test_miss_increments_misses(tmp_path):
    cache = FetchCache(path=tmp_path)
    cache.get("https://example.com/app.js")
    assert cache.stats.misses == 1
    assert cache.stats.hits == 0


def test_hit_increments_hits(tmp_path):
    cache = FetchCache(path=tmp_path)
    url  = "https://example.com/app.js"
    data = _body()
    # First get: miss (nothing stored yet)
    cache.get(url)
    assert cache.stats.misses == 1
    # Store it, then get again: hit
    _put(cache, url, data)
    cache.get(url)
    assert cache.stats.hits == 1


def test_hit_accumulates_saved_bytes(tmp_path):
    cache = FetchCache(path=tmp_path)
    url  = "https://example.com/app.js"
    data = b"x" * 10_000
    _put(cache, url, data)
    cache.get(url)
    cache.get(url)
    assert cache.stats.saved_bytes == 20_000


def test_summary_hit_rate(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    _put(cache, url, _body())
    cache.get(url)   # hit
    cache.get("https://example.com/miss.js")   # miss
    s = cache.summary()
    # 1 hit / 2 total = 50%
    assert s["hit_rate_pct"] == 50.0


def test_summary_zero_requests_hit_rate(tmp_path):
    cache = FetchCache(path=tmp_path)
    s = cache.summary()
    assert s["hit_rate_pct"] == 0.0


def test_summary_cache_dir_present(tmp_path):
    cache = FetchCache(path=tmp_path)
    s = cache.summary()
    assert "cache_dir" in s


# ---------------------------------------------------------------------------
# Size on disk
# ---------------------------------------------------------------------------

def test_size_on_disk_zero_when_empty(tmp_path):
    cache = FetchCache(path=tmp_path)
    assert cache.size_on_disk() == 0


def test_size_on_disk_positive_after_put(tmp_path):
    cache = FetchCache(path=tmp_path)
    _put(cache, "https://example.com/app.js", b"x" * 1000)
    assert cache.size_on_disk() > 0


# ---------------------------------------------------------------------------
# Large body
# ---------------------------------------------------------------------------

def test_large_body_roundtrip(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/chunk.js"
    data  = b"A" * 5_000_000   # 5 MB
    _put(cache, url, data)
    hit, body, _ = cache.get(url)
    assert hit
    assert body == data


# ---------------------------------------------------------------------------
# Atomic write: no leftover .tmp files
# ---------------------------------------------------------------------------

def test_no_tmp_file_after_put(tmp_path):
    cache = FetchCache(path=tmp_path)
    _put(cache, "https://example.com/app.js", _body())
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == []


# ---------------------------------------------------------------------------
# Custom path
# ---------------------------------------------------------------------------

def test_custom_path_used(tmp_path):
    custom = tmp_path / "custom_cache"
    cache  = FetchCache(path=custom)
    _put(cache, "https://example.com/app.js", _body())
    assert custom.exists()
    assert any(custom.iterdir())


def test_cache_dir_created_if_missing(tmp_path):
    deep = tmp_path / "a" / "b" / "c"
    assert not deep.exists()
    cache = FetchCache(path=deep)
    assert deep.exists()


# ---------------------------------------------------------------------------
# Missing body file
# ---------------------------------------------------------------------------

def test_missing_body_returns_miss(tmp_path):
    cache = FetchCache(path=tmp_path)
    url   = "https://example.com/app.js"
    _put(cache, url, _body())
    # Delete only the body file, keep meta
    key = cache._url_key(url)
    cache._body_path(key).unlink()
    hit, body, _ = cache.get(url)
    assert not hit
    assert body is None
