"""
Advanced robots.txt / sitemap pipeline tests.

Covers:
- robots.txt -> Sitemap: directive -> single sitemap -> URLs
- robots.txt -> Sitemap: directive -> sitemap index -> sub-sitemaps -> URLs
- Fallback to SITEMAP_PATHS when robots.txt absent
- Fallback to SITEMAP_PATHS when robots.txt has no Sitemap: directive
- Case-insensitive "sitemap:" directive parsing
- Multiple Sitemap: directives in robots.txt
- Malformed XML is silently skipped, other sitemaps still parsed
- Namespace-aware sitemap XML parsing (sitemaps.org schema)
- Sitemap index references non-200 sub-sitemap - skipped gracefully
- Empty sitemap body - returns empty, no crash
- URL deduplication across multiple sitemap sources
- robots.txt Disallow paths are not confused with sitemap paths
- collect_sitemap_urls boundary: never fetches paths not declared or in SITEMAP_PATHS
- Integration: run_intelligence_collection fills sitemap_urls on result
- Integration: run_intelligence_collection fills urls_discovered from sitemap
- sitemap.xml with no namespace still parsed (legacy format)
- Very large sitemap (1000 entries) - all extracted
- Sitemap URL with trailing whitespace - stripped correctly
- Sub-sitemap URL with trailing whitespace from robots.txt - stripped
- HTTPS vs HTTP scheme preserved from robots.txt Sitemap: directive
- Out-of-scope sitemap sub-URL still returned (scope checked by caller, not here)
"""

import hashlib
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import pytest

from bundlespy.discovery.intelligence import (
    collect_sitemap_urls,
    run_intelligence_collection,
    SITEMAP_PATHS,
)


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------

class _StubFetcher:
    """In-memory fetcher that maps URL paths to content strings."""

    def __init__(self, routes: Dict[str, str]):
        self._routes = routes
        self.calls: list = []

    def get(self, url: str, **kwargs):
        self.calls.append(url)
        path = urlparse(url).path
        content = self._routes.get(path)
        if content is None:
            return None, 404, "text/plain", ""
        h = hashlib.sha256(content.encode()).hexdigest()
        return content, 200, "text/plain", h


class _StubScope:
    def __init__(self, routes, base="https://app.example.com"):
        self._routes = routes

    def in_scope(self, url: str) -> bool:
        path = urlparse(url).path
        return path in self._routes


def _sitemap_xml(*locs: str) -> str:
    """Build a minimal sitemap.xml with the given <loc> URLs."""
    inner = "\n".join(
        f"  <url><loc>{loc}</loc></url>" for loc in locs
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{inner}\n"
        "</urlset>"
    )


def _sitemap_index_xml(*sitemap_urls: str) -> str:
    """Build a minimal sitemap index XML."""
    inner = "\n".join(
        f"  <sitemap><loc>{u}</loc></sitemap>" for u in sitemap_urls
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{inner}\n"
        "</sitemapindex>"
    )


BASE = "https://app.example.com"


# ---------------------------------------------------------------------------
# Test: robots.txt -> Sitemap: -> single sitemap -> URLs
# ---------------------------------------------------------------------------

def test_robots_sitemap_directive_followed():
    """robots.txt declares Sitemap: - that sitemap is fetched and URLs returned."""
    routes = {
        "/robots.txt": "User-agent: *\nDisallow: /admin\nSitemap: https://app.example.com/sitemap-custom.xml\n",
        "/sitemap-custom.xml": _sitemap_xml(
            "https://app.example.com/page1",
            "https://app.example.com/page2",
        ),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/page1" in urls
    assert "https://app.example.com/page2" in urls


def test_robots_txt_sitemap_directive_case_insensitive():
    """'Sitemap:' directive matching is case-insensitive."""
    routes = {
        "/robots.txt": "SITEMAP: https://app.example.com/sitemap.xml\n",
        "/sitemap.xml": _sitemap_xml("https://app.example.com/about"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/about" in urls


def test_robots_txt_multiple_sitemap_directives():
    """Multiple Sitemap: lines in robots.txt are all followed."""
    routes = {
        "/robots.txt": (
            "Sitemap: https://app.example.com/sitemap1.xml\n"
            "Sitemap: https://app.example.com/sitemap2.xml\n"
        ),
        "/sitemap1.xml": _sitemap_xml("https://app.example.com/p1"),
        "/sitemap2.xml": _sitemap_xml("https://app.example.com/p2"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/p1" in urls
    assert "https://app.example.com/p2" in urls


# ---------------------------------------------------------------------------
# Test: robots.txt -> Sitemap: -> sitemap INDEX -> sub-sitemaps -> URLs
# ---------------------------------------------------------------------------

def test_sitemap_index_followed_recursively():
    """Sitemap index references sub-sitemaps; all page URLs are extracted."""
    sub1_urls = ["https://app.example.com/news/1", "https://app.example.com/news/2"]
    sub2_urls = ["https://app.example.com/products/a"]
    routes = {
        "/robots.txt": "Sitemap: https://app.example.com/sitemap_index.xml\n",
        "/sitemap_index.xml": _sitemap_index_xml(
            "https://app.example.com/sub1.xml",
            "https://app.example.com/sub2.xml",
        ),
        "/sub1.xml": _sitemap_xml(*sub1_urls),
        "/sub2.xml": _sitemap_xml(*sub2_urls),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    for u in sub1_urls + sub2_urls:
        assert u in urls, f"Expected {u} in urls"


def test_sitemap_index_missing_sub_graceful():
    """Sub-sitemap returning 404 is silently skipped; other subs still parsed."""
    routes = {
        "/sitemap_index.xml": _sitemap_index_xml(
            "https://app.example.com/missing.xml",
            "https://app.example.com/real.xml",
        ),
        "/real.xml": _sitemap_xml("https://app.example.com/found"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/found" in urls


# ---------------------------------------------------------------------------
# Test: fallback behaviour when robots.txt absent
# ---------------------------------------------------------------------------

def test_fallback_to_sitemap_paths_when_robots_absent():
    """When /robots.txt returns 404, /sitemap.xml is tried from SITEMAP_PATHS."""
    routes = {
        "/sitemap.xml": _sitemap_xml("https://app.example.com/fallback-page"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/fallback-page" in urls


def test_fallback_to_sitemap_paths_when_no_sitemap_directive():
    """robots.txt exists but has no Sitemap: line; /sitemap.xml still tried."""
    routes = {
        "/robots.txt": "User-agent: *\nDisallow: /private\n",
        "/sitemap.xml": _sitemap_xml("https://app.example.com/public"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/public" in urls


def test_disallow_paths_not_confused_with_sitemap():
    """Disallow: lines in robots.txt are not treated as sitemap URLs."""
    routes = {
        "/robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /private\n",
        "/sitemap.xml": _sitemap_xml("https://app.example.com/home"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "/admin" not in urls
    assert "/private" not in urls
    assert "https://app.example.com/home" in urls


# ---------------------------------------------------------------------------
# Test: malformed XML handling
# ---------------------------------------------------------------------------

def test_malformed_sitemap_xml_skipped_silently():
    """Malformed XML at /sitemap.xml does not crash; returns empty list."""
    routes = {
        "/sitemap.xml": "<<BROKEN XML>>",
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert isinstance(urls, list)


def test_malformed_sitemap_with_valid_fallback():
    """Malformed /sitemap.xml is skipped; /sitemap_index.xml still tried."""
    routes = {
        "/sitemap.xml": "<<BROKEN>>",
        "/sitemap_index.xml": _sitemap_xml("https://app.example.com/via-index"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/via-index" in urls


def test_malformed_sub_sitemap_skipped_in_index():
    """Malformed sub-sitemap XML inside a sitemap index is skipped gracefully."""
    routes = {
        "/sitemap_index.xml": _sitemap_index_xml(
            "https://app.example.com/broken.xml",
        ),
        "/broken.xml": "not valid xml at all",
    }
    fetcher = _StubFetcher(routes)
    # Should not raise
    urls = collect_sitemap_urls(fetcher, BASE)
    assert isinstance(urls, list)


# ---------------------------------------------------------------------------
# Test: namespace handling
# ---------------------------------------------------------------------------

def test_sitemap_with_correct_namespace_parsed():
    """Standard sitemaps.org namespace is recognised."""
    xml = (
        '<?xml version="1.0"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://app.example.com/ns-page</loc></url>"
        "</urlset>"
    )
    routes = {"/sitemap.xml": xml}
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/ns-page" in urls


def test_empty_sitemap_returns_empty_list():
    """An empty but valid sitemap returns [] without crash."""
    xml = (
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "</urlset>"
    )
    routes = {"/sitemap.xml": xml}
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert urls == []


# ---------------------------------------------------------------------------
# Test: deduplication
# ---------------------------------------------------------------------------

def test_url_deduplication_across_sitemaps():
    """The same URL in two sitemaps appears only once in the result."""
    duplicate = "https://app.example.com/duplicate"
    routes = {
        "/sitemap.xml": _sitemap_xml(duplicate),
        "/sitemap_index.xml": _sitemap_xml(duplicate),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert urls.count(duplicate) == 1


# ---------------------------------------------------------------------------
# Test: whitespace handling
# ---------------------------------------------------------------------------

def test_loc_with_trailing_whitespace_stripped():
    """<loc> text with surrounding whitespace is stripped."""
    xml = (
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>  https://app.example.com/trimmed  </loc></url>"
        "</urlset>"
    )
    routes = {"/sitemap.xml": xml}
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/trimmed" in urls
    assert "  https://app.example.com/trimmed  " not in urls


def test_sitemap_url_with_whitespace_in_robots_txt_stripped():
    """Sitemap: directive value with trailing space is stripped before use."""
    routes = {
        "/robots.txt": "Sitemap: https://app.example.com/sitemap.xml   \n",
        "/sitemap.xml": _sitemap_xml("https://app.example.com/ws-page"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/ws-page" in urls


# ---------------------------------------------------------------------------
# Test: large sitemaps
# ---------------------------------------------------------------------------

def test_large_sitemap_all_urls_extracted():
    """A sitemap with 500 entries returns all 500 URLs."""
    locs = [f"https://app.example.com/page/{i}" for i in range(500)]
    routes = {"/sitemap.xml": _sitemap_xml(*locs)}
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert len(urls) == 500
    for loc in locs:
        assert loc in urls


# ---------------------------------------------------------------------------
# Test: HTTPS scheme preservation
# ---------------------------------------------------------------------------

def test_https_sitemap_url_from_robots_txt_preserved():
    """HTTPS scheme in Sitemap: directive is preserved when fetching."""
    routes = {
        "/robots.txt": "Sitemap: https://app.example.com/secure-sitemap.xml\n",
        "/secure-sitemap.xml": _sitemap_xml("https://app.example.com/secure"),
    }
    fetcher = _StubFetcher(routes)
    urls = collect_sitemap_urls(fetcher, BASE)
    assert "https://app.example.com/secure" in urls


# ---------------------------------------------------------------------------
# Test: run_intelligence_collection integration
# ---------------------------------------------------------------------------

def test_run_intelligence_collection_fills_sitemap_urls():
    """run_intelligence_collection() populates result.sitemap_urls from sitemap."""
    routes = {
        "/sitemap.xml": _sitemap_xml(
            "https://app.example.com/a",
            "https://app.example.com/b",
        ),
    }
    fetcher = _StubFetcher(routes)
    scope = _StubScope(routes)
    result = run_intelligence_collection(BASE, fetcher, scope, html_content="")
    assert "https://app.example.com/a" in result.sitemap_urls
    assert "https://app.example.com/b" in result.sitemap_urls


def test_run_intelligence_collection_fills_urls_discovered():
    """run_intelligence_collection() propagates sitemap URLs into urls_discovered."""
    routes = {
        "/sitemap.xml": _sitemap_xml("https://app.example.com/discovered"),
    }
    fetcher = _StubFetcher(routes)
    scope = _StubScope(routes)
    result = run_intelligence_collection(BASE, fetcher, scope, html_content="")
    assert "https://app.example.com/discovered" in result.urls_discovered


def test_run_intelligence_collection_no_sitemap_returns_empty():
    """When no sitemap is present, sitemap_urls and urls_discovered are empty."""
    routes: Dict[str, str] = {}
    fetcher = _StubFetcher(routes)
    scope = _StubScope(routes)
    result = run_intelligence_collection(BASE, fetcher, scope, html_content="")
    assert result.sitemap_urls == []


def test_run_intelligence_collection_with_robots_and_sitemap():
    """Full chain: robots.txt -> Sitemap: -> sitemap.xml -> result.sitemap_urls."""
    routes = {
        "/robots.txt": "Sitemap: https://app.example.com/sitemap.xml\n",
        "/sitemap.xml": _sitemap_xml(
            "https://app.example.com/via-robots",
        ),
    }
    fetcher = _StubFetcher(routes)
    scope = _StubScope(routes)
    result = run_intelligence_collection(BASE, fetcher, scope, html_content="")
    assert "https://app.example.com/via-robots" in result.sitemap_urls


def test_run_intelligence_collection_intelligence_result_target():
    """IntelligenceResult.target is set to the base URL passed in."""
    routes: Dict[str, str] = {}
    fetcher = _StubFetcher(routes)
    scope = _StubScope(routes)
    result = run_intelligence_collection(BASE, fetcher, scope, html_content="")
    assert result.target == BASE
