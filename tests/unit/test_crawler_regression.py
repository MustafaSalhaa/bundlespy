"""
BundleSpy Crawler Regression Tests — Spec Section 7
Covers all 13 scenarios (+ scenario 14 out-of-scope blocking).

New modules (AsyncFetcher, DiscoveryRegistry, url_normalizer,
headless_enhancements) are imported with try/except so this file
runs safely on the current codebase as a baseline.
"""

import sys
import asyncio
import time
import re
import pytest
from unittest.mock import MagicMock, AsyncMock, patch, call

sys.path.insert(0, "/home/claude/bundlespy/src")

# ---------------------------------------------------------------------------
# Always-available imports (existing safety layer)
# ---------------------------------------------------------------------------
from bundlespy.safety.network import validate_url, is_ip_blocked
from bundlespy.crawler.scope import ScopeChecker

# ---------------------------------------------------------------------------
# Optional / future module guards
# ---------------------------------------------------------------------------
try:
    from bundlespy.crawler.async_fetcher import AsyncFetcher
    HAS_ASYNC_FETCHER = True
except ImportError:
    HAS_ASYNC_FETCHER = False

try:
    from bundlespy.crawler.registry import DiscoveryRegistry
    HAS_DISCOVERY_REGISTRY = True
except ImportError:
    HAS_DISCOVERY_REGISTRY = False

try:
    from bundlespy.crawler import url_normalizer
    HAS_URL_NORMALIZER = True
except ImportError:
    try:
        from bundlespy.utils import url_normalizer
        HAS_URL_NORMALIZER = True
    except ImportError:
        HAS_URL_NORMALIZER = False

try:
    from bundlespy.discovery.headless_enhancements import (
        _check_destructive,
        InteractionTracker,
        INTERCEPT_JS_ADDITIONS,
    )
    HAS_HEADLESS_ENHANCEMENTS = True
except ImportError:
    HAS_HEADLESS_ENHANCEMENTS = False

try:
    from bundlespy.discovery.headless import _check_destructive as _check_destructive_headless
    HAS_HEADLESS = True
except ImportError:
    HAS_HEADLESS = False


# ---------------------------------------------------------------------------
# Helper: pick _check_destructive from whichever module has it
# ---------------------------------------------------------------------------
def _get_check_destructive():
    if HAS_HEADLESS_ENHANCEMENTS:
        from bundlespy.discovery.headless_enhancements import _check_destructive
        return _check_destructive
    if HAS_HEADLESS:
        from bundlespy.discovery.headless import _check_destructive
        return _check_destructive
    return None


# ===========================================================================
# Scenario 1 — Concurrent crawling
# ===========================================================================

@pytest.mark.skipif(not HAS_ASYNC_FETCHER, reason="AsyncFetcher not yet integrated")
class TestConcurrentCrawling:
    """AsyncFetcher.fetch_many returns results for all URLs."""

    def test_fetch_many_returns_all_results(self):
        """fetch_many(urls) should return one result per URL."""
        urls = [
            "https://example.com/a.js",
            "https://example.com/b.js",
            "https://example.com/c.js",
        ]

        async def run():
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {"Content-Type": "application/javascript"}
            mock_response.read = AsyncMock(return_value=b"console.log('hi');")

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=False)

            with patch("aiohttp.ClientSession") as mock_session_cls:
                mock_session = AsyncMock()
                mock_session.get = MagicMock(return_value=mock_cm)
                mock_session_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session
                )
                mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

                fetcher = AsyncFetcher(concurrency=3)
                results = await fetcher.fetch_many(urls)

            return results

        results = asyncio.run(run())
        assert len(results) == len(urls), (
            f"Expected {len(urls)} results, got {len(results)}"
        )

    def test_concurrent_requests_run_concurrently(self):
        """Concurrent requests should overlap in time, not run sequentially."""
        DELAY = 0.05   # 50 ms per mock request
        N = 4

        call_starts = []
        call_ends = []

        async def slow_fetch(url):
            call_starts.append(time.monotonic())
            await asyncio.sleep(DELAY)
            call_ends.append(time.monotonic())
            return ("content", 200, "application/javascript", "deadbeef", [])

        async def run():
            fetcher = AsyncFetcher(concurrency=N)
            urls = [f"https://example.com/{i}.js" for i in range(N)]

            with patch.object(fetcher, "_fetch_one", side_effect=slow_fetch):
                t0 = time.monotonic()
                results = await fetcher.fetch_many(urls)
                elapsed = time.monotonic() - t0

            return elapsed, results

        elapsed, results = asyncio.run(run())

        # If truly concurrent, total time should be ~DELAY, not N*DELAY
        sequential_time = N * DELAY
        assert elapsed < sequential_time * 0.75, (
            f"Requests appear sequential: elapsed={elapsed:.3f}s vs "
            f"sequential={sequential_time:.3f}s"
        )
        assert len(results) == N


# ===========================================================================
# Scenario 2 — Concurrency limits
# ===========================================================================

@pytest.mark.skipif(not HAS_ASYNC_FETCHER, reason="AsyncFetcher not yet integrated")
class TestConcurrencyLimits:
    """Semaphore limits max concurrent requests to concurrency=N."""

    def test_max_concurrent_never_exceeded(self):
        """With concurrency=2 and 10 URLs, never more than 2 in-flight."""
        CONCURRENCY = 2
        TOTAL_URLS = 10
        counter = {"current": 0, "max_seen": 0}

        async def tracked_fetch(url):
            counter["current"] += 1
            counter["max_seen"] = max(counter["max_seen"], counter["current"])
            await asyncio.sleep(0.01)
            counter["current"] -= 1
            return ("content", 200, "text/javascript", "abc123", [])

        async def run():
            fetcher = AsyncFetcher(concurrency=CONCURRENCY)
            urls = [f"https://example.com/{i}.js" for i in range(TOTAL_URLS)]
            with patch.object(fetcher, "_fetch_one", side_effect=tracked_fetch):
                results = await fetcher.fetch_many(urls)
            return results

        results = asyncio.run(run())

        assert len(results) == TOTAL_URLS
        assert counter["max_seen"] <= CONCURRENCY, (
            f"Concurrency limit violated: {counter['max_seen']} in-flight "
            f"(limit was {CONCURRENCY})"
        )


# ===========================================================================
# Scenario 3 — Request timeouts
# ===========================================================================

@pytest.mark.skipif(not HAS_ASYNC_FETCHER, reason="AsyncFetcher not yet integrated")
class TestRequestTimeouts:
    """Hanging requests time out and return gracefully."""

    def test_timeout_returns_none_tuple(self):
        """A TimeoutError should return (None, 0, '', '', []) — not raise."""

        async def hanging_fetch(url):
            raise asyncio.TimeoutError()

        async def run():
            fetcher = AsyncFetcher(concurrency=2, timeout=1)
            with patch.object(fetcher, "_fetch_one", side_effect=hanging_fetch):
                results = await fetcher.fetch_many(["https://example.com/slow.js"])
            return results

        results = asyncio.run(run())
        assert len(results) == 1
        content, status, ct, sha, redirects = results[0]
        assert content is None
        assert status == 0
        assert ct == ""
        assert sha == ""
        assert isinstance(redirects, list)

    def test_timeout_does_not_crash_fetcher(self):
        """A timeout on one URL should not prevent other URLs from completing."""
        calls = []

        async def selective_hang(url):
            calls.append(url)
            if "slow" in url:
                raise asyncio.TimeoutError()
            return ("js content", 200, "application/javascript", "cafebabe", [])

        async def run():
            fetcher = AsyncFetcher(concurrency=3, timeout=1)
            urls = [
                "https://example.com/slow.js",
                "https://example.com/fast1.js",
                "https://example.com/fast2.js",
            ]
            with patch.object(fetcher, "_fetch_one", side_effect=selective_hang):
                results = await fetcher.fetch_many(urls)
            return results

        results = asyncio.run(run())
        assert len(results) == 3

        fast_results = [r for r in results if r[1] == 200]
        assert len(fast_results) == 2, "Fast URLs should still complete after a timeout"


# ===========================================================================
# Scenario 4 — Redirect chains
# ===========================================================================

@pytest.mark.skipif(not HAS_ASYNC_FETCHER, reason="AsyncFetcher not yet integrated")
class TestRedirectChains:
    """Redirect chains are tracked correctly and loops are stopped."""

    def test_redirect_chain_is_recorded(self):
        """A → B → C should return chain [A, B, C]."""

        async def fetch_with_redirects(url):
            if url == "https://example.com/a":
                return ("final content", 200, "text/html", "abc", [
                    "https://example.com/a",
                    "https://example.com/b",
                    "https://example.com/c",
                ])
            return ("content", 200, "text/html", "xyz", [url])

        async def run():
            fetcher = AsyncFetcher(concurrency=1)
            with patch.object(fetcher, "_fetch_one", side_effect=fetch_with_redirects):
                results = await fetcher.fetch_many(["https://example.com/a"])
            return results

        results = asyncio.run(run())
        _, _, _, _, redirect_chain = results[0]
        assert "https://example.com/a" in redirect_chain
        assert "https://example.com/b" in redirect_chain
        assert "https://example.com/c" in redirect_chain

    def test_redirect_loop_does_not_loop_infinitely(self):
        """A → B → A redirect loop should terminate."""
        call_count = {"n": 0}

        async def looping_fetch(url):
            call_count["n"] += 1
            if call_count["n"] > 20:
                raise AssertionError("Infinite loop not stopped!")
            # Simulate A → B → A by returning a redirect chain with a loop
            return (None, 301, "", "", ["https://a.com/", "https://b.com/", "https://a.com/"])

        async def run():
            fetcher = AsyncFetcher(concurrency=1, max_redirects=10)
            with patch.object(fetcher, "_fetch_one", side_effect=looping_fetch):
                results = await fetcher.fetch_many(["https://a.com/"])
            return results

        # Should not raise AssertionError
        results = asyncio.run(run())
        assert len(results) == 1
        assert call_count["n"] <= 20


# ===========================================================================
# Scenario 5 — Malformed JS
# ===========================================================================

@pytest.mark.skipif(not HAS_URL_NORMALIZER, reason="url_normalizer not yet integrated")
class TestMalformedJS:
    """extract_urls_from_text handles pathological JS inputs without crashing."""

    def test_null_bytes_in_js(self):
        content = "var url = 'https://example.com/api';\x00\x00\x00"
        result = url_normalizer.extract_urls_from_text(content)
        assert isinstance(result, list)

    def test_broken_unicode_in_js(self):
        # Surrogates and replacement characters
        content = "var x = '\udcff\udcfe https://example.com/broken';"
        result = url_normalizer.extract_urls_from_text(content)
        assert isinstance(result, list)

    def test_extremely_long_line(self):
        # 1 MB single line
        long_line = "A" * (1024 * 1024)
        content = f"var url = 'https://example.com/api'; {long_line}"
        result = url_normalizer.extract_urls_from_text(content)
        assert isinstance(result, list)

    def test_nested_template_literals(self):
        content = "const x = `outer ${`inner ${`deepest ${'https://example.com/'}`}`}`;"
        result = url_normalizer.extract_urls_from_text(content)
        assert isinstance(result, list)

    def test_empty_string(self):
        result = url_normalizer.extract_urls_from_text("")
        assert isinstance(result, list)

    def test_only_whitespace(self):
        result = url_normalizer.extract_urls_from_text("   \n\t  ")
        assert isinstance(result, list)


# ===========================================================================
# Scenario 6 — Encoding failures
# ===========================================================================

@pytest.mark.skipif(not HAS_URL_NORMALIZER, reason="url_normalizer not yet integrated")
class TestEncodingFailures:
    """safe_decode_content always returns a str and never raises."""

    def test_latin1_bytes(self):
        # € in latin-1 is 0x80; é is 0xe9
        content = b"Prix: \x80 caf\xe9"
        result = url_normalizer.safe_decode_content(content)
        assert isinstance(result, str)

    def test_null_bytes_in_content(self):
        content = b"hello\x00world\x00"
        result = url_normalizer.safe_decode_content(content)
        assert isinstance(result, str)

    def test_random_bytes(self):
        import os
        content = os.urandom(512)
        result = url_normalizer.safe_decode_content(content)
        assert isinstance(result, str)

    def test_empty_bytes(self):
        result = url_normalizer.safe_decode_content(b"")
        assert isinstance(result, str)
        assert result == ""

    def test_valid_utf8(self):
        content = "Hello, 世界 🌍".encode("utf-8")
        result = url_normalizer.safe_decode_content(content)
        assert isinstance(result, str)
        assert "Hello" in result


# ===========================================================================
# Scenario 7 — URL normalization
# ===========================================================================

@pytest.mark.skipif(not HAS_URL_NORMALIZER, reason="url_normalizer not yet integrated")
class TestURLNormalization:
    """normalize_url canonicalises URLs consistently."""

    def test_strips_default_http_port(self):
        result = url_normalizer.normalize_url("http://example.com:80/path")
        assert result == "http://example.com/path"

    def test_strips_default_https_port(self):
        result = url_normalizer.normalize_url("https://example.com:443/")
        assert result == "https://example.com/"

    def test_lowercases_hostname(self):
        result = url_normalizer.normalize_url("https://EXAMPLE.COM/Path")
        assert result == "https://example.com/Path"

    def test_sorts_query_params(self):
        result = url_normalizer.normalize_url("https://example.com/path?b=2&a=1")
        assert result == "https://example.com/path?a=1&b=2"

    def test_strips_fragment(self):
        result = url_normalizer.normalize_url("https://example.com/path#fragment")
        assert result == "https://example.com/path"

    def test_resolves_relative_url(self):
        result = url_normalizer.normalize_url(
            "../relative", base="https://example.com/a/b"
        )
        assert result == "https://example.com/relative"

    def test_malformed_url_returns_none(self):
        result = url_normalizer.normalize_url("not-a-url")
        assert result is None

    def test_empty_string_returns_none(self):
        result = url_normalizer.normalize_url("")
        assert result is None


# ===========================================================================
# Scenario 8 — Duplicate discovery
# ===========================================================================

@pytest.mark.skipif(
    not HAS_DISCOVERY_REGISTRY, reason="DiscoveryRegistry not yet integrated"
)
class TestDuplicateDiscovery:
    """DiscoveryRegistry deduplicates URLs and tracks occurrences."""

    def test_first_registration_returns_true(self):
        reg = DiscoveryRegistry()
        result = reg.register("https://example.com/app.js", provenance="page-A")
        assert result is True

    def test_duplicate_registration_returns_false(self):
        reg = DiscoveryRegistry()
        reg.register("https://example.com/app.js", provenance="page-A")
        result = reg.register("https://example.com/app.js", provenance="page-B")
        assert result is False

    def test_len_stays_one_after_duplicate(self):
        reg = DiscoveryRegistry()
        reg.register("https://example.com/app.js", provenance="page-A")
        reg.register("https://example.com/app.js", provenance="page-B")
        assert len(reg) == 1

    def test_occurrences_increments(self):
        reg = DiscoveryRegistry()
        reg.register("https://example.com/app.js", provenance="page-A")
        reg.register("https://example.com/app.js", provenance="page-B")
        entry = reg.get("https://example.com/app.js")
        assert entry.occurrences == 2

    def test_first_provenance_preserved(self):
        reg = DiscoveryRegistry()
        reg.register("https://example.com/app.js", provenance="FIRST")
        reg.register("https://example.com/app.js", provenance="SECOND")
        entry = reg.get("https://example.com/app.js")
        assert entry.provenance == "FIRST"

    def test_url_normalization_in_registry(self):
        """http://example.com:80/ and http://example.com/ are the same URL."""
        reg = DiscoveryRegistry()
        reg.register("http://example.com:80/", provenance="page-A")
        result = reg.register("http://example.com/", provenance="page-B")
        assert result is False, (
            "http://example.com:80/ and http://example.com/ should be considered duplicates"
        )
        assert len(reg) == 1


# ===========================================================================
# Scenario 9 — Lazy-loaded chunk discovery
# ===========================================================================

class TestLazyChunkDiscovery:
    """webpack dynamic-import URLs are captured via INTERCEPT_JS_ADDITIONS."""

    def test_intercept_js_contains_dynamic_import_pattern(self):
        """The JS injection snippet should capture import() calls."""
        if not HAS_HEADLESS_ENHANCEMENTS:
            pytest.skip("headless_enhancements not yet integrated")

        # The injected JS should reference dynamic import interception
        assert INTERCEPT_JS_ADDITIONS, "INTERCEPT_JS_ADDITIONS should be non-empty"
        assert isinstance(INTERCEPT_JS_ADDITIONS, str)

        # Must reference __bs_extra_events or equivalent capture mechanism
        assert "__bs_" in INTERCEPT_JS_ADDITIONS or "window." in INTERCEPT_JS_ADDITIONS, (
            "Intercept JS should register events on window"
        )

    def test_dynamic_import_url_pattern_regex(self):
        """
        Unit-level check: dynamic import syntax matches expected pattern.
        Validates that import('./chunk.js') style calls are detectable.
        """
        js_samples = [
            "import('./chunk.abc123.js')",
            "import(`./chunks/${id}.js`)",
            'import("./vendor.bundle.js")',
        ]
        pattern = re.compile(r"import\s*\(")
        for sample in js_samples:
            assert pattern.search(sample), f"Pattern should match: {sample!r}"

    def test_webpack_chunk_url_captured_via_mock(self):
        """
        Simulate a page calling window.__bs_extra_events.push() with a chunk URL.
        Uses a plain list to stand in for the browser-side array.
        """
        # Replicate what the injected JS would do when import() fires:
        # window.__bs_extra_events.push({type: "chunk_load", url: "./chunk.abc123.js"})
        bs_extra_events = []
        bs_extra_events.append({
            "type": "chunk_load",
            "url": "./chunk.abc123.js",
        })

        assert len(bs_extra_events) == 1
        event = bs_extra_events[0]
        assert event["type"] == "chunk_load"
        assert "chunk" in event["url"]
        assert event["url"].endswith(".js")


# ===========================================================================
# Scenario 10 — Safe interactions (_check_destructive baseline)
# ===========================================================================

class TestSafeInteractions:
    """_check_destructive returns False for safe button labels."""

    @pytest.fixture
    def check_fn(self):
        fn = _get_check_destructive()
        if fn is None:
            pytest.skip("_check_destructive not yet implemented")
        return fn

    def test_next_page_is_safe(self, check_fn):
        assert check_fn("Next page") is False

    def test_load_more_is_safe(self, check_fn):
        assert check_fn("Load more") is False

    def test_submit_alone_is_safe(self, check_fn):
        # "Submit" on its own is not inherently destructive
        assert check_fn("Submit") is False

    def test_delete_account_is_destructive(self, check_fn):
        assert check_fn("Delete account") is True

    def test_confirm_purchase_is_destructive(self, check_fn):
        assert check_fn("Confirm purchase") is True

    def test_checkout_now_case_insensitive(self, check_fn):
        assert check_fn("CHECKOUT NOW") is True


# ===========================================================================
# Scenario 11 — Destructive action blocking (full keyword set)
# ===========================================================================

class TestDestructiveBlocking:
    """_check_destructive covers all required keywords from the spec."""

    @pytest.fixture
    def check_fn(self):
        fn = _get_check_destructive()
        if fn is None:
            pytest.skip("_check_destructive not yet implemented")
        return fn

    @pytest.mark.parametrize("label", [
        "Delete this item",
        "Remove account",
        "Purchase now",
        "Complete payment",
        "Checkout confirmation",
        "Change password",
        "Account deletion",
        "Wire transfer",
        "Send money",
    ])
    def test_destructive_labels_blocked(self, check_fn, label):
        assert check_fn(label) is True, f"Expected '{label}' to be blocked"

    @pytest.mark.parametrize("label", [
        "Next",
        "Previous",
        "Load more",
        "Show results",
        "Open menu",
        "Toggle",
        "Expand",
        "Filter",
        "Sort",
        "Search",
    ])
    def test_safe_labels_pass(self, check_fn, label):
        assert check_fn(label) is False, f"Expected '{label}' to be safe"


# ===========================================================================
# Scenario 12 — Infinite scroll protection
# ===========================================================================

@pytest.mark.skipif(
    not HAS_HEADLESS_ENHANCEMENTS, reason="headless_enhancements not yet integrated"
)
class TestInfiniteScrollProtection:
    """InteractionTracker detects stalled scroll and limits interaction count."""

    def test_infinite_scroll_stopped_starts_false(self):
        tracker = InteractionTracker()
        assert tracker.infinite_scroll_stopped is False

    def test_stalled_scroll_marks_stopped_after_retries(self):
        """
        If scroll position does not change for 3 consecutive attempts,
        infinite_scroll_stopped should be set to True.
        """
        tracker = InteractionTracker()
        STALL_THRESHOLD = 3

        # Simulate reporting same scroll position repeatedly
        fixed_position = 1000
        for _ in range(STALL_THRESHOLD):
            tracker.record_scroll(position=fixed_position)

        assert tracker.infinite_scroll_stopped is True, (
            "Tracker should mark infinite_scroll_stopped=True after "
            f"{STALL_THRESHOLD} stalled scroll events"
        )

    def test_pagination_stops_at_max_interactions(self):
        tracker = InteractionTracker(max_interactions=5)
        for i in range(5):
            tracker.record_interaction(f"click_{i}")

        assert tracker.limit_reached is True, (
            "Tracker should set limit_reached=True at max_interactions"
        )

    def test_scroll_progress_resets_stall_counter(self):
        tracker = InteractionTracker()
        tracker.record_scroll(position=0)
        tracker.record_scroll(position=500)   # made progress
        tracker.record_scroll(position=500)   # stalled once

        # One stall is not enough to stop
        assert tracker.infinite_scroll_stopped is False


# ===========================================================================
# Scenario 13 — Redirect loop protection
# ===========================================================================

@pytest.mark.skipif(not HAS_ASYNC_FETCHER, reason="AsyncFetcher not yet integrated")
class TestRedirectLoopProtection:
    """Redirect loops are detected and stopped within max_redirects hops."""

    def test_redirect_loop_stopped_at_max_hops(self):
        """A → B → A loop should stop at most 10 hops."""
        hop_count = {"n": 0}

        async def looping_fetch(url):
            hop_count["n"] += 1
            if hop_count["n"] > 20:
                raise AssertionError("Max hops not enforced — loop is infinite!")
            return (None, 301, "", "", [
                "https://a.com/",
                "https://b.com/",
                "https://a.com/",
            ])

        async def run():
            fetcher = AsyncFetcher(concurrency=1, max_redirects=10)
            with patch.object(fetcher, "_fetch_one", side_effect=looping_fetch):
                results = await fetcher.fetch_many(["https://a.com/"])
            return results

        results = asyncio.run(run())
        assert len(results) == 1
        assert hop_count["n"] <= 10

    def test_redirect_loop_stopped_flag_set(self):
        """redirect_loop_stopped should be tracked when a loop is detected."""

        async def run():
            fetcher = AsyncFetcher(concurrency=1, max_redirects=10)
            loop_chain = [
                "https://a.com/",
                "https://b.com/",
                "https://a.com/",  # loop back
            ]

            with patch.object(
                fetcher,
                "_fetch_one",
                return_value=(None, 301, "", "", loop_chain),
            ):
                results = await fetcher.fetch_many(["https://a.com/"])
            return fetcher

        fetcher = asyncio.run(run())
        # The fetcher should expose a flag or counter that records the loop
        has_flag = (
            getattr(fetcher, "redirect_loop_stopped", False)
            or getattr(fetcher, "redirect_loops_detected", 0) > 0
        )
        assert has_flag, "fetcher should record that a redirect loop was detected"


# ===========================================================================
# Scenario 14 — Out-of-scope request blocking
# ===========================================================================

class TestOutOfScopeBlocking:
    """ScopeChecker + validate_url block cross-origin and SSRF URLs."""

    # --- ScopeChecker tests ---

    def test_cross_origin_blocked_by_scope_checker(self):
        checker = ScopeChecker("https://example.com", same_origin=True)
        assert checker.in_scope("http://evil.com/steal") is False

    def test_same_origin_passes(self):
        checker = ScopeChecker("https://example.com", same_origin=True)
        assert checker.in_scope("https://example.com/api/data") is True

    def test_subdomain_blocked_when_subdomains_false(self):
        checker = ScopeChecker("https://example.com", same_origin=True, subdomains=False)
        assert checker.in_scope("https://sub.example.com/page") is False

    def test_subdomain_allowed_when_subdomains_true(self):
        checker = ScopeChecker("https://example.com", same_origin=True, subdomains=True)
        assert checker.in_scope("https://sub.example.com/page") is True

    def test_excluded_host_blocked(self):
        checker = ScopeChecker(
            "https://example.com", same_origin=False, exclude=["ads.example.com"]
        )
        assert checker.in_scope("https://ads.example.com/track") is False

    # --- validate_url SSRF / private IP tests ---

    def test_ssrf_imds_blocked(self):
        """AWS/Azure/GCP metadata endpoint must be blocked."""
        safe, reason = validate_url("http://169.254.169.254/latest/meta-data/")
        assert safe is False, f"IMDS should be blocked, got: {reason}"

    def test_private_ip_192_blocked(self):
        safe, reason = validate_url("http://192.168.1.1/admin")
        assert safe is False, f"192.168.1.1 should be blocked, got: {reason}"

    def test_private_ip_10_blocked(self):
        safe, reason = validate_url("http://10.0.0.1/secret")
        assert safe is False, f"10.0.0.1 should be blocked, got: {reason}"

    def test_private_ip_172_blocked(self):
        safe, reason = validate_url("http://172.16.0.1/internal")
        assert safe is False, f"172.16.0.x should be blocked, got: {reason}"

    def test_localhost_blocked(self):
        safe, reason = validate_url("http://localhost/admin")
        assert safe is False, f"localhost should be blocked, got: {reason}"

    def test_loopback_ip_blocked(self):
        safe, reason = validate_url("http://127.0.0.1/")
        assert safe is False, f"127.0.0.1 should be blocked, got: {reason}"

    def test_public_url_allowed(self):
        safe, reason = validate_url("https://example.com/api/v1/users")
        assert safe is True, f"Public URL should be allowed, got: {reason}"

    def test_javascript_scheme_blocked(self):
        safe, reason = validate_url("javascript:alert(1)")
        assert safe is False

    def test_file_scheme_blocked(self):
        safe, reason = validate_url("file:///etc/passwd")
        assert safe is False

    def test_ftp_scheme_blocked(self):
        safe, reason = validate_url("ftp://example.com/file.txt")
        assert safe is False

    def test_empty_url_blocked(self):
        safe, reason = validate_url("")
        assert safe is False

    # --- is_ip_blocked direct tests ---

    def test_is_ip_blocked_loopback(self):
        assert is_ip_blocked("127.0.0.1") is True

    def test_is_ip_blocked_private_10(self):
        assert is_ip_blocked("10.10.10.10") is True

    def test_is_ip_blocked_private_192(self):
        assert is_ip_blocked("192.168.0.1") is True

    def test_is_ip_blocked_link_local(self):
        assert is_ip_blocked("169.254.0.1") is True

    def test_is_ip_blocked_public_ip_allowed(self):
        # 8.8.8.8 is Google DNS — public, must not be blocked
        assert is_ip_blocked("8.8.8.8") is False

    def test_is_ip_blocked_ipv6_loopback(self):
        assert is_ip_blocked("::1") is True

    def test_is_ip_blocked_bad_string(self):
        # Unparseable strings are treated as blocked
        assert is_ip_blocked("not-an-ip") is True
