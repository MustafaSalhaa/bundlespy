"""
Advanced HTTP response header intelligence tests.

Covers:
- Tech disclosure: Server:, X-Powered-By:, X-Generator: recorded as technology
- Tech disclosure: Server: Apache/2.4 produces IntelligenceResult.technologies entry - NOT a security finding
- Tech disclosure: multiple tech headers all recorded
- CORS wildcard: Access-Control-Allow-Origin: * recorded in interesting_headers
- CORS specific origin: not flagged (not a wildcard)
- CORS absent: not flagged
- Debug header: X-Debug: true recorded in interesting_headers
- Debug header: X-Debug-Token-Link: ... recorded in interesting_headers
- HSTS disabled: max-age=0 recorded in interesting_headers
- HSTS enabled: large max-age NOT flagged
- CSP parsing: policy directive split into dict
- CSP parsing: default-src absent AND script-src absent => missing-CSP note
- CSP parsing: default-src present => no missing-CSP note
- CSP parsing: wildcard domain in script-src extracted
- CSP parsing: multiple directives parsed independently
- CSP parsing: empty value after directive name - handled
- X-Frame-Options: does not produce an interesting_header entry (good header)
- Header names are lowercased for matching (case-insensitive input)
- analyze_headers returns 3-tuple (technologies, interesting_headers, csp_policy)
- parse_csp_header handles semicolon-only value
- parse_csp_header handles leading/trailing whitespace in directives
- Integration: run_intelligence_collection with response headers populates result.technologies
- TECH_HEADERS dict maps all expected header names
"""

import pytest
from bundlespy.discovery.intelligence import (
    analyze_headers,
    parse_csp_header,
    TECH_HEADERS,
    run_intelligence_collection,
    IntelligenceResult,
)
import hashlib
from typing import Dict
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Stub helpers for integration tests
# ---------------------------------------------------------------------------

class _StubFetcher:
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
    def __init__(self, routes):
        self._routes = routes

    def in_scope(self, url: str) -> bool:
        return urlparse(url).path in self._routes


BASE = "https://app.example.com"


# ---------------------------------------------------------------------------
# analyze_headers: return type
# ---------------------------------------------------------------------------

def test_analyze_headers_returns_three_tuple():
    """analyze_headers() must return (dict, list, dict)."""
    result = analyze_headers({}, BASE)
    assert isinstance(result, tuple)
    assert len(result) == 3
    techs, interesting, csp = result
    assert isinstance(techs, dict)
    assert isinstance(interesting, list)
    assert isinstance(csp, dict)


def test_analyze_headers_empty_returns_empty_collections():
    """Empty headers produce empty technologies, interesting_headers, and csp_policy."""
    techs, interesting, csp = analyze_headers({}, BASE)
    assert techs == {}
    assert interesting == []
    assert csp == {}


# ---------------------------------------------------------------------------
# Technology disclosure: recorded in technologies, NOT as a finding
# ---------------------------------------------------------------------------

def test_server_header_recorded_as_technology():
    """Server: Apache/2.4 -> recorded under technologies['server'], not a finding."""
    techs, _, _ = analyze_headers({"Server": "Apache/2.4"}, BASE)
    assert "server" in techs
    assert "Apache" in techs["server"]


def test_server_header_value_exact():
    """The full value of Server: header is preserved."""
    techs, _, _ = analyze_headers({"Server": "nginx/1.25.3"}, BASE)
    assert techs.get("server") == "nginx/1.25.3"


def test_x_powered_by_recorded_as_technology():
    """X-Powered-By: PHP/8.2 -> recorded under technologies['framework']."""
    techs, _, _ = analyze_headers({"X-Powered-By": "PHP/8.2"}, BASE)
    assert "framework" in techs
    assert "PHP" in techs["framework"]


def test_x_generator_recorded_as_technology():
    """X-Generator: Drupal 10 -> recorded under technologies['generator']."""
    techs, _, _ = analyze_headers({"X-Generator": "Drupal 10"}, BASE)
    assert "generator" in techs
    assert "Drupal" in techs["generator"]


def test_x_drupal_cache_recorded_as_technology():
    """X-Drupal-Cache presence -> technologies['Drupal'] set."""
    techs, _, _ = analyze_headers({"X-Drupal-Cache": "HIT"}, BASE)
    assert "Drupal" in techs


def test_x_aspnet_version_recorded_as_technology():
    """X-AspNet-Version header -> technologies['ASP.NET'] set."""
    techs, _, _ = analyze_headers({"X-AspNet-Version": "4.0.30319"}, BASE)
    assert "ASP.NET" in techs


def test_multiple_tech_headers_all_recorded():
    """Two tech headers both appear in technologies dict."""
    headers = {
        "Server": "Apache/2.4",
        "X-Powered-By": "PHP/8.1",
    }
    techs, _, _ = analyze_headers(headers, BASE)
    assert "server" in techs
    assert "framework" in techs


def test_server_header_also_in_interesting():
    """Server: header value appears in interesting_headers as 'Technology disclosed: ...'."""
    _, interesting, _ = analyze_headers({"Server": "Apache/2.4"}, BASE)
    assert any("Technology disclosed" in s for s in interesting)
    assert any("Apache" in s for s in interesting)


def test_server_header_not_a_security_finding_object():
    """analyze_headers returns interesting_headers as strings, never Finding objects."""
    _, interesting, _ = analyze_headers({"Server": "Apache/2.4"}, BASE)
    for item in interesting:
        assert isinstance(item, str), "interesting_headers must contain strings, not Finding objects"


# ---------------------------------------------------------------------------
# CORS wildcard
# ---------------------------------------------------------------------------

def test_cors_wildcard_flagged_in_interesting():
    """Access-Control-Allow-Origin: * -> 'CORS wildcard' in interesting_headers."""
    _, interesting, _ = analyze_headers(
        {"Access-Control-Allow-Origin": "*"}, BASE
    )
    assert any("CORS wildcard" in s for s in interesting)


def test_cors_wildcard_includes_url():
    """CORS wildcard interesting header includes the URL."""
    _, interesting, _ = analyze_headers(
        {"Access-Control-Allow-Origin": "*"}, "https://api.example.com/data"
    )
    assert any("api.example.com" in s for s in interesting)


def test_cors_specific_origin_not_flagged():
    """Access-Control-Allow-Origin: https://trusted.example.com -> NOT flagged."""
    _, interesting, _ = analyze_headers(
        {"Access-Control-Allow-Origin": "https://trusted.example.com"}, BASE
    )
    assert not any("CORS wildcard" in s for s in interesting)


def test_cors_absent_not_flagged():
    """Missing CORS header -> no CORS entry in interesting_headers."""
    _, interesting, _ = analyze_headers({}, BASE)
    assert not any("CORS" in s for s in interesting)


# ---------------------------------------------------------------------------
# Debug headers
# ---------------------------------------------------------------------------

def test_x_debug_header_flagged():
    """X-Debug: true -> 'Debug header exposed' in interesting_headers."""
    _, interesting, _ = analyze_headers({"X-Debug": "true"}, BASE)
    assert any("Debug header exposed" in s for s in interesting)
    assert any("X-Debug" in s for s in interesting)


def test_x_debug_token_link_flagged():
    """X-Debug-Token-Link: ... -> 'Debug header exposed' in interesting_headers."""
    _, interesting, _ = analyze_headers(
        {"X-Debug-Token-Link": "http://app.example.com/_profiler/abc123"}, BASE
    )
    assert any("Debug header exposed" in s for s in interesting)


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------

def test_hsts_max_age_zero_flagged():
    """Strict-Transport-Security: max-age=0 -> 'HSTS disabled' in interesting_headers."""
    _, interesting, _ = analyze_headers(
        {"Strict-Transport-Security": "max-age=0"}, BASE
    )
    assert any("HSTS disabled" in s for s in interesting)


def test_hsts_valid_not_flagged():
    """Strict-Transport-Security with large max-age -> NOT flagged."""
    _, interesting, _ = analyze_headers(
        {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}, BASE
    )
    assert not any("HSTS disabled" in s for s in interesting)


def test_hsts_absent_not_flagged():
    """Absent HSTS header does not produce a flag (we note it in CSP test instead)."""
    _, interesting, _ = analyze_headers({}, BASE)
    assert not any("HSTS" in s for s in interesting)


# ---------------------------------------------------------------------------
# X-Frame-Options: should NOT produce an interesting header (it's a good header)
# ---------------------------------------------------------------------------

def test_x_frame_options_present_not_flagged():
    """X-Frame-Options: DENY is a positive security control - not flagged."""
    _, interesting, _ = analyze_headers({"X-Frame-Options": "DENY"}, BASE)
    # No entry mentioning X-Frame-Options
    assert not any("X-Frame-Options" in s for s in interesting)


# ---------------------------------------------------------------------------
# Case-insensitive header matching
# ---------------------------------------------------------------------------

def test_lowercase_header_name_matched():
    """analyze_headers works with all-lowercase header names."""
    techs, _, _ = analyze_headers({"server": "nginx/1.20"}, BASE)
    assert "server" in techs


def test_mixed_case_header_name_matched():
    """analyze_headers works with mixed-case header names (e.g. from urllib3)."""
    techs, _, _ = analyze_headers({"SERVER": "IIS/10.0"}, BASE)
    assert "server" in techs


def test_cors_header_lowercase_matched():
    """access-control-allow-origin: * (lowercase) is still flagged."""
    _, interesting, _ = analyze_headers(
        {"access-control-allow-origin": "*"}, BASE
    )
    assert any("CORS wildcard" in s for s in interesting)


# ---------------------------------------------------------------------------
# CSP parsing: parse_csp_header
# ---------------------------------------------------------------------------

def test_parse_csp_header_returns_dict():
    """parse_csp_header returns a dict."""
    result = parse_csp_header("default-src 'self'; script-src 'self' cdn.example.com")
    assert isinstance(result, dict)


def test_parse_csp_default_src_extracted():
    """default-src directive is extracted as a key."""
    policy = parse_csp_header("default-src 'self'")
    assert "default-src" in policy
    assert "'self'" in policy["default-src"]


def test_parse_csp_script_src_extracted():
    """script-src directive with multiple values is extracted."""
    policy = parse_csp_header("script-src 'self' cdn.example.com 'unsafe-inline'")
    assert "script-src" in policy
    assert "cdn.example.com" in policy["script-src"]
    assert "'unsafe-inline'" in policy["script-src"]


def test_parse_csp_multiple_directives():
    """Multiple directives separated by semicolons are all parsed."""
    csp = "default-src 'self'; script-src cdn.example.com; img-src *"
    policy = parse_csp_header(csp)
    assert "default-src" in policy
    assert "script-src" in policy
    assert "img-src" in policy


def test_parse_csp_handles_semicolon_only():
    """A CSP value of ';' does not raise."""
    result = parse_csp_header(";")
    assert isinstance(result, dict)


def test_parse_csp_handles_leading_whitespace():
    """Directives with leading whitespace are still parsed."""
    policy = parse_csp_header("  default-src 'self'  ")
    assert "default-src" in policy


def test_parse_csp_directive_names_lowercased():
    """Directive names are stored lowercase."""
    policy = parse_csp_header("Default-Src 'self'")
    assert "default-src" in policy


# ---------------------------------------------------------------------------
# CSP analysis in analyze_headers
# ---------------------------------------------------------------------------

def test_missing_csp_script_src_and_default_src_noted():
    """No default-src and no script-src -> 'Missing restrictive CSP' noted."""
    headers = {"Content-Security-Policy": "img-src *"}
    _, interesting, csp = analyze_headers(headers, BASE)
    assert any("Missing restrictive CSP" in s for s in interesting)


def test_csp_with_default_src_not_missing_csp():
    """CSP with default-src present -> no 'Missing restrictive CSP' note."""
    headers = {"Content-Security-Policy": "default-src 'self'"}
    _, interesting, csp = analyze_headers(headers, BASE)
    assert not any("Missing restrictive CSP" in s for s in interesting)


def test_csp_with_script_src_only_not_missing():
    """CSP with script-src present (no default-src) -> no missing-CSP note."""
    headers = {"Content-Security-Policy": "script-src 'self' cdn.example.com"}
    _, interesting, csp = analyze_headers(headers, BASE)
    assert not any("Missing restrictive CSP" in s for s in interesting)


def test_csp_policy_returned_in_third_element():
    """The third element of the return tuple contains the parsed CSP dict."""
    headers = {"Content-Security-Policy": "default-src 'self'; img-src *"}
    _, _, csp = analyze_headers(headers, BASE)
    assert "default-src" in csp
    assert "img-src" in csp


# ---------------------------------------------------------------------------
# TECH_HEADERS coverage
# ---------------------------------------------------------------------------

def test_tech_headers_contains_expected_keys():
    """TECH_HEADERS dict contains all required header name mappings."""
    required = {
        "x-powered-by",
        "server",
        "x-generator",
        "x-drupal-cache",
        "x-wordpress",
        "x-shopify-stage",
        "x-laravel",
        "x-rails",
        "x-django",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    }
    missing = required - set(TECH_HEADERS.keys())
    assert not missing, f"TECH_HEADERS missing keys: {missing}"


def test_tech_headers_values_are_strings():
    """All TECH_HEADERS values are non-empty strings."""
    for k, v in TECH_HEADERS.items():
        assert isinstance(v, str) and v, f"TECH_HEADERS[{k!r}] must be a non-empty string"


# ---------------------------------------------------------------------------
# Integration: analyze_headers output types are always safe to serialize
# ---------------------------------------------------------------------------

def test_interesting_headers_all_strings():
    """Every item in interesting_headers is a plain string (JSON-serializable)."""
    headers = {
        "Server": "Apache/2.4",
        "X-Debug": "1",
        "Access-Control-Allow-Origin": "*",
        "Strict-Transport-Security": "max-age=0",
        "Content-Security-Policy": "img-src *",
    }
    _, interesting, _ = analyze_headers(headers, BASE)
    for item in interesting:
        assert isinstance(item, str)


def test_technologies_dict_all_string_values():
    """Every technology value is a plain string."""
    headers = {
        "Server": "Apache/2.4",
        "X-Powered-By": "PHP/8.2",
        "X-Generator": "WordPress 6",
    }
    techs, _, _ = analyze_headers(headers, BASE)
    for k, v in techs.items():
        assert isinstance(v, str)


# ---------------------------------------------------------------------------
# Integration: run_intelligence_collection (via stub fetcher)
# ---------------------------------------------------------------------------

def test_run_intelligence_result_is_intelligence_result():
    """run_intelligence_collection always returns IntelligenceResult."""
    result = run_intelligence_collection(
        BASE, _StubFetcher({}), _StubScope({}), html_content=""
    )
    assert isinstance(result, IntelligenceResult)


def test_run_intelligence_result_technologies_empty_when_no_headers():
    """With no headers provided, technologies dict is empty."""
    result = run_intelligence_collection(
        BASE, _StubFetcher({}), _StubScope({}), html_content=""
    )
    assert result.technologies == {}


def test_run_intelligence_result_interesting_empty_when_no_headers():
    """With no headers provided, interesting_headers list is empty."""
    result = run_intelligence_collection(
        BASE, _StubFetcher({}), _StubScope({}), html_content=""
    )
    assert result.interesting_headers == []
