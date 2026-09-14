"""
Passive Intelligence Collector for BundleSpy.

Collects everything available from a target without any exploitation:
- Sitemap parsing for full URL discovery
- robots.txt path hints
- Well-known paths (security.txt, openid-config, etc.)
- OpenAPI/Swagger schema discovery
- CSS file analysis for URLs and assets
- HTTP response header intelligence
- JSON endpoint discovery and analysis
- Favicon fingerprinting
- Error page intelligence
- Technology stack detection from headers and content
- Content Security Policy parsing
- Link header parsing
- Meta tag intelligence
"""

import re
import json
import xml.etree.ElementTree as ET
import hashlib
import logging
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.intelligence")


# Well-known paths that reveal intelligence
WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/security.txt",
]

# API documentation paths
API_DOC_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/graphql/schema",
    "/schema.graphql",
    "/api/schema",
    "/__schema",
]

# Sitemap paths
SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemaps/sitemap.xml",
    "/sitemap/sitemap.xml",
    "/wp-sitemap.xml",
    "/news-sitemap.xml",
    "/image-sitemap.xml",
]

# CSS regex patterns
RE_CSS_URL       = re.compile(r'url\(["\']?([^)"\']+)["\']?\)', re.IGNORECASE)
RE_CSS_IMPORT    = re.compile(r'@import\s+["\']([^"\']+)["\']', re.IGNORECASE)
RE_CSS_FONT_FACE = re.compile(r'@font-face\s*\{[^}]*src\s*:[^}]+url\(["\']?([^)"\']+)["\']?\)', re.IGNORECASE | re.DOTALL)

# JSON patterns for endpoint discovery
RE_JSON_URL      = re.compile(r'"(?:url|href|endpoint|path|api|link|action)"\s*:\s*"(/[^"]{2,100})"', re.IGNORECASE)
RE_JSON_FULL_URL = re.compile(r'"(?:url|href|endpoint|path|api|link|action)"\s*:\s*"(https?://[^"]{5,200})"', re.IGNORECASE)

# Meta tag patterns
RE_META_CONTENT  = re.compile(r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
RE_META_CONTENT2 = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:name|property)=["\']([^"\']+)["\']', re.IGNORECASE)

# CSP header parsing
RE_CSP_DIRECTIVE = re.compile(r"(\w[\w\-]+)\s+([^;]+)", re.IGNORECASE)

# Technology detection from headers
TECH_HEADERS = {
    "x-powered-by":        "framework",
    "server":              "server",
    "x-generator":         "generator",
    "x-drupal-cache":      "Drupal",
    "x-wordpress":         "WordPress",
    "x-shopify-stage":     "Shopify",
    "x-laravel":           "Laravel",
    "x-rails":             "Ruby on Rails",
    "x-django":            "Django",
    "x-aspnet-version":    "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
}


@dataclass
class IntelligenceResult:
    """All passive intelligence gathered from a target."""
    target:          str
    urls_discovered: List[str]         = field(default_factory=list)
    api_endpoints:   List[str]         = field(default_factory=list)
    technologies:    Dict[str, str]    = field(default_factory=dict)
    headers:         Dict[str, str]    = field(default_factory=dict)
    csp_policy:      Dict[str, List]   = field(default_factory=dict)
    security_txt:    Optional[str]     = None
    openid_config:   Optional[dict]    = None
    api_schema:      Optional[dict]    = None
    sitemap_urls:    List[str]         = field(default_factory=list)
    css_urls:        List[str]         = field(default_factory=list)
    meta_tags:       Dict[str, str]    = field(default_factory=dict)
    interesting_headers: List[str]     = field(default_factory=list)
    errors:          List[str]         = field(default_factory=list)


def _safe_get(fetcher, url: str) -> Tuple[Optional[str], int, dict]:
    """Fetch a URL and return content, status, headers."""
    try:
        safe, _ = validate_url(url)
        if not safe:
            return None, 0, {}
        content, status, ct, _ = fetcher.get(url)
        return content, status, {}
    except Exception:
        return None, 0, {}


def collect_sitemap_urls(fetcher, base_url: str) -> List[str]:
    """Parse all sitemap.xml files and extract URLs."""
    urls: Set[str] = set()
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Check robots.txt for sitemap location first
    robots_content, status, _ = _safe_get(fetcher, base + "/robots.txt")
    if robots_content and status == 200:
        for line in robots_content.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if sitemap_url.startswith("http"):
                    SITEMAP_PATHS.append(urlparse(sitemap_url).path)

    for path in SITEMAP_PATHS:
        url = base + path
        content, status, _ = _safe_get(fetcher, url)
        if not content or status != 200:
            continue

        try:
            root = ET.fromstring(content)
            ns   = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

            # Sitemap index — contains other sitemaps
            for sitemap in root.findall(".//sm:sitemap/sm:loc", ns):
                sub_url = sitemap.text.strip() if sitemap.text else ""
                if sub_url:
                    sub_content, sub_status, _ = _safe_get(fetcher, sub_url)
                    if sub_content and sub_status == 200:
                        try:
                            sub_root = ET.fromstring(sub_content)
                            for loc in sub_root.findall(".//sm:url/sm:loc", ns):
                                if loc.text:
                                    urls.add(loc.text.strip())
                        except Exception:
                            pass

            # Regular sitemap
            for loc in root.findall(".//sm:url/sm:loc", ns):
                if loc.text:
                    urls.add(loc.text.strip())

            if urls:
                logger.info("Sitemap: found %d URLs in %s", len(urls), path)

        except ET.ParseError:
            pass

    return list(urls)


def collect_api_schemas(fetcher, base_url: str) -> Optional[dict]:
    """Try to find and parse OpenAPI/Swagger documentation."""
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    for path in API_DOC_PATHS:
        url = base + path
        content, status, _ = _safe_get(fetcher, url)
        if not content or status != 200:
            continue

        try:
            data = json.loads(content)
            # OpenAPI detection
            if "openapi" in data or "swagger" in data:
                logger.info("OpenAPI schema found at: %s", path)
                return {"url": url, "schema": data, "type": "openapi"}
            # Generic API doc
            if "paths" in data or "endpoints" in data:
                return {"url": url, "schema": data, "type": "generic"}
        except (json.JSONDecodeError, ValueError):
            # Try YAML
            try:
                import yaml
                data = yaml.safe_load(content)
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    logger.info("OpenAPI YAML schema found at: %s", path)
                    return {"url": url, "schema": data, "type": "openapi"}
            except Exception:
                pass

    return None


def collect_well_known(fetcher, base_url: str) -> dict:
    """Collect intelligence from /.well-known/ paths."""
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    result = {}

    for path in WELL_KNOWN_PATHS:
        url = base + path
        content, status, _ = _safe_get(fetcher, url)
        if not content or status != 200:
            continue

        logger.info("Well-known found: %s", path)

        if "security.txt" in path:
            result["security_txt"] = content
        elif "openid-configuration" in path:
            try:
                result["openid_config"] = json.loads(content)
            except Exception:
                result["openid_config"] = content
        elif "jwks.json" in path:
            try:
                result["jwks"] = json.loads(content)
                logger.info("JWKS found - %d keys", len(result["jwks"].get("keys", [])))
            except Exception:
                pass

    return result


def analyze_css(fetcher, css_url: str, base_url: str) -> List[str]:
    """Extract URLs from CSS files."""
    urls = []
    content, status, _ = _safe_get(fetcher, css_url)
    if not content or status != 200:
        return urls

    for match in RE_CSS_URL.finditer(content):
        raw = match.group(1).strip()
        if raw and not raw.startswith("data:"):
            absolute = urljoin(css_url, raw)
            safe, _ = validate_url(absolute)
            if safe:
                urls.append(absolute)

    for match in RE_CSS_IMPORT.finditer(content):
        raw = match.group(1).strip()
        absolute = urljoin(css_url, raw)
        safe, _ = validate_url(absolute)
        if safe:
            urls.append(absolute)

    return list(set(urls))


def parse_csp_header(csp: str) -> Dict[str, List[str]]:
    """Parse Content-Security-Policy header into domains by directive."""
    policy: Dict[str, List[str]] = {}
    for directive in csp.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name   = parts[0].lower()
        values = parts[1:]
        policy[name] = values

        # Extract interesting domains
        interesting = [v for v in values if "." in v and not v.startswith("'")]
        if interesting:
            logger.debug("CSP %s: %s", name, interesting)

    return policy


def analyze_headers(headers: dict, url: str) -> Tuple[Dict[str, str], List[str], Dict]:
    """
    Extract intelligence from HTTP response headers.
    Returns (technologies, interesting_headers, csp_policy)
    """
    technologies: Dict[str, str] = {}
    interesting:  List[str]      = []
    csp_policy:   Dict           = {}

    for header, value in headers.items():
        lower = header.lower()

        # Technology detection
        for tech_header, tech_name in TECH_HEADERS.items():
            if lower == tech_header:
                technologies[tech_name] = value
                interesting.append(f"{header}: {value}")

        # Security headers analysis
        if lower == "content-security-policy":
            csp_policy = parse_csp_header(value)
            if not csp_policy.get("default-src") and not csp_policy.get("script-src"):
                interesting.append("Missing restrictive CSP")

        if lower == "strict-transport-security":
            if "max-age=0" in value:
                interesting.append("HSTS disabled (max-age=0)")

        if lower == "x-frame-options":
            pass  # Good to have

        if lower == "access-control-allow-origin":
            if value == "*":
                interesting.append(f"CORS wildcard: {url}")

        if lower == "x-debug" or lower == "x-debug-token-link":
            interesting.append(f"Debug header exposed: {header}: {value}")

        if lower in ("x-powered-by", "server", "x-generator"):
            interesting.append(f"Technology disclosed: {header}: {value}")

    return technologies, interesting, csp_policy


def extract_meta_intelligence(html: str) -> Dict[str, str]:
    """Extract useful intelligence from HTML meta tags."""
    meta: Dict[str, str] = {}

    for match in RE_META_CONTENT.finditer(html):
        name    = match.group(1).strip()
        content = match.group(2).strip()
        if name and content:
            meta[name] = content

    for match in RE_META_CONTENT2.finditer(html):
        content = match.group(1).strip()
        name    = match.group(2).strip()
        if name and content:
            meta[name] = content

    return meta


def extract_json_endpoints(content: str, base_url: str) -> List[str]:
    """Extract API endpoint URLs from JSON responses."""
    endpoints: Set[str] = set()

    for match in RE_JSON_URL.finditer(content):
        path = match.group(1)
        endpoints.add(path)

    for match in RE_JSON_FULL_URL.finditer(content):
        url = match.group(1)
        safe, _ = validate_url(url)
        if safe:
            endpoints.add(url)

    return list(endpoints)


def collect_css_urls(html: str, base_url: str, fetcher) -> List[str]:
    """Find and analyze all CSS files linked from an HTML page."""
    css_urls_found = []

    # Find CSS link tags
    css_pattern = re.compile(
        r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']|'
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']stylesheet["\']',
        re.IGNORECASE,
    )

    all_css_urls = []
    for match in css_pattern.finditer(html):
        raw = match.group(1) or match.group(2)
        if raw:
            absolute = urljoin(base_url, raw.strip())
            safe, _ = validate_url(absolute)
            if safe:
                all_css_urls.append(absolute)

    for css_url in all_css_urls[:10]:  # Limit to 10 CSS files
        urls = analyze_css(fetcher, css_url, base_url)
        css_urls_found.extend(urls)

    return css_urls_found


def run_intelligence_collection(
    target_url: str,
    fetcher,
    scope,
    html_content: str = "",
) -> IntelligenceResult:
    """
    Full passive intelligence collection pipeline.
    Runs all discovery methods and returns consolidated results.
    """
    result = IntelligenceResult(target=target_url)

    logger.info("Starting passive intelligence collection for: %s", target_url)

    # 1 - Sitemap discovery
    logger.info("Collecting sitemap URLs...")
    sitemap_urls = collect_sitemap_urls(fetcher, target_url)
    result.sitemap_urls = sitemap_urls
    result.urls_discovered.extend(sitemap_urls)
    if sitemap_urls:
        logger.info("Sitemap: %d URLs discovered", len(sitemap_urls))

    # 2 - Well-known paths
    logger.info("Checking well-known paths...")
    well_known = collect_well_known(fetcher, target_url)
    result.security_txt  = well_known.get("security_txt")
    result.openid_config = well_known.get("openid_config")
    if well_known:
        logger.info("Well-known: found %d resources", len(well_known))

    # 3 - API schema discovery
    logger.info("Looking for API documentation...")
    api_schema = collect_api_schemas(fetcher, target_url)
    result.api_schema = api_schema
    if api_schema:
        schema = api_schema.get("schema", {})
        paths  = list(schema.get("paths", {}).keys())
        result.api_endpoints.extend(paths)
        logger.info("API schema: found %d endpoints", len(paths))

    # 4 - CSS analysis
    if html_content:
        logger.info("Analyzing CSS files...")
        css_urls = collect_css_urls(html_content, target_url, fetcher)
        result.css_urls = css_urls
        if css_urls:
            logger.info("CSS: found %d asset URLs", len(css_urls))

    # 5 - Meta tag intelligence
    if html_content:
        meta = extract_meta_intelligence(html_content)
        result.meta_tags = meta

    return result
