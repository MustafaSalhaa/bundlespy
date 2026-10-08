"""
ConfigurationMapper - THE ONLY MAPPER THAT MAKES HTTP REQUESTS.
Probes common configuration/debug paths with safe GET requests.
All other mappers work from collected ScanResult data only.
"""
from typing import List
from urllib.parse import urlparse

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, SurfaceStatus, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ..safety import SurfaceSafetyPolicy
from ...storage.models import ScanResult, Endpoint

# Paths that are public by design - accessible = expected, not a finding
_INFORMATIONAL_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}

# Comprehensive list of common config/debug paths to probe
CONFIG_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/robots.txt", "/sitemap.xml",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/playground",
    "/phpinfo.php", "/info.php", "/server-info",
    "/admin", "/administrator",
    "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
    "/config.json", "/config.yaml", "/settings.json",
    "/backup", "/backup.zip", "/backup.sql", "/dump.sql",
    "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/web.config", "/appsettings.json",
    "/server-status", "/server-info",
    "/metrics", "/health", "/status", "/ping",
    "/console", "/phpmyadmin", "/adminer",
]

# Burp notes per path category
_BURP_NOTES_MAP = {
    "/.env":       "/.env exposed - download immediately. Check for DB credentials, API keys, app secrets.",
    "/.git/config": "/.git/config found - dump entire repo with git-dumper. May expose source code and secrets.",
    "/.git/HEAD":  "/.git/HEAD found - full git repo likely exposed. Run git-dumper.",
    "/actuator":   "Spring Boot actuator exposed. Check /actuator/env for credentials, /actuator/heapdump for memory dump.",
    "/swagger":    "API docs exposed. Map all endpoints. Look for undocumented admin operations.",
    "/openapi":    "OpenAPI spec exposed. Map all endpoints and parameters for testing.",
    "/api-docs":   "API documentation exposed. Extract all endpoints for Burp testing.",
    "/wp-admin":   "WordPress admin panel found. Test for weak credentials.",
    "/phpinfo":    "phpinfo() exposed. Shows server config, PHP settings, environment variables.",
    "/config":     "Config file accessible. Check for credentials and connection strings.",
    "/backup":     "Backup file accessible. May contain source code or database dump.",
    "/graphql":    "GraphQL endpoint accessible. Run introspection to map schema.",
    "/graphiql":   "GraphQL playground exposed. Interactive query interface - use for schema exploration.",
    "/console":    "Admin console potentially exposed. Test for weak authentication.",
    "/phpmyadmin": "phpMyAdmin interface found. Test for default/weak credentials.",
    "/adminer":    "Adminer database tool exposed. Test for authentication bypass.",
    "/metrics":    "Metrics endpoint exposed. May leak internal service data.",
    "/health":     "Health endpoint exposed. May reveal internal service topology.",
}

_DEFAULT_BURP_NOTES = "Sensitive path accessible. Review content and check for information disclosure."


def _get_burp_notes(path: str) -> str:
    for prefix, notes in _BURP_NOTES_MAP.items():
        if path.startswith(prefix):
            return notes
    return _DEFAULT_BURP_NOTES


class ConfigurationMapper(BaseSurfaceMapper):
    category = AttackCategory.CONFIGURATION

    def __init__(self, fetcher=None, policy: SurfaceSafetyPolicy = None, verbose: bool = False):
        super().__init__(policy=policy, verbose=verbose)
        self._fetcher = fetcher

    def _config_candidate(
        self,
        url:          str,
        path:         str,
        surface_type: str,
        confidence:   str,
        evidence:     List[str],
        status_code:  int,
        status:       str = SurfaceStatus.CANDIDATE,
    ) -> SurfaceResult:
        """Build a config probe result. requests_made=1 since we probe HTTP."""
        from ...storage.models import Endpoint as _Endpoint
        synthetic_ep = _Endpoint(
            url=url,
            path=path,
            method="GET",
            category="",
            source_file="config_probe",
            line_number=0,
            confidence=0.5,
            query_params=[],
            path_params=[],
            body_fields=[],
            request_headers={},
            auth_context="",
            source_type="static",
        )
        r = SurfaceResult(
            endpoint_url     = url,
            method           = "GET",
            category         = self.category,
            surface_type     = surface_type,
            parameters       = [],
            auth_context     = "",
            confidence       = confidence,
            evidence         = evidence,
            provenance_source = "config_probe",
            burp_notes       = _get_burp_notes(path),
            requests_made    = 1,   # ConfigurationMapper is allowed to make requests
            status           = status,
        )
        self._results.append(r)
        return r

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        parsed = urlparse(result.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        if not self._fetcher or not self._policy:
            return self._results

        seen_paths: set = set()
        for path in CONFIG_PATHS:
            # Normalize trailing slash so /admin and /admin/ don't both fire
            norm_path = path.rstrip("/") or "/"
            if norm_path in seen_paths:
                continue
            seen_paths.add(norm_path)

            probe_url = base + path

            allowed, reason = self._policy.allow_get(probe_url)
            if not allowed:
                continue

            # Safe GET request - the only HTTP call in the entire mapper layer
            try:
                fetch_result = self._fetcher.get(probe_url)
            except Exception as e:
                continue

            if fetch_result is None:
                continue

            try:
                content, status_code, content_type, _ = fetch_result
            except (TypeError, ValueError):
                continue

            # 404/410/other 4xx with no content - skip
            if status_code in (404, 410, 400, 405):
                continue

            evidence     = []
            confidence   = ConfidenceLevel.LOW
            surface_type = "Config/Debug Path"

            if status_code == 200:
                body = content or ""

                # Public-by-design paths - informational only, not a security issue
                if path in _INFORMATIONAL_PATHS:
                    evidence.append(f"HTTP 200 at {path} - public path, accessible as expected")
                    confidence   = ConfidenceLevel.LOW
                    surface_type = "INFORMATIONAL"
                    # Still useful for recon (robots.txt discloses paths, sitemap lists routes)
                    if path == "/robots.txt" and "Disallow:" in body:
                        evidence.append("robots.txt contains Disallow entries - review for hidden paths")
                    elif path == "/sitemap.xml" and "<url>" in body:
                        evidence.append("sitemap.xml lists site URLs - useful for endpoint discovery")

                else:
                    evidence.append(f"HTTP 200 at {path} - path is accessible")
                    confidence = ConfidenceLevel.HIGH
                    surface_type = "EXPOSED"

                    # Content-based boosters
                    if path in ("/.env", "/.env.local", "/.env.production", "/.env.backup"):
                        if any(k in body for k in ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL", "PASSWORD", "TOKEN"]):
                            evidence.append("Environment file contains credential key names")
                        else:
                            evidence.append("Environment file accessible")
                    elif "/.git/" in path:
                        if "[core]" in body or "[remote" in body:
                            evidence.append("Git config content confirmed - repo likely fully exposed")
                    elif "/actuator" in path:
                        evidence.append("Spring Boot actuator endpoint responding")
                    elif path in ("/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml"):
                        if any(k in body for k in ['"paths"', '"swagger"', '"openapi"', "paths:"]):
                            evidence.append("API specification content confirmed")
                    elif "/graphql" in path or "/graphiql" in path or "/playground" in path:
                        evidence.append("GraphQL endpoint responding")

            elif status_code == 403:
                evidence.append(f"HTTP 403 at {path} - path exists but is restricted (may be bypassable)")
                confidence   = ConfidenceLevel.MEDIUM
                surface_type = "EXISTS_RESTRICTED"

            elif status_code == 401:
                evidence.append(f"HTTP 401 at {path} - path requires authentication")
                confidence   = ConfidenceLevel.MEDIUM
                surface_type = "EXISTS_AUTH_REQUIRED"

            elif status_code in (301, 302, 307, 308):
                evidence.append(f"HTTP {status_code} at {path} - redirect detected")
                confidence   = ConfidenceLevel.LOW
                surface_type = "REDIRECT"

            else:
                # Other status codes - low signal
                evidence.append(f"HTTP {status_code} at {path}")
                confidence = ConfidenceLevel.LOW

            if evidence:
                self._config_candidate(
                    url          = probe_url,
                    path         = path,
                    surface_type = surface_type,
                    confidence   = confidence,
                    evidence     = evidence,
                    status_code  = status_code,
                    status       = SurfaceStatus.MAPPED,
                )
                config_ev = [
                    Evidence(
                        evidence_type = EvidenceType.ROUTE_DECLARATION,
                        source        = "active",
                        asset         = probe_url,
                        context       = f"Config probe: {path} returned HTTP {status_code}",
                        details       = f"Path '{path}' is accessible at {probe_url}",
                    ),
                    Evidence(
                        evidence_type = EvidenceType.METADATA,
                        source        = "active",
                        asset         = probe_url,
                        context       = f"HTTP {status_code} response at {path}",
                        details       = evidence[0] if evidence else f"HTTP {status_code}",
                    ),
                ]
                self._emit_evidence(
                    evidence     = config_ev,
                    surface_type = surface_type,
                    endpoint     = probe_url,
                    method       = "GET",
                    parameter    = "",
                    notes        = _get_burp_notes(path),
                )

        return self._results
