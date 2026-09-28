"""
Security misconfiguration tester.
Passive checks first; minimal active probing for common exposures.
"""
import re
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_observation
from ...storage.models import ScanResult

_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

_DEBUG_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/appsettings.json",
    "/.git/config", "/web.config",
    "/phpinfo.php", "/info.php",
    "/actuator", "/actuator/health", "/actuator/env",
    "/api/swagger", "/swagger.json", "/openapi.json",
    "/_profiler", "/telescope", "/horizon",
    "/debug", "/console", "/server-info",
]

_CORS_ISSUE_PATTERNS = [
    re.compile(r'access-control-allow-origin:\s*\*', re.I),
]

class ConfigurationTester(BaseTester):
    category = AttackCategory.CONFIGURATION

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        from urllib.parse import urlparse
        parsed = urlparse(result.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Probe common debug/config paths
        probed = set()
        for probe_path in _DEBUG_PATHS:
            probe_url = base + probe_path
            if probe_url in probed:
                continue
            probed.add(probe_url)

            allowed, reason = self._policy.check(
                probe_url, "GET", "", "CONFIG_PROBE", "",
            )
            if not allowed:
                continue

            obs = capture_observation(self._fetcher, probe_url)
            if obs is None:
                continue

            evidence = []
            status   = TestStatus.CANDIDATE
            confidence = 0.2

            if obs.status_code == 200:
                body = obs.body_excerpt or ""
                if probe_path in ("/.env", "/.env.local", "/.env.production"):
                    if any(k in body for k in ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL"]):
                        evidence.append(f"Environment file exposed at {probe_path} with credential keys")
                        status = TestStatus.CONFIRMED
                        confidence = 0.95
                    else:
                        evidence.append(f"Environment file accessible at {probe_path}")
                        status = TestStatus.OBSERVED
                        confidence = 0.7
                elif probe_path in ("/swagger.json", "/openapi.json", "/api/swagger"):
                    if '"paths"' in body or '"swagger"' in body or '"openapi"' in body:
                        evidence.append(f"API documentation exposed at {probe_path}")
                        status = TestStatus.OBSERVED
                        confidence = 0.8
                elif probe_path == "/.git/config":
                    if "[core]" in body or "[remote" in body:
                        evidence.append(f"Git configuration exposed at {probe_path}")
                        status = TestStatus.CONFIRMED
                        confidence = 0.95
                elif "/actuator" in probe_path:
                    evidence.append(f"Spring Boot actuator endpoint accessible at {probe_path}")
                    status = TestStatus.OBSERVED
                    confidence = 0.75
                else:
                    evidence.append(f"Potentially sensitive path accessible: {probe_path} (HTTP 200)")
                    status = TestStatus.CANDIDATE
                    confidence = 0.3

                if evidence:
                    r = AttackTestResult(
                        category=self.category,
                        attack_class="Security Misconfiguration",
                        target_url=probe_url,
                        method="GET",
                        status=status,
                        confidence=confidence,
                        evidence=evidence,
                        why_tested=f"Common sensitive path: {probe_path}",
                        what_changed="Direct path probe",
                        what_observed=f"HTTP {obs.status_code}, {obs.content_length} bytes",
                        what_remains_unverified="Content analysis limited to first 500 bytes",
                        requests_made=1,
                    )
                    self._results.append(r)

        # 2. Check existing endpoints for CORS misconfiguration
        for ep in result.endpoints:
            headers = ep.request_headers or {}
            for k, v in headers.items():
                for pat in _CORS_ISSUE_PATTERNS:
                    if pat.search(f"{k}: {v}"):
                        r = AttackTestResult(
                            category=self.category,
                            attack_class="CORS Misconfiguration",
                            target_url=ep.url,
                            method=ep.method,
                            status=TestStatus.OBSERVED,
                            confidence=0.7,
                            evidence=[f"Access-Control-Allow-Origin: * observed on {ep.url}"],
                            why_tested="CORS header analysis",
                            what_changed="Static analysis - no request sent",
                            what_observed="Wildcard CORS header",
                            what_remains_unverified="Credentialed CORS request not tested",
                            requests_made=0,
                        )
                        self._results.append(r)

        return self._results
