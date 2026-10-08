"""
SurfaceMappingEngine - orchestrates all passive surface mappers against a completed ScanResult.
Produces a SurfaceReport suitable for Burp Suite follow-up.

No payload injection. No exploitation. No destructive requests.
Only ConfigurationMapper makes any HTTP requests (safe GETs to bounded list).
"""
import logging
import time
from datetime import datetime
from typing import List, Optional

from .models import SurfaceReport, SurfaceSummary, SurfaceStatus, AttackCategory
from .safety import SurfaceSafetyPolicy
from .prioritizer import prioritize_surfaces, prioritize_findings
from .fingerprint import deduplicate
from .correlator import correlate
from .testers.access_control import AccessControlMapper
from .testers.xss import XssMapper
from .testers.injection import InjectionMapper
from .testers.ssrf import SsrfMapper
from .testers.open_redirect import OpenRedirectMapper
from .testers.csrf import CsrfMapper
from .testers.path_traversal import PathTraversalMapper
from .testers.configuration import ConfigurationMapper
from .testers.cors import CorsMapper
from .testers.prototype_pollution import PrototypePollutionMapper
from .testers.deserialization import DeserializationMapper
from .testers.cache_poisoning import CachePoisoningMapper
from .testers.oauth import OAuthMapper
from .testers.websocket import WebSocketMapper
from .testers.business_logic import BusinessLogicMapper
from ..storage.models import ScanResult

# Keep the old name as an alias for backwards compatibility
AttackTestingEngine = None  # will be set at bottom of file

_log = logging.getLogger("bundlespy.testing.engine")


class SurfaceMappingEngine:
    """
    Passive attack surface mapping engine.

    Consumes a completed ScanResult and maps attack surface candidates
    from the collected intelligence. Returns a SurfaceReport with prioritized
    candidates ready for manual follow-up in Burp Suite.

    Rules:
    - Zero payload injection
    - Zero destructive HTTP requests
    - Only ConfigurationMapper makes any requests (safe GET probes)
    - All candidates are SURFACE CANDIDATES, not confirmed vulnerabilities
    """

    def __init__(
        self,
        fetcher          = None,
        scope            = None,
        rate_per_second: float = 2.0,
        max_requests:    int   = 100,
        verbose:         bool  = False,
        enabled_mappers: Optional[List[str]] = None,
    ):
        self._fetcher  = fetcher
        self._scope    = scope
        self._verbose  = verbose
        self._policy   = SurfaceSafetyPolicy(
            scope           = scope,
            rate_per_second = rate_per_second,
            max_requests    = max_requests,
        ) if scope else None

        self._enabled = set(enabled_mappers or [
            AttackCategory.ACCESS_CONTROL,
            AttackCategory.XSS,
            AttackCategory.INJECTION,
            AttackCategory.SSRF,
            AttackCategory.OPEN_REDIRECT,
            AttackCategory.CSRF,
            AttackCategory.PATH_TRAVERSAL,
            AttackCategory.CONFIGURATION,
            AttackCategory.CORS,
            AttackCategory.PROTOTYPE_POLLUTION,
            AttackCategory.DESERIALIZATION,
            AttackCategory.CACHE_POISONING,
            AttackCategory.OAUTH,
            AttackCategory.WEBSOCKET,
            AttackCategory.BUSINESS_LOGIC,
        ])

    def _build_mappers(self):
        static_kwargs = dict(policy=self._policy, verbose=self._verbose)
        config_kwargs = dict(fetcher=self._fetcher, policy=self._policy, verbose=self._verbose)

        all_mappers = [
            AccessControlMapper(**static_kwargs),
            XssMapper(**static_kwargs),
            InjectionMapper(**static_kwargs),
            SsrfMapper(**static_kwargs),
            OpenRedirectMapper(**static_kwargs),
            CsrfMapper(**static_kwargs),
            PathTraversalMapper(**static_kwargs),
            ConfigurationMapper(**config_kwargs),
            CorsMapper(**static_kwargs),
            PrototypePollutionMapper(**static_kwargs),
            DeserializationMapper(**static_kwargs),
            CachePoisoningMapper(**static_kwargs),
            OAuthMapper(**static_kwargs),
            WebSocketMapper(**static_kwargs),
            BusinessLogicMapper(**static_kwargs),
        ]
        return [m for m in all_mappers if m.category in self._enabled]

    def run(self, result: ScanResult) -> SurfaceReport:
        started = datetime.utcnow()
        report  = SurfaceReport(
            target_url  = result.target_url,
            started_at  = started,
            finished_at = None,
        )

        mappers = self._build_mappers()

        for mapper in mappers:
            _log.debug("Mapping %s", mapper.category)
            t0 = time.monotonic()
            try:
                mapper.map(result)
            except Exception as e:
                _log.warning("%s failed: %s", mapper.category, e)
                report.errors.append(f"{mapper.category}: {e}")
            elapsed = time.monotonic() - t0
            _log.debug("%s done in %.1fs - %d candidates", mapper.category, elapsed, len(mapper.results))

            report.results.extend(mapper.results)
            report.findings.extend(mapper.findings)
            report.summaries.append(mapper.summary())

        # Cross-mapper correlation pass - upgrades confidence where signals overlap
        report.results = correlate(report.results)

        # Prioritize all results
        report.results = prioritize_surfaces(report.results)

        # Deduplicate and prioritize structured findings
        report.findings = deduplicate(report.findings)
        report.findings = prioritize_findings(report.findings)

        # Aggregate counts
        for r in report.results:
            report.total_candidates += 1
            if r.status == SurfaceStatus.MAPPED:
                report.total_mapped += 1
            elif r.status == SurfaceStatus.SKIPPED:
                report.total_skipped += 1

        report.finished_at = datetime.utcnow()
        return report


# Backwards compatibility alias - old import path still works
AttackTestingEngine = SurfaceMappingEngine
