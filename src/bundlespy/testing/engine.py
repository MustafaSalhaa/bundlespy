"""
AttackTestingEngine - orchestrates all testers against a completed ScanResult.
Consumes existing BundleSpy intelligence; produces AttackEngineReport.
"""
import logging
import time
from datetime import datetime
from typing import List, Optional

from .models import AttackEngineReport, AttackTestSummary, AttackCategory, TestStatus
from .safety import SafetyPolicy
from .prioritizer import prioritize
from .testers.access_control import AccessControlTester
from .testers.xss import XssTester
from .testers.injection import InjectionTester
from .testers.ssrf import SsrfTester
from .testers.open_redirect import OpenRedirectTester
from .testers.csrf import CsrfTester
from .testers.path_traversal import PathTraversalTester
from .testers.configuration import ConfigurationTester
from ..storage.models import ScanResult

_log = logging.getLogger("bundlespy.testing.engine")

class AttackTestingEngine:
    """
    Consumes a completed ScanResult and runs bounded, evidence-driven
    security tests against the discovered attack surface.

    Does not modify any existing BundleSpy infrastructure.
    All testers are read-only consumers of the ScanResult.
    """

    def __init__(
        self,
        fetcher,
        scope,
        rate_per_second: float = 2.0,
        max_requests:    int   = 500,
        allow_post:      bool  = False,
        verbose:         bool  = False,
        enabled_testers: Optional[List[str]] = None,
    ):
        self._fetcher  = fetcher
        self._scope    = scope
        self._verbose  = verbose
        self._policy   = SafetyPolicy(
            scope=scope,
            rate_per_second=rate_per_second,
            max_requests=max_requests,
            allow_post=allow_post,
        )
        # Which attack categories to run (default: all safe GET-based ones)
        self._enabled = set(enabled_testers or [
            AttackCategory.ACCESS_CONTROL,
            AttackCategory.XSS,
            AttackCategory.INJECTION,
            AttackCategory.SSRF,
            AttackCategory.OPEN_REDIRECT,
            AttackCategory.CSRF,
            AttackCategory.PATH_TRAVERSAL,
            AttackCategory.CONFIGURATION,
        ])

    def _build_testers(self):
        kwargs = dict(fetcher=self._fetcher, policy=self._policy, verbose=self._verbose)
        all_testers = [
            AccessControlTester(**kwargs),
            XssTester(**kwargs),
            InjectionTester(**kwargs),
            SsrfTester(**kwargs),
            OpenRedirectTester(**kwargs),
            CsrfTester(**kwargs),
            PathTraversalTester(**kwargs),
            ConfigurationTester(**kwargs),
        ]
        return [t for t in all_testers if t.category in self._enabled]

    def run(self, result: ScanResult) -> AttackEngineReport:
        started = datetime.utcnow()
        report  = AttackEngineReport(
            target_url=result.target_url,
            started_at=started,
        )

        testers = self._build_testers()

        # Sort endpoints by priority so high-value targets are tested first
        _sorted = prioritize(result.endpoints)
        # Build a temporary ScanResult-like view with sorted endpoints
        class _SortedResult:
            def __init__(self, r, eps):
                self.target_url  = r.target_url
                self.endpoints   = [ep for _, ep in eps]
                self.js_files    = r.js_files
                self.findings    = r.findings
                self.infrastructure = r.infrastructure
                self.graph       = r.graph
                self.page_states = r.page_states
        sorted_result = _SortedResult(result, _sorted)

        for tester in testers:
            _log.debug("Running %s", tester.category)
            t0 = time.monotonic()
            try:
                tester.run(sorted_result)
            except Exception as e:
                _log.warning("%s failed: %s", tester.category, e)
                report.errors.append(f"{tester.category}: {e}")
            elapsed = time.monotonic() - t0
            _log.debug("%s done in %.1fs - %d results", tester.category, elapsed, len(tester.results))

            report.results.extend(tester.results)
            report.summaries.append(tester.summary())

        # Aggregate counts
        for r in report.results:
            report.total_candidates += 1
            if r.status not in (TestStatus.SKIPPED, TestStatus.NOT_TESTED, TestStatus.OUT_OF_SCOPE):
                report.total_tested += 1
            if r.status == TestStatus.SKIPPED:
                report.total_skipped += 1
            if r.status in (TestStatus.VALIDATED, TestStatus.CONFIRMED):
                report.total_validated += 1
            if r.status == TestStatus.CONFIRMED:
                report.total_confirmed += 1
            report.total_requests += r.requests_made

        report.finished_at = datetime.utcnow()
        return report
