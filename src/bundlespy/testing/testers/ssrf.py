"""
SSRF tester.
Identifies parameters that may influence server-side URL retrieval.
Uses safe probes only - never internal network access.
"""
import re
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_baseline, capture_observation, differential
from ...storage.models import ScanResult

_SSRF_PARAM_SIGNALS = {
    "url", "uri", "callback", "redirect", "webhook",
    "image", "fetch", "proxy", "target", "destination",
    "resource", "endpoint", "host", "domain", "link",
    "src", "source", "href", "location",
}

# Safe test values - public DNS resolvable, no internal network
_SSRF_SAFE_PROBE = "https://www.example.com/"
_SSRF_INVALID    = "https://ssrf-test-invalid-domain-xyzabc.example.invalid/"

class SsrfTester(BaseTester):
    category = AttackCategory.SSRF

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        for ep in result.endpoints:
            all_params = list(ep.query_params or []) + list(ep.body_fields or [])
            for qp in all_params:
                pname = (qp.get("name") or "").lower()
                if pname not in _SSRF_PARAM_SIGNALS:
                    continue

                allowed, reason = self._policy.check(
                    ep.url, ep.method, pname, "SSRF", ep.auth_context or "",
                )
                if not allowed:
                    self._skip(reason, category=self.category, attack_class="SSRF",
                               target_url=ep.url, parameter=pname)
                    continue

                # Capture baseline with empty/original param
                baseline = capture_baseline(self._fetcher, ep.url)

                sep = "&" if "?" in ep.url else "?"
                test_url = f"{ep.url}{sep}{pname}={_SSRF_SAFE_PROBE}"

                allowed2, _ = self._policy.check(
                    test_url, ep.method, pname, "SSRF_PROBE", ep.auth_context or "",
                )
                if not allowed2:
                    continue

                obs = capture_observation(self._fetcher, test_url)

                evidence = [f"Parameter '{pname}' accepts URL-like input - SSRF candidate"]
                status   = TestStatus.CANDIDATE
                confidence = 0.3

                if obs and baseline:
                    diff = differential(baseline, obs)
                    if obs.status_code in (200, 302) and diff.get("body_changed"):
                        evidence.append("Response body changed when URL parameter was modified")
                        status = TestStatus.OBSERVED
                        confidence = 0.5
                    if "example.com" in (obs.body_excerpt or "").lower():
                        evidence.append("Response contains content from injected URL - strong SSRF indicator")
                        status = TestStatus.VALIDATED
                        confidence = 0.85

                r = AttackTestResult(
                    category=self.category,
                    attack_class="SSRF",
                    target_url=ep.url,
                    parameter=pname,
                    method=ep.method,
                    route=ep.path,
                    authentication_context=ep.auth_context or "",
                    payload=_SSRF_SAFE_PROBE,
                    baseline=baseline,
                    observation=obs,
                    status=status,
                    confidence=confidence,
                    evidence=evidence,
                    why_tested=f"Parameter name '{pname}' strongly suggests server-side URL fetching",
                    what_changed=f"Injected safe external URL into '{pname}'",
                    what_observed=f"HTTP {obs.status_code if obs else 'N/A'}",
                    what_remains_unverified="Out-of-band callback not configured - blind SSRF not tested",
                    requests_made=2,
                )
                self._results.append(r)

        return self._results
