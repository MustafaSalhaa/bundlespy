"""Open redirect tester."""
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_baseline, capture_observation
from ...storage.models import ScanResult

_REDIRECT_PARAMS = {
    "redirect", "return", "next", "url", "continue",
    "destination", "callback", "goto", "target", "redir",
    "redirect_uri", "redirect_url", "return_url", "return_to",
    "success_url", "cancel_url", "after_login", "ref",
}

_SAFE_EXTERNAL = "https://www.example.com/"
_SAFE_PROTO    = "//www.example.com/"

class OpenRedirectTester(BaseTester):
    category = AttackCategory.OPEN_REDIRECT

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        for ep in result.endpoints:
            for qp in (ep.query_params or []):
                pname = (qp.get("name") or "").lower()
                if pname not in _REDIRECT_PARAMS:
                    continue

                allowed, reason = self._policy.check(
                    ep.url, ep.method, pname, "OPEN_REDIRECT", ep.auth_context or "",
                )
                if not allowed:
                    self._skip(reason, category=self.category, attack_class="Open Redirect",
                               target_url=ep.url, parameter=pname)
                    continue

                baseline = capture_baseline(self._fetcher, ep.url)
                sep = "&" if "?" in ep.url else "?"

                for probe in (_SAFE_EXTERNAL, _SAFE_PROTO):
                    test_url = f"{ep.url}{sep}{pname}={probe}"
                    allowed2, _ = self._policy.check(
                        test_url, ep.method, pname, "OPEN_REDIRECT_PROBE", ep.auth_context or "",
                    )
                    if not allowed2:
                        continue

                    obs = capture_observation(self._fetcher, test_url)
                    if obs is None:
                        continue

                    evidence = []
                    status   = TestStatus.CANDIDATE
                    confidence = 0.25

                    if obs.status_code in (301, 302, 303, 307, 308):
                        loc = obs.headers.get("location", obs.headers.get("Location", ""))
                        if "example.com" in loc:
                            evidence.append(f"Location header redirects to injected domain: {loc}")
                            status = TestStatus.VALIDATED
                            confidence = 0.9
                        else:
                            evidence.append(f"Redirect observed (HTTP {obs.status_code}) but destination is internal")
                            status = TestStatus.OBSERVED
                            confidence = 0.4
                    elif obs.status_code == 200 and "example.com" in (obs.body_excerpt or ""):
                        evidence.append("Injected domain appears in 200 response - JS redirect possible")
                        status = TestStatus.OBSERVED
                        confidence = 0.45

                    if not evidence:
                        continue

                    r = AttackTestResult(
                        category=self.category,
                        attack_class="Open Redirect",
                        target_url=ep.url,
                        parameter=pname,
                        method=ep.method,
                        route=ep.path,
                        authentication_context=ep.auth_context or "",
                        payload=probe,
                        baseline=baseline,
                        observation=obs,
                        status=status,
                        confidence=confidence,
                        evidence=evidence,
                        why_tested=f"Parameter '{pname}' is a known redirect parameter name",
                        what_changed=f"Injected external URL '{probe}' into '{pname}'",
                        what_observed=f"HTTP {obs.status_code}",
                        what_remains_unverified="JS-based redirect and meta-refresh not tested",
                        requests_made=2,
                    )
                    self._results.append(r)
                    break  # one probe per param is enough

        return self._results
