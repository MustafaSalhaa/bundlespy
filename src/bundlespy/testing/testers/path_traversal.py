"""Path traversal / file access tester."""
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_baseline, capture_observation
from ...storage.models import ScanResult

_FILE_PARAM_SIGNALS = {
    "file", "path", "filename", "template", "document",
    "download", "resource", "include", "page", "view",
    "attachment", "asset", "name", "doc",
}

# Safe traversal probes - well-known but harmless
_TRAVERSAL_PROBES = [
    "../etc/passwd",
    "..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
]

_TRAVERSAL_EVIDENCE = [
    "root:x:0:0",          # /etc/passwd
    "[extensions]",         # win.ini
    "[fonts]",             # win.ini
    "for 16-bit app support",
]

class PathTraversalTester(BaseTester):
    category = AttackCategory.PATH_TRAVERSAL

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        for ep in result.endpoints:
            all_params = list(ep.query_params or []) + list(ep.path_params or [])
            for qp in all_params:
                pname = (qp.get("name") or "").lower()
                if pname not in _FILE_PARAM_SIGNALS:
                    continue

                allowed, reason = self._policy.check(
                    ep.url, ep.method, pname, "PATH_TRAVERSAL", ep.auth_context or "",
                )
                if not allowed:
                    self._skip(reason, category=self.category, attack_class="Path Traversal",
                               target_url=ep.url, parameter=pname)
                    continue

                baseline = capture_baseline(self._fetcher, ep.url)

                for probe in _TRAVERSAL_PROBES[:1]:  # test one probe per param
                    sep = "&" if "?" in ep.url else "?"
                    test_url = f"{ep.url}{sep}{pname}={probe}"

                    allowed2, _ = self._policy.check(
                        test_url, ep.method, pname, "PATH_TRAVERSAL_PROBE", ep.auth_context or "",
                    )
                    if not allowed2:
                        continue

                    obs = capture_observation(self._fetcher, test_url)
                    if obs is None:
                        continue

                    evidence = []
                    status   = TestStatus.CANDIDATE
                    confidence = 0.2

                    body = obs.body_excerpt or ""
                    for indicator in _TRAVERSAL_EVIDENCE:
                        if indicator in body:
                            evidence.append(f"File content indicator found: '{indicator}'")
                            status = TestStatus.CONFIRMED
                            confidence = 0.95

                    if not evidence:
                        if obs.status_code == 200 and baseline and obs.content_length != baseline.content_length:
                            evidence.append("Response size changed with traversal probe - inconclusive")
                            status = TestStatus.INCONCLUSIVE
                            confidence = 0.3
                        else:
                            continue

                    r = AttackTestResult(
                        category=self.category,
                        attack_class="Path Traversal",
                        target_url=ep.url,
                        parameter=pname,
                        method=ep.method,
                        route=ep.path,
                        payload=probe,
                        baseline=baseline,
                        observation=obs,
                        status=status,
                        confidence=confidence,
                        evidence=evidence,
                        why_tested=f"Parameter '{pname}' suggests file/path access",
                        what_changed=f"Injected traversal sequence into '{pname}'",
                        what_observed=f"HTTP {obs.status_code}, {obs.content_length} bytes",
                        what_remains_unverified="Encoding variations not tested (URL-encoded dots, null bytes)",
                        requests_made=2,
                    )
                    self._results.append(r)

        return self._results
