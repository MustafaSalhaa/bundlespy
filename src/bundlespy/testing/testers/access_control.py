"""
Access control tester.
Identifies endpoints with object identifiers and tests authorization boundaries.
"""
import re
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_baseline, capture_observation, differential
from ...storage.models import ScanResult, Endpoint

# Patterns that suggest an object ID in the path
_ID_PATTERNS = [
    re.compile(r'/(\d{1,12})(?:/|$|\?)'),          # /123 or /123/
    re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)', re.I),  # UUID
    re.compile(r'/([a-z0-9]{20,})(?:/|$)', re.I),  # long opaque ID
]

_IDOR_PARAM_NAMES = {
    "id", "user_id", "account_id", "order_id", "item_id",
    "product_id", "report_id", "doc_id", "document_id",
    "file_id", "message_id", "record_id", "object_id",
}

def _extract_id_candidates(ep: Endpoint):
    """Returns list of (param_name, current_value_or_pattern) for IDOR testing."""
    candidates = []
    # Path parameters
    for pp in (ep.path_params or []):
        name = (pp.get("name") or "").lower()
        if name in _IDOR_PARAM_NAMES or name == "id":
            candidates.append(("path:" + name, pp.get("example", "1")))
    # Query parameters
    for qp in (ep.query_params or []):
        name = (qp.get("name") or "").lower()
        if name in _IDOR_PARAM_NAMES:
            candidates.append(("query:" + name, qp.get("example", "1")))
    # Regex scan on path
    for pattern in _ID_PATTERNS:
        m = pattern.search(ep.path or ep.url or "")
        if m:
            candidates.append(("path:id", m.group(1)))
    return candidates

class AccessControlTester(BaseTester):
    category = AttackCategory.ACCESS_CONTROL

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        for ep in result.endpoints:
            if ep.category not in ("API", "AUTH", "ADMIN", "ROUTE"):
                continue
            candidates = _extract_id_candidates(ep)
            if not candidates:
                continue

            for param_name, current_value in candidates:
                # Safety check
                allowed, reason = self._policy.check(
                    url=ep.url, method=ep.method,
                    param=param_name, test_type="IDOR",
                    auth_state=ep.auth_context or "",
                )
                if not allowed:
                    self._skip(reason, category=self.category, attack_class="IDOR",
                               target_url=ep.url, parameter=param_name, method=ep.method,
                               why_tested="Object identifier present in endpoint")
                    continue

                # Capture baseline
                baseline = capture_baseline(self._fetcher, ep.url)
                if baseline is None:
                    self._skip("baseline_unreachable", category=self.category,
                               attack_class="IDOR", target_url=ep.url, parameter=param_name)
                    continue

                # Test with adjacent ID (baseline+1 and baseline-1)
                test_results = []
                for delta in (1, -1):
                    try:
                        val = int(current_value)
                        test_val = str(max(1, val + delta))
                        test_url = ep.url.replace(f"/{current_value}", f"/{test_val}", 1)
                        if test_url == ep.url:
                            continue
                        obs_allowed, obs_reason = self._policy.check(
                            test_url, ep.method, param_name, "IDOR_DELTA",
                            ep.auth_context or "",
                        )
                        if not obs_allowed:
                            continue
                        obs = capture_observation(self._fetcher, test_url)
                        if obs:
                            test_results.append((test_url, test_val, obs))
                    except (ValueError, TypeError):
                        break

                # Differential analysis
                for test_url, test_val, obs in test_results:
                    diff = differential(baseline, obs)
                    evidence = []
                    status = TestStatus.CANDIDATE

                    if obs.status_code in (200, 201) and baseline.status_code in (200, 201):
                        if diff.get("body_changed") and not diff.get("content_length"):
                            evidence.append(f"Body changed with ID={test_val} but same size - structural similarity")
                            status = TestStatus.OBSERVED
                        elif diff.get("content_length"):
                            bl, ol = diff["content_length"]
                            if ol > bl * 1.5:
                                evidence.append(f"Response larger with ID={test_val} ({bl} -> {ol} bytes)")
                                status = TestStatus.OBSERVED
                    elif obs.status_code == 200 and baseline.status_code == 403:
                        evidence.append(f"403 baseline but 200 with ID={test_val} - possible authorization bypass")
                        status = TestStatus.VALIDATED

                    r = AttackTestResult(
                        category=self.category,
                        attack_class="IDOR",
                        target_url=ep.url,
                        parameter=param_name,
                        method=ep.method,
                        route=ep.path,
                        authentication_context=ep.auth_context or "",
                        payload=test_val,
                        baseline=baseline,
                        observation=obs,
                        status=status,
                        confidence=0.6 if status == TestStatus.OBSERVED else (0.8 if status == TestStatus.VALIDATED else 0.3),
                        evidence=evidence,
                        why_tested=f"Numeric/UUID identifier in endpoint path or parameter ({param_name})",
                        what_changed=f"Requested resource ID {current_value} -> {test_val}",
                        what_observed=f"HTTP {obs.status_code}, {obs.content_length} bytes" + (f" (diff: {diff})" if diff else ""),
                        what_remains_unverified="Response body not parsed for ownership - manual review required",
                        requests_made=2,
                    )
                    self._results.append(r)

        return self._results
