"""
XSS tester.
Detects reflection of canary values and static JS sink reachability.
Does NOT execute JavaScript. Uses safe non-destructive canaries.
"""
import re
import hashlib
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_baseline, capture_observation
from ...storage.models import ScanResult

# Safe canary that proves reflection without executing code
_CANARY = "bspy7x3k"

# DOM sinks that indicate XSS risk in static JS
_DOM_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "location.href", "location.replace", "location.assign",
    "$.html(", "$(", ".html(",  # jQuery
]

_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.referrer", "window.name",
    "URLSearchParams", "new URL(",
    "postMessage", "localStorage.getItem", "sessionStorage.getItem",
]

def _find_dom_sinks(js_content: str) -> List[str]:
    """Returns list of dangerous sinks found in JS content."""
    found = []
    for sink in _DOM_SINKS:
        if sink in js_content:
            found.append(sink)
    return found

def _find_sources(js_content: str) -> List[str]:
    found = []
    for src in _SOURCES:
        if src in js_content:
            found.append(src)
    return found

class XssTester(BaseTester):
    category = AttackCategory.XSS

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        # 1. Static DOM XSS analysis from JS files
        for js_file in result.js_files:
            if not js_file.content:
                continue
            sinks   = _find_dom_sinks(js_file.content)
            sources = _find_sources(js_file.content)
            if sinks and sources:
                evidence = [
                    f"Sources found: {', '.join(sources[:3])}",
                    f"Sinks found:   {', '.join(sinks[:3])}",
                    "Data-flow path not confirmed - manual verification required",
                ]
                r = AttackTestResult(
                    category=self.category,
                    attack_class="DOM XSS Candidate",
                    target_url=js_file.url,
                    status=TestStatus.CANDIDATE,
                    confidence=0.4,
                    evidence=evidence,
                    why_tested="JS file contains both taint sources and dangerous sinks",
                    what_changed="Static analysis only - no request sent",
                    what_observed=f"{len(sinks)} sinks, {len(sources)} sources in {js_file.url.split('/')[-1]}",
                    what_remains_unverified="Source-to-sink data flow not traced - dynamic testing required",
                    requests_made=0,
                )
                self._results.append(r)

        # 2. Reflected XSS - inject canary into query parameters
        for ep in result.endpoints:
            for qp in (ep.query_params or []):
                param = qp.get("name", "")
                if not param:
                    continue

                allowed, reason = self._policy.check(
                    ep.url, ep.method, param, "REFLECTED_XSS", ep.auth_context or "",
                )
                if not allowed:
                    self._skip(reason, category=self.category, attack_class="Reflected XSS",
                               target_url=ep.url, parameter=param)
                    continue

                sep = "&" if "?" in ep.url else "?"
                test_url = f"{ep.url}{sep}{param}={_CANARY}"

                baseline = capture_baseline(self._fetcher, ep.url)
                obs      = capture_observation(self._fetcher, test_url)

                if obs is None:
                    self._skip("observation_unreachable", category=self.category,
                               attack_class="Reflected XSS", target_url=ep.url, parameter=param)
                    continue

                status   = TestStatus.CANDIDATE
                evidence = []
                confidence = 0.2

                if _CANARY in obs.body_excerpt:
                    evidence.append(f"Canary '{_CANARY}' reflected in response body")
                    # Check context
                    excerpt = obs.body_excerpt
                    idx = excerpt.find(_CANARY)
                    context_window = excerpt[max(0, idx-20):idx+len(_CANARY)+20]
                    if "<script" in context_window.lower() or "javascript:" in context_window.lower():
                        evidence.append("Canary appears inside script context")
                        status = TestStatus.VALIDATED
                        confidence = 0.8
                    elif re.search(r'<[a-z].*?' + re.escape(_CANARY), context_window, re.I):
                        evidence.append("Canary appears inside HTML tag")
                        status = TestStatus.OBSERVED
                        confidence = 0.6
                    else:
                        evidence.append("Canary reflected but context unclear - manual review required")
                        status = TestStatus.OBSERVED
                        confidence = 0.4

                    r = AttackTestResult(
                        category=self.category,
                        attack_class="Reflected XSS",
                        target_url=ep.url,
                        parameter=param,
                        method=ep.method,
                        route=ep.path,
                        authentication_context=ep.auth_context or "",
                        payload=_CANARY,
                        baseline=baseline,
                        observation=obs,
                        status=status,
                        confidence=confidence,
                        evidence=evidence,
                        why_tested=f"Query parameter '{param}' tested for reflection",
                        what_changed=f"Injected canary value '{_CANARY}' into parameter '{param}'",
                        what_observed=f"HTTP {obs.status_code}" + (" - canary reflected" if _CANARY in obs.body_excerpt else " - not reflected"),
                        what_remains_unverified="Full XSS execution not confirmed - encoding bypass not tested",
                        requests_made=2,
                    )
                    self._results.append(r)

        return self._results
