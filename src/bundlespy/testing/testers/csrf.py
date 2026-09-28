"""CSRF tester - analyzes state-changing requests for missing CSRF controls."""
import re
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ...storage.models import ScanResult

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH"}
_CSRF_TOKEN_PATTERNS = [
    re.compile(r'csrf[-_]?token', re.I),
    re.compile(r'x-csrf-token', re.I),
    re.compile(r'_token', re.I),
    re.compile(r'authenticity_token', re.I),
    re.compile(r'__requestverificationtoken', re.I),
]

def _has_csrf_protection(ep) -> bool:
    """Check if endpoint shows evidence of CSRF protection."""
    headers = ep.request_headers or {}
    for k in headers:
        for pat in _CSRF_TOKEN_PATTERNS:
            if pat.search(k):
                return True
    for field in (ep.body_fields or []):
        fname = field.get("name", "")
        for pat in _CSRF_TOKEN_PATTERNS:
            if pat.search(fname):
                return True
    return False

class CsrfTester(BaseTester):
    category = AttackCategory.CSRF

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        for ep in result.endpoints:
            if (ep.method or "GET").upper() not in _STATE_CHANGING_METHODS:
                continue
            if ep.category == "API" and ep.auth_context and "bearer" in (ep.auth_context or "").lower():
                # Bearer token auth = CSRF not applicable
                continue

            allowed, reason = self._policy.check(
                ep.url, ep.method, "", "CSRF", ep.auth_context or "",
            )
            if not allowed:
                self._skip(reason, category=self.category, attack_class="CSRF",
                           target_url=ep.url, method=ep.method)
                continue

            has_protection = _has_csrf_protection(ep)
            samesite_cookie = False  # would need cookie analysis to verify

            evidence = []
            status   = TestStatus.CANDIDATE
            confidence = 0.2

            if not has_protection:
                evidence.append(f"No CSRF token found in request headers or body fields for {ep.method} {ep.path}")
                evidence.append("Cookie-based authentication context suggests CSRF may be possible")
                if ep.category == "AUTH":
                    evidence.append("Auth endpoint without CSRF protection is higher risk")
                    confidence = 0.55
                    status = TestStatus.OBSERVED
                else:
                    confidence = 0.35
                    status = TestStatus.CANDIDATE
            else:
                continue  # has protection, skip

            r = AttackTestResult(
                category=self.category,
                attack_class="CSRF",
                target_url=ep.url,
                parameter="",
                method=ep.method,
                route=ep.path,
                authentication_context=ep.auth_context or "",
                payload="",
                status=status,
                confidence=confidence,
                evidence=evidence,
                why_tested=f"{ep.method} request with no visible CSRF protection",
                what_changed="Static analysis only - no request sent",
                what_observed="No CSRF token observed in known fields",
                what_remains_unverified="SameSite cookie attribute not verified - server-side CSRF enforcement not tested",
                requests_made=0,
            )
            self._results.append(r)

        return self._results
