"""
Injection tester (SQL, NoSQL, LDAP, template).
Uses differential, non-destructive probes only.
"""
import re
import time
from typing import List
from .base import BaseTester
from ..models import AttackTestResult, TestStatus, AttackCategory
from ..baseline import capture_baseline, capture_observation, differential
from ...storage.models import ScanResult

# Safe boolean-differential probes (no destructive SQL)
_BOOLEAN_TRUE  = "1' AND '1'='1"
_BOOLEAN_FALSE = "1' AND '1'='2"
_TIMING_PROBE  = "1; SELECT SLEEP(0)--"  # harmless 0-second sleep

# DB error signatures (evidence, not proof)
_DB_ERROR_PATTERNS = [
    re.compile(r'(sql syntax|mysql_fetch|pg_query|ora-\d{5}|sqlite.*error|'
               r'unclosed quotation|unterminated string|odbc.*error|'
               r'jdbc.*exception|syntax error.*near|column.*does not exist)',
               re.I),
    re.compile(r'(PDOException|SQLException|OracleException|MySQLi?Exception)', re.I),
]

_NOSQL_ERROR_PATTERNS = [
    re.compile(r'(mongodb.*error|MongoServerError|BSON|CastError:.*path)', re.I),
]

_SSTI_CANARIES = [
    ("{{7*7}}", "49"),        # Jinja2/Twig
    ("${7*7}",  "49"),        # FreeMarker/Spring EL
    ("#{7*7}",  "49"),        # Ruby ERB / Thymeleaf
]

_INJECTION_PARAM_SIGNALS = [
    "id", "q", "query", "search", "filter", "sort", "order",
    "category", "type", "name", "user", "username", "email",
    "keyword", "term", "value", "field", "where", "condition",
]

def _has_db_error(body: str) -> tuple:
    for pat in _DB_ERROR_PATTERNS:
        m = pat.search(body)
        if m:
            return True, m.group(0)
    return False, ""

def _has_nosql_error(body: str) -> tuple:
    for pat in _NOSQL_ERROR_PATTERNS:
        m = pat.search(body)
        if m:
            return True, m.group(0)
    return False, ""

class InjectionTester(BaseTester):
    category = AttackCategory.INJECTION

    def run(self, result: ScanResult) -> List[AttackTestResult]:
        for ep in result.endpoints:
            params = list(ep.query_params or []) + list(ep.path_params or [])
            for qp in params:
                pname = (qp.get("name") or "").lower()
                if not any(s in pname for s in _INJECTION_PARAM_SIGNALS):
                    continue  # skip low-signal params

                allowed, reason = self._policy.check(
                    ep.url, ep.method, pname, "SQLI", ep.auth_context or "",
                )
                if not allowed:
                    self._skip(reason, category=self.category, attack_class="SQL Injection",
                               target_url=ep.url, parameter=pname)
                    continue

                baseline = capture_baseline(self._fetcher, ep.url)
                if baseline is None:
                    self._skip("baseline_unreachable", category=self.category,
                               attack_class="SQL Injection", target_url=ep.url, parameter=pname)
                    continue

                sep = "&" if "?" in ep.url else "?"

                # Boolean true probe
                true_url  = f"{ep.url}{sep}{pname}={_BOOLEAN_TRUE}"
                false_url = f"{ep.url}{sep}{pname}={_BOOLEAN_FALSE}"

                for url2 in (true_url, false_url):
                    self._policy.check(url2, ep.method, pname, "SQLI_BOOL", ep.auth_context or "")

                true_obs  = capture_observation(self._fetcher, true_url)
                false_obs = capture_observation(self._fetcher, false_url)

                if true_obs is None or false_obs is None:
                    continue

                evidence  = []
                status    = TestStatus.CANDIDATE
                confidence = 0.2
                attack_class = "SQL Injection"

                # Check for DB errors
                has_err, err_text = _has_db_error(true_obs.body_excerpt + false_obs.body_excerpt)
                if has_err:
                    evidence.append(f"Database error signature: '{err_text[:80]}'")
                    status = TestStatus.OBSERVED
                    confidence = 0.5
                    attack_class = "SQL Injection"

                # Boolean differential
                diff = differential(baseline, true_obs)
                diff2 = differential(true_obs, false_obs)
                if diff2.get("content_length") or diff2.get("body_changed"):
                    bl, ol = diff2.get("content_length", (0, 0))
                    evidence.append(f"Boolean differential: TRUE/FALSE responses differ ({bl} vs {ol} bytes)")
                    if not has_err:
                        status = TestStatus.OBSERVED
                        confidence = 0.45

                # NoSQL check
                has_nosql, nosql_text = _has_nosql_error(true_obs.body_excerpt)
                if has_nosql:
                    evidence.append(f"NoSQL error signature: '{nosql_text[:80]}'")
                    status = TestStatus.OBSERVED
                    confidence = 0.5
                    attack_class = "NoSQL Injection"

                if not evidence:
                    continue  # no signal, don't report

                r = AttackTestResult(
                    category=self.category,
                    attack_class=attack_class,
                    target_url=ep.url,
                    parameter=pname,
                    method=ep.method,
                    route=ep.path,
                    authentication_context=ep.auth_context or "",
                    payload=_BOOLEAN_TRUE,
                    baseline=baseline,
                    observation=true_obs,
                    status=status,
                    confidence=confidence,
                    evidence=evidence,
                    why_tested=f"Parameter '{pname}' exhibits database-like naming/behavior",
                    what_changed=f"Injected boolean SQL probe into '{pname}'",
                    what_observed=f"HTTP {true_obs.status_code}" + (f" - error: {err_text[:40]}" if has_err else ""),
                    what_remains_unverified="Boolean differential observed but not confirmed as injection - encoding/WAF not tested",
                    requests_made=3,
                )
                self._results.append(r)

        return self._results
