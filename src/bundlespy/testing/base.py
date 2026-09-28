"""Base class for all attack testers."""
from abc import ABC, abstractmethod
from typing import List
from ..models import AttackTestResult, AttackTestSummary, TestStatus
from ..safety import SafetyPolicy
from ...storage.models import Endpoint, ScanResult

class BaseTester(ABC):
    category: str = ""

    def __init__(self, fetcher, policy: SafetyPolicy, verbose: bool = False):
        self._fetcher = fetcher
        self._policy  = policy
        self._verbose = verbose
        self._results: List[AttackTestResult] = []

    @abstractmethod
    def run(self, result: ScanResult) -> List[AttackTestResult]:
        """
        Consume the ScanResult, test relevant endpoints/findings,
        and return a list of AttackTestResult.
        """

    @property
    def results(self) -> List[AttackTestResult]:
        return self._results

    def summary(self) -> AttackTestSummary:
        s = AttackTestSummary(category=self.category)
        for r in self._results:
            s.candidates += 1
            if r.status == TestStatus.SKIPPED:
                s.skipped += 1
            elif r.status == TestStatus.OUT_OF_SCOPE:
                s.out_of_scope += 1
            elif r.status not in (TestStatus.NOT_TESTED,):
                s.tested += 1
            if r.status == TestStatus.VALIDATED:
                s.validated += 1
            if r.status == TestStatus.CONFIRMED:
                s.confirmed += 1
            if r.status == TestStatus.INCONCLUSIVE:
                s.inconclusive += 1
        return s

    def _skip(self, reason: str, **kwargs) -> AttackTestResult:
        r = AttackTestResult(status=TestStatus.SKIPPED, skipped_reason=reason, **kwargs)
        self._results.append(r)
        return r

    def _out_of_scope(self, url: str, **kwargs) -> AttackTestResult:
        r = AttackTestResult(status=TestStatus.OUT_OF_SCOPE, target_url=url, **kwargs)
        self._results.append(r)
        return r
