"""Base class for all passive surface mappers."""
from abc import ABC, abstractmethod
from typing import List, Optional, Sequence
from ..models import (
    SurfaceResult, SurfaceSummary, SurfaceStatus,
    AttackCategory, ConfidenceLevel,
)
from ..evidence import Evidence, SurfaceFinding
from ..confidence import ConfidenceEngine
from ..fingerprint import make_fingerprint
from ..safety import SurfaceSafetyPolicy
from ...storage.models import Endpoint, ScanResult


class BaseSurfaceMapper(ABC):
    """
    Abstract base for all attack surface mappers.

    Rules enforced here:
    - requests_made is always 0 (ConfigurationMapper overrides this)
    - map() populates self.results; subclasses append to self._results
    - No payload injection, no HTTP mutations, no exploitation
    """
    category: str = ""

    def __init__(self, policy: Optional[SurfaceSafetyPolicy] = None, verbose: bool = False):
        self._policy   = policy
        self._verbose  = verbose
        self._results:  List[SurfaceResult]  = []
        self._findings: List[SurfaceFinding] = []   # Phase 1 evidence-model findings

    @abstractmethod
    def map(self, result: ScanResult) -> List[SurfaceResult]:
        """
        Consume the completed ScanResult and return surface candidates.
        No HTTP requests except in ConfigurationMapper.
        """

    @property
    def results(self) -> List[SurfaceResult]:
        return self._results

    @property
    def findings(self) -> List[SurfaceFinding]:
        """Phase 1 evidence-model findings (parallel to legacy results)."""
        return self._findings

    def summary(self) -> SurfaceSummary:
        s = SurfaceSummary(category=self.category)
        for r in self._results:
            s.total_candidates += 1
            # CANDIDATE = successfully identified surface (static analysis)
            # MAPPED    = HTTP-confirmed surface (ConfigurationMapper only)
            # Both count as "mapped" in the summary table
            if r.status in (SurfaceStatus.MAPPED, SurfaceStatus.CANDIDATE):
                s.mapped += 1
            elif r.status == SurfaceStatus.SKIPPED:
                s.skipped += 1
            elif r.status == SurfaceStatus.OUT_OF_SCOPE:
                s.out_of_scope += 1
        return s

    def _candidate(
        self,
        endpoint:     Endpoint,
        surface_type: str,
        parameters:   List[str],
        confidence:   str,
        evidence:     List[str],
        burp_notes:   str,
        auth_context: str = "",
    ) -> SurfaceResult:
        """
        Build a SurfaceResult candidate. requests_made is always 0 here.
        ConfigurationMapper overrides to set requests_made=1.
        """
        r = SurfaceResult(
            endpoint_url     = endpoint.url,
            method           = endpoint.method or "GET",
            category         = self.category,
            surface_type     = surface_type,
            parameters       = parameters,
            auth_context     = auth_context or (endpoint.auth_context or ""),
            confidence       = confidence,
            evidence         = evidence,
            provenance_source = getattr(endpoint, "source_type", "static") or "static",
            burp_notes       = burp_notes,
            requests_made    = 0,
            status           = SurfaceStatus.CANDIDATE,
        )
        # Invariant: non-ConfigurationMapper mappers never make requests
        assert r.requests_made == 0, (
            f"{self.__class__.__name__} must not make HTTP requests (requests_made={r.requests_made}). "
            "Only ConfigurationMapper may probe HTTP."
        )
        self._results.append(r)
        return r

    def _emit_evidence(
        self,
        evidence:     Sequence[Evidence],
        surface_type: str,
        subtype:      str  = "",
        endpoint:     str  = "",
        method:       str  = "GET",
        parameter:    str  = "",
        notes:        str  = "",
        risk:         str  = "",
    ) -> SurfaceFinding:
        """
        Build a SurfaceFinding from a list of Evidence objects.

        Scores confidence via ConfidenceEngine (single scorer for all detectors).
        Computes fingerprint for dedup.
        Appends to self._findings (parallel to legacy self._results).

        risk defaults to category baseline if not specified.
        """
        ev_list = list(evidence)
        score, level, status = ConfidenceEngine.score(ev_list)

        if not risk:
            risk = ConfidenceEngine.risk_from_category(self.category)

        fp = make_fingerprint(
            method       = method,
            endpoint     = endpoint,
            parameter    = parameter,
            surface_type = surface_type,
            subtype      = subtype,
        )

        finding = SurfaceFinding(
            fingerprint      = fp,
            surface_type     = surface_type,
            subtype          = subtype,
            endpoint         = endpoint,
            method           = method,
            parameter        = parameter,
            risk             = risk,
            confidence       = score,
            confidence_level = level,
            status           = status,
            evidence         = ev_list,
            provenance       = ev_list[0].source if ev_list else "",
            notes            = notes,
        )
        self._findings.append(finding)
        return finding
