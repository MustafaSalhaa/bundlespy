"""
Stage 6: Application State Intelligence
════════════════════════════════════════════════════════════════════════════════

Turns raw HTTP status codes recorded during the crawl into structured
access-state intelligence: which pages are public, which are auth-gated,
which returned hard denials, and which were never reached.

The module is intentionally stateless: all functions are pure transforms
over the data already collected by the crawler and headless browser.

Public API
──────────
  infer_access_state(http_status)     → AccessState constant
  infer_route_state(http_status, …)   → RouteState constant
  build_page_states(url_status_map)   → Dict[str, PageAccessRecord]
  build_state_transitions(page_states)→ List[StateTransition]
  apply_states_to_endpoints(…)        → mutates Endpoint objects in-place
  classify_endpoint_access(endpoint, page_states) → AccessState constant
  build_state_intelligence_report(result) → StateIntelligenceReport
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from ..storage.models import (
    AccessState,
    RouteState,
    PageAccessRecord,
    StateTransition,
    Endpoint,
    ScanResult,
)

logger = logging.getLogger("bundlespy.analysis.state_intelligence")


# ── Status-to-state mappings ──────────────────────────────────────────────────

def infer_access_state(http_status: int) -> str:
    """
    Map an HTTP status code to an AccessState constant.

    200-299  → PUBLIC         (responded without auth challenge)
    401      → AUTHENTICATED  (explicit credential demand)
    403      → AUTHENTICATED  (authenticated but unauthorised — still auth-gated)
    301/302  → UNKNOWN        (redirect destination determines real state)
    0        → UNKNOWN        (never reached / connection error)
    4xx/5xx  → UNKNOWN        (ambiguous — could be any state)
    """
    if 200 <= http_status <= 299:
        return AccessState.PUBLIC
    if http_status in (401, 403):
        return AccessState.AUTHENTICATED
    return AccessState.UNKNOWN


def infer_route_state(
    http_status:         int,
    observed_at_runtime: bool = False,
    redirected_to:       str  = "",
) -> str:
    """
    Map an HTTP status + context to a RouteState constant.

    observed_at_runtime: True when the headless browser saw an API call to this URL.
    redirected_to:       Non-empty string when a redirect was followed.
    """
    if observed_at_runtime:
        return RouteState.OBSERVED

    if http_status == 0:
        return RouteState.DISCOVERED        # attempted but no response

    if http_status == 401:
        return RouteState.AUTH_REQUIRED

    if http_status == 403:
        return RouteState.FORBIDDEN

    if http_status in (301, 302, 307, 308):
        return RouteState.REDIRECTED

    if 200 <= http_status <= 299:
        return RouteState.VISITED

    # 4xx (except 401/403), 5xx, other — treat as unreachable
    return RouteState.UNREACHABLE


# ── Build PageAccessRecord objects from raw crawler data ──────────────────────

def build_page_states(
    url_status_map: Dict[str, int],
    runtime_observed: Optional[Dict[str, str]] = None,
    redirect_map: Optional[Dict[str, str]] = None,
) -> Dict[str, "PageAccessRecord"]:
    """
    Convert a raw {url: http_status} dict into {url: PageAccessRecord}.

    Parameters
    ──────────
    url_status_map   : {url: last_http_status} from Crawler.page_access_states
    runtime_observed : {url: observed_at_page}  from headless browser API intercepts (optional)
    redirect_map     : {url: redirect_target}   from fetcher redirect tracking (optional)

    Returns
    ──────────────────────────────────────────────────────────────────────────
    {url: PageAccessRecord}  — one entry per URL in url_status_map
    """
    runtime_observed = runtime_observed or {}
    redirect_map     = redirect_map     or {}

    page_states: Dict[str, PageAccessRecord] = {}

    for url, http_status in url_status_map.items():
        observed_at_runtime = url in runtime_observed
        redirected_to       = redirect_map.get(url, "")

        access_state = infer_access_state(http_status)
        route_state  = infer_route_state(
            http_status,
            observed_at_runtime=observed_at_runtime,
            redirected_to=redirected_to,
        )

        auth_required: Optional[bool] = None
        if http_status in (401, 403):
            auth_required = True
        elif 200 <= http_status <= 299:
            auth_required = False

        record = PageAccessRecord(
            url           = url,
            http_status   = http_status,
            route_state   = route_state,
            access_state  = access_state,
            redirected_to = redirected_to,
            auth_required = auth_required,
        )

        # Single transition representing the latest probe
        record.transitions.append(StateTransition(
            url          = url,
            http_status  = http_status,
            route_state  = route_state,
            access_state = access_state,
            redirected_to= redirected_to,
        ))

        page_states[url] = record
        logger.debug(
            "PageState %s → HTTP %d  route=%s  access=%s",
            url, http_status, route_state, access_state,
        )

    return page_states


# ── Build state transition chain ──────────────────────────────────────────────

def build_state_transitions(
    page_states: Dict[str, "PageAccessRecord"],
) -> List["StateTransition"]:
    """
    Flatten all PageAccessRecord.transitions into one ordered list,
    sorted by route state priority (most interesting first).

    Useful for the terminal reporter's APPLICATION STATE section.
    """
    priority = {
        RouteState.AUTH_REQUIRED : 0,
        RouteState.FORBIDDEN     : 1,
        RouteState.REDIRECTED    : 2,
        RouteState.VISITED       : 3,
        RouteState.OBSERVED      : 4,
        RouteState.UNREACHABLE   : 5,
        RouteState.DISCOVERED    : 6,
    }

    all_transitions: List[StateTransition] = []
    for record in page_states.values():
        all_transitions.extend(record.transitions)

    all_transitions.sort(key=lambda t: priority.get(t.route_state, 99))
    return all_transitions


# ── Apply states to Endpoint objects ─────────────────────────────────────────

def classify_endpoint_access(
    endpoint:    "Endpoint",
    page_states: Dict[str, "PageAccessRecord"],
) -> str:
    """
    Determine the AccessState for an endpoint by checking whether the page
    that hosts it (source_page / observed_at) was auth-gated.

    Returns an AccessState constant.
    """
    # Check direct URL match first
    direct = page_states.get(endpoint.url)
    if direct:
        return direct.access_state

    # Check path-only match (endpoint URL may be relative)
    for url, record in page_states.items():
        if endpoint.path and endpoint.path in url:
            return record.access_state

    # Inherit from auth_context field if set
    if endpoint.auth_context and endpoint.auth_context not in ("", "None", "none"):
        return AccessState.AUTHENTICATED

    return AccessState.UNKNOWN


def apply_states_to_endpoints(
    endpoints:   List["Endpoint"],
    page_states: Dict[str, "PageAccessRecord"],
) -> None:
    """
    Mutate each Endpoint in-place, filling:
      - http_status   from matching PageAccessRecord
      - access_state  from classify_endpoint_access()
      - route_state   from matching PageAccessRecord (or DISCOVERED if not visited)

    Also updates endpoint.provenance.access_level when provenance exists.
    """
    for ep in endpoints:
        record = page_states.get(ep.url)

        if record:
            ep.http_status  = record.http_status
            ep.route_state  = record.route_state
            ep.access_state = record.access_state
        else:
            ep.access_state = classify_endpoint_access(ep, page_states)
            # Leave route_state as DISCOVERED (default) — never visited directly

        # Sync to provenance.access_level
        if ep.provenance is not None:
            ep.provenance.access_level = ep.access_state
            if ep.access_state == AccessState.AUTHENTICATED:
                ep.provenance.auth_required = True
            elif ep.access_state == AccessState.PUBLIC:
                ep.provenance.auth_required = False


# ── Aggregate report ──────────────────────────────────────────────────────────

@dataclass
class StateIntelligenceReport:
    """
    Summary of Application State Intelligence for one scan.
    Surfaced in the terminal reporter and JSON output.
    """
    total_urls:     int = 0
    public:         int = 0
    authenticated:  int = 0
    privileged:     int = 0
    unknown:        int = 0

    # Route state breakdown
    discovered:     int = 0
    visited:        int = 0
    observed:       int = 0
    auth_required:  int = 0
    forbidden:      int = 0
    redirected:     int = 0
    unreachable:    int = 0

    # Notable records
    auth_gated_urls:  List[str] = field(default_factory=list)
    forbidden_urls:   List[str] = field(default_factory=list)
    redirected_urls:  List[str] = field(default_factory=list)
    transitions:      List["StateTransition"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_urls":     self.total_urls,
            "access_states": {
                "public":        self.public,
                "authenticated": self.authenticated,
                "privileged":    self.privileged,
                "unknown":       self.unknown,
            },
            "route_states": {
                "discovered":    self.discovered,
                "visited":       self.visited,
                "observed":      self.observed,
                "auth_required": self.auth_required,
                "forbidden":     self.forbidden,
                "redirected":    self.redirected,
                "unreachable":   self.unreachable,
            },
            "auth_gated_urls":  self.auth_gated_urls,
            "forbidden_urls":   self.forbidden_urls,
            "redirected_urls":  self.redirected_urls,
            "transitions":      [t.to_dict() for t in self.transitions],
        }


def build_state_intelligence_report(result: "ScanResult") -> StateIntelligenceReport:
    """
    Build a StateIntelligenceReport from a completed ScanResult.
    Reads result.page_states (already built by build_page_states()).
    """
    report = StateIntelligenceReport()

    page_states = getattr(result, "page_states", {}) or {}
    report.total_urls = len(page_states)

    for record in page_states.values():
        # Access state counts
        if record.access_state == AccessState.PUBLIC:
            report.public += 1
        elif record.access_state == AccessState.AUTHENTICATED:
            report.authenticated += 1
        elif record.access_state == AccessState.PRIVILEGED:
            report.privileged += 1
        else:
            report.unknown += 1

        # Route state counts
        rs = record.route_state
        if rs == RouteState.DISCOVERED:
            report.discovered += 1
        elif rs == RouteState.VISITED:
            report.visited += 1
        elif rs == RouteState.OBSERVED:
            report.observed += 1
        elif rs == RouteState.AUTH_REQUIRED:
            report.auth_required += 1
            report.auth_gated_urls.append(record.url)
        elif rs == RouteState.FORBIDDEN:
            report.forbidden += 1
            report.forbidden_urls.append(record.url)
        elif rs == RouteState.REDIRECTED:
            report.redirected += 1
            report.redirected_urls.append(record.url)
        elif rs == RouteState.UNREACHABLE:
            report.unreachable += 1

    report.transitions = build_state_transitions(page_states)
    return report
