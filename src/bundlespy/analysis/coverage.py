"""
Coverage Reporting — observed facts only, no fake percentages.

Every number here comes from actual scan data.
No scores are invented or estimated.

Stage 5 additions:
  - CoverageLedger: per-entity provenance summary (how each finding/endpoint
    was discovered, corroborated, and validated).
  - build_coverage_ledger(): aggregates provenance counts from ScanResult.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PageStats:
    discovered:     int = 0
    visited:        int = 0
    failed:         int = 0
    auth_required:  int = 0
    auth_urls:      List[str] = field(default_factory=list)


@dataclass
class JSStats:
    discovered:  int = 0
    analyzed:    int = 0
    failed:      int = 0
    failed_urls: List[str] = field(default_factory=list)


@dataclass
class RouteStats:
    discovered: int = 0
    visited:    int = 0
    unvisited:  int = 0
    unvisited_urls: List[str] = field(default_factory=list)


@dataclass
class RuntimeStats:
    api_requests: int = 0
    websockets:   int = 0
    workers:      int = 0
    iframes:      int = 0


@dataclass
class SourceMapStats:
    discovered:  int = 0
    recovered:   int = 0
    unavailable: int = 0
    unavailable_urls: List[str] = field(default_factory=list)


@dataclass
class BlindSpot:
    severity:    str   # HIGH / MEDIUM / LOW
    description: str
    urls:        List[str] = field(default_factory=list)
    mitigation:  str = ""


@dataclass
class CoverageReport:
    pages:       PageStats
    js:          JSStats
    routes:      RouteStats
    runtime:     RuntimeStats
    source_maps: SourceMapStats
    blind_spots: List[BlindSpot]


def compute_coverage(
    js_files:            list,
    endpoints:           list,
    findings:            list,
    pages_crawled:       int,
    headless_used:       bool,
    source_maps:         bool,
    chunks_used:         bool,
    passive_used:        bool,
    has_cookie:          bool,
    has_headless_routes: int,
    lib_findings:        list,
    scan_errors:         list,
    headless_stats:      dict = None,
    sm_details:          dict = None,
    visited_pages:       set  = None,
) -> CoverageReport:
    """
    Build a coverage report from real observed scan data.
    Every number is a real count — nothing is invented.
    """

    hs  = headless_stats or {}
    smd = sm_details     or {}

    # ── Pages ─────────────────────────────────────────────────────────────────

    # Auth-required: pages that returned 401/403
    auth_required_urls = [
        e.url for e in (scan_errors or [])
        if isinstance(e, dict) and e.get("status") in (401, 403)
    ]
    # Also detect from errors list (may be strings like "403 /admin")
    auth_urls_from_errors = []
    for err in (scan_errors or []):
        if isinstance(err, str) and ("401" in err or "403" in err):
            # Try to extract URL
            parts = err.split()
            for p in parts:
                if p.startswith("http") or p.startswith("/"):
                    auth_urls_from_errors.append(p)

    all_auth_urls = list(set(auth_required_urls + auth_urls_from_errors))

    # Total pages = crawler pages + headless pages (headless visits additional routes)
    headless_pages = hs.get("pages", 0)
    total_visited  = pages_crawled + headless_pages
    total_discovered = max(
        len(visited_pages) if visited_pages else pages_crawled,
        total_visited
    )

    pages = PageStats(
        discovered    = total_discovered,
        visited       = total_visited,
        failed        = sum(1 for e in (scan_errors or [])
                           if isinstance(e, str) and
                           any(c in e for c in ["500","502","503","timeout","error"])),
        auth_required = len(all_auth_urls),
        auth_urls     = all_auth_urls[:5],
    )

    # ── JavaScript ────────────────────────────────────────────────────────────

    failed_js = [
        e for e in (scan_errors or [])
        if isinstance(e, str) and ".js" in e.lower()
    ]
    analyzed = [j for j in js_files if j.content and len(j.content) > 0]

    js = JSStats(
        discovered  = len(js_files),
        analyzed    = len(analyzed),
        failed      = len(failed_js),
        failed_urls = failed_js[:3],
    )

    # ── Routes ────────────────────────────────────────────────────────────────

    route_eps = [e for e in endpoints
                 if getattr(e, "kind", "") == "route"
                 or getattr(e, "category", "") == "ROUTE"]

    # Routes discovered from JS router extraction
    routes_discovered = has_headless_routes if has_headless_routes else len(route_eps)
    routes_visited    = hs.get("pages", 0) if headless_used else pages_crawled

    # Unvisited = discovered but not visited (max_pages limit or errors)
    unvisited = max(0, routes_discovered - routes_visited)

    routes = RouteStats(
        discovered    = routes_discovered,
        visited       = min(routes_visited, routes_discovered),
        unvisited     = unvisited,
        unvisited_urls = [],  # populated below if we have the data
    )

    # ── Runtime ───────────────────────────────────────────────────────────────

    workers_count = sum(1 for j in js_files
                        if getattr(j, "technology", "") == "webworker")

    runtime = RuntimeStats(
        api_requests = hs.get("xhr", 0) + hs.get("fetch", 0),
        websockets   = hs.get("ws", 0),
        workers      = workers_count,
        iframes      = 0,  # tracked if iframe detection added
    )

    # ── Source maps ───────────────────────────────────────────────────────────

    sm_discovered  = smd.get("discovered", 0)
    sm_recovered   = smd.get("recovered", 0) if smd else 0
    sm_unavailable = sm_discovered - sm_recovered

    # Collect unavailable map URLs from details
    unavail_urls = []
    for item in smd.get("items", []):
        if item.get("sources", 0) == 0:
            unavail_urls.append(item.get("map", ""))

    source_maps_stat = SourceMapStats(
        discovered       = sm_discovered,
        recovered        = sm_recovered,
        unavailable      = max(0, sm_unavailable),
        unavailable_urls = unavail_urls[:3],
    )

    # ── Blind spots — only real observed gaps ─────────────────────────────────

    blind_spots: List[BlindSpot] = []

    # Auth-required pages actually observed
    if all_auth_urls:
        blind_spots.append(BlindSpot(
            severity    = "HIGH",
            description = f"{len(all_auth_urls)} page(s) returned 401/403 — content not analyzed",
            urls        = all_auth_urls[:5],
            mitigation  = "Re-run with --cookie 'session=<token>' after authenticating manually",
        ))
    elif not has_cookie:
        blind_spots.append(BlindSpot(
            severity    = "HIGH",
            description = "No session cookie provided — all auth-gated pages and JS are out of scope",
            mitigation  = "Re-run with --cookie 'session=<token>'",
        ))

    # JS files that failed
    if js.failed > 0:
        blind_spots.append(BlindSpot(
            severity    = "MEDIUM",
            description = f"{js.failed} JavaScript asset(s) could not be fetched",
            urls        = failed_js[:3],
            mitigation  = "Check if these are blocked by WAF or require auth. Re-run with --stealth.",
        ))

    # Source maps referenced but unavailable
    if source_maps_stat.unavailable > 0:
        blind_spots.append(BlindSpot(
            severity    = "MEDIUM",
            description = f"{source_maps_stat.unavailable} source map(s) referenced in JS but could not be recovered",
            urls        = unavail_urls[:3],
            mitigation  = "The .map file exists in code but the server did not serve it. Check staging or ask the dev team.",
        ))
    elif source_maps and sm_discovered == 0:
        blind_spots.append(BlindSpot(
            severity    = "LOW",
            description = "Source maps scanned but none found — no .map references in JS and predictable paths returned nothing",
            mitigation  = "Source maps may be disabled in production. Check if staging exposes them.",
        ))
    elif not source_maps:
        blind_spots.append(BlindSpot(
            severity    = "LOW",
            description = "Source map recovery not attempted",
            mitigation  = "Re-run with --source-maps to attempt recovery of original pre-minification source.",
        ))

    # Routes not visited due to max-pages
    if routes.unvisited > 0:
        blind_spots.append(BlindSpot(
            severity    = "LOW",
            description = f"{routes.unvisited} discovered route(s) not visited — increase --max-pages",
            mitigation  = f"Re-run with --max-pages {max(500, routes_discovered * 2)}",
        ))

    # No headless
    if not headless_used:
        blind_spots.append(BlindSpot(
            severity    = "HIGH",
            description = "Headless browser not used — runtime-only endpoints not captured",
            mitigation  = "Re-run with --headless",
        ))

    # Page failures
    if pages.failed > 0:
        blind_spots.append(BlindSpot(
            severity    = "LOW",
            description = f"{pages.failed} page(s) failed during crawl (5xx / timeout)",
            mitigation  = "Check target availability. Re-run with --rate 1 --timeout 20",
        ))

    return CoverageReport(
        pages       = pages,
        js          = js,
        routes      = routes,
        runtime     = runtime,
        source_maps = source_maps_stat,
        blind_spots = blind_spots,
    )


# ── Stage 5: Coverage Ledger ──────────────────────────────────────────────────

@dataclass
class ProvenanceSummary:
    """
    Aggregate counts for one entity class (findings or endpoints).
    Every field is a real observed count — nothing is estimated.
    """
    total:          int = 0

    # ── Discovery source breakdown ────────────────────────────────────────────
    from_static:    int = 0   # Found in static JS analysis
    from_runtime:   int = 0   # Observed at runtime via headless browser
    from_passive:   int = 0   # Sourced from passive recon (Wayback, etc.)
    from_correlated: int = 0  # Found in both static and runtime

    # ── Validation breakdown ──────────────────────────────────────────────────
    not_validated:  int = 0   # No probe attempted
    confirmed:      int = 0   # Probe returned 2xx / pattern still present
    unreachable:    int = 0   # Probe got 4xx/5xx/timeout
    validation_err: int = 0   # Probe raised exception

    # ── Access level breakdown ────────────────────────────────────────────────
    auth_required:  int = 0   # Known auth-gated
    public:         int = 0   # Confirmed publicly accessible
    unknown_access: int = 0   # Access level not determined

    # Stage 6: Route state breakdown (endpoints only — populated when page_states available)
    route_discovered:    int = 0
    route_visited:       int = 0
    route_observed:      int = 0
    route_auth_required: int = 0
    route_forbidden:     int = 0
    route_redirected:    int = 0
    route_unreachable:   int = 0

    def to_dict(self) -> Dict:
        return {
            "total":           self.total,
            "by_source": {
                "static":      self.from_static,
                "runtime":     self.from_runtime,
                "passive":     self.from_passive,
                "correlated":  self.from_correlated,
            },
            "by_validation": {
                "not_validated":  self.not_validated,
                "confirmed":      self.confirmed,
                "unreachable":    self.unreachable,
                "error":          self.validation_err,
            },
            "by_access": {
                "auth_required":  self.auth_required,
                "public":         self.public,
                "unknown":        self.unknown_access,
            },
            "by_route_state": {
                "discovered":    self.route_discovered,
                "visited":       self.route_visited,
                "observed":      self.route_observed,
                "auth_required": self.route_auth_required,
                "forbidden":     self.route_forbidden,
                "redirected":    self.route_redirected,
                "unreachable":   self.route_unreachable,
            },
        }


@dataclass
class CoverageLedger:
    """
    The provenance ledger for a complete scan.

    Produced by build_coverage_ledger() from a ScanResult after all
    provenances have been populated.  Safe to attach to CoverageReport
    or ScanResult — zero breaking changes.
    """
    findings:  ProvenanceSummary = field(default_factory=ProvenanceSummary)
    endpoints: ProvenanceSummary = field(default_factory=ProvenanceSummary)

    # Validation breadth: how many high/critical findings were probed
    high_critical_total:    int = 0
    high_critical_probed:   int = 0
    high_critical_confirmed: int = 0

    def to_dict(self) -> Dict:
        return {
            "findings":  self.findings.to_dict(),
            "endpoints": self.endpoints.to_dict(),
            "high_critical": {
                "total":     self.high_critical_total,
                "probed":    self.high_critical_probed,
                "confirmed": self.high_critical_confirmed,
            },
        }


def build_coverage_ledger(findings: list, endpoints: list) -> CoverageLedger:
    """
    Build a CoverageLedger from findings and endpoints whose provenance
    fields have already been populated (either by passive_validator or
    by lazy construction at report-time via Provenance.from_*).

    This function is pure — no network I/O, no side effects.
    """
    from ..storage.models import Provenance

    def _prov(obj, factory) -> "Provenance":
        """Return the attached provenance or build a baseline from the object."""
        p = getattr(obj, "provenance", None)
        if p is not None:
            return p
        return factory(obj)

    ledger = CoverageLedger()
    fs  = ledger.findings
    eps = ledger.endpoints

    # ── Findings ──────────────────────────────────────────────────────────────
    for f in findings:
        fs.total += 1
        prov = _prov(f, Provenance.from_finding)

        if prov.source == "static":         fs.from_static    += 1
        elif prov.source == "runtime":      fs.from_runtime   += 1
        elif prov.source == "passive":      fs.from_passive   += 1
        elif prov.source == "correlated":   fs.from_correlated += 1
        else:                               fs.from_static    += 1  # default

        vs = prov.validation_status
        if vs == "CONFIRMED":       fs.confirmed      += 1
        elif vs == "UNREACHABLE":   fs.unreachable    += 1
        elif vs == "ERROR":         fs.validation_err += 1
        else:                       fs.not_validated  += 1

        al = prov.access_level
        if al == "AUTHENTICATED":   fs.auth_required  += 1
        elif al == "PUBLIC":        fs.public         += 1
        else:                       fs.unknown_access += 1

        # High/critical probe tracking
        sev = getattr(f, "severity", "")
        if sev in ("CRITICAL", "HIGH"):
            ledger.high_critical_total += 1
            if vs != "NOT_VALIDATED":
                ledger.high_critical_probed += 1
            if vs == "CONFIRMED":
                ledger.high_critical_confirmed += 1

    # ── Endpoints ─────────────────────────────────────────────────────────────
    for ep in endpoints:
        eps.total += 1
        prov = _prov(ep, Provenance.from_endpoint)

        if prov.source == "static":         eps.from_static    += 1
        elif prov.source == "runtime":      eps.from_runtime   += 1
        elif prov.source == "passive":      eps.from_passive   += 1
        elif prov.source == "correlated":   eps.from_correlated += 1
        else:                               eps.from_static    += 1

        vs = prov.validation_status
        if vs == "CONFIRMED":       eps.confirmed      += 1
        elif vs == "UNREACHABLE":   eps.unreachable    += 1
        elif vs == "ERROR":         eps.validation_err += 1
        else:                       eps.not_validated  += 1

        al = prov.access_level
        if al == "AUTHENTICATED":   eps.auth_required  += 1
        elif al == "PUBLIC":        eps.public         += 1
        else:                       eps.unknown_access += 1

        # Stage 6: Route state breakdown from endpoint.route_state
        rs = getattr(ep, "route_state", "DISCOVERED")
        if rs == "DISCOVERED":      eps.route_discovered    += 1
        elif rs == "VISITED":       eps.route_visited       += 1
        elif rs == "OBSERVED":      eps.route_observed      += 1
        elif rs == "AUTH_REQUIRED": eps.route_auth_required += 1
        elif rs == "FORBIDDEN":     eps.route_forbidden     += 1
        elif rs == "REDIRECTED":    eps.route_redirected    += 1
        elif rs == "UNREACHABLE":   eps.route_unreachable   += 1
        else:                       eps.route_discovered    += 1  # fallback

    return ledger
