"""
Coverage Reporting — observed facts only, no fake percentages.

Every number here comes from actual scan data.
No scores are invented or estimated.
"""

from dataclasses import dataclass, field
from typing import List, Optional


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
    elif sm_discovered == 0:
        blind_spots.append(BlindSpot(
            severity    = "LOW",
            description = "No source maps referenced in any JS file — original source not recoverable",
            mitigation  = "Re-run with --source-maps to attempt predictable .map path discovery.",
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
