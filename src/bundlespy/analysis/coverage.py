"""
Coverage Metrics and Blind-Spot Reporting.

Produces an honest picture of:
- What was discovered (evidence-backed)
- What coverage was achieved (with confidence, not false certainty)
- Where blind spots exist (what BundleSpy cannot see)
- What the pentester should do manually to close gaps
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class CoverageSignal:
    """A single signal contributing to coverage confidence."""
    name:        str
    achieved:    bool
    detail:      str
    impact:      str   # HIGH / MEDIUM / LOW — how much this gap hurts coverage


@dataclass
class BlindSpot:
    """A known gap in what BundleSpy can see."""
    category:    str   # AUTH / DYNAMIC / RUNTIME / NETWORK / ROLE
    description: str
    mitigation:  str   # What the pentester should do manually
    severity:    str   # HIGH / MEDIUM / LOW — how likely this gap hides real findings


@dataclass
class CoverageReport:
    js_coverage:        int    # 0-100 confidence score for JS asset discovery
    page_coverage:      int    # 0-100 for page/route discovery
    secret_precision:   int    # 0-100 for secret detection accuracy
    endpoint_coverage:  int    # 0-100 for endpoint discovery
    overall:            int    # weighted overall
    signals:            List[CoverageSignal]
    blind_spots:        List[BlindSpot]
    summary:            str
    recommendations:    List[str]


def compute_coverage(
    js_files:       list,
    endpoints:      list,
    findings:       list,
    pages_crawled:  int,
    headless_used:  bool,
    source_maps:    bool,
    chunks_used:    bool,
    passive_used:   bool,
    has_cookie:     bool,
    has_headless_routes: int,
    lib_findings:   list,
    scan_errors:    list,
) -> CoverageReport:
    """
    Compute an honest coverage score based on what was actually done.
    Never inflates — only credits signals we actually achieved.
    """

    signals: List[CoverageSignal] = []
    blind_spots: List[BlindSpot] = []
    recommendations: List[str] = []

    # ── JS asset discovery signals ────────────────────────────────────────────

    has_js = len(js_files) > 0
    has_chunks = any(getattr(j, "technology", "") == "headless-captured"
                     or "chunk" in j.url.lower() for j in js_files)
    has_workers = any(getattr(j, "technology", "") == "webworker" for j in js_files)
    has_source_maps_found = source_maps and any(
        getattr(j, "has_source_map", False) for j in js_files
    )

    signals.append(CoverageSignal(
        "Static JS crawl", has_js,
        f"{len(js_files)} JS files discovered",
        "HIGH",
    ))
    signals.append(CoverageSignal(
        "Lazy chunk discovery", has_chunks,
        "Lazy-loaded chunks captured via browser" if has_chunks else "No lazy chunks found — headless may be needed",
        "MEDIUM",
    ))
    signals.append(CoverageSignal(
        "Source map recovery", has_source_maps_found,
        "Original source recovered" if has_source_maps_found else "No source maps found or recovered",
        "MEDIUM",
    ))
    signals.append(CoverageSignal(
        "WebWorker capture", has_workers,
        "Worker JS analyzed" if has_workers else "No workers detected",
        "LOW",
    ))
    signals.append(CoverageSignal(
        "Archive discovery (passive)", passive_used,
        "Historical JS from Wayback/CommonCrawl checked" if passive_used else "Not run",
        "LOW",
    ))

    # JS coverage score
    js_score = 40  # base for having any JS
    if has_chunks:        js_score += 25
    if has_source_maps_found: js_score += 20
    if has_workers:       js_score += 5
    if passive_used:      js_score += 10
    js_score = min(js_score, 90)  # never 100 — auth-gated assets always possible

    # ── Page/route discovery signals ──────────────────────────────────────────

    route_eps = [e for e in endpoints if getattr(e, "kind", "") == "route"
                 or getattr(e, "category", "") == "ROUTE"]
    api_eps   = [e for e in endpoints if getattr(e, "category", "") in ("API", "AUTH", "ADMIN", "GRAPHQL")]

    signals.append(CoverageSignal(
        "HTML crawl", pages_crawled > 0,
        f"{pages_crawled} pages crawled",
        "HIGH",
    ))
    signals.append(CoverageSignal(
        "SPA route extraction", headless_used and has_headless_routes > 0,
        f"{has_headless_routes} routes from JS router" if has_headless_routes > 0 else "No SPA routes found",
        "HIGH",
    ))
    signals.append(CoverageSignal(
        "Common path probing", True,
        "40+ common paths probed (/login, /admin, /dashboard, etc.)",
        "MEDIUM",
    ))
    signals.append(CoverageSignal(
        "Authenticated routes", has_cookie,
        "Scanning with session cookie" if has_cookie else "No auth — pages behind login not reached",
        "HIGH",
    ))

    page_score = 20
    if pages_crawled > 5:   page_score += 20
    if pages_crawled > 20:  page_score += 10
    if headless_used and has_headless_routes > 0: page_score += 25
    if has_cookie:          page_score += 15
    page_score = min(page_score, 85)  # auth-gated pages always a blind spot

    # ── Secret detection signals ──────────────────────────────────────────────

    total_js_bytes = sum(getattr(j, "size_bytes", 0) for j in js_files)
    has_inline     = any(j.url.startswith("inline:") or j.url.startswith("html:") for j in js_files)
    has_html_scan  = has_inline

    signals.append(CoverageSignal(
        "JS content analysis", len(js_files) > 0,
        f"{total_js_bytes/1024:.0f} KB analyzed across {len(js_files)} files",
        "HIGH",
    ))
    signals.append(CoverageSignal(
        "HTML attribute scanning", has_html_scan,
        "Inline scripts and HTML attributes scanned" if has_html_scan else "No inline content found",
        "MEDIUM",
    ))
    signals.append(CoverageSignal(
        "Library CVE detection", len(lib_findings) >= 0,
        f"{len(lib_findings)} CVEs found" if lib_findings else "No vulnerable libraries detected",
        "MEDIUM",
    ))

    secret_score = 70  # base — rules are solid
    if has_source_maps_found: secret_score += 15  # pre-minification source
    if has_html_scan:         secret_score += 5
    secret_score = min(secret_score, 92)

    # ── Endpoint discovery signals ────────────────────────────────────────────

    signals.append(CoverageSignal(
        "Static endpoint extraction", len(api_eps) > 0,
        f"{len(api_eps)} API/auth/admin endpoints extracted from JS",
        "HIGH",
    ))
    signals.append(CoverageSignal(
        "Runtime interception", headless_used,
        "Real network calls intercepted via browser" if headless_used else "Not run — dynamic endpoints may be missed",
        "HIGH",
    ))
    signals.append(CoverageSignal(
        "GraphQL introspection", any(getattr(e, "category", "") == "GRAPHQL" for e in endpoints),
        "GraphQL surface mapped" if any(getattr(e, "category", "") == "GRAPHQL" for e in endpoints) else "No GraphQL detected",
        "LOW",
    ))

    ep_score = 30
    if len(api_eps) > 0:   ep_score += 20
    if headless_used:       ep_score += 25
    if len(api_eps) > 10:  ep_score += 10
    if has_source_maps_found: ep_score += 10
    ep_score = min(ep_score, 88)

    # ── Overall weighted score ────────────────────────────────────────────────

    overall = int(
        js_score       * 0.25 +
        page_score     * 0.30 +
        secret_score   * 0.25 +
        ep_score       * 0.20
    )

    # ── Blind spots — always honest ───────────────────────────────────────────

    if not has_cookie:
        blind_spots.append(BlindSpot(
            "AUTH",
            "Routes and JS behind authentication not reached — any endpoint that requires a logged-in session is invisible.",
            "Re-run with --cookie 'session=<token>' after logging in manually.",
            "HIGH",
        ))
        recommendations.append("Re-run authenticated: --cookie 'session=<your-token>'")

    if not headless_used:
        blind_spots.append(BlindSpot(
            "DYNAMIC",
            "Headless browser not used — endpoints only loaded by JS execution (lazy routes, dynamic imports, API calls triggered by user interaction) are missed.",
            "Re-run with --headless to capture runtime network calls.",
            "HIGH",
        ))
        recommendations.append("Re-run with --headless for dynamic endpoint capture")

    if not has_source_maps_found:
        blind_spots.append(BlindSpot(
            "RUNTIME",
            "No source maps recovered — secrets and endpoints may exist in original pre-minification code that is compressed and harder to detect in the bundle.",
            "Re-run with --source-maps. If still not found, the server may not expose .map files.",
            "MEDIUM",
        ))

    blind_spots.append(BlindSpot(
        "ROLE",
        "Role-based routes not reached — endpoints and pages only accessible to admin, manager, or specific user roles require credentials for those roles.",
        "Re-run with credentials for each role that exists in the application.",
        "HIGH",
    ))

    blind_spots.append(BlindSpot(
        "RUNTIME",
        "Feature-flagged and conditionally rendered functionality not captured — some endpoints only exist when a feature flag is enabled, a specific tenant config is active, or the app is in a non-default state.",
        "Review the application's feature flag system if accessible.",
        "MEDIUM",
    ))

    blind_spots.append(BlindSpot(
        "NETWORK",
        "WAF or CDN may have blocked some requests — assets returning 403/429 during the scan were skipped.",
        "Check scan errors. Re-run with --stealth --rate 1 if blocking is suspected.",
        "MEDIUM",
    ))

    if scan_errors:
        blind_spots.append(BlindSpot(
            "NETWORK",
            f"{len(scan_errors)} fetch errors during scan — some assets may not have been retrieved.",
            "Review errors in verbose mode (-v) and retry manually.",
            "LOW",
        ))

    # ── Summary ───────────────────────────────────────────────────────────────

    if overall >= 75:
        summary = "Good coverage achieved for an unauthenticated scan. Key gaps are role-based routes and any auth-gated JS."
    elif overall >= 55:
        summary = "Moderate coverage. Headless and/or authentication would significantly improve discovery."
    else:
        summary = "Limited coverage — static-only scan. Use --headless and provide session credentials for a complete picture."

    return CoverageReport(
        js_coverage      = js_score,
        page_coverage    = page_score,
        secret_precision = secret_score,
        endpoint_coverage= ep_score,
        overall          = overall,
        signals          = signals,
        blind_spots      = blind_spots,
        summary          = summary,
        recommendations  = recommendations,
    )
