"""
Cross-mapper correlation pass.
Runs after all mappers complete on the same SurfaceReport.
Detects compound attack chains and upgrades confidence where signals overlap.

Chains detected:
  1. SSRF + Open Redirect on the same endpoint/param - SSRF-via-redirect chain
  2. CORS + CSRF on the same endpoint - both are exploitable together (no-SameSite + no-origin check)
  3. OAuth authorize/callback paths present in OpenRedirectMapper results - boost confidence
"""
from typing import List
from .models import SurfaceResult, AttackCategory, ConfidenceLevel, SurfaceStatus


def _url_key(result: SurfaceResult) -> str:
    return (result.endpoint_url or "").lower().split("?")[0]


def _param_overlap(a: SurfaceResult, b: SurfaceResult) -> bool:
    """True if the two results share at least one parameter name."""
    sa = set(p.lower() for p in (a.parameters or []))
    sb = set(p.lower() for p in (b.parameters or []))
    return bool(sa & sb)


def _upgrade(result: SurfaceResult, to: str) -> None:
    """Upgrade confidence level if the new level is higher."""
    order = ConfidenceLevel._ORDER
    if order.get(to, 99) < order.get(result.confidence, 99):
        result.confidence = to


def _append_evidence(result: SurfaceResult, note: str) -> None:
    if note not in (result.evidence or []):
        result.evidence.append(note)


def correlate(results: List[SurfaceResult]) -> List[SurfaceResult]:
    """
    Apply cross-mapper correlation to the flat results list.
    Mutates confidence and evidence in place.
    Returns the same list (possibly with additional synthetic entries).
    """
    if not results:
        return results

    # Index by category for fast lookup
    by_cat: dict = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)

    ssrf_results        = by_cat.get(AttackCategory.SSRF, [])
    redirect_results    = by_cat.get(AttackCategory.OPEN_REDIRECT, [])
    cors_results        = by_cat.get(AttackCategory.CORS, [])
    csrf_results        = by_cat.get(AttackCategory.CSRF, [])

    # --- Chain 1: SSRF + Open Redirect on the same URL/param ---
    # An open redirect on an endpoint that already has SSRF signals
    # means the SSRF can bounce through the redirect - escalate both.
    if ssrf_results and redirect_results:
        ssrf_by_url  = {_url_key(r): r for r in ssrf_results}
        redir_by_url: dict = {}
        for r in redirect_results:
            redir_by_url.setdefault(_url_key(r), []).append(r)

        for url, ssrf_r in ssrf_by_url.items():
            for redir_r in redir_by_url.get(url, []):
                # Same URL - potential SSRF-via-redirect chain
                chain_note = (
                    "Chain: SSRF + Open Redirect on the same endpoint - "
                    "SSRF payload can be routed through the redirect parameter to bypass allowlists"
                )
                _append_evidence(ssrf_r, chain_note)
                _append_evidence(redir_r, chain_note)
                _upgrade(ssrf_r, ConfidenceLevel.HIGH)
                _upgrade(redir_r, ConfidenceLevel.HIGH)

                # If they share a parameter, it is doubly interesting
                if _param_overlap(ssrf_r, redir_r):
                    param_note = (
                        f"Shared parameter(s) {set(ssrf_r.parameters) & set(redir_r.parameters)} "
                        "appear in both SSRF and Open Redirect findings - same sink exploitable both ways"
                    )
                    _append_evidence(ssrf_r, param_note)
                    _append_evidence(redir_r, param_note)

    # --- Chain 2: CORS + CSRF on the same endpoint ---
    # Permissive CORS (allows credentials + reflected/wildcard origin) combined with
    # a missing CSRF token means the attacker can read the response AND forge requests.
    if cors_results and csrf_results:
        cors_by_url: dict = {}
        for r in cors_results:
            cors_by_url.setdefault(_url_key(r), []).append(r)

        csrf_by_url = {_url_key(r): r for r in csrf_results}

        for url, csrf_r in csrf_by_url.items():
            for cors_r in cors_by_url.get(url, []):
                chain_note = (
                    "Chain: CORS + CSRF on the same endpoint - "
                    "permissive CORS lets the attacker read cross-origin responses; "
                    "missing CSRF token lets them forge state-changing requests"
                )
                _append_evidence(cors_r, chain_note)
                _append_evidence(csrf_r, chain_note)
                _upgrade(cors_r, ConfidenceLevel.HIGH)
                _upgrade(csrf_r, ConfidenceLevel.HIGH)

    # --- Chain 3: OAuth authorize/callback paths in Open Redirect findings ---
    # A redirect_uri bypass on /authorize or /callback is a full account takeover -
    # boost the open redirect to HIGH and annotate it.
    _OAUTH_PATH_SIGNALS = ("/authorize", "/oauth/authorize", "/auth/callback", "/callback", "/oauth/callback")
    for redir_r in redirect_results:
        url_lower = (redir_r.endpoint_url or "").lower()
        if any(sig in url_lower for sig in _OAUTH_PATH_SIGNALS):
            oauth_note = (
                "OAuth path in open redirect finding - "
                "if redirect_uri validation is weak, authorization codes leak to attacker domain"
            )
            _append_evidence(redir_r, oauth_note)
            _upgrade(redir_r, ConfidenceLevel.HIGH)

    return results
