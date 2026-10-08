"""
BusinessLogicMapper - Business logic flaws and race condition attack surface detection.
Pure static analysis of collected endpoint data. Zero HTTP requests.

Detection cases:
  1. Race conditions on state-changing endpoints without idempotency tokens
  2. Negative value injection surfaces (price, quantity, discount params)
  3. Mass assignment - more body fields than expected for the endpoint type
  4. Privilege escalation via account/user parameters on user-facing endpoints
  5. Workflow bypass - direct access to later steps without earlier step token
  6. Integer overflow vectors - quantity/amount params that might accept very large numbers
  7. Account takeover vectors - password reset / email change endpoints without re-auth
"""
import re
from typing import List, Set, Dict

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ..param_semantics import classify_param, ParamType, ParamTier
from ...storage.models import ScanResult, Endpoint

# Numeric/amount param names - negative value injection and integer overflow
_AMOUNT_PARAMS = frozenset({
    "price", "amount", "quantity", "qty", "count", "total", "subtotal",
    "discount", "coupon_amount", "credit", "points", "balance",
    "fee", "tax", "shipping", "tip", "refund",
})

# Params that hint at workflow state - being sent directly = workflow bypass risk
_WORKFLOW_STATE_PARAMS = frozenset({
    "step", "stage", "phase", "workflow", "flow", "next_step",
    "current_step", "process", "state", "checkout_step",
    "order_step", "wizard", "page",
})

# Idempotency headers - their PRESENCE indicates the dev knew about races
_IDEMPOTENCY_HEADERS = frozenset({
    "idempotency-key", "x-idempotency-key", "x-request-id", "request-id",
})

# Account takeover vector paths
_ATO_PATH_SIGNALS = (
    "/password-reset", "/reset-password", "/change-password", "/forgot-password",
    "/email-change", "/change-email", "/update-email",
    "/verify-email", "/confirm-email",
    "/account-recovery", "/recovery",
)

# Price/monetary endpoint path signals
_MONETARY_PATH_SIGNALS = (
    "/checkout", "/payment", "/order", "/cart", "/purchase",
    "/refund", "/invoice", "/billing", "/subscription",
    "/price", "/pricing", "/discount", "/promo",
)

_BURP_NOTES_RACE = (
    "Race condition surface - state-changing endpoint without idempotency controls. "
    "Steps: 1) In Burp Repeater, send the same request 20+ times simultaneously. "
    "Use the 'Send group (parallel)' feature (Burp Suite 2023+). "
    "2) Watch for duplicate effects: double charges, duplicate items, balance inconsistencies. "
    "3) Use Turbo Intruder for high-volume race attack with HTTP/2 single-packet attack. "
    "4) Common targets: transfer funds, apply discount, claim reward, confirm order."
)

_BURP_NOTES_NEGATIVE = (
    "Negative value injection - numeric parameter may accept negative amounts. "
    "Steps: 1) Set quantity or price to -1 and submit. "
    "2) Check if total price decreases (negative price = refund to attacker). "
    "3) Try very large integers (overflow wrap-around). "
    "4) Try decimal fractions to test rounding errors (0.001 repeated = free items). "
    "5) Combine: negative discount coupon may ADD to the price of others."
)

_BURP_NOTES_MASS_ASSIGN = (
    "Mass assignment surface - endpoint accepts many body fields. "
    "Additional fields may be processed even if not in the official API docs. "
    "Steps: 1) Add extra fields like 'is_admin', 'role', 'price', 'discount_percent'. "
    "2) Check if they affect the resulting object in a subsequent GET. "
    "3) Send the full user object schema with sensitive fields added. "
    "4) Use Param Miner or manual fuzzing to discover hidden accepted fields."
)

_BURP_NOTES_WORKFLOW_BYPASS = (
    "Workflow bypass surface - step/stage parameter accepted directly. "
    "If the workflow state is client-controlled, steps can be skipped. "
    "Steps: 1) Change 'step' parameter to a later value (e.g. step=3 without completing step 2). "
    "2) If the server accepts it, the intermediate validation is bypassed. "
    "3) Common exploits: skip payment step, skip email verification, skip terms acceptance. "
    "4) Try sending step=complete or step=final directly."
)

_BURP_NOTES_ATO = (
    "Account takeover vector - password reset or email change without re-authentication. "
    "Steps: 1) Test password reset token reuse (use the same reset token twice). "
    "2) Test email change without current password (change to attacker email). "
    "3) Check if reset tokens expire properly (test a 24h old token). "
    "4) Test for predictable reset tokens (sequential, timestamp-based). "
    "5) Test if reset link works after email is already changed (stale token)."
)

_BURP_NOTES_PRIV_PARAM = (
    "Privilege escalation via user/account parameters on user-facing endpoint. "
    "Steps: 1) Test by changing the account ID or role field to another user's value. "
    "2) Submit is_admin=true or role=admin in the request body. "
    "3) Check if the server-side object state changes reflect the injected field. "
    "4) Combine with mass assignment to set multiple privilege fields at once."
)


def _endpoint_has_idempotency(ep: Endpoint) -> bool:
    """Return True if idempotency controls are present."""
    for k in (ep.request_headers or {}):
        if k.lower() in _IDEMPOTENCY_HEADERS:
            return True
    return False


def _is_monetary_path(path: str) -> bool:
    p = path.lower()
    return any(sig in p for sig in _MONETARY_PATH_SIGNALS)


def _is_ato_path(path: str) -> bool:
    p = path.lower()
    return any(sig in p for sig in _ATO_PATH_SIGNALS)


class BusinessLogicMapper(BaseSurfaceMapper):
    category = AttackCategory.BUSINESS_LOGIC

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        for ep in result.endpoints:
            url      = ep.url or ""
            path     = ep.path or ""
            method   = (ep.method or "GET").upper()
            auth_ctx = ep.auth_context or ""
            is_authed = auth_ctx and auth_ctx.lower() not in ("", "none")

            all_params = list(ep.query_params or []) + list(ep.body_fields or [])
            param_names = {
                (p.get("name") or "").lower() if isinstance(p, dict) else str(p).lower()
                for p in all_params
            }

            # Check 1: race condition on POST/PUT without idempotency
            if method in ("POST", "PUT", "PATCH") and not _endpoint_has_idempotency(ep):
                # Score higher for monetary paths
                is_monetary = _is_monetary_path(path)
                key = f"race:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"State-changing {method} endpoint without idempotency header: {url}",
                    ]
                    if is_monetary:
                        evidence.append("Monetary/order endpoint - race conditions here can cause double charges or free items")
                    if is_authed:
                        evidence.append(f"Auth context: {auth_ctx}")
                    conf = ConfidenceLevel.HIGH if is_monetary else ConfidenceLevel.MEDIUM
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Business Logic: Race Condition",
                        parameters   = [],
                        confidence   = conf,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_RACE,
                        auth_context = auth_ctx,
                    )
                    raw_conf = 65 if is_monetary else 45
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.ROUTE_DECLARATION,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = f"Race condition surface: {method} {url} (no idempotency)",
                                details        = "No idempotency header - concurrent requests may produce duplicate effects",
                                raw_confidence = raw_conf,
                            ),
                        ],
                        surface_type = "Business Logic: Race Condition",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_RACE,
                    )

            # Check 2: negative value injection on amount params
            amount_found = param_names & _AMOUNT_PARAMS
            if amount_found and method in ("POST", "PUT", "PATCH"):
                key = f"neg_value:{method}:{url}:{','.join(sorted(amount_found))}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"Numeric amount parameters on {method} {url}: {', '.join(sorted(amount_found))}",
                        "Negative values or extreme integers may cause business logic flaws",
                    ]
                    if _is_monetary_path(path):
                        evidence.append("Monetary endpoint - negative amounts may result in balance increase or free items")
                    if is_authed:
                        evidence.append(f"Auth context: {auth_ctx}")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Business Logic: Negative Value Injection",
                        parameters   = list(sorted(amount_found)),
                        confidence   = ConfidenceLevel.HIGH if _is_monetary_path(path) else ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_NEGATIVE,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = f"Numeric amount params: {', '.join(sorted(amount_found))}",
                                details        = "Amount parameters on state-changing endpoint - negative value injection risk",
                                raw_confidence = 65 if _is_monetary_path(path) else 45,
                            ),
                        ],
                        surface_type = "Business Logic: Negative Value Injection",
                        endpoint     = url,
                        method       = method,
                        parameter    = next(iter(sorted(amount_found))),
                        notes        = _BURP_NOTES_NEGATIVE,
                    )

            # Check 3: mass assignment - many body fields on POST/PUT
            body_count = len(ep.body_fields or [])
            if body_count >= 5 and method in ("POST", "PUT", "PATCH"):
                # Check for any privilege-related fields in the body
                priv_fields = {
                    (p.get("name") or "").lower() if isinstance(p, dict) else str(p).lower()
                    for p in (ep.body_fields or [])
                    if classify_param(
                        (p.get("name") or "") if isinstance(p, dict) else str(p)
                    ).param_type == ParamType.PRIVILEGE
                }
                if priv_fields:
                    key = f"mass_assign:{method}:{url}"
                    if key not in seen:
                        seen.add(key)
                        evidence = [
                            f"{method} {url} has {body_count} body fields including privilege fields: {', '.join(priv_fields)}",
                            "High field count suggests the server may accept extra fields (mass assignment)",
                        ]
                        if is_authed:
                            evidence.append(f"Auth context: {auth_ctx}")
                        self._candidate(
                            endpoint     = ep,
                            surface_type = "Business Logic: Mass Assignment",
                            parameters   = list(priv_fields),
                            confidence   = ConfidenceLevel.HIGH,
                            evidence     = evidence,
                            burp_notes   = _BURP_NOTES_MASS_ASSIGN,
                            auth_context = auth_ctx,
                        )
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                    source         = "static",
                                    asset          = url,
                                    endpoint       = url,
                                    context        = f"Mass assignment surface: privilege fields in body",
                                    details        = f"Privilege params: {', '.join(priv_fields)} in {body_count}-field request body",
                                    raw_confidence = 65,
                                ),
                            ],
                            surface_type = "Business Logic: Mass Assignment",
                            endpoint     = url,
                            method       = method,
                            parameter    = next(iter(priv_fields)),
                            notes        = _BURP_NOTES_MASS_ASSIGN,
                        )

            # Check 4: workflow state params - direct step manipulation
            workflow_params = param_names & _WORKFLOW_STATE_PARAMS
            if workflow_params:
                key = f"workflow:{method}:{url}:{','.join(sorted(workflow_params))}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"{method} {url} has workflow state parameter(s): {', '.join(sorted(workflow_params))}",
                        "Client-controlled workflow state can allow skipping required steps",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Business Logic: Workflow Bypass",
                        parameters   = list(sorted(workflow_params)),
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_WORKFLOW_BYPASS,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = f"Workflow state param: {', '.join(sorted(workflow_params))}",
                                details        = "Client-controlled step/stage parameter - workflow bypass risk",
                                raw_confidence = 50,
                            ),
                        ],
                        surface_type = "Business Logic: Workflow Bypass",
                        endpoint     = url,
                        method       = method,
                        parameter    = next(iter(sorted(workflow_params))),
                        notes        = _BURP_NOTES_WORKFLOW_BYPASS,
                    )

            # Check 5: account takeover paths
            if _is_ato_path(path):
                key = f"ato:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"{method} {url} - account takeover vector (password reset / email change path)",
                        "Test for token reuse, weak tokens, missing re-auth, and race conditions",
                    ]
                    if is_authed:
                        evidence.append(f"Auth context: {auth_ctx}")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Business Logic: Account Takeover Vector",
                        parameters   = list(param_names)[:5],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_ATO,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.ROUTE_DECLARATION,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "ATO vector: password reset / email change endpoint",
                                details        = f"Path '{path}' is an account takeover surface - test token handling",
                                raw_confidence = 65,
                            ),
                        ],
                        surface_type = "Business Logic: Account Takeover Vector",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_ATO,
                    )

        return self._results
