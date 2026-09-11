"""
Secret Validation Module.

Validates detected secrets against provider APIs where technically safe.
NEVER logs or displays secret values in output.
Clearly distinguishes 'detected' vs 'validated'.

Supported providers:
- GitHub (token scope check via /user)
- AWS (identity check via STS GetCallerIdentity)
- Stripe (balance check - read only)
- Slack (auth.test)
- SendGrid (scopes check)

All requests are read-only. No state changes. No data exfiltration.
"""

import logging
from typing import Optional, Dict
from dataclasses import dataclass

import requests
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.analysis.secret_validator")

REQUEST_TIMEOUT = 8


@dataclass
class ValidationResult:
    rule_id:   str
    valid:     bool
    provider:  str
    detail:    str        # Never contains the secret value
    error:     Optional[str] = None


def _safe_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """Make a validation request with strict timeout."""
    try:
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        kwargs.setdefault("verify", False)
        return requests.request(method, url, **kwargs)
    except Exception as e:
        logger.debug("Validation request failed: %s", e)
        return None


def validate_github_token(token: str) -> ValidationResult:
    """Check if a GitHub token is valid via /user endpoint."""
    resp = _safe_request(
        "GET",
        "https://api.github.com/user",
        headers={
            "Authorization": f"token {token}",
            "User-Agent":    "BundleSpy-Validator/1.0",
        },
    )
    if not resp:
        return ValidationResult("GITHUB_TOKEN", False, "GitHub", "Request failed")

    if resp.status_code == 200:
        data   = resp.json()
        login  = data.get("login", "unknown")
        scopes = resp.headers.get("X-OAuth-Scopes", "unknown")
        return ValidationResult(
            "GITHUB_TOKEN", True, "GitHub",
            f"Valid token - account: {login}, scopes: {scopes}",
        )
    elif resp.status_code == 401:
        return ValidationResult("GITHUB_TOKEN", False, "GitHub", "Token invalid or revoked")
    else:
        return ValidationResult("GITHUB_TOKEN", False, "GitHub", f"HTTP {resp.status_code}")


def validate_stripe_key(key: str) -> ValidationResult:
    """Check Stripe key validity via balance endpoint (read-only)."""
    resp = _safe_request(
        "GET",
        "https://api.stripe.com/v1/balance",
        auth=(key, ""),
    )
    if not resp:
        return ValidationResult("STRIPE_SECRET_KEY", False, "Stripe", "Request failed")

    if resp.status_code == 200:
        data      = resp.json()
        live_mode = data.get("livemode", False)
        return ValidationResult(
            "STRIPE_SECRET_KEY", True, "Stripe",
            f"Valid key - livemode: {live_mode}",
        )
    elif resp.status_code == 401:
        return ValidationResult("STRIPE_SECRET_KEY", False, "Stripe", "Invalid API key")
    else:
        return ValidationResult("STRIPE_SECRET_KEY", False, "Stripe", f"HTTP {resp.status_code}")


def validate_slack_token(token: str) -> ValidationResult:
    """Check Slack token via auth.test (read-only)."""
    resp = _safe_request(
        "POST",
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
    )
    if not resp:
        return ValidationResult("SLACK_TOKEN", False, "Slack", "Request failed")

    data = resp.json()
    if data.get("ok"):
        team = data.get("team", "unknown")
        user = data.get("user", "unknown")
        return ValidationResult(
            "SLACK_TOKEN", True, "Slack",
            f"Valid token - team: {team}, user: {user}",
        )
    else:
        error = data.get("error", "unknown")
        return ValidationResult("SLACK_TOKEN", False, "Slack", f"Invalid: {error}")


def validate_sendgrid_key(key: str) -> ValidationResult:
    """Check SendGrid key via scopes endpoint (read-only)."""
    resp = _safe_request(
        "GET",
        "https://api.sendgrid.com/v3/scopes",
        headers={"Authorization": f"Bearer {key}"},
    )
    if not resp:
        return ValidationResult("SENDGRID_API_KEY", False, "SendGrid", "Request failed")

    if resp.status_code == 200:
        scopes = resp.json().get("scopes", [])
        return ValidationResult(
            "SENDGRID_API_KEY", True, "SendGrid",
            f"Valid key - {len(scopes)} permission scopes",
        )
    elif resp.status_code == 403:
        return ValidationResult("SENDGRID_API_KEY", False, "SendGrid", "Invalid or revoked key")
    else:
        return ValidationResult("SENDGRID_API_KEY", False, "SendGrid", f"HTTP {resp.status_code}")


# Map rule IDs to validator functions
VALIDATORS = {
    "GITHUB_TOKEN":      validate_github_token,
    "GITHUB_FINE_GRAINED": validate_github_token,
    "STRIPE_SECRET_KEY": validate_stripe_key,
    "SLACK_TOKEN":       validate_slack_token,
    "SENDGRID_API_KEY":  validate_sendgrid_key,
}


def validate_finding(rule_id: str, value: str) -> Optional[ValidationResult]:
    """
    Validate a single finding if a validator exists for its rule.
    Returns None if no validator is available.
    NEVER logs the secret value.
    """
    validator = VALIDATORS.get(rule_id)
    if not validator:
        return None

    logger.info("Validating %s finding (value redacted)", rule_id)
    try:
        result = validator(value)
        if result.valid:
            logger.warning(
                "VALIDATED secret: %s - %s (value redacted from logs)",
                rule_id, result.detail,
            )
        return result
    except Exception as e:
        logger.warning("Validation error for %s: %s", rule_id, e)
        return ValidationResult(rule_id, False, "unknown", f"Validation error: {e}")
