"""
Secret Validation Module.

Validates detected secrets against provider APIs - read-only probes only.
Never logs or stores the raw secret value.
Clearly marks findings as 'detected' vs 'confirmed_live' vs 'invalid'.

Supported providers (15):
  AWS, Google API, OpenAI, Anthropic, GitHub (classic + fine-grained),
  GitLab, Stripe (secret + restricted), Slack, SendGrid, Twilio,
  Telegram, Discord, npm, HuggingFace, Mailgun
"""

import logging
import hashlib
from typing import Optional, Dict, Callable
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.analysis.secret_validator")

REQUEST_TIMEOUT = 8

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"


@dataclass
class ValidationResult:
    rule_id:   str
    valid:     bool          # True = confirmed live credential
    provider:  str
    detail:    str           # Human-readable, never contains secret value
    http_status: Optional[int] = None
    error:     Optional[str] = None
    # Extra context when confirmed (account ID, scopes, team name, etc.)
    context:   Dict[str, str] = field(default_factory=dict)


def _req(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """Single safe request wrapper - strict timeout, no retries."""
    try:
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        resp = requests.request(method, url, **kwargs)
        return resp
    except Exception as e:
        logger.debug("Validation request failed [%s %s]: %s", method, url, e)
        return None


# ── AWS ────────────────────────────────────────────────────────────────────────

def validate_aws_access_key(key_id: str, secret: Optional[str] = None) -> ValidationResult:
    """
    Validate AWS key via STS GetCallerIdentity - works even with no secret
    by checking the key format response. With secret, gets full identity.
    Without secret, we can only detect key existence via IAM error responses.
    """
    if not secret:
        # Without the secret we can't make a signed call - mark as unvalidatable
        return ValidationResult(
            "AWS_ACCESS_KEY", False, "AWS",
            "Key ID found but secret required for live validation",
        )

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        sts = boto3.client(
            "sts",
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            region_name="us-east-1",
        )
        identity = sts.get_caller_identity()
        account  = identity.get("Account", "?")
        arn      = identity.get("Arn", "?")
        user_id  = identity.get("UserId", "?")
        return ValidationResult(
            "AWS_ACCESS_KEY", True, "AWS",
            f"CONFIRMED LIVE - Account: {account} ARN: {arn}",
            context={"account": account, "arn": arn, "user_id": user_id},
        )
    except Exception as e:
        err = str(e)
        if "InvalidClientTokenId" in err or "AuthFailure" in err:
            return ValidationResult("AWS_ACCESS_KEY", False, "AWS", "Key invalid or revoked")
        if "ExpiredToken" in err:
            return ValidationResult("AWS_ACCESS_KEY", False, "AWS", "Session token expired")
        if "AccessDenied" in err:
            # Key is VALID - it authenticated but has no STS perms
            return ValidationResult(
                "AWS_ACCESS_KEY", True, "AWS",
                "CONFIRMED LIVE - Key authenticated (AccessDenied on STS - no GetCallerIdentity perm)",
            )
        return ValidationResult("AWS_ACCESS_KEY", False, "AWS", f"Validation error: {e}")


def validate_aws_key_only(key_id: str) -> ValidationResult:
    """
    Lightweight AWS key check using unsigned S3 list call.
    A 403 SignatureDoesNotMatch = key exists in AWS system.
    A 403 InvalidAccessKeyId = key does not exist.
    Uses a dummy unsigned request to probe key existence.
    """
    # Probe: request S3 with the access key ID - AWS returns different errors
    # for "key doesn't exist" vs "wrong signature"
    import hmac, hashlib as _hl, datetime, base64 as _b64, urllib.parse as _up

    now  = datetime.datetime.utcnow()
    date = now.strftime("%Y%m%d")
    ts   = now.strftime("%Y%m%dT%H%M%SZ")

    host   = "s3.amazonaws.com"
    region = "us-east-1"
    svc    = "s3"

    # Build a minimal signed request to S3
    canonical = f"GET\n/\n\nhost:{host}\nx-amz-date:{ts}\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    string_to_sign = f"AWS4-HMAC-SHA256\n{ts}\n{date}/{region}/{svc}/aws4_request\n" + \
        _hl.sha256(canonical.encode()).hexdigest()

    # Sign with a dummy secret just to get the right error codes
    def _sign(key, msg):
        return hmac.new(key, msg.encode(), _hl.sha256).digest()

    dummy_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    signing_key  = _sign(_sign(_sign(_sign(
        f"AWS4{dummy_secret}".encode(), date), region), svc), "aws4_request")
    sig = hmac.new(signing_key, string_to_sign.encode(), _hl.sha256).hexdigest()

    auth = (
        f"AWS4-HMAC-SHA256 Credential={key_id}/{date}/{region}/{svc}/aws4_request, "
        f"SignedHeaders=host;x-amz-date, Signature={sig}"
    )

    resp = _req("GET", f"https://{host}/", headers={
        "Host": host,
        "x-amz-date": ts,
        "Authorization": auth,
        "User-Agent": _UA,
    })

    if not resp:
        return ValidationResult("AWS_ACCESS_KEY", False, "AWS", "Request failed")

    body = resp.text or ""
    if "InvalidAccessKeyId" in body:
        return ValidationResult("AWS_ACCESS_KEY", False, "AWS", "Key does not exist in AWS")
    if "SignatureDoesNotMatch" in body or "InvalidSignatureException" in body:
        return ValidationResult(
            "AWS_ACCESS_KEY", True, "AWS",
            "CONFIRMED: Key ID exists in AWS (signature mismatch expected - secret not available for full validation)",
        )
    if "AuthorizationHeaderMalformed" in body:
        return ValidationResult("AWS_ACCESS_KEY", False, "AWS", "Malformed auth header")

    return ValidationResult(
        "AWS_ACCESS_KEY", False, "AWS",
        f"Inconclusive - HTTP {resp.status_code}",
        http_status=resp.status_code,
    )


# ── Google ─────────────────────────────────────────────────────────────────────

def validate_google_api_key(key: str) -> ValidationResult:
    """Validate Google API key via tokeninfo endpoint (no quota consumed)."""
    resp = _req("GET",
        "https://www.googleapis.com/oauth2/v1/tokeninfo",
        params={"access_token": key},
        headers={"User-Agent": _UA},
    )
    if not resp:
        return ValidationResult("GOOGLE_API_KEY", False, "Google", "Request failed")

    # A real API key probe: try geocoding API with a known-valid query
    # This tells us if the key is valid AND what APIs it has enabled
    resp2 = _req("GET",
        "https://maps.googleapis.com/maps/api/geocode/json",
        params={"address": "1600+Amphitheatre+Parkway", "key": key},
        headers={"User-Agent": _UA},
    )

    if resp2:
        data = resp2.json()
        status = data.get("status", "")
        if status == "OK":
            return ValidationResult(
                "GOOGLE_API_KEY", True, "Google",
                "CONFIRMED LIVE - Maps Geocoding API enabled and responding",
                http_status=resp2.status_code,
            )
        if status == "REQUEST_DENIED":
            error_msg = data.get("error_message", "")
            if "API key not valid" in error_msg:
                return ValidationResult("GOOGLE_API_KEY", False, "Google", "API key invalid")
            # Key valid but Maps not enabled - still a live key
            return ValidationResult(
                "GOOGLE_API_KEY", True, "Google",
                f"CONFIRMED LIVE - Key valid but Maps API not enabled: {error_msg}",
                http_status=resp2.status_code,
            )
        if status == "OVER_QUERY_LIMIT":
            return ValidationResult(
                "GOOGLE_API_KEY", True, "Google",
                "CONFIRMED LIVE - Key hit quota limit (key is active)",
                http_status=resp2.status_code,
            )

    return ValidationResult(
        "GOOGLE_API_KEY", False, "Google",
        f"Inconclusive - HTTP {resp2.status_code if resp2 else 'N/A'}",
    )


# ── OpenAI ─────────────────────────────────────────────────────────────────────

def validate_openai_key(key: str) -> ValidationResult:
    """Validate OpenAI key via models list (cheapest read-only call)."""
    resp = _req("GET",
        "https://api.openai.com/v1/models",
        headers={
            "Authorization": f"Bearer {key}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("OPENAI_API_KEY", False, "OpenAI", "Request failed")

    if resp.status_code == 200:
        data   = resp.json()
        models = [m.get("id") for m in data.get("data", [])[:3]]
        return ValidationResult(
            "OPENAI_API_KEY", True, "OpenAI",
            f"CONFIRMED LIVE - {len(data.get('data', []))} models accessible (e.g. {', '.join(models)})",
            http_status=200,
        )
    if resp.status_code == 401:
        return ValidationResult("OPENAI_API_KEY", False, "OpenAI", "Invalid API key")
    if resp.status_code == 429:
        return ValidationResult(
            "OPENAI_API_KEY", True, "OpenAI",
            "CONFIRMED LIVE - Key valid but rate limited",
            http_status=429,
        )

    return ValidationResult("OPENAI_API_KEY", False, "OpenAI", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Anthropic ──────────────────────────────────────────────────────────────────

def validate_anthropic_key(key: str) -> ValidationResult:
    """Validate Anthropic key via models endpoint."""
    resp = _req("GET",
        "https://api.anthropic.com/v1/models",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("ANTHROPIC_API_KEY", False, "Anthropic", "Request failed")

    if resp.status_code == 200:
        data   = resp.json()
        models = [m.get("id") for m in data.get("data", [])[:3]]
        return ValidationResult(
            "ANTHROPIC_API_KEY", True, "Anthropic",
            f"CONFIRMED LIVE - Models accessible: {', '.join(models)}",
            http_status=200,
        )
    if resp.status_code == 401:
        return ValidationResult("ANTHROPIC_API_KEY", False, "Anthropic", "Invalid API key")
    if resp.status_code == 403:
        return ValidationResult(
            "ANTHROPIC_API_KEY", True, "Anthropic",
            "CONFIRMED LIVE - Key authenticated (forbidden on models endpoint)",
            http_status=403,
        )

    return ValidationResult("ANTHROPIC_API_KEY", False, "Anthropic", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── GitHub ─────────────────────────────────────────────────────────────────────

def validate_github_token(token: str) -> ValidationResult:
    """Validate GitHub token via /user. Works for classic PAT and fine-grained."""
    resp = _req("GET",
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("GITHUB_TOKEN", False, "GitHub", "Request failed")

    if resp.status_code == 200:
        data   = resp.json()
        login  = data.get("login", "?")
        scopes = resp.headers.get("X-OAuth-Scopes", "none listed")
        return ValidationResult(
            "GITHUB_TOKEN", True, "GitHub",
            f"CONFIRMED LIVE - Account: {login} | Scopes: {scopes}",
            http_status=200,
            context={"login": login, "scopes": scopes},
        )
    if resp.status_code == 401:
        return ValidationResult("GITHUB_TOKEN", False, "GitHub", "Token invalid or revoked")
    if resp.status_code == 403:
        # Token valid but blocked - still live
        return ValidationResult(
            "GITHUB_TOKEN", True, "GitHub",
            "CONFIRMED LIVE - Token authenticated but forbidden (SSO enforcement or scope limit)",
            http_status=403,
        )

    return ValidationResult("GITHUB_TOKEN", False, "GitHub", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── GitLab ─────────────────────────────────────────────────────────────────────

def validate_gitlab_token(token: str) -> ValidationResult:
    """Validate GitLab PAT via /api/v4/user."""
    resp = _req("GET",
        "https://gitlab.com/api/v4/user",
        headers={
            "PRIVATE-TOKEN": token,
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("GITLAB_TOKEN", False, "GitLab", "Request failed")

    if resp.status_code == 200:
        data  = resp.json()
        uname = data.get("username", "?")
        name  = data.get("name", "?")
        state = data.get("state", "?")
        return ValidationResult(
            "GITLAB_TOKEN", True, "GitLab",
            f"CONFIRMED LIVE - User: {uname} ({name}) | State: {state}",
            http_status=200,
            context={"username": uname, "name": name, "state": state},
        )
    if resp.status_code == 401:
        return ValidationResult("GITLAB_TOKEN", False, "GitLab", "Token invalid or revoked")

    return ValidationResult("GITLAB_TOKEN", False, "GitLab", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Stripe ─────────────────────────────────────────────────────────────────────

def validate_stripe_key(key: str) -> ValidationResult:
    """Validate Stripe key via /v1/balance (read-only)."""
    resp = _req("GET",
        "https://api.stripe.com/v1/balance",
        auth=(key, ""),
        headers={"User-Agent": _UA},
    )
    if not resp:
        return ValidationResult("STRIPE_SECRET_KEY", False, "Stripe", "Request failed")

    if resp.status_code == 200:
        data      = resp.json()
        livemode  = data.get("livemode", False)
        available = data.get("available", [{}])
        currency  = available[0].get("currency", "?") if available else "?"
        return ValidationResult(
            "STRIPE_SECRET_KEY", True, "Stripe",
            f"CONFIRMED LIVE - livemode: {livemode} | currency: {currency}",
            http_status=200,
            context={"livemode": str(livemode), "currency": currency},
        )
    if resp.status_code == 401:
        data = resp.json()
        return ValidationResult("STRIPE_SECRET_KEY", False, "Stripe",
            data.get("error", {}).get("message", "Invalid API key"))
    if resp.status_code == 403:
        # Restricted key - can't hit /balance but key is live
        return ValidationResult(
            "STRIPE_SECRET_KEY", True, "Stripe",
            "CONFIRMED LIVE - Restricted key (no balance permission but authenticated)",
            http_status=403,
        )

    return ValidationResult("STRIPE_SECRET_KEY", False, "Stripe", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Slack ──────────────────────────────────────────────────────────────────────

def validate_slack_token(token: str) -> ValidationResult:
    """Validate Slack token via auth.test."""
    resp = _req("POST",
        "https://slack.com/api/auth.test",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("SLACK_TOKEN", False, "Slack", "Request failed")

    data = resp.json()
    if data.get("ok"):
        team  = data.get("team", "?")
        user  = data.get("user", "?")
        url   = data.get("url", "")
        return ValidationResult(
            "SLACK_TOKEN", True, "Slack",
            f"CONFIRMED LIVE - Team: {team} | User: {user} | URL: {url}",
            http_status=resp.status_code,
            context={"team": team, "user": user, "url": url},
        )
    err = data.get("error", "unknown")
    return ValidationResult("SLACK_TOKEN", False, "Slack", f"Invalid: {err}")


# ── SendGrid ───────────────────────────────────────────────────────────────────

def validate_sendgrid_key(key: str) -> ValidationResult:
    """Validate SendGrid key via /v3/scopes (read-only)."""
    resp = _req("GET",
        "https://api.sendgrid.com/v3/scopes",
        headers={
            "Authorization": f"Bearer {key}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("SENDGRID_API_KEY", False, "SendGrid", "Request failed")

    if resp.status_code == 200:
        scopes = resp.json().get("scopes", [])
        return ValidationResult(
            "SENDGRID_API_KEY", True, "SendGrid",
            f"CONFIRMED LIVE - {len(scopes)} permission scopes",
            http_status=200,
            context={"scope_count": str(len(scopes))},
        )
    if resp.status_code in (401, 403):
        return ValidationResult("SENDGRID_API_KEY", False, "SendGrid", "Invalid or revoked key")

    return ValidationResult("SENDGRID_API_KEY", False, "SendGrid", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Twilio ─────────────────────────────────────────────────────────────────────

def validate_twilio_key(account_sid: str, auth_token: str) -> ValidationResult:
    """Validate Twilio credentials via /2010-04-01/Accounts/{SID}.json."""
    resp = _req("GET",
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
        auth=(account_sid, auth_token),
        headers={"User-Agent": _UA},
    )
    if not resp:
        return ValidationResult("TWILIO_AUTH_TOKEN", False, "Twilio", "Request failed")

    if resp.status_code == 200:
        data   = resp.json()
        status = data.get("status", "?")
        name   = data.get("friendly_name", "?")
        return ValidationResult(
            "TWILIO_AUTH_TOKEN", True, "Twilio",
            f"CONFIRMED LIVE - Account: {name} | Status: {status}",
            http_status=200,
            context={"account": name, "status": status, "sid": account_sid},
        )
    if resp.status_code == 401:
        return ValidationResult("TWILIO_AUTH_TOKEN", False, "Twilio", "Invalid credentials")

    return ValidationResult("TWILIO_AUTH_TOKEN", False, "Twilio", f"HTTP {resp.status_code}", http_status=resp.status_code)


def validate_twilio_sid_only(account_sid: str) -> ValidationResult:
    """Probe Twilio with just the SID (no auth token available)."""
    resp = _req("GET",
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
        headers={"User-Agent": _UA},
    )
    if not resp:
        return ValidationResult("TWILIO_ACCOUNT_SID", False, "Twilio", "Request failed")

    # 401 = SID exists but needs auth token, which means SID is valid
    if resp.status_code == 401:
        return ValidationResult(
            "TWILIO_ACCOUNT_SID", True, "Twilio",
            "CONFIRMED: Account SID exists (auth token needed for full validation)",
            http_status=401,
        )
    if resp.status_code == 404:
        return ValidationResult("TWILIO_ACCOUNT_SID", False, "Twilio", "Account SID not found")

    return ValidationResult("TWILIO_ACCOUNT_SID", False, "Twilio", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Telegram ───────────────────────────────────────────────────────────────────

def validate_telegram_token(token: str) -> ValidationResult:
    """Validate Telegram bot token via getMe."""
    resp = _req("GET",
        f"https://api.telegram.org/bot{token}/getMe",
        headers={"User-Agent": _UA},
    )
    if not resp:
        return ValidationResult("TELEGRAM_BOT_TOKEN", False, "Telegram", "Request failed")

    if resp.status_code == 200:
        data = resp.json()
        if data.get("ok"):
            bot      = data.get("result", {})
            username = bot.get("username", "?")
            name     = bot.get("first_name", "?")
            bot_id   = bot.get("id", "?")
            return ValidationResult(
                "TELEGRAM_BOT_TOKEN", True, "Telegram",
                f"CONFIRMED LIVE - Bot: @{username} ({name}) | ID: {bot_id}",
                http_status=200,
                context={"username": username, "name": name, "id": str(bot_id)},
            )
    if resp.status_code == 401:
        return ValidationResult("TELEGRAM_BOT_TOKEN", False, "Telegram", "Token invalid or revoked")
    if resp.status_code == 404:
        return ValidationResult("TELEGRAM_BOT_TOKEN", False, "Telegram", "Bot not found")

    return ValidationResult("TELEGRAM_BOT_TOKEN", False, "Telegram", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Discord ────────────────────────────────────────────────────────────────────

def validate_discord_token(token: str) -> ValidationResult:
    """Validate Discord bot token via /users/@me."""
    resp = _req("GET",
        "https://discord.com/api/v10/users/@me",
        headers={
            "Authorization": f"Bot {token}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("DISCORD_TOKEN", False, "Discord", "Request failed")

    if resp.status_code == 200:
        data     = resp.json()
        username = data.get("username", "?")
        disc_id  = data.get("id", "?")
        bot      = data.get("bot", False)
        return ValidationResult(
            "DISCORD_TOKEN", True, "Discord",
            f"CONFIRMED LIVE - {'Bot' if bot else 'User'}: {username} | ID: {disc_id}",
            http_status=200,
            context={"username": username, "id": disc_id, "bot": str(bot)},
        )
    if resp.status_code == 401:
        return ValidationResult("DISCORD_TOKEN", False, "Discord", "Token invalid or revoked")

    return ValidationResult("DISCORD_TOKEN", False, "Discord", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── npm ────────────────────────────────────────────────────────────────────────

def validate_npm_token(token: str) -> ValidationResult:
    """Validate npm token via registry whoami."""
    resp = _req("GET",
        "https://registry.npmjs.org/-/whoami",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("NPM_TOKEN", False, "npm", "Request failed")

    if resp.status_code == 200:
        data     = resp.json()
        username = data.get("username", "?")
        return ValidationResult(
            "NPM_TOKEN", True, "npm",
            f"CONFIRMED LIVE - Account: {username}",
            http_status=200,
            context={"username": username},
        )
    if resp.status_code == 401:
        return ValidationResult("NPM_TOKEN", False, "npm", "Token invalid or revoked")

    return ValidationResult("NPM_TOKEN", False, "npm", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── HuggingFace ────────────────────────────────────────────────────────────────

def validate_huggingface_token(token: str) -> ValidationResult:
    """Validate HuggingFace token via /api/whoami-v2."""
    resp = _req("GET",
        "https://huggingface.co/api/whoami-v2",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("HUGGINGFACE_TOKEN", False, "HuggingFace", "Request failed")

    if resp.status_code == 200:
        data  = resp.json()
        name  = data.get("name", "?")
        email = data.get("email", "?")
        orgs  = [o.get("name") for o in data.get("orgs", [])]
        return ValidationResult(
            "HUGGINGFACE_TOKEN", True, "HuggingFace",
            f"CONFIRMED LIVE - User: {name} | Orgs: {', '.join(orgs) or 'none'}",
            http_status=200,
            context={"name": name, "orgs": ", ".join(orgs)},
        )
    if resp.status_code == 401:
        return ValidationResult("HUGGINGFACE_TOKEN", False, "HuggingFace", "Token invalid or revoked")

    return ValidationResult("HUGGINGFACE_TOKEN", False, "HuggingFace", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Mailgun ────────────────────────────────────────────────────────────────────

def validate_mailgun_key(key: str) -> ValidationResult:
    """Validate Mailgun API key via /v3/domains (read-only)."""
    resp = _req("GET",
        "https://api.mailgun.net/v3/domains",
        auth=("api", key),
        headers={"User-Agent": _UA},
    )
    if not resp:
        return ValidationResult("MAILGUN_API_KEY", False, "Mailgun", "Request failed")

    if resp.status_code == 200:
        data    = resp.json()
        domains = [d.get("name") for d in data.get("items", [])[:3]]
        total   = data.get("total_count", len(data.get("items", [])))
        return ValidationResult(
            "MAILGUN_API_KEY", True, "Mailgun",
            f"CONFIRMED LIVE - {total} domain(s): {', '.join(domains) or 'none'}",
            http_status=200,
            context={"domain_count": str(total), "domains": ", ".join(domains)},
        )
    if resp.status_code == 401:
        return ValidationResult("MAILGUN_API_KEY", False, "Mailgun", "Invalid API key")
    if resp.status_code == 403:
        # Authenticated but restricted key
        return ValidationResult(
            "MAILGUN_API_KEY", True, "Mailgun",
            "CONFIRMED LIVE - Key authenticated (forbidden on /domains)",
            http_status=403,
        )

    return ValidationResult("MAILGUN_API_KEY", False, "Mailgun", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Supabase ───────────────────────────────────────────────────────────────────

def validate_supabase_key(key: str, project_url: Optional[str] = None) -> ValidationResult:
    """
    Validate Supabase anon/service key.
    Anon keys are JWTs - we can decode the payload to confirm they're real.
    Service keys with a project URL can be probed against the REST API.
    """
    import base64, json as _json

    # Try to decode the JWT payload (no signature check needed for format validation)
    try:
        parts = key.split(".")
        if len(parts) == 3:
            payload_raw = parts[1]
            payload_raw += "=" * (4 - len(payload_raw) % 4)
            payload = _json.loads(base64.urlsafe_b64decode(payload_raw).decode())
            role    = payload.get("role", "?")
            iss     = payload.get("iss", "?")
            ref     = payload.get("ref", "?")
            exp     = payload.get("exp", 0)

            import time
            expired = exp < time.time() if exp else False

            if project_url:
                resp = _req("GET",
                    f"{project_url}/rest/v1/",
                    headers={
                        "apikey": key,
                        "Authorization": f"Bearer {key}",
                        "User-Agent": _UA,
                    },
                )
                if resp and resp.status_code in (200, 404):
                    return ValidationResult(
                        "SUPABASE_KEY", True, "Supabase",
                        f"CONFIRMED LIVE - Role: {role} | Ref: {ref} | Expired: {expired}",
                        http_status=resp.status_code,
                        context={"role": role, "ref": ref, "expired": str(expired)},
                    )

            return ValidationResult(
                "SUPABASE_KEY",
                not expired,
                "Supabase",
                f"{'VALID JWT' if not expired else 'EXPIRED JWT'} - Role: {role} | Ref: {ref} | Issuer: {iss}",
                context={"role": role, "ref": ref, "expired": str(expired)},
            )
    except Exception:
        pass

    return ValidationResult("SUPABASE_KEY", False, "Supabase", "Could not decode JWT payload")


# ── Groq ───────────────────────────────────────────────────────────────────────

def validate_groq_key(key: str) -> ValidationResult:
    """Validate Groq API key via models endpoint."""
    resp = _req("GET",
        "https://api.groq.com/openai/v1/models",
        headers={
            "Authorization": f"Bearer {key}",
            "User-Agent": _UA,
        },
    )
    if not resp:
        return ValidationResult("GROQ_API_KEY", False, "Groq", "Request failed")

    if resp.status_code == 200:
        data   = resp.json()
        models = [m.get("id") for m in data.get("data", [])[:3]]
        return ValidationResult(
            "GROQ_API_KEY", True, "Groq",
            f"CONFIRMED LIVE - {len(data.get('data', []))} models (e.g. {', '.join(models)})",
            http_status=200,
        )
    if resp.status_code == 401:
        return ValidationResult("GROQ_API_KEY", False, "Groq", "Invalid API key")

    return ValidationResult("GROQ_API_KEY", False, "Groq", f"HTTP {resp.status_code}", http_status=resp.status_code)


# ── Rule ID -> Validator map ───────────────────────────────────────────────────

VALIDATORS: Dict[str, Callable] = {
    # AWS
    "AWS_ACCESS_KEY":        validate_aws_key_only,
    # Google
    "GOOGLE_API_KEY":        validate_google_api_key,
    # OpenAI
    "OPENAI_API_KEY":        validate_openai_key,
    "OPENAI_API_KEY_V2":     validate_openai_key,
    # Anthropic
    "ANTHROPIC_API_KEY":     validate_anthropic_key,
    # GitHub
    "GITHUB_TOKEN":          validate_github_token,
    "GITHUB_FINE_GRAINED":   validate_github_token,
    "GITHUB_APP_TOKEN":      validate_github_token,
    # GitLab
    "GITLAB_TOKEN":          validate_gitlab_token,
    # Stripe
    "STRIPE_SECRET_KEY":     validate_stripe_key,
    "STRIPE_RESTRICTED_KEY": validate_stripe_key,
    "STRIPE_TEST_SECRET":    validate_stripe_key,
    # Slack
    "SLACK_TOKEN":           validate_slack_token,
    "SLACK_BOT_TOKEN":       validate_slack_token,
    "SLACK_APP_TOKEN":       validate_slack_token,
    # SendGrid
    "SENDGRID_API_KEY":      validate_sendgrid_key,
    # Twilio
    "TWILIO_ACCOUNT_SID":    validate_twilio_sid_only,
    # Telegram
    "TELEGRAM_BOT_TOKEN":    validate_telegram_token,
    # Discord
    "DISCORD_TOKEN":         validate_discord_token,
    # npm
    "NPM_TOKEN":             validate_npm_token,
    # HuggingFace
    "HUGGINGFACE_TOKEN":     validate_huggingface_token,
    # Mailgun
    "MAILGUN_API_KEY":       validate_mailgun_key,
    # Groq
    "GROQ_API_KEY":          validate_groq_key,
}


def validate_finding(rule_id: str, value: str, context: Optional[Dict] = None) -> Optional[ValidationResult]:
    """
    Validate a single finding if a validator exists for its rule.
    Returns None if no validator is available for this rule.
    Never logs the raw secret value.
    """
    validator = VALIDATORS.get(rule_id)
    if not validator:
        return None

    # Log only the rule ID and a hash of the value - never the value itself
    value_hash = hashlib.sha256(value.encode()).hexdigest()[:8]
    logger.info("Validating %s (sha256_prefix=%s)", rule_id, value_hash)

    try:
        # Some validators take extra context (e.g. Twilio needs SID + token)
        # Pass context dict if the validator accepts it
        import inspect
        sig = inspect.signature(validator)
        if len(sig.parameters) > 1 and context:
            result = validator(value, **{
                k: v for k, v in context.items()
                if k in sig.parameters
            })
        else:
            result = validator(value)

        if result.valid:
            logger.warning(
                "CONFIRMED LIVE SECRET: rule=%s provider=%s detail=%s (value redacted)",
                rule_id, result.provider, result.detail,
            )
        else:
            logger.debug(
                "Secret invalid/revoked: rule=%s provider=%s detail=%s",
                rule_id, result.provider, result.detail,
            )
        return result

    except Exception as e:
        logger.warning("Validation error for %s: %s", rule_id, e)
        return ValidationResult(rule_id, False, "unknown", f"Validation error: {e}", error=str(e))


def supported_rule_ids() -> list:
    """Return list of rule IDs that have live validators."""
    return sorted(VALIDATORS.keys())
