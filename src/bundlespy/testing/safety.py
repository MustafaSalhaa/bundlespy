"""
Central safety policy for all attack test requests.
Every test request passes through check() before execution.
"""
import hashlib
import time
import threading
from typing import Tuple, Optional
from ..safety.network import validate_url

# Methods that are hard-blocked unconditionally
_BLOCKED_METHODS = {"DELETE", "PURGE"}

# Path fragments that indicate destructive operations
_DESTRUCTIVE_PATHS = [
    "/delete", "/destroy", "/remove", "/drop", "/truncate",
    "/reset-password", "/change-password", "/deactivate",
    "/purchase", "/checkout", "/payment", "/pay",
    "/send-message", "/send-email",
]

# Parameter names that should never be mutated
_PROTECTED_PARAMS = {
    "password", "passwd", "new_password", "confirm_password",
    "credit_card", "cvv", "card_number",
    "account_number", "routing_number",
    "delete", "destroy", "drop",
}

class SafetyPolicy:
    """
    Central gatekeeper for all outbound test requests.
    Enforces scope, method safety, parameter safety, rate limits.
    """

    def __init__(
        self,
        scope,                          # ScopeChecker instance
        rate_per_second: float = 2.0,
        max_requests: int = 500,
        allow_post: bool = True,
    ):
        self._scope         = scope
        self._rate          = rate_per_second
        self._max_requests  = max_requests
        self._allow_post    = allow_post
        self._request_count = 0
        self._lock          = threading.Lock()
        self._last_request  = 0.0
        # Dedup: track (url, method, param, test_type, auth_state)
        self._seen: set = set()

    @property
    def requests_made(self) -> int:
        return self._request_count

    def check(
        self,
        url: str,
        method: str = "GET",
        param: str = "",
        test_type: str = "",
        auth_state: str = "",
        payload: str = "",
    ) -> Tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        Reason is empty string when allowed.
        """
        with self._lock:
            # 1. Scope check
            if not self._scope.in_scope(url):
                return False, f"out_of_scope: {url}"

            # 2. URL safety (SSRF / private network protection)
            safe, reason = validate_url(url, check_dns=False)
            if not safe:
                return False, f"url_blocked: {reason}"

            # 3. Method safety
            method_upper = method.upper()
            if method_upper in _BLOCKED_METHODS:
                return False, f"blocked_method: {method_upper}"
            if method_upper == "POST" and not self._allow_post:
                return False, "post_disabled"

            # 4. Destructive path check
            url_lower = url.lower()
            for frag in _DESTRUCTIVE_PATHS:
                if frag in url_lower:
                    return False, f"destructive_path: {frag}"

            # 5. Protected parameter check
            if param.lower() in _PROTECTED_PARAMS:
                return False, f"protected_param: {param}"

            # 6. Rate limit
            if self._request_count >= self._max_requests:
                return False, f"max_requests_reached: {self._max_requests}"

            # 7. Dedup check
            dedup_key = hashlib.md5(
                f"{url}:{method_upper}:{param}:{test_type}:{auth_state}".encode()
            ).hexdigest()
            if dedup_key in self._seen:
                return False, "duplicate_test"
            self._seen.add(dedup_key)

            # 8. Rate throttle
            now = time.monotonic()
            gap = now - self._last_request
            min_gap = 1.0 / self._rate
            if gap < min_gap:
                time.sleep(min_gap - gap)
            self._last_request = time.monotonic()
            self._request_count += 1

        return True, ""
