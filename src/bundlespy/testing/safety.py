"""
Safety policy for ConfigurationMapper - the only mapper that makes HTTP requests.
All other mappers work purely from collected ScanResult data.
"""
import hashlib
import time
import threading
from typing import Tuple
from ..safety.network import validate_url


class SurfaceSafetyPolicy:
    """
    Gatekeeper for ConfigurationMapper's outbound GET requests.
    Enforces scope, dedup, rate limit, and request cap.
    Only allows safe GETs - no mutations, no payloads.
    """

    def __init__(
        self,
        scope,
        rate_per_second: float = 2.0,
        max_requests:    int   = 100,
    ):
        self._scope        = scope
        self._rate         = rate_per_second
        self._max_requests = max_requests
        self._request_count = 0
        self._lock         = threading.Lock()
        self._last_request = 0.0
        self._seen: set    = set()

    @property
    def requests_made(self) -> int:
        return self._request_count

    def allow_get(self, url: str) -> Tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        Only permits safe GET requests within scope and under the request cap.
        """
        with self._lock:
            # Scope check
            if not self._scope.in_scope(url):
                return False, f"out_of_scope: {url}"

            # URL safety check (blocks private IPs, loopback, cloud metadata)
            safe, reason = validate_url(url, check_dns=False)
            if not safe:
                return False, f"url_blocked: {reason}"

            # Request cap
            if self._request_count >= self._max_requests:
                return False, f"max_requests_reached: {self._max_requests}"

            # Dedup by URL
            dedup_key = hashlib.md5(url.encode()).hexdigest()
            if dedup_key in self._seen:
                return False, "duplicate_url"
            self._seen.add(dedup_key)

            # Rate throttle
            now = time.monotonic()
            gap = now - self._last_request
            min_gap = 1.0 / self._rate
            if gap < min_gap:
                time.sleep(min_gap - gap)
            self._last_request = time.monotonic()
            self._request_count += 1

        return True, ""
