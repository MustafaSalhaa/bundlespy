"""
Scope enforcement for the crawler.
Every URL the crawler considers visiting gets checked here first.
"""

from urllib.parse import urlparse
from typing import List
from ..safety.network import validate_url, ALLOWED_SCHEMES


class ScopeChecker:
    def __init__(
        self,
        target_url: str,
        same_origin: bool = True,
        subdomains: bool = False,
        exclude: List[str] = None,
    ):
        parsed = urlparse(target_url)
        self.target_scheme   = parsed.scheme.lower()
        self.target_hostname = (parsed.hostname or "").lower()
        self.same_origin     = same_origin
        self.subdomains      = subdomains
        self.exclude         = [e.lower() for e in (exclude or [])]

    def in_scope(self, url: str) -> bool:
        """Returns True if a URL is in scope for crawling."""
        safe, _ = validate_url(url)
        if not safe:
            return False

        try:
            parsed = urlparse(url)
        except Exception:
            return False

        scheme   = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        if scheme not in ALLOWED_SCHEMES:
            return False

        # Exclusion list
        if any(hostname == ex or hostname.endswith("." + ex) for ex in self.exclude):
            return False

        if self.same_origin:
            if hostname == self.target_hostname:
                return True
            if self.subdomains and hostname.endswith("." + self.target_hostname):
                return True
            return False

        return True  # no origin restriction

    def is_js_url(self, url: str) -> bool:
        """Check if a URL points to a JavaScript file."""
        try:
            path = urlparse(url).path.lower()
            return path.endswith(".js") or path.endswith(".mjs")
        except Exception:
            return False
