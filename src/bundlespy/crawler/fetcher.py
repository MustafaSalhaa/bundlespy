"""
HTTP fetcher with rate limiting, retries, backoff, safety checks,
and optional stealth mode for WAF evasion.
"""

import time
import hashlib
import logging
from typing import TYPE_CHECKING, Optional, Tuple

import requests
import requests.adapters
import urllib3

from ..config import USER_AGENT
from ..safety.network import validate_url
from ..utils.stealth import random_ua, get_stealth_headers, stealth_delay

if TYPE_CHECKING:
    from .cache import FetchCache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("bundlespy.fetcher")


class Fetcher:
    def __init__(
        self,
        timeout: int = 10,
        max_response_size: int = 10 * 1024 * 1024,
        retry_limit: int = 2,
        requests_per_second: int = 2,
        user_agent: str = USER_AGENT,
        stealth: bool = False,
        extra_headers: dict = None,
        verify_ssl: bool = False,
        cache: Optional["FetchCache"] = None,
    ):
        self.timeout           = timeout
        self.max_response_size = max_response_size
        self.retry_limit       = retry_limit
        self.min_delay         = 1.0 / max(requests_per_second, 1)
        self.user_agent        = user_agent
        self.stealth           = stealth
        self.rps               = requests_per_second
        self.extra_headers     = extra_headers or {}
        self._last_request     = 0.0
        self._current_ua       = random_ua() if stealth else user_agent
        # SSL verification: on by default. Pass verify_ssl=False for targets with
        # self-signed certs (--no-verify CLI flag). Warnings suppressed regardless
        # since urllib3 warns even for verify=True on some cert chains.
        self.verify_ssl        = verify_ssl
        self._cache            = cache

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=urllib3.Retry(
                total=retry_limit,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET", "HEAD"],
            )
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        if not stealth:
            self.session.headers.update({"User-Agent": self.user_agent})

    def _rate_limit(self) -> None:
        if self.stealth:
            stealth_delay(self.rps)
            # Rotate UA every few requests
            if time.monotonic() % 5 < 1:
                self._current_ua = random_ua()
        else:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
        self._last_request = time.monotonic()

    def get(
        self,
        url: str,
        referer: str = "",
        check_content_type: Optional[str] = None,
    ) -> Tuple[Optional[str], int, str, str]:
        """
        Fetch a URL safely.
        Returns: (content, status_code, content_type, sha256)

        Note: response headers (Link, X-Link, etc.) are available via
        get_with_headers() if you need them.
        """
        safe, reason = validate_url(url, check_dns=True)
        if not safe:
            logger.warning("Blocked request to %s: %s", url, reason)
            return None, 0, "", ""

        # Check cache before hitting the network
        cached_body: Optional[bytes] = None
        cache_meta: dict = {}
        if self._cache is not None:
            hit, cached_body, cache_meta = self._cache.get(url)
            if hit and cached_body is not None:
                # Fresh cache hit - decode and return without a network request
                try:
                    content = cached_body.decode("utf-8", errors="replace")
                except Exception:
                    content = cached_body.decode("latin-1", errors="replace")
                sha256 = hashlib.sha256(cached_body).hexdigest()
                content_type = cache_meta.get("content_type", "")
                return content, 200, content_type, sha256

        self._rate_limit()

        # Build headers
        if self.stealth:
            headers = get_stealth_headers(self._current_ua, referer=referer)
        else:
            headers = {"User-Agent": self.user_agent}

        # Merge auth headers (cookie, custom headers) — always applied
        if self.extra_headers:
            headers.update(self.extra_headers)

        # Add conditional GET headers if we have stale cache data
        if cache_meta.get("etag"):
            headers["If-None-Match"] = cache_meta["etag"]
        if cache_meta.get("last_modified"):
            headers["If-Modified-Since"] = cache_meta["last_modified"]

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
                stream=True,
                headers=headers,
            )

            # 304 Not Modified - serve from cache
            if resp.status_code == 304 and cached_body is not None:
                if self._cache is not None:
                    self._cache.record_revalidated(url, len(cached_body))
                try:
                    content = cached_body.decode("utf-8", errors="replace")
                except Exception:
                    content = cached_body.decode("latin-1", errors="replace")
                sha256 = hashlib.sha256(cached_body).hexdigest()
                content_type = cache_meta.get("content_type", "")
                return content, 200, content_type, sha256

            content_type = resp.headers.get("Content-Type", "")

            chunks = []
            total  = 0
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > self.max_response_size:
                    logger.warning(
                        "Response from %s exceeded size limit, truncating", url
                    )
                    break
                chunks.append(chunk)

            raw = b"".join(chunks)

            try:
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                content = raw.decode("latin-1", errors="replace")

            sha256 = hashlib.sha256(raw).hexdigest()

            # Cache successful responses
            if resp.status_code == 200 and self._cache is not None:
                self._cache.put(url, raw, dict(resp.headers))

            return content, resp.status_code, content_type, sha256

        except requests.exceptions.SSLError as e:
            logger.warning("SSL error for %s: %s", url, e)
            if self.verify_ssl:
                logger.info(
                    "Hint: if this target uses a self-signed cert, retry with --no-verify"
                )
            return None, 0, "", ""
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error for %s: %s", url, e)
            return None, 0, "", ""
        except requests.exceptions.Timeout:
            logger.warning("Timeout for %s", url)
            return None, 0, "", ""
        except Exception as e:
            logger.warning("Unexpected error fetching %s: %s", url, e)
            return None, 0, "", ""

    def get_with_headers(
        self,
        url: str,
        referer: str = "",
    ) -> Tuple[Optional[str], int, str, str, dict]:
        """
        Fetch a URL and return response headers too.
        Returns: (content, status_code, content_type, sha256, response_headers)

        Use this when you need Link/X-Link headers for JS preload discovery.
        Falls back to empty dict on error.
        """
        safe, reason = validate_url(url, check_dns=True)
        if not safe:
            logger.warning("Blocked request to %s: %s", url, reason)
            return None, 0, "", "", {}

        # Check cache before hitting the network
        cached_body: Optional[bytes] = None
        cache_meta: dict = {}
        if self._cache is not None:
            hit, cached_body, cache_meta = self._cache.get(url)
            if hit and cached_body is not None:
                # Fresh cache hit - decode and return without a network request
                try:
                    content = cached_body.decode("utf-8", errors="replace")
                except Exception:
                    content = cached_body.decode("latin-1", errors="replace")
                sha256 = hashlib.sha256(cached_body).hexdigest()
                content_type = cache_meta.get("content_type", "")
                # Reconstruct minimal response headers from what we stored
                resp_headers = {"Content-Type": content_type}
                if cache_meta.get("etag"):
                    resp_headers["ETag"] = cache_meta["etag"]
                if cache_meta.get("last_modified"):
                    resp_headers["Last-Modified"] = cache_meta["last_modified"]
                return content, 200, content_type, sha256, resp_headers

        self._rate_limit()

        if self.stealth:
            headers = get_stealth_headers(self._current_ua, referer=referer)
        else:
            headers = {"User-Agent": self.user_agent}

        if self.extra_headers:
            headers.update(self.extra_headers)

        # Add conditional GET headers if we have stale cache data
        if cache_meta.get("etag"):
            headers["If-None-Match"] = cache_meta["etag"]
        if cache_meta.get("last_modified"):
            headers["If-Modified-Since"] = cache_meta["last_modified"]

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
                stream=True,
                headers=headers,
            )

            content_type = resp.headers.get("Content-Type", "")
            resp_headers = dict(resp.headers)

            # 304 Not Modified - serve from cache
            if resp.status_code == 304 and cached_body is not None:
                if self._cache is not None:
                    self._cache.record_revalidated(url, len(cached_body))
                try:
                    content = cached_body.decode("utf-8", errors="replace")
                except Exception:
                    content = cached_body.decode("latin-1", errors="replace")
                sha256 = hashlib.sha256(cached_body).hexdigest()
                cached_ct = cache_meta.get("content_type", "")
                return content, 200, cached_ct, sha256, resp_headers

            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > self.max_response_size:
                    logger.warning(
                        "Response from %s exceeded size limit, truncating", url
                    )
                    break
                chunks.append(chunk)

            raw = b"".join(chunks)

            try:
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                content = raw.decode("latin-1", errors="replace")

            sha256 = hashlib.sha256(raw).hexdigest()

            # Cache successful responses
            if resp.status_code == 200 and self._cache is not None:
                self._cache.put(url, raw, dict(resp.headers))

            return content, resp.status_code, content_type, sha256, resp_headers

        except requests.exceptions.SSLError as e:
            logger.warning("SSL error for %s: %s", url, e)
            return None, 0, "", "", {}
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error for %s: %s", url, e)
            return None, 0, "", "", {}
        except requests.exceptions.Timeout:
            logger.warning("Timeout for %s", url)
            return None, 0, "", "", {}
        except Exception as e:
            logger.warning("Unexpected error fetching %s: %s", url, e)
            return None, 0, "", "", {}
