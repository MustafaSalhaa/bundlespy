"""
HTTP fetcher with rate limiting, retries, backoff, safety checks,
optional stealth mode for WAF evasion, and on-disk HTTP cache.

Cache behaviour
---------------
- On every GET the cache is checked first.
- Fresh hit (< 7 days old): returned immediately, zero network traffic.
- Stale hit or cache miss with stored ETag/Last-Modified: a conditional
  GET is sent (If-None-Match / If-Modified-Since).  A 304 response saves
  the full body download while still confirming the resource is unchanged.
- True miss: full GET, response stored for next time.
- Pass cache=False to bypass cache reads for a single call (writes still
  happen so the NEXT call benefits).
"""

import time
import hashlib
import logging
from typing import Optional, Tuple

import requests
import requests.adapters
import urllib3

from ..config import USER_AGENT
from ..safety.network import validate_url
from ..utils.stealth import random_ua, get_stealth_headers, stealth_delay
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
        cache: Optional[FetchCache] = None,
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

        # Cache: caller passes a FetchCache instance; None means no cache.
        self.cache: Optional[FetchCache] = cache

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
        return_headers: bool = False,
        use_cache: bool = True,
    ) -> Tuple[Optional[str], int, str, str]:
        """
        Fetch a URL safely with optional caching.

        Returns: (content, status_code, content_type, sha256)

        When return_headers=True the tuple is extended to 5 elements:
        (content, status_code, content_type, sha256, response_headers_dict)
        where response_headers_dict is a plain {str: str} mapping of lowercase
        header names -> values. Callers that don't pass return_headers=True get
        the original 4-tuple so every existing call site is unaffected.

        Pass use_cache=False to skip cache reads for this single call.
        """
        safe, reason = validate_url(url, check_dns=True)
        if not safe:
            logger.warning("Blocked request to %s: %s", url, reason)
            return (None, 0, "", "", {}) if return_headers else (None, 0, "", "")

        # -- Cache lookup --------------------------------------------------
        cached_meta: dict = {}
        cached_body: Optional[bytes] = None

        if self.cache and use_cache:
            hit, cached_body, cached_meta = self.cache.get(url)
            if hit and cached_body is not None:
                # Fresh cache hit - no network needed
                logger.debug("Cache HIT (fresh): %s", url)
                try:
                    content = cached_body.decode("utf-8", errors="replace")
                except Exception:
                    content = cached_body.decode("latin-1", errors="replace")
                sha256 = cached_meta.get("sha256") or hashlib.sha256(cached_body).hexdigest()
                ct     = cached_meta.get("content_type", "")
                if return_headers:
                    return content, 200, ct, sha256, {}
                return content, 200, ct, sha256

        self._rate_limit()

        # -- Build request headers -----------------------------------------
        if self.stealth:
            headers = get_stealth_headers(self._current_ua, referer=referer)
        else:
            headers = {"User-Agent": self.user_agent}

        # Merge auth headers (cookie, custom headers) - always applied
        if self.extra_headers:
            headers.update(self.extra_headers)

        # Add conditional-request headers from stale cache entry
        if cached_meta.get("etag"):
            headers["If-None-Match"] = cached_meta["etag"]
        if cached_meta.get("last_modified"):
            headers["If-Modified-Since"] = cached_meta["last_modified"]

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                stream=True,
                headers=headers,
            )

            # -- 304 Not Modified - serve from cache -----------------------
            if resp.status_code == 304 and self.cache:
                # Re-read stale body from disk (we only skipped it on fresh check)
                _, stale_body, stale_meta = self.cache.get(url)
                if stale_body is None:
                    # Edge case: body missing from disk, fall through to re-fetch
                    pass
                else:
                    self.cache.record_revalidated(url, len(stale_body))
                    logger.debug("Cache REVALIDATED (304): %s", url)
                    # Update stored entry with any new headers from 304 response
                    resp_headers_low = {k.lower(): v for k, v in resp.headers.items()}
                    if resp_headers_low.get("etag") or resp_headers_low.get("last-modified"):
                        self.cache.put(url, stale_body, resp_headers_low)
                    try:
                        content = stale_body.decode("utf-8", errors="replace")
                    except Exception:
                        content = stale_body.decode("latin-1", errors="replace")
                    sha256 = stale_meta.get("sha256") or hashlib.sha256(stale_body).hexdigest()
                    ct     = stale_meta.get("content_type", "")
                    if return_headers:
                        return content, 200, ct, sha256, resp_headers_low
                    return content, 200, ct, sha256

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

            # -- Store in cache --------------------------------------------
            if self.cache and resp.status_code in range(200, 300) and raw:
                resp_headers_low = {k.lower(): v for k, v in resp.headers.items()}
                self.cache.put(url, raw, resp_headers_low)
                logger.debug("Cache STORE: %s (%d bytes)", url, len(raw))

            if return_headers:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return content, resp.status_code, content_type, sha256, resp_headers
            return content, resp.status_code, content_type, sha256

        except requests.exceptions.SSLError as e:
            logger.warning("SSL error for %s: %s", url, e)
            return (None, 0, "", "", {}) if return_headers else (None, 0, "", "")
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error for %s: %s", url, e)
            return (None, 0, "", "", {}) if return_headers else (None, 0, "", "")
        except requests.exceptions.Timeout:
            logger.warning("Timeout for %s", url)
            return (None, 0, "", "", {}) if return_headers else (None, 0, "", "")
        except Exception as e:
            logger.warning("Unexpected error fetching %s: %s", url, e)
            return (None, 0, "", "", {}) if return_headers else (None, 0, "", "")
