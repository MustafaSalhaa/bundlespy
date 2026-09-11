"""
HTTP fetcher with rate limiting, retries, backoff, and safety checks.
Every request in BundleSpy goes through this module.
"""

import time
import hashlib
import logging
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests
import requests.adapters
import urllib3

from ..config import USER_AGENT
from ..safety.network import validate_url

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
    ):
        self.timeout           = timeout
        self.max_response_size = max_response_size
        self.retry_limit       = retry_limit
        self.min_delay         = 1.0 / max(requests_per_second, 1)
        self.user_agent        = user_agent
        self._last_request     = 0.0

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
        self.session.headers.update({"User-Agent": self.user_agent})

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self._last_request = time.monotonic()

    def get(
        self,
        url: str,
        check_content_type: Optional[str] = None,
    ) -> Tuple[Optional[str], int, str, str]:
        """
        Fetch a URL safely.

        Returns: (content, status_code, content_type, sha256)
        content is None on failure.
        """
        safe, reason = validate_url(url, check_dns=True)
        if not safe:
            logger.warning("Blocked request to %s: %s", url, reason)
            return None, 0, "", ""

        self._rate_limit()

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                stream=True,
            )

            content_type = resp.headers.get("Content-Type", "")

            # Read up to size limit
            chunks = []
            total  = 0
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > self.max_response_size:
                    logger.warning(
                        "Response from %s exceeded size limit (%d bytes), truncating",
                        url, self.max_response_size,
                    )
                    break
                chunks.append(chunk)

            raw = b"".join(chunks)

            # Decode safely
            try:
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                content = raw.decode("latin-1", errors="replace")

            sha256 = hashlib.sha256(raw).hexdigest()
            return content, resp.status_code, content_type, sha256

        except requests.exceptions.SSLError as e:
            logger.warning("SSL error for %s: %s", url, e)
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
