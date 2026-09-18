"""
HTTP fetcher with rate limiting, retries, backoff, safety checks,
and optional stealth mode for WAF evasion.
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
        """
        safe, reason = validate_url(url, check_dns=True)
        if not safe:
            logger.warning("Blocked request to %s: %s", url, reason)
            return None, 0, "", ""

        self._rate_limit()

        # Build headers
        if self.stealth:
            headers = get_stealth_headers(self._current_ua, referer=referer)
        else:
            headers = {"User-Agent": self.user_agent}

        # Merge auth headers (cookie, custom headers) — always applied
        if self.extra_headers:
            headers.update(self.extra_headers)

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                stream=True,
                headers=headers,
            )

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


# ---------------------------------------------------------------------------
# Async fetcher
# ---------------------------------------------------------------------------

import asyncio
import hashlib as _hashlib
import logging as _logging
import ssl
from typing import Dict, List, Optional as _Optional, Tuple as _Tuple

try:
    import aiohttp
    import aiohttp.connector
except ImportError as _aiohttp_err:
    raise ImportError(
        "aiohttp is required for AsyncFetcher. Install it with: pip install aiohttp"
    ) from _aiohttp_err

try:
    import chardet as _chardet
    _CHARDET_AVAILABLE = True
except ImportError:
    _chardet = None  # type: ignore[assignment]
    _CHARDET_AVAILABLE = False

_async_logger = _logging.getLogger("bundlespy.async_fetcher")

_MAX_RETRIES = 3
_DEFAULT_CONCURRENCY = 10
_DEFAULT_TIMEOUT = 10
_DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
_RETRY_STATUS_CODES = {429, 500, 502, 503, 504}


def _decode_bytes(raw: bytes) -> str:
    """Decode raw bytes to str, using chardet for non-UTF-8 content."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass

    if _CHARDET_AVAILABLE:
        detected = _chardet.detect(raw)
        enc = detected.get("encoding") or "latin-1"
        try:
            return raw.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            pass

    return raw.decode("latin-1", errors="replace")


class AsyncFetcher:
    """
    Async HTTP fetcher built on aiohttp.

    Features:
    - Bounded concurrency via asyncio.Semaphore
    - Connection pooling via aiohttp.TCPConnector
    - Per-request timeout via aiohttp.ClientTimeout
    - Controlled retries (max 3) with exponential backoff
    - Redirect chain tracking
    - Response-size limits (default 10 MB, truncate and warn)
    - Graceful error handling for SSL, DNS, timeout, client errors
    - chardet for non-UTF-8 content detection
    - validate_url() safety check before every request
    - Rate limiting between requests
    """

    def __init__(
        self,
        concurrency: int = _DEFAULT_CONCURRENCY,
        timeout: int = _DEFAULT_TIMEOUT,
        max_response_size: int = _DEFAULT_MAX_RESPONSE_SIZE,
        requests_per_second: int = 2,
        user_agent: str = USER_AGENT,
        extra_headers: dict = None,
        ssl_verify: bool = False,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.min_delay = 1.0 / max(requests_per_second, 1)
        self.user_agent = user_agent
        self.extra_headers = extra_headers or {}
        self.ssl_verify = ssl_verify

        self._semaphore: _Optional[asyncio.Semaphore] = None
        self._session: _Optional[aiohttp.ClientSession] = None
        self._last_request: float = 0.0

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def _build_session(self) -> aiohttp.ClientSession:
        ssl_ctx: object
        if self.ssl_verify:
            ssl_ctx = ssl.create_default_context()
        else:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False  # type: ignore[union-attr]
            ssl_ctx.verify_mode = ssl.CERT_NONE  # type: ignore[union-attr]

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=self.concurrency * 2,
            limit_per_host=self.concurrency,
            enable_cleanup_closed=True,
        )
        headers = {"User-Agent": self.user_agent}
        headers.update(self.extra_headers)
        return aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            trust_env=False,
        )

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            self._session = self._build_session()
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)

    async def close(self) -> None:
        """Close the underlying aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncFetcher":
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _rate_limit(self) -> None:
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request
        if elapsed < self.min_delay:
            await asyncio.sleep(self.min_delay - elapsed)
        self._last_request = asyncio.get_event_loop().time()

    # ------------------------------------------------------------------
    # Core fetch
    # ------------------------------------------------------------------

    async def get(
        self,
        url: str,
        referer: str = "",
        check_content_type: _Optional[str] = None,
    ) -> _Tuple[_Optional[str], int, str, str, List[str]]:
        """
        Fetch a URL safely.

        Returns:
            (content, status_code, content_type, sha256, redirect_chain)

        redirect_chain is a list of all URLs visited (including the original).
        On error, content is None and other fields are empty/zero.
        """
        # Safety check first — no DNS resolution required here
        safe, reason = validate_url(url, check_dns=False)
        if not safe:
            _async_logger.warning("Blocked async request to %s: %s", url, reason)
            return None, 0, "", "", []

        await self._ensure_session()
        assert self._session is not None
        assert self._semaphore is not None

        client_timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers: Dict[str, str] = {}
        if referer:
            headers["Referer"] = referer

        last_exc: _Optional[Exception] = None

        for attempt in range(_MAX_RETRIES):
            if attempt > 0:
                backoff = 2 ** (attempt - 1)  # 1s, 2s
                _async_logger.debug(
                    "Retry %d/%d for %s, backoff %.1fs", attempt, _MAX_RETRIES - 1, url, backoff
                )
                await asyncio.sleep(backoff)

            async with self._semaphore:
                await self._rate_limit()

                try:
                    redirect_chain: List[str] = [url]

                    async with self._session.get(
                        url,
                        headers=headers,
                        timeout=client_timeout,
                        allow_redirects=True,
                        max_redirects=10,
                        trace_request_ctx={"redirect_chain": redirect_chain},
                    ) as resp:
                        # Build redirect chain from response history
                        redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]

                        status = resp.status
                        content_type = resp.headers.get("Content-Type", "")

                        # Retry on transient server errors
                        if status in _RETRY_STATUS_CODES and attempt < _MAX_RETRIES - 1:
                            _async_logger.debug(
                                "Retryable status %d for %s", status, url
                            )
                            last_exc = Exception(f"HTTP {status}")
                            continue

                        # Content-type filter
                        if check_content_type and check_content_type not in content_type:
                            _async_logger.debug(
                                "Content-type mismatch for %s: expected %s, got %s",
                                url, check_content_type, content_type,
                            )
                            return None, status, content_type, "", redirect_chain

                        # Read body with size limit
                        raw_chunks: List[bytes] = []
                        total = 0
                        truncated = False
                        async for chunk in resp.content.iter_chunked(8192):
                            total += len(chunk)
                            if total > self.max_response_size:
                                raw_chunks.append(
                                    chunk[: self.max_response_size - (total - len(chunk))]
                                )
                                truncated = True
                                _async_logger.warning(
                                    "Response from %s exceeded size limit (%d bytes), truncating",
                                    url, self.max_response_size,
                                )
                                break
                            raw_chunks.append(chunk)

                        raw = b"".join(raw_chunks)
                        if truncated:
                            # drain to avoid connection errors
                            resp.content.set_exception(Exception("truncated"))

                        content = _decode_bytes(raw)
                        sha256 = _hashlib.sha256(raw).hexdigest()

                        return content, status, content_type, sha256, redirect_chain

                except asyncio.TimeoutError as exc:
                    _async_logger.warning("Timeout on attempt %d for %s", attempt + 1, url)
                    last_exc = exc

                except ssl.SSLError as exc:
                    _async_logger.warning("SSL error for %s: %s", url, exc)
                    return None, 0, "", "", [url]

                except aiohttp.ClientConnectorError as exc:
                    # Covers DNS errors too (socket.gaierror wraps to ClientConnectorError)
                    _async_logger.warning("Connection/DNS error for %s: %s", url, exc)
                    last_exc = exc

                except aiohttp.ClientError as exc:
                    _async_logger.warning("Client error for %s: %s", url, exc)
                    last_exc = exc

                except Exception as exc:
                    _async_logger.warning("Unexpected error fetching %s: %s", url, exc)
                    last_exc = exc

        _async_logger.warning(
            "All %d attempts exhausted for %s. Last error: %s",
            _MAX_RETRIES, url, last_exc,
        )
        return None, 0, "", "", [url]

    # ------------------------------------------------------------------
    # Bulk fetch
    # ------------------------------------------------------------------

    async def fetch_many(
        self,
        urls: List[str],
        referer: str = "",
        check_content_type: _Optional[str] = None,
    ) -> Dict[str, _Tuple[_Optional[str], int, str, str, List[str]]]:
        """
        Fetch multiple URLs concurrently, bounded by the semaphore.

        Returns a dict mapping each URL to its (content, status, content_type, sha256, redirect_chain).
        """
        await self._ensure_session()

        tasks = {
            url: asyncio.ensure_future(
                self.get(url, referer=referer, check_content_type=check_content_type)
            )
            for url in urls
        }

        results: Dict[str, _Tuple[_Optional[str], int, str, str, List[str]]] = {}
        for url, task in tasks.items():
            try:
                results[url] = await task
            except Exception as exc:
                _async_logger.warning("fetch_many: unhandled error for %s: %s", url, exc)
                results[url] = (None, 0, "", "", [url])

        return results
