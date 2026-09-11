"""
Headless Browser Discovery Module.

Uses Playwright to launch a real Chromium browser, visit target pages,
intercept all network requests, and collect JS files that only appear
after JavaScript execution — webpack chunks, XHR endpoints, dynamically
injected scripts, etc.

Playwright is an optional dependency. If not installed, this module
degrades gracefully and logs a warning.
"""

import logging
from typing import List, Set, Optional, Dict
from datetime import datetime
import hashlib

from ..storage.models import JSFile
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.headless")


def _playwright_available() -> bool:
    try:
        import playwright
        return True
    except ImportError:
        return False


def collect_headless_js(
    url:        str,
    scope,
    timeout:    int  = 30,
    stealth:    bool = False,
) -> List[JSFile]:
    """
    Launch headless Chromium, visit the URL, intercept all JS requests.
    Returns list of JSFile objects for analysis.

    Requires: pip install playwright && playwright install chromium
    """
    if not _playwright_available():
        logger.warning(
            "Playwright not installed. Install with: "
            "pip install playwright && playwright install chromium"
        )
        return []

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    collected: List[JSFile] = []
    seen_urls: Set[str]    = set()

    logger.info("Starting headless browser for: %s", url)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )

        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/146.0.0.0 Safari/537.36"
            ) if stealth else None,
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )

        page = context.new_page()

        def handle_response(response):
            try:
                resp_url  = response.url
                resp_type = response.headers.get("content-type", "")

                # Only capture JS files
                if not any(t in resp_type.lower() for t in [
                    "javascript", "application/json"
                ]):
                    if not resp_url.endswith((".js", ".mjs", ".ts")):
                        return

                if resp_url in seen_urls:
                    return

                safe, _ = validate_url(resp_url)
                if not safe:
                    return

                if not scope.in_scope(resp_url):
                    return

                seen_urls.add(resp_url)

                try:
                    body = response.body()
                    content = body.decode("utf-8", errors="replace")
                except Exception:
                    return

                js_file = JSFile(
                    url           = resp_url,
                    source_page   = url,
                    status_code   = response.status,
                    content_type  = resp_type,
                    size_bytes    = len(body),
                    sha256        = hashlib.sha256(body).hexdigest(),
                    content       = content,
                    discovered_at = datetime.utcnow(),
                    technology    = "headless-captured",
                )
                collected.append(js_file)
                logger.debug("Headless captured: %s (%d bytes)", resp_url, len(body))

            except Exception as e:
                logger.debug("Response handler error: %s", e)

        page.on("response", handle_response)

        try:
            page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
            # Wait a bit more for lazy-loaded chunks
            page.wait_for_timeout(3000)
        except PWTimeout:
            logger.warning("Headless timeout for: %s", url)
        except Exception as e:
            logger.warning("Headless error for %s: %s", url, e)
        finally:
            context.close()
            browser.close()

    logger.info(
        "Headless browser collected %d JS files from %s",
        len(collected), url
    )
    return collected
