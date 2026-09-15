"""
Source Map Exploitation Module.

Detects .map files referenced in JS bundles, downloads them safely,
reconstructs original source files, and feeds them back into the
analysis pipeline for secret/endpoint detection.

Supports:
- sourceMappingURL inline references
- .js.map files at predictable paths
- Base64 encoded inline source maps
- webpack, Vite, Rollup, esbuild source map formats
"""

import re
import json
import base64
import hashlib
import logging
from typing import List, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime

from ..storage.models import JSFile
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.source_maps")

# Matches: //# sourceMappingURL=app.js.map
# Also matches: //@ sourceMappingURL= (older format)
RE_SOURCE_MAP_URL  = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s\"']+)",
    re.IGNORECASE,
)

# Inline base64 source maps: sourceMappingURL=data:application/json;base64,...
RE_INLINE_MAP      = re.compile(
    r"//[#@]\s*sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)

MAX_MAP_SIZE       = 20 * 1024 * 1024   # 20 MB per map file
MAX_SOURCE_SIZE    = 5  * 1024 * 1024   # 5 MB per recovered source


class SourceMapResult:
    """Holds everything recovered from a single source map."""
    def __init__(self, map_url: str, js_url: str):
        self.map_url        = map_url
        self.js_url         = js_url
        self.sources:  List[str] = []       # original file paths
        self.contents: List[str] = []       # recovered source contents
        self.recovered_files: List[JSFile] = []
        self.error:    Optional[str] = None


def detect_source_map_url(js_content: str, js_url: str) -> Optional[str]:
    """
    Extract the source map URL from a JS file.
    Returns absolute URL or None.

    Scans the ENTIRE file but prioritizes the last 2000 bytes
    where sourceMappingURL always appears in minified bundles.
    Also checks X-SourceMap and SourceMap HTTP header conventions
    encoded in the file.
    """
    if not js_content:
        return None

    # Strategy 1: Check last 2000 chars — this is where it always is in minified code
    tail = js_content[-2000:]
    inline = RE_INLINE_MAP.search(tail)
    if inline:
        return f"data:application/json;base64,{inline.group(1)}"

    match = RE_SOURCE_MAP_URL.search(tail)
    if match:
        raw = match.group(1).strip()
        if raw.startswith(("http://", "https://")):
            return raw
        try:
            return urljoin(js_url, raw)
        except Exception:
            pass

    # Strategy 2: Full file scan (catches non-standard placements)
    inline = RE_INLINE_MAP.search(js_content)
    if inline:
        return f"data:application/json;base64,{inline.group(1)}"

    match = RE_SOURCE_MAP_URL.search(js_content)
    if match:
        raw = match.group(1).strip()
        if raw.startswith(("http://", "https://")):
            return raw
        try:
            return urljoin(js_url, raw)
        except Exception:
            pass

    # Strategy 3: Look for X-SourceMap or SourceMap embedded as comment
    header_pattern = re.compile(
        r'//\s*(?:X-SourceMap|SourceMap)\s*:\s*([^\s"\x27]+)',
        re.IGNORECASE,
    )
    m = header_pattern.search(js_content)
    if m:
        raw = m.group(1).strip()
        if raw.startswith(("http://", "https://")):
            return raw
        try:
            return urljoin(js_url, raw)
        except Exception:
            pass

    return None


def fetch_source_map(map_url: str, fetcher) -> Optional[str]:
    """
    Download a source map file safely.
    Returns raw content string or None.
    """
    # Handle inline base64
    if map_url.startswith("data:application/json"):
        try:
            b64 = map_url.split("base64,", 1)[1]
            return base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning("Failed to decode inline source map: %s", e)
            return None

    # Validate URL safety
    safe, reason = validate_url(map_url)
    if not safe:
        logger.warning("Source map URL blocked: %s - %s", map_url, reason)
        return None

    content, status, content_type, _ = fetcher.get(map_url)
    if not content or status not in range(200, 300):
        logger.debug("Source map not found: %s (HTTP %d)", map_url, status)
        return None

    if len(content) > MAX_MAP_SIZE:
        logger.warning("Source map too large, skipping: %s", map_url)
        return None

    return content


def parse_source_map(raw: str) -> Optional[dict]:
    """Parse source map JSON safely."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        # Must have version and sources
        if "sources" not in data:
            return None
        return data
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("Failed to parse source map JSON: %s", e)
        return None


def recover_sources(
    map_data: dict,
    map_url:  str,
    js_url:   str,
) -> List[Tuple[str, str]]:
    """
    Extract original source files from a parsed source map.
    Returns list of (source_path, source_content) tuples.
    """
    sources         = map_data.get("sources", [])
    sources_content = map_data.get("sourcesContent", [])
    source_root     = map_data.get("sourceRoot", "")
    recovered       = []

    for i, source_path in enumerate(sources):
        if not source_path:
            continue

        # Build a meaningful path
        if source_root:
            full_path = source_root.rstrip("/") + "/" + source_path.lstrip("./")
        else:
            full_path = source_path

        # Get content - either inline or mark as external
        content = ""
        if i < len(sources_content) and sources_content[i]:
            content = sources_content[i]
            if len(content) > MAX_SOURCE_SIZE:
                logger.warning("Recovered source too large, truncating: %s", full_path)
                content = content[:MAX_SOURCE_SIZE]
        else:
            # No inline content - could fetch from webpack devServer but skip for safety
            logger.debug("No inline content for source: %s", full_path)
            continue

        recovered.append((full_path, content))

    return recovered


def process_js_file(js_file: JSFile, fetcher, scope) -> Optional[SourceMapResult]:
    """
    Full source map processing pipeline for a single JS file.

    1. Detect source map reference
    2. Fetch the map
    3. Parse it
    4. Recover original sources
    5. Return as JSFile objects for analysis
    """
    map_url = detect_source_map_url(js_file.content, js_file.url)
    if not map_url:
        # Try predictable map paths even when no sourceMappingURL comment
        map_url = try_predictable_map_paths(js_file.url, fetcher, scope)
    if not map_url:
        return None

    result = SourceMapResult(map_url=map_url, js_url=js_file.url)
    logger.info("Source map found: %s -> %s", js_file.url, map_url)

    raw = fetch_source_map(map_url, fetcher)
    if not raw:
        result.error = "Failed to fetch source map"
        return result

    map_data = parse_source_map(raw)
    if not map_data:
        result.error = "Failed to parse source map"
        return result

    recovered = recover_sources(map_data, map_url, js_file.url)
    logger.info(
        "Recovered %d source files from %s",
        len(recovered), js_file.url
    )

    for source_path, content in recovered:
        result.sources.append(source_path)
        result.contents.append(content)

        # Create a JSFile object so existing analyzers work on recovered source
        recovered_js = JSFile(
            url          = f"sourcemap://{source_path}",
            source_page  = js_file.url,
            status_code  = 200,
            content_type = "application/javascript",
            size_bytes   = len(content.encode("utf-8")),
            sha256       = hashlib.sha256(content.encode()).hexdigest(),
            content      = content,
            discovered_at = datetime.utcnow(),
            technology   = js_file.technology,
        )
        result.recovered_files.append(recovered_js)

    return result


def try_predictable_map_paths(js_url: str, fetcher, scope) -> Optional[str]:
    """
    Try common predictable source map locations even when no
    sourceMappingURL comment is present.
    e.g. /static/js/main.js -> /static/js/main.js.map
    """
    candidates = [
        js_url + ".map",
        js_url.replace(".js", ".js.map"),
        js_url.replace(".min.js", ".js.map"),
    ]

    for candidate in candidates:
        safe, _ = validate_url(candidate)
        if not safe:
            continue
        # Quick HEAD check first
        try:
            content, status, ct, _ = fetcher.get(candidate)
            if content and status == 200 and ("json" in ct.lower() or content.strip().startswith("{")):
                logger.info("Found source map at predictable path: %s", candidate)
                return candidate
        except Exception:
            continue

    return None
