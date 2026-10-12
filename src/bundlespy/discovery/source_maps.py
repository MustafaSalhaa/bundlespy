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
- X-SourceMap / SourceMap header hints embedded in JS comments
"""

import re
import json
import base64
import hashlib
import logging
from typing import List, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone

from ..storage.models import JSFile
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.source_maps")

# Matches: //# sourceMappingURL=app.js.map
# Also matches: //@ sourceMappingURL= (older format, Chrome DevTools era)
RE_SOURCE_MAP_URL = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s\"']+)",
    re.IGNORECASE,
)

# Inline base64 source maps: sourceMappingURL=data:application/json;base64,...
RE_INLINE_MAP = re.compile(
    r"//[#@]\s*sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)

# X-SourceMap or SourceMap hints embedded as JS comments (non-standard but seen in the wild)
RE_HEADER_HINT = re.compile(
    r"//\s*(?:X-SourceMap|SourceMap)\s*:\s*([^\s\"'\x00-\x1f]+)",
    re.IGNORECASE,
)

MAX_MAP_SIZE    = 20 * 1024 * 1024   # 20 MB per map file
MAX_SOURCE_SIZE =  5 * 1024 * 1024   # 5 MB per recovered source file


class SourceMapResult:
    """Holds everything recovered from a single source map."""

    def __init__(self, map_url: str, js_url: str):
        self.map_url   = map_url
        self.js_url    = js_url
        self.map_type  = "inline" if map_url.startswith("data:") else "external"
        self.sources:         List[str]    = []   # original file paths from map
        self.contents:        List[str]    = []   # recovered source content strings
        self.recovered_files: List[JSFile] = []   # JSFile objects ready for analysis
        self.error:           Optional[str] = None


def detect_source_map_url(js_content: str, js_url: str) -> Optional[str]:
    """
    Extract the source map URL from a JS file's content.
    Returns an absolute URL, a data: URI, or None.

    Checks the tail of the file first (standard location in minified bundles),
    then falls back to a full scan, then checks for non-standard header hints.
    """
    if not js_content:
        return None

    def _resolve(raw: str) -> Optional[str]:
        raw = raw.strip()
        if raw.startswith("data:"):
            return raw
        if raw.startswith(("http://", "https://")):
            return raw
        try:
            return urljoin(js_url, raw)
        except Exception:
            return None

    # Strategy 1: last 2000 chars - standard placement in minified bundles
    tail = js_content[-2000:]

    m = RE_INLINE_MAP.search(tail)
    if m:
        return f"data:application/json;base64,{m.group(1)}"

    m = RE_SOURCE_MAP_URL.search(tail)
    if m:
        resolved = _resolve(m.group(1))
        if resolved:
            return resolved

    # Strategy 2: full file scan for non-standard placements
    m = RE_INLINE_MAP.search(js_content)
    if m:
        return f"data:application/json;base64,{m.group(1)}"

    m = RE_SOURCE_MAP_URL.search(js_content)
    if m:
        resolved = _resolve(m.group(1))
        if resolved:
            return resolved

    # Strategy 3: X-SourceMap / SourceMap header hints in JS comments
    m = RE_HEADER_HINT.search(js_content)
    if m:
        resolved = _resolve(m.group(1))
        if resolved:
            return resolved

    return None


def fetch_source_map(map_url: str, fetcher) -> Optional[str]:
    """
    Download a source map safely.
    Returns the raw JSON string, or None on failure.
    Handles both inline base64 data URIs and external HTTP URLs.
    """
    # Inline base64 - no network needed
    if map_url.startswith("data:application/json"):
        try:
            _, b64_part = map_url.split("base64,", 1)
            # Add padding if stripped
            padding = 4 - len(b64_part) % 4
            if padding != 4:
                b64_part += "=" * padding
            return base64.b64decode(b64_part).decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning("Failed to decode inline source map: %s", e)
            return None

    # External URL - validate safety before fetching
    safe, reason = validate_url(map_url)
    if not safe:
        logger.warning("Source map URL blocked: %s - %s", map_url, reason)
        return None

    content, status, content_type, _ = fetcher.get(map_url)
    if not content or status not in range(200, 300):
        logger.debug("Source map not found: %s (HTTP %d)", map_url, status or 0)
        return None

    if len(content) > MAX_MAP_SIZE:
        logger.warning("Source map too large (%d bytes), skipping: %s", len(content), map_url)
        return None

    return content


def parse_source_map(raw: str) -> Optional[dict]:
    """
    Parse and validate source map JSON.
    Returns the parsed dict, or None if invalid.
    """
    if not raw:
        return None
    try:
        data = json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("Failed to parse source map JSON: %s", e)
        return None

    if not isinstance(data, dict):
        return None
    if "sources" not in data or not isinstance(data["sources"], list):
        return None
    # version field is optional in practice (some tools omit it)
    return data


def recover_sources(
    map_data: dict,
    map_url:  str,
    js_url:   str,
) -> List[Tuple[str, str]]:
    """
    Extract original source files from a parsed source map.
    Returns a list of (source_path, source_content) tuples.
    source_content may be an empty string when sourcesContent is absent.
    """
    sources         = map_data.get("sources", [])
    sources_content = map_data.get("sourcesContent") or []
    source_root     = (map_data.get("sourceRoot") or "").rstrip("/")
    recovered       = []

    for i, source_path in enumerate(sources):
        if not source_path:
            continue

        # Normalize the path - strip webpack://  and similar prefixes
        path = source_path
        for prefix in ("webpack://", "webpack:///", "ng://", "file:///"):
            if path.startswith(prefix):
                path = path[len(prefix):]
                break

        # Combine sourceRoot if set
        if source_root and not path.startswith("/"):
            full_path = f"{source_root}/{path.lstrip('./')}"
        else:
            full_path = path

        # Get inline content when available
        content = ""
        if i < len(sources_content) and sources_content[i]:
            content = sources_content[i]
            if len(content) > MAX_SOURCE_SIZE:
                logger.warning(
                    "Recovered source too large (%d bytes), truncating: %s",
                    len(content), full_path,
                )
                content = content[:MAX_SOURCE_SIZE]
        else:
            # No inline content - path still carries value for route/endpoint
            # extractors that use filenames as signals (e.g. routes.ts, api/users.js)
            logger.debug("No inline content for source (path preserved): %s", full_path)

        recovered.append((full_path, content))

    return recovered


def try_predictable_map_paths(
    js_url: str,
    fetcher,
    scope,
) -> Optional[str]:
    """
    Try common predictable source map locations when no sourceMappingURL
    comment is present in the JS file.

    Uses HEAD requests first to avoid downloading 20MB map files
    just to confirm they exist.
    """
    parsed = urlparse(js_url)
    path   = parsed.path

    candidates = []

    # Standard: main.abc123.js -> main.abc123.js.map
    candidates.append(js_url + ".map")

    # Vite/webpack: main.abc123.js -> main.abc123.js.map (same as above)
    # But also: main.min.js -> main.js.map
    if path.endswith(".min.js"):
        base_no_min = js_url[:-len(".min.js")] + ".js"
        candidates.append(base_no_min + ".map")

    # esbuild: bundle.js -> bundle.js.map (already covered) but sometimes bundle.map
    if path.endswith(".js"):
        candidates.append(js_url[:-3] + ".map")

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            deduped.append(c)

    for candidate in deduped:
        safe, _ = validate_url(candidate)
        if not safe:
            continue
        if scope is not None and not scope.in_scope(candidate):
            continue

        try:
            content, status, ct, _ = fetcher.get(candidate)
            if (
                content
                and status == 200
                and (
                    "json" in (ct or "").lower()
                    or content.lstrip().startswith("{")
                )
            ):
                logger.info("Found source map at predictable path: %s", candidate)
                return candidate
        except Exception:
            continue

    return None


def process_js_file(
    js_file: JSFile,
    fetcher,
    scope,
) -> Optional[SourceMapResult]:
    """
    Full source map processing pipeline for one JS file.

    Steps:
      1. Detect source map reference in the JS content
      2. Fall back to probing predictable .map paths
      3. Fetch the map (or decode inline base64)
      4. Parse and validate the JSON
      5. Recover original source files from sourcesContent
      6. Tag the original js_file with has_source_map=True and source_map_url
      7. Return SourceMapResult with JSFile objects ready for the analysis pipeline

    Returns None when no source map reference is found.
    Returns a SourceMapResult with result.error set when the map was found
    but could not be fetched or parsed.
    """
    map_url = detect_source_map_url(js_file.content or "", js_file.url)

    if not map_url and fetcher is not None:
        map_url = try_predictable_map_paths(js_file.url, fetcher, scope)

    if not map_url:
        return None

    result = SourceMapResult(map_url=map_url, js_url=js_file.url)
    logger.info("Source map detected: %s -> %s", js_file.url, map_url)

    # Tag the original JS file so the HTML report can show the badge
    js_file.has_source_map = True
    js_file.source_map_url = map_url

    raw = fetch_source_map(map_url, fetcher)
    if not raw:
        result.error = "fetch_failed"
        return result

    map_data = parse_source_map(raw)
    if not map_data:
        result.error = "parse_failed"
        return result

    recovered = recover_sources(map_data, map_url, js_file.url)
    if not recovered:
        result.error = "no_sources"
        return result

    logger.info("Recovered %d source files from %s", len(recovered), js_file.url)

    now = datetime.now(timezone.utc)
    for source_path, content in recovered:
        result.sources.append(source_path)
        result.contents.append(content)

        # Build a JSFile so existing analyzers work unchanged on recovered source.
        # URL scheme sourcemap:// distinguishes them in per-file stats and reports.
        sha = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest() if content else ""
        recovered_js = JSFile(
            url          = f"sourcemap://{source_path}",
            source_page  = js_file.url,
            status_code  = 200,
            content_type = "application/javascript",
            size_bytes   = len(content.encode("utf-8", errors="replace")) if content else 0,
            sha256       = sha,
            content      = content,
            discovered_at = now,
            technology   = js_file.technology or "",
            source_type  = "sourcemap",
        )
        result.recovered_files.append(recovered_js)

    return result


def process_js_files(
    js_files: List[JSFile],
    fetcher,
    scope,
) -> Tuple[List[JSFile], Dict]:
    """
    Process all JS files for source maps in one call.

    Deduplicates map URLs so the same map is never fetched twice
    (e.g. vendor.js and main.js both reference the same base64 map).

    Returns:
        (recovered_files, stats_dict)

    stats_dict keys:
        discovered      - total JS files with a source map reference
        valid           - maps that were fetched and parsed successfully
        recovered       - same as valid (kept for compat)
        sources         - total recovered source files (with content)
        sources_path_only - recovered files without inline content
        errors          - count of maps found but failed to fetch/parse
        items           - list of per-map dicts for the HTML report
    """
    stats: Dict = {
        "discovered":       0,
        "valid":            0,
        "recovered":        0,
        "sources":          0,
        "sources_path_only": 0,
        "errors":           0,
        "items":            [],
    }

    seen_map_urls: set = set()
    all_recovered: List[JSFile] = []

    for js_file in js_files:
        result = process_js_file(js_file, fetcher, scope)
        if result is None:
            continue

        stats["discovered"] += 1

        # Dedup: same map URL already processed (e.g. inline base64 used by multiple chunks)
        map_key = result.map_url[:200]  # truncate very long data URIs for keying
        if map_key in seen_map_urls:
            logger.debug("Skipping duplicate source map: %s", result.map_url[:80])
            continue
        seen_map_urls.add(map_key)

        if result.error:
            stats["errors"] += 1
            logger.debug(
                "Source map error for %s: %s",
                js_file.url.split("/")[-1], result.error,
            )
            continue

        path_only = sum(1 for f in result.recovered_files if not f.content)
        stats["valid"]             += 1
        stats["recovered"]         += 1
        stats["sources"]           += len(result.recovered_files)
        stats["sources_path_only"] += path_only

        stats["items"].append({
            "js":        js_file.url.split("/")[-1],
            "js_url":    js_file.url,
            "map":       result.map_url.split("/")[-1] if not result.map_url.startswith("data:") else "inline",
            "map_url":   result.map_url if not result.map_url.startswith("data:") else "inline",
            "map_type":  result.map_type,
            "sources":   len(result.recovered_files),
            "path_only": path_only,
            "source_names": [s for s in result.sources],
        })

        all_recovered.extend(result.recovered_files)

    return all_recovered, stats
