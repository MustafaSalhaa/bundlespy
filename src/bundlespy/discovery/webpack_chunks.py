"""
Webpack Chunk Discovery Module.

Parses webpack runtime manifests and asset manifests to find all chunk
IDs and filenames, then fetches and analyzes every chunk — including
lazy-loaded ones a normal crawler would never see.

Supports:
- webpack 4 and webpack 5 runtime chunk maps
- asset-manifest.json (Create React App)
- webpack-manifest.json, manifest.json with entrypoints
- Next.js build-manifest.json and _buildManifest.js
- Vite/Rollup hashed asset chunks
- Runtime chunkId -> filename reconstruction
"""

import re
import json
import logging
from typing import List, Set, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime
import hashlib

from ..storage.models import JSFile
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.webpack_chunks")

# Webpack 5 runtime: __webpack_require__.u = (chunkId) => ...
RE_WP5_CHUNK_MAP = re.compile(
    r'__webpack_require__\.u\s*=\s*\(?\w+\)?\s*=>\s*\{([^}]{0,4000})\}',
    re.DOTALL,
)

# Webpack 5 chunk map with hash: (e={},{123:"a1b2c3d4",456:"e5f6g7h8",...}[e]||e)+".chunk.js"
RE_WP5_HASH_MAP = re.compile(
    r'\{([^}]{0,4000})\}\s*\[[\w\s]+\]\s*\|\|[\w\s]+\)\s*\+\s*["\']',
    re.DOTALL,
)

# Webpack 4 runtime: chunkId + ".js"
RE_WP4_CHUNK_MAP = re.compile(
    r'\{([^}]{0,2000})\}\s*\[\s*\w+\s*\]\s*\+\s*["\']\.js["\']',
    re.DOTALL,
)

# Webpack 5: chunkId:hash pairs inside any object literal
# matches: 123:"abcdef12", "456":"def45678"
RE_CHUNK_HASH_PAIRS = re.compile(
    r'["\'`]?(\d+)["\'`]?\s*:\s*["\'`]([a-f0-9]{6,16})["\'`]'
)

# Fallback: just numeric chunk IDs as keys
RE_CHUNK_IDS = re.compile(r'["\'`]?(\d+)["\'`]?\s*:')

# Named chunks: "main":"abc123", "vendor":"def456"
RE_NAMED_CHUNKS = re.compile(
    r'["\']([a-zA-Z0-9_\-\.]+)["\']:\s*["\']([a-zA-Z0-9_\-\.]{4,})["\']'
)

# publicPath: __webpack_require__.p = "/static/"
RE_PUBLIC_PATH = re.compile(
    r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']'
)

# Vite publicBase
RE_VITE_BASE = re.compile(
    r'const\s+__vite_base\s*=\s*["\']([^"\']+)["\']|'
    r'__VITE_ASSET_BASE_URL__\s*=\s*["\']([^"\']+)["\']'
)

# Explicit chunk URLs already in strings
RE_CHUNK_URL = re.compile(
    r'["\']([^"\']*chunk[^"\']*\.js)["\']',
    re.IGNORECASE,
)

# Vite/Rollup hashed chunks: assets/Index.a1b2c3d4.js
RE_VITE_CHUNK = re.compile(
    r'["\']([^"\']*assets/[^"\']+\.[a-f0-9]{8}\.js)["\']',
    re.IGNORECASE,
)

# Next.js specific: _next/static/chunks/...
RE_NEXTJS_CHUNK = re.compile(
    r'["\'](\/_next\/static\/[^"\']+\.js)["\']',
    re.IGNORECASE,
)

# Webpack 5 chunk filename template reconstruction:
# (__webpack_require__.u = e => e + ".chunk.js")  no hash variant
RE_WP5_NO_HASH = re.compile(
    r'__webpack_require__\.u\s*=\s*\(?\w+\)?\s*=>\s*\(?\w+\s*\+\s*["\']',
)

MAX_CHUNKS = 300

# Candidate manifest paths to probe
MANIFEST_PATHS = [
    "/asset-manifest.json",         # Create React App
    "/static/js/asset-manifest.json",
    "/webpack-manifest.json",
    "/static/webpack-manifest.json",
    "/_next/static/chunks/webpack.js",   # Next.js runtime
    "/_next/static/_buildManifest.js",
    "/_next/build-manifest.json",
    "/manifest.json",               # generic - validated before use
    "/static/manifest.json",
    "/build/asset-manifest.json",
    "/dist/asset-manifest.json",
]


def detect_webpack(content: str) -> bool:
    """Check if a JS file is a webpack bundle or runtime."""
    markers = [
        "__webpack_require__",
        "webpackBootstrap",
        "webpackChunk",
        "__webpack_modules__",
        "webpack/runtime",
    ]
    return any(m in content for m in markers)


def detect_vite(content: str) -> bool:
    """Check if a JS file is a Vite bundle."""
    return any(m in content for m in ["/@vite/", "import.meta.hot", "vite/preload"])


def detect_nextjs(content: str) -> bool:
    """Check for Next.js bundle markers."""
    return any(m in content for m in ["_next/static", "__NEXT_DATA__", "next/dist"])


def extract_public_path(content: str, base_url: str) -> str:
    """
    Extract webpack publicPath. Falls back to the JS file's directory.
    """
    match = RE_PUBLIC_PATH.search(content)
    if match:
        pp = match.group(1)
        if pp and pp != "auto" and not pp.startswith("__"):
            if pp.startswith("http"):
                return pp
            return urljoin(base_url, pp)

    # Vite base
    match = RE_VITE_BASE.search(content)
    if match:
        pp = match.group(1) or match.group(2)
        if pp:
            return urljoin(base_url, pp)

    parsed = urlparse(base_url)
    path   = parsed.path.rsplit("/", 1)[0] + "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _resolve_chunk_url(raw: str, public_path: str) -> Optional[str]:
    """Resolve a raw chunk path to an absolute URL, validate scope."""
    if not raw:
        return None
    url = raw if raw.startswith("http") else urljoin(public_path, raw)
    safe, _ = validate_url(url)
    return url if safe else None


def parse_asset_manifest(data: dict, base_url: str) -> List[str]:
    """
    Extract JS URLs from CRA asset-manifest.json format.

    Two shapes:
      { "files": { "main.js": "/static/js/main.abc123.js", ... } }
      { "main.js": "/static/js/main.abc123.js", ... }          (older CRA)
    """
    urls: List[str] = []

    # Modern CRA: { files: {...}, entrypoints: [...] }
    files = data.get("files", data)
    if isinstance(files, dict):
        for key, val in files.items():
            if isinstance(val, str) and val.endswith(".js"):
                url = _resolve_chunk_url(val, base_url)
                if url:
                    urls.append(url)

    # entrypoints array
    for ep in data.get("entrypoints", []):
        if isinstance(ep, str) and ep.endswith(".js"):
            url = _resolve_chunk_url(ep, base_url)
            if url:
                urls.append(url)

    return urls


def parse_nextjs_build_manifest(data: dict, base_url: str) -> List[str]:
    """
    Extract chunk URLs from Next.js _buildManifest.js / build-manifest.json.

    Shape: { "__rewrites": {...}, "/": ["static/chunks/pages/index-xxx.js", ...], ... }
    Also: { "pages": { "/": ["..."], "/about": ["..."] } }
    """
    urls: List[str] = []

    pages = data.get("pages", data)
    if isinstance(pages, dict):
        for page_chunks in pages.values():
            if isinstance(page_chunks, list):
                for chunk in page_chunks:
                    if isinstance(chunk, str) and chunk.endswith(".js"):
                        # Next.js paths start with _next/ or static/
                        raw = chunk if chunk.startswith("/") else "/" + chunk
                        url = _resolve_chunk_url(raw, base_url)
                        if url:
                            urls.append(url)

    return urls


def fetch_manifest_chunks(base_url: str, fetcher, scope) -> Tuple[List[str], str]:
    """
    Probe well-known manifest paths to discover chunk URLs.
    Returns (list_of_chunk_urls, manifest_type_label).
    """
    origin = "{u.scheme}://{u.netloc}".format(u=urlparse(base_url))

    for path in MANIFEST_PATHS:
        manifest_url = origin + path
        safe, _ = validate_url(manifest_url)
        if not safe:
            continue
        if not scope.in_scope(manifest_url):
            continue

        try:
            content, status, ct, _ = fetcher.get(manifest_url)
        except Exception:
            continue

        if not content or status != 200:
            continue

        # _buildManifest.js is JS not JSON - extract the object literal
        if path.endswith(".js"):
            urls = _extract_from_manifest_js(content, origin)
            if urls:
                logger.info("Next.js manifest found at %s: %d chunks", path, len(urls))
                return urls, "nextjs-manifest"
            continue

        # JSON manifests
        if "json" not in ct.lower() and not content.strip().startswith("{"):
            continue

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            continue

        if not isinstance(data, dict):
            continue

        # Reject PWA manifests (name/icons/start_url pattern)
        if "icons" in data or "start_url" in data:
            continue

        # Next.js build-manifest.json
        if "pages" in data or any(k.startswith("/") for k in data):
            urls = parse_nextjs_build_manifest(data, origin)
            if urls:
                logger.info("Next.js build manifest at %s: %d chunks", path, len(urls))
                return urls, "nextjs-manifest"

        # CRA asset-manifest.json
        if "files" in data or any(k.endswith(".js") for k in data):
            urls = parse_asset_manifest(data, origin)
            if urls:
                logger.info("CRA asset manifest at %s: %d chunks", path, len(urls))
                return urls, "asset-manifest"

    return [], ""


def _extract_from_manifest_js(content: str, base_url: str) -> List[str]:
    """
    Pull chunk paths out of a Next.js _buildManifest.js file.
    These look like: self.__BUILD_MANIFEST = {"/": ["static/chunks/...js"], ...}
    """
    urls: List[str] = []
    # Find all JS strings ending in .js
    for m in re.finditer(r'"([^"]+\.js)"', content):
        raw = m.group(1)
        if "chunk" in raw or "pages" in raw or "static" in raw:
            raw = raw if raw.startswith("/") else "/" + raw
            url = _resolve_chunk_url(raw, base_url)
            if url:
                urls.append(url)
    return urls


def reconstruct_chunk_urls_from_runtime(content: str, public_path: str) -> List[str]:
    """
    Reconstruct chunk URLs from webpack runtime chunk ID/hash maps.

    Webpack 5 pattern:
        (e => ({123:"a1b2c3",456:"d4e5f6"}[e]||e)+".chunk.js")
    means chunk 123 is at: <publicPath>123.a1b2c3.chunk.js

    Also handles no-hash variant: chunkId + ".chunk.js"
    """
    urls: Set[str] = set()

    # Try to find the hash map block (wp5 with hashes)
    for block_match in RE_WP5_CHUNK_MAP.finditer(content):
        block = block_match.group(1)
        pairs = RE_CHUNK_HASH_PAIRS.findall(block)
        if pairs:
            # Determine suffix - look after the block for the filename suffix
            suffix_match = re.search(r'\)\s*\+\s*["\']([^"\']+)["\']', content[block_match.end():block_match.end()+200])
            suffix = suffix_match.group(1) if suffix_match else ".chunk.js"
            for chunk_id, chunk_hash in pairs:
                for tmpl in [
                    f"{chunk_id}.{chunk_hash}{suffix}",
                    f"{chunk_id}{suffix}",
                ]:
                    url = _resolve_chunk_url(tmpl, public_path)
                    if url:
                        urls.add(url)
        else:
            # No hash pairs, just numeric IDs
            ids = RE_CHUNK_IDS.findall(block)
            for chunk_id in ids:
                for tmpl in [f"{chunk_id}.chunk.js", f"{chunk_id}.js"]:
                    url = _resolve_chunk_url(tmpl, public_path)
                    if url:
                        urls.add(url)

    # Webpack 5 hash map variant: {123:"abcdef",456:"fedcba"}[e]
    for block_match in RE_WP5_HASH_MAP.finditer(content):
        block = block_match.group(1)
        pairs = RE_CHUNK_HASH_PAIRS.findall(block)
        # Get suffix from surrounding context
        ctx = content[block_match.start():block_match.end()+200]
        suffix_m = re.search(r'"\.(chunk\.js|js)"', ctx)
        suffix = "." + suffix_m.group(1) if suffix_m else ".chunk.js"
        for chunk_id, chunk_hash in pairs:
            for tmpl in [
                f"{chunk_id}.{chunk_hash}{suffix}",
                f"{chunk_id}{suffix}",
            ]:
                url = _resolve_chunk_url(tmpl, public_path)
                if url:
                    urls.add(url)

    # Webpack 4: {0: "vendors", 1: "app"}[chunkId] + ".js"
    for block_match in RE_WP4_CHUNK_MAP.finditer(content):
        block = block_match.group(1)
        for name_match in RE_NAMED_CHUNKS.finditer(block):
            key, val = name_match.group(1), name_match.group(2)
            for tmpl in [f"{val}.js", f"{key}.{val}.js"]:
                url = _resolve_chunk_url(tmpl, public_path)
                if url:
                    urls.add(url)

    return list(urls)


def extract_chunk_urls(content: str, js_url: str) -> List[str]:
    """
    Extract all chunk URLs from a webpack/vite bundle.
    Combines runtime reconstruction, explicit URL strings, and framework-specific patterns.
    """
    urls: Set[str] = set()
    public_path = extract_public_path(content, js_url)

    # Method 1: runtime chunk map reconstruction (most reliable for hashed chunks)
    for url in reconstruct_chunk_urls_from_runtime(content, public_path):
        urls.add(url)

    # Method 2: explicit chunk URL strings already in the bundle
    for match in RE_CHUNK_URL.finditer(content):
        url = _resolve_chunk_url(match.group(1), public_path)
        if url:
            urls.add(url)

    # Method 3: Vite/Rollup hashed chunks
    for match in RE_VITE_CHUNK.finditer(content):
        url = _resolve_chunk_url(match.group(1), public_path)
        if url:
            urls.add(url)

    # Method 4: Next.js static chunks
    for match in RE_NEXTJS_CHUNK.finditer(content):
        url = _resolve_chunk_url(match.group(1), public_path)
        if url:
            urls.add(url)

    return list(urls)


def fetch_chunks(
    js_file:    JSFile,
    fetcher,
    scope,
    seen_urls:  Set[str],
    max_chunks: int = MAX_CHUNKS,
) -> List[JSFile]:
    """
    Discover and fetch all webpack/vite chunks from a JS file.

    Pipeline:
    1. Probe well-known manifest paths for the target (asset-manifest.json, etc.)
    2. Parse the runtime chunk map to reconstruct hashed chunk URLs
    3. Extract any explicit chunk URL strings from bundle content
    4. Fetch everything, deduplicate, enforce limits

    Returns JSFile objects ready for analysis.
    """
    is_webpack = detect_webpack(js_file.content)
    is_vite    = detect_vite(js_file.content)
    is_next    = detect_nextjs(js_file.content)

    if not is_webpack and not is_vite and not is_next:
        return []

    all_chunk_urls: Set[str] = set()
    manifest_type = ""

    # Step 1: manifest probing (once per target, keyed by origin)
    manifest_urls, manifest_type = fetch_manifest_chunks(js_file.url, fetcher, scope)
    for url in manifest_urls:
        all_chunk_urls.add(url)

    # Step 2+3: extract from runtime content
    for url in extract_chunk_urls(js_file.content, js_file.url):
        all_chunk_urls.add(url)

    if not all_chunk_urls:
        return []

    logger.info(
        "Found %d potential chunk URLs for %s (manifest: %s)",
        len(all_chunk_urls), js_file.url, manifest_type or "none"
    )

    fetched: List[JSFile] = []
    count = 0

    for url in sorted(all_chunk_urls):  # sorted for determinism
        if count >= max_chunks:
            logger.warning("Chunk limit reached (%d), stopping", max_chunks)
            break
        if url in seen_urls:
            continue
        if not scope.in_scope(url):
            logger.debug("Chunk out of scope: %s", url)
            continue

        seen_urls.add(url)

        try:
            content, status, content_type, sha256 = fetcher.get(url)
        except Exception:
            continue

        if not content or status not in range(200, 300):
            continue

        ct_lower = (content_type or "").lower()
        if content_type and not any(t in ct_lower for t in [
            "javascript", "text/plain", "application/", "text/html"
        ]):
            continue

        chunk_file = JSFile(
            url           = url,
            source_page   = js_file.url,
            status_code   = status,
            content_type  = content_type,
            size_bytes    = len(content.encode("utf-8")),
            sha256        = sha256 or hashlib.sha256(content.encode()).hexdigest(),
            content       = content,
            discovered_at = datetime.utcnow(),
            technology    = f"webpack-chunk" if not is_vite else "vite-chunk",
        )
        fetched.append(chunk_file)
        count += 1
        logger.debug("Fetched chunk: %s (%d bytes)", url, chunk_file.size_bytes)

    logger.info(
        "Fetched %d/%d chunks from %s",
        len(fetched), len(all_chunk_urls), js_file.url
    )
    return fetched
