"""
Webpack Chunk Discovery Module.

Parses webpack runtime manifests to find all chunk IDs and filenames,
then fetches and analyzes every chunk — including lazy-loaded ones
that a normal crawler would never see.

Supports webpack 4, webpack 5, and common chunk naming patterns.
"""

import re
import json
import logging
from typing import List, Set, Optional, Dict
from urllib.parse import urljoin, urlparse
from datetime import datetime
import hashlib

from ..storage.models import JSFile
from ..safety.network import validate_url

logger = logging.getLogger("bundlespy.discovery.webpack_chunks")

# Webpack 5 runtime: __webpack_require__.u = (chunkId) => ...
RE_WP5_CHUNK_MAP   = re.compile(
    r'__webpack_require__\.u\s*=\s*\(?\w+\)?\s*=>\s*\{([^}]{0,2000})\}',
    re.DOTALL,
)

# Webpack 4 runtime: chunkId + ".js"
RE_WP4_CHUNK_MAP   = re.compile(
    r'\{([^}]{0,2000})\}\s*\[\s*\w+\s*\]\s*\+\s*["\']\.js["\']',
    re.DOTALL,
)

# chunk IDs as numbers or strings in arrays/objects
RE_CHUNK_IDS       = re.compile(r'["\'`]?(\d+)["\'`]?\s*:', )

# Named chunks: "main":"abc123", "vendor":"def456"
RE_NAMED_CHUNKS    = re.compile(
    r'["\']([a-zA-Z0-9_\-]+)["\']:\s*["\']([a-zA-Z0-9_\-]+)["\']'
)

# publicPath detection
RE_PUBLIC_PATH     = re.compile(
    r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']'
)

# Common chunk URL patterns from bundle content
RE_CHUNK_URL       = re.compile(
    r'["\']([^"\']*chunk[^"\']*\.js)["\']',
    re.IGNORECASE,
)

# Vite/Rollup chunk patterns
RE_VITE_CHUNK      = re.compile(
    r'["\']([^"\']*assets/[^"\']+\.[a-f0-9]{8}\.js)["\']',
    re.IGNORECASE,
)

MAX_CHUNKS         = 300   # safety limit


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


def extract_public_path(content: str, base_url: str) -> str:
    """
    Extract webpack publicPath (the base URL for chunks).
    Falls back to the directory of the current JS file.
    """
    match = RE_PUBLIC_PATH.search(content)
    if match:
        pp = match.group(1)
        if pp and pp != "auto" and not pp.startswith("__"):
            if pp.startswith("http"):
                return pp
            return urljoin(base_url, pp)

    # Default: same directory as the JS file
    parsed = urlparse(base_url)
    path   = parsed.path.rsplit("/", 1)[0] + "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def extract_chunk_urls(content: str, js_url: str) -> List[str]:
    """
    Extract all chunk URLs from a webpack bundle.
    Handles webpack 4, webpack 5, Vite, and generic chunk references.
    """
    urls: Set[str] = set()
    public_path    = extract_public_path(content, js_url)

    # Method 1: explicit chunk URLs in strings
    for match in RE_CHUNK_URL.finditer(content):
        raw = match.group(1)
        if raw.startswith("http"):
            url = raw
        else:
            url = urljoin(public_path, raw)
        safe, _ = validate_url(url)
        if safe:
            urls.add(url)

    # Method 2: Vite/Rollup hashed chunks
    for match in RE_VITE_CHUNK.finditer(content):
        raw = match.group(1)
        url = urljoin(public_path, raw)
        safe, _ = validate_url(url)
        if safe:
            urls.add(url)

    # Method 3: webpack 5 chunk map reconstruction
    wp5 = RE_WP5_CHUNK_MAP.search(content)
    if wp5:
        chunk_body = wp5.group(1)
        # Try to extract chunk IDs
        for match in RE_CHUNK_IDS.finditer(chunk_body):
            chunk_id = match.group(1)
            # Common naming: <chunkId>.chunk.js, <chunkId>.js
            for pattern in [f"{chunk_id}.chunk.js", f"{chunk_id}.js"]:
                url = urljoin(public_path, pattern)
                safe, _ = validate_url(url)
                if safe:
                    urls.add(url)

    # Method 4: named chunks
    for match in RE_NAMED_CHUNKS.finditer(content):
        name, hash_val = match.group(1), match.group(2)
        for pattern in [
            f"{name}.{hash_val}.chunk.js",
            f"{name}.{hash_val}.js",
            f"{hash_val}.js",
        ]:
            url = urljoin(public_path, pattern)
            safe, _ = validate_url(url)
            if safe:
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
    Discover and fetch all webpack chunks from a JS file.
    Returns list of JSFile objects ready for analysis.
    """
    if not detect_webpack(js_file.content) and not detect_vite(js_file.content):
        return []

    chunk_urls = extract_chunk_urls(js_file.content, js_file.url)
    if not chunk_urls:
        return []

    logger.info(
        "Found %d potential chunk URLs in %s",
        len(chunk_urls), js_file.url
    )

    fetched:  List[JSFile] = []
    count     = 0

    for url in chunk_urls:
        if count >= max_chunks:
            logger.warning("Chunk limit reached (%d), stopping", max_chunks)
            break

        if url in seen_urls:
            continue

        # Scope check
        if not scope.in_scope(url):
            logger.debug("Chunk out of scope: %s", url)
            continue

        seen_urls.add(url)

        content, status, content_type, sha256 = fetcher.get(url)
        if not content or status not in range(200, 300):
            continue

        # Must look like JS
        ct_lower = content_type.lower()
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
            sha256        = sha256,
            content       = content,
            discovered_at = datetime.utcnow(),
            technology    = "webpack-chunk",
        )
        fetched.append(chunk_file)
        count += 1
        logger.debug("Fetched chunk: %s (%d bytes)", url, chunk_file.size_bytes)

    logger.info(
        "Fetched %d/%d chunks from %s",
        len(fetched), len(chunk_urls), js_file.url
    )
    return fetched
