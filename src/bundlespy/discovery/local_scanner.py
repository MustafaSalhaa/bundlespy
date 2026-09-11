"""
Local Scan Mode.

Recursively scans local JS/TS bundles, source maps, and chunks
without any network requests. Useful for:
- Pre-deployment secret scanning in CI/CD
- Scanning build artifacts before release
- Auditing downloaded JS bundles
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import List, Iterator
from datetime import datetime

from ..storage.models import JSFile

logger = logging.getLogger("bundlespy.discovery.local")

JS_EXTENSIONS  = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".map"}
MAX_FILE_SIZE  = 50 * 1024 * 1024  # 50 MB
SKIP_DIRS      = {"node_modules", ".git", ".svn", "vendor", "__pycache__", ".cache"}


def iter_js_files(directory: str) -> Iterator[Path]:
    """
    Recursively yield all JS/TS/map files from a directory.
    Skips common dependency and cache directories.
    """
    root = Path(directory)
    if not root.exists():
        logger.error("Directory not found: %s", directory)
        return

    if not root.is_dir():
        # Single file mode
        if root.suffix in JS_EXTENSIONS:
            yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        # Skip unwanted directories
        parts = set(path.parts)
        if parts & SKIP_DIRS:
            continue

        if path.suffix not in JS_EXTENSIONS:
            continue

        if path.stat().st_size > MAX_FILE_SIZE:
            logger.warning("Skipping large file: %s", path)
            continue

        yield path


def load_local_files(directory: str) -> List[JSFile]:
    """
    Load all JS files from a local directory as JSFile objects.
    Returns list ready for analysis by existing modules.
    """
    files   = []
    skipped = 0

    for path in iter_js_files(directory):
        try:
            raw     = path.read_bytes()
            content = raw.decode("utf-8", errors="replace")
            sha256  = hashlib.sha256(raw).hexdigest()

            js_file = JSFile(
                url           = f"local://{path.resolve()}",
                source_page   = f"local://{Path(directory).resolve()}",
                status_code   = 200,
                content_type  = "application/javascript",
                size_bytes    = len(raw),
                sha256        = sha256,
                content       = content,
                discovered_at = datetime.utcnow(),
                technology    = _detect_technology(content, str(path)),
                has_source_map = path.suffix == ".map" or "sourceMappingURL" in content,
            )
            files.append(js_file)
            logger.debug("Loaded local file: %s (%d bytes)", path, len(raw))

        except PermissionError:
            logger.warning("Permission denied: %s", path)
            skipped += 1
        except Exception as e:
            logger.warning("Failed to load %s: %s", path, e)
            skipped += 1

    logger.info(
        "Local scan: loaded %d files, skipped %d from %s",
        len(files), skipped, directory,
    )
    return files


def _detect_technology(content: str, filename: str) -> str:
    """Detect JS framework from content."""
    if "__webpack_require__" in content:
        return "webpack"
    if "/@vite/" in content or "import.meta.hot" in content:
        return "vite"
    if "React.createElement" in content or "react" in filename.lower():
        return "React"
    if "Vue.config" in content or "createApp(" in content:
        return "Vue"
    if "NgModule" in content or "platformBrowserDynamic" in content:
        return "Angular"
    if filename.endswith(".map"):
        return "source-map"
    return ""
