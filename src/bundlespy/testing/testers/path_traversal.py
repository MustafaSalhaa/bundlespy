"""
PathTraversalMapper - path traversal / LFI attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Param names strongly associated with file/path operations
_HIGH_FILE_PARAMS = {
    "file", "filename", "path", "filepath", "dir", "directory",
    "folder", "doc", "document",
}

# Medium signal - often used for page includes and downloads
_MEDIUM_FILE_PARAMS = {
    "page", "template", "view", "include", "load", "read",
    "download", "export", "attachment", "resource",
}

# Lower signal - asset serving
_LOW_FILE_PARAMS = {
    "asset", "image", "img", "photo", "pdf", "report",
}

_ALL_FILE_PARAMS = _HIGH_FILE_PARAMS | _MEDIUM_FILE_PARAMS | _LOW_FILE_PARAMS

# Path fragments that suggest file serving or download functionality
_FILE_PATH_SIGNALS = {
    "/download", "/export", "/file", "/document", "/attachment",
    "/static", "/assets", "/media", "/upload",
}

_BURP_NOTES = (
    "Test with ../../../etc/passwd. "
    "Try URL encoding: %2e%2e%2f. "
    "Test null byte: file.php%00.txt. "
    "Use Burp Intruder with traversal wordlist."
)


def _path_confidence(name: str, ep_path: str) -> str:
    name     = name.lower()
    ep_lower = ep_path.lower()
    is_file_path = any(sig in ep_lower for sig in _FILE_PATH_SIGNALS)

    if name in _HIGH_FILE_PARAMS and is_file_path:
        return ConfidenceLevel.HIGH
    if name in _HIGH_FILE_PARAMS:
        return ConfidenceLevel.MEDIUM
    if name in _MEDIUM_FILE_PARAMS:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


class PathTraversalMapper(BaseSurfaceMapper):
    category = AttackCategory.PATH_TRAVERSAL

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        for ep in result.endpoints:
            ep_path = ep.path or ep.url or ""
            method  = (ep.method or "GET").upper()
            is_file_path = any(sig in ep_path.lower() for sig in _FILE_PATH_SIGNALS)

            # 1. Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_FILE_PARAMS:
                    continue
                confidence = _path_confidence(name, ep_path)
                evidence   = [f"File/path-signal query param '{name}' on {ep.url}"]
                if is_file_path:
                    evidence.append(f"Endpoint path suggests file serving: {ep_path}")
                self._candidate(
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = _BURP_NOTES,
                )

            # 2. Body fields
            for bf in (ep.body_fields or []):
                name = (bf.get("name") or "").lower()
                if name not in _ALL_FILE_PARAMS:
                    continue
                confidence = _path_confidence(name, ep_path)
                self._candidate(
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [f"body:{name}"],
                    confidence   = confidence,
                    evidence     = [f"File/path-signal body field '{name}' on {method} {ep.url}"],
                    burp_notes   = _BURP_NOTES,
                )

            # 3. Path params that look file-related
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name not in _ALL_FILE_PARAMS:
                    continue
                confidence = _path_confidence(name, ep_path)
                self._candidate(
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [f"path_param:{name}"],
                    confidence   = confidence,
                    evidence     = [f"File/path-signal path parameter '{name}' on {ep.url}"],
                    burp_notes   = _BURP_NOTES,
                )

            # 4. Download/file endpoint with no params yet still interesting
            if is_file_path and not any(
                (qp.get("name") or "").lower() in _ALL_FILE_PARAMS
                for qp in (ep.query_params or [])
            ):
                self._candidate(
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [],
                    confidence   = ConfidenceLevel.LOW,
                    evidence     = [f"File-serving endpoint with no detected params: {ep_path}"],
                    burp_notes   = _BURP_NOTES,
                )

        return self._results
