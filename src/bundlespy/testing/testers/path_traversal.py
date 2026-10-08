"""
PathTraversalMapper - path traversal / LFI attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
import re
from typing import List, Set, Tuple
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ..param_semantics import (
    ALL_FILE_PARAMS as _ALL_FILE_PARAMS,
    HIGH_FILE_PARAMS as _HIGH_FILE_PARAMS,
    HIGH_PATH_PARAM_NAMES,
    classify_param,
    ParamType,
    tier_to_confidence_level,
)
from ...storage.models import ScanResult, Endpoint

# Path fragments that suggest file serving or download functionality
_FILE_PATH_SIGNALS = {
    "/download", "/export", "/file", "/document", "/attachment",
    "/static", "/assets", "/media", "/upload",
}

# File extensions in a param VALUE that indicate HIGH confidence
# e.g. file=config.php, path=../etc/passwd, attachment=report.pdf
_HIGH_VALUE_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".txt", ".log", ".conf",
    ".ini", ".bak", ".xml", ".yaml", ".yml", ".env",
}

# Regex to detect a file extension at the end of a param's example value
_FILE_EXTENSION_RE = re.compile(
    r"\.[a-zA-Z0-9]{1,10}$"
)

# Extensions in the URL path itself (e.g. /download?file=x.pdf)
_URL_FILE_EXTENSION_RE = re.compile(
    r"\.(pdf|zip|tar|gz|doc|docx|xls|xlsx|ppt|pptx|csv|json|xml|txt|log|conf|ini|bak|env|php|asp|aspx|jsp)"
    r"(\?|$|/)",
    re.IGNORECASE,
)

# Windows path patterns in param values
_WINDOWS_PATH_RE = re.compile(
    r"(\\|%5c|%255c|\.\.\\|%2e%2e%5c)",
    re.IGNORECASE,
)

_BURP_NOTES = (
    "Test path traversal sequences:\n"
    "  ../../../etc/passwd\n"
    "  ../../../etc/shadow\n"
    "  /proc/self/environ\n"
    "  /proc/self/cmdline\n"
    "Windows:\n"
    "  ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts\n"
    "  ..\\..\\..\\..\\..\\..\\.\\windows\\win.ini\n"
    "Null byte bypass: file.php%00.txt\n"
    "URL encoding: %2e%2e%2f\n"
    "Double encoding: %252e%252e%252f\n"
    "Use Burp Intruder with traversal wordlist (e.g. SecLists/Fuzzing/LFI/)."
)

_BURP_NOTES_ZIP = (
    "Upload context - test zip slip:\n"
    "  Create archive with entry path: ../../../evil.jsp\n"
    "  Tools: evilarc, zip-slip-poc\n"
    "Also test:\n"
    "  Symlinks inside archive pointing to /etc/passwd\n"
    "  Double-extension filenames: evil.jsp.jpg"
)

_BURP_NOTES_WINDOWS = (
    "Windows-specific traversal:\n"
    "  ..\\..\\..\\.\\windows\\system32\\drivers\\etc\\hosts\n"
    "  ..%5c..%5c..%5cwindows%5cwin.ini\n"
    "  %255c (double-encoded backslash)\n"
    "  UNC paths: \\\\attacker\\share\\file\n"
    "URL-encoded variants: %2e%2e%5c, %2e%2e%255c"
)


def _get_param_example_value(param: dict) -> str:
    """Pull the example/default value from a param dict regardless of key name."""
    for key in ("example", "value", "default"):
        val = param.get(key)
        if val and isinstance(val, str):
            return val
    return ""


def _has_high_value_extension(value: str) -> bool:
    """Return True if the value ends with a HIGH-confidence file extension."""
    v = value.lower().strip()
    for ext in _HIGH_VALUE_EXTENSIONS:
        if v.endswith(ext):
            return True
    return False


def _url_has_file_extension(url: str) -> bool:
    """Return True if the URL itself contains a file extension (e.g. /download?file=x.pdf)."""
    return bool(_URL_FILE_EXTENSION_RE.search(url))


def _has_windows_path_signal(value: str) -> bool:
    """Return True if the value contains a Windows path indicator."""
    return bool(_WINDOWS_PATH_RE.search(value))


def _pick_burp_notes(ep_path: str, param_name: str, example_value: str) -> str:
    """Choose the most relevant burp note block for this finding."""
    path_lower = ep_path.lower()
    if any(sig in path_lower for sig in ("/upload", "/import", "/archive", "/zip")):
        return _BURP_NOTES_ZIP
    if _has_windows_path_signal(example_value):
        return _BURP_NOTES_WINDOWS + "\n\n" + _BURP_NOTES
    return _BURP_NOTES


def _path_confidence(name: str, ep_path: str, example_value: str = "") -> str:
    ep_lower     = ep_path.lower()
    is_file_path = any(sig in ep_lower for sig in _FILE_PATH_SIGNALS)
    url_has_ext  = _url_has_file_extension(ep_path)

    # Value extension is a direct, unambiguous signal - always HIGH
    if example_value and _has_high_value_extension(example_value):
        return ConfidenceLevel.HIGH

    # Use centralized classifier for base tier
    cls  = classify_param(name, example_value)
    conf = tier_to_confidence_level(cls.tier)

    # Boost HIGH-tier names when URL/path context also signals file serving
    if conf == ConfidenceLevel.HIGH and (is_file_path or url_has_ext):
        return ConfidenceLevel.HIGH

    return conf


class PathTraversalMapper(BaseSurfaceMapper):
    category = AttackCategory.PATH_TRAVERSAL

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Dedup by (method, url, param_name) to avoid duplicate candidates
        seen: Set[Tuple[str, str, str]] = set()

        def _deduped_candidate(method: str, url: str, param_name: str, **kwargs) -> bool:
            # Returns True if the candidate was emitted, False if dedup'd
            key = (method.upper(), url, param_name)
            if key in seen:
                return False
            seen.add(key)
            self._candidate(**kwargs)
            return True

        for ep in result.endpoints:
            ep_path = ep.path or ep.url or ""
            method  = (ep.method or "GET").upper()
            ep_url  = ep.url or ep_path
            is_file_path = any(sig in ep_path.lower() for sig in _FILE_PATH_SIGNALS)

            # 1. Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_FILE_PARAMS:
                    continue
                example_val = _get_param_example_value(qp)
                confidence  = _path_confidence(name, ep_path, example_val)
                evidence    = [f"File/path-signal query param '{name}' on {ep_url}"]
                if is_file_path:
                    evidence.append(f"Endpoint path suggests file serving: {ep_path}")
                if example_val and _has_high_value_extension(example_val):
                    evidence.append(f"Param example value has file extension: '{example_val}'")
                if example_val and _has_windows_path_signal(example_val):
                    evidence.append(f"Param example value contains Windows path indicator: '{example_val}'")
                burp = _pick_burp_notes(ep_path, name, example_val)
                qp_cls = classify_param(name, example_val)
                if _deduped_candidate(
                    method     = method,
                    url        = ep_url,
                    param_name = f"query:{name}",
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = burp,
                ):
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = ep_url,
                                context        = f"File/path-signal query param '{name}'",
                                details        = f"Param name '{name}' commonly references a file path",
                                raw_confidence = int(qp_cls.raw_confidence * 100),
                            ),
                        ],
                        surface_type = "Path Traversal / LFI",
                        endpoint     = ep_url,
                        method       = method,
                        parameter    = f"query:{name}",
                        notes        = burp,
                    )

            # 2. Body fields
            for bf in (ep.body_fields or []):
                name = (bf.get("name") or "").lower()
                if name not in _ALL_FILE_PARAMS:
                    continue
                example_val = _get_param_example_value(bf)
                confidence  = _path_confidence(name, ep_path, example_val)
                bf_cls      = classify_param(name, example_val)
                evidence    = [f"File/path-signal body field '{name}' on {method} {ep_url}"]
                if example_val and _has_high_value_extension(example_val):
                    evidence.append(f"Body field example value has file extension: '{example_val}'")
                if example_val and _has_windows_path_signal(example_val):
                    evidence.append(f"Body field example value contains Windows path indicator: '{example_val}'")
                burp = _pick_burp_notes(ep_path, name, example_val)
                if _deduped_candidate(
                    method     = method,
                    url        = ep_url,
                    param_name = f"body:{name}",
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [f"body:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = burp,
                ):
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = ep_url,
                                context        = f"File/path-signal body field '{name}'",
                                details        = f"Body field '{name}' commonly references a file path",
                                raw_confidence = int(bf_cls.raw_confidence * 100),
                            ),
                        ],
                        surface_type = "Path Traversal / LFI",
                        endpoint     = ep_url,
                        method       = method,
                        parameter    = f"body:{name}",
                        notes        = burp,
                    )

            # 3. Path params - existing logic + REST-style file reference detection
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                example_val = _get_param_example_value(pp)

                # Existing: param name matches known file param sets
                if name in _ALL_FILE_PARAMS:
                    confidence = _path_confidence(name, ep_path, example_val)
                    pp_cls     = classify_param(name, example_val)
                    evidence   = [f"File/path-signal path parameter '{name}' on {ep_url}"]
                    if example_val and _has_high_value_extension(example_val):
                        evidence.append(f"Path param example value has file extension: '{example_val}'")
                    burp = _pick_burp_notes(ep_path, name, example_val)
                    if _deduped_candidate(
                        method     = method,
                        url        = ep_url,
                        param_name = f"path_param:{name}",
                        endpoint     = ep,
                        surface_type = "Path Traversal / LFI",
                        parameters   = [f"path_param:{name}"],
                        confidence   = confidence,
                        evidence     = evidence,
                        burp_notes   = burp,
                    ):
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                    source         = "static",
                                    asset          = ep_url,
                                    context        = f"File/path-signal path param '{name}'",
                                    details        = f"Path param '{name}' commonly references a file path",
                                    raw_confidence = int(pp_cls.raw_confidence * 100),
                                ),
                            ],
                            surface_type = "Path Traversal / LFI",
                            endpoint     = ep_url,
                            method       = method,
                            parameter    = f"path_param:{name}",
                            notes        = burp,
                        )
                    continue

                # New: REST-style file reference - /files/{filename}, /docs/{document_id}
                # Flag when the path param name itself strongly suggests a file reference
                if name in _HIGH_PATH_PARAM_NAMES:
                    evidence = [
                        f"REST-style path param '{name}' suggests file reference on {ep_url}",
                        f"Pattern: path param name '{name}' is a known file-reference identifier",
                    ]
                    if example_val and _has_high_value_extension(example_val):
                        evidence.append(f"Path param example value has file extension: '{example_val}'")
                    if _deduped_candidate(
                        method     = method,
                        url        = ep_url,
                        param_name = f"path_param:{name}",
                        endpoint     = ep,
                        surface_type = "Path Traversal / LFI",
                        parameters   = [f"path_param:{name}"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES,
                    ):
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type = EvidenceType.ROUTE_DECLARATION,
                                    source        = "static",
                                    asset         = ep_url,
                                    context       = f"REST-style file reference path param '{name}'",
                                    details       = f"Path param name '{name}' is a known file-reference identifier",
                                ),
                            ],
                            surface_type = "Path Traversal / LFI",
                            endpoint     = ep_url,
                            method       = method,
                            parameter    = f"path_param:{name}",
                            notes        = _BURP_NOTES,
                        )
                    continue

                # Also catch REST path params where the example value has a file extension
                if example_val and _has_high_value_extension(example_val):
                    ext_cls = classify_param(name, example_val)
                    if _deduped_candidate(
                        method     = method,
                        url        = ep_url,
                        param_name = f"path_param:{name}",
                        endpoint     = ep,
                        surface_type = "Path Traversal / LFI",
                        parameters   = [f"path_param:{name}"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"Path param '{name}' example value has file extension: '{example_val}'",
                            f"Endpoint: {ep_url}",
                        ],
                        burp_notes   = _BURP_NOTES,
                    ):
                        self._emit_evidence(
                            evidence     = [
                                Evidence(
                                    evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                    source         = "static",
                                    asset          = ep_url,
                                    context        = f"Path param '{name}' example value has file extension",
                                    details        = f"example value: '{example_val}'",
                                    raw_confidence = int(ext_cls.raw_confidence * 100),
                                ),
                            ],
                            surface_type = "Path Traversal / LFI",
                            endpoint     = ep_url,
                            method       = method,
                            parameter    = f"path_param:{name}",
                            notes        = _BURP_NOTES,
                        )

            # 4. Download/file endpoint with no matching params - still worth flagging
            if is_file_path and not any(
                (qp.get("name") or "").lower() in _ALL_FILE_PARAMS
                for qp in (ep.query_params or [])
            ):
                if _deduped_candidate(
                    method     = method,
                    url        = ep_url,
                    param_name = "__no_param__",
                    endpoint     = ep,
                    surface_type = "Path Traversal / LFI",
                    parameters   = [],
                    confidence   = ConfidenceLevel.LOW,
                    evidence     = [f"File-serving endpoint with no detected params: {ep_path}"],
                    burp_notes   = _BURP_NOTES,
                ):
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type = EvidenceType.ROUTE_DECLARATION,
                                source        = "static",
                                asset         = ep_url,
                                context       = f"File-serving endpoint with no detected file params",
                                details       = ep_path,
                            ),
                        ],
                        surface_type = "Path Traversal / LFI",
                        endpoint     = ep_url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES,
                    )

        return self._results
