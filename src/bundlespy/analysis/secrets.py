"""
Secret detection engine.
Loads rules from rules/secrets.yaml, applies patterns against JS content,
scores findings, and filters likely false positives.
"""

import re
import math
import hashlib
import logging
import os
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path

import yaml

from ..storage.models import Finding

logger = logging.getLogger("bundlespy.analysis.secrets")

# Strings that almost always indicate a placeholder or example value
FP_INDICATORS = [
    "example", "placeholder", "your-key", "your_key", "insert_key",
    "api_key_here", "xxxx", "1234567890", "abcdefgh", "changeme",
    "replace_me", "todo", "fixme", "dummy", "fake", "test_key",
    "sample", "demo", "enter_your", "<your", "your-api", "xxxxxxxx",
    "aaaaaaaaa", "0000000000", "your_secret",
]


@dataclass
class SecretRule:
    id: str
    name: str
    category: str
    pattern: re.Pattern
    severity: str
    confidence: float
    description: str
    remediation: str
    fp_notes: str
    min_length: int = 0


def _shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random = more likely real."""
    if not value:
        return 0.0
    freq = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    length = len(value)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _is_likely_fp(value: str) -> Tuple[bool, str]:
    """Check if a matched value looks like a placeholder or example."""
    lower = value.lower()
    for indicator in FP_INDICATORS:
        if indicator in lower:
            return True, f"contains placeholder indicator '{indicator}'"

    # Very low entropy (all same chars, sequential, etc.)
    entropy = _shannon_entropy(value)
    if len(value) > 8 and entropy < 2.0:
        return True, f"low entropy ({entropy:.2f}) suggests non-random value"

    # Repeated character sequences
    if len(set(value)) < 4 and len(value) > 8:
        return True, "too few unique characters"

    return False, ""


def _get_context(content: str, pos: int, chars: int = 120) -> str:
    """Extract surrounding context around a match position."""
    start = max(0, pos - chars // 2)
    end   = min(len(content), pos + chars // 2)
    return content[start:end].replace("\n", " ").strip()


# Known CDN / library hostnames — secrets found in these files are almost
# certainly false positives from example keys embedded in documentation or
# source comments shipped with the library itself.
_LIBRARY_HOSTS = {
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "cdn.skypack.dev",
    "esm.sh",
    "esm.run",
    "cdn.bootcdn.net",
    "ajax.googleapis.com",
    "ajax.aspnetcdn.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "code.jquery.com",
    "cdn.plot.ly",
    "d3js.org",
    "cdn.datatables.net",
    "cdn.auth0.com",
    "cdn.segment.com",
    "js.stripe.com",
    "js.braintreegateway.com",
    "static.hotjar.com",
    "cdn.optimizely.com",
    "assets.adobedtm.com",
}

# URL path fragments that strongly indicate a vendored / bundled library
_LIBRARY_PATH_PATTERNS = [
    "/vendor/",
    "/vendors/",
    "/vendors~",
    "/node_modules/",
    "/lib/",
    "/static/js/chunk-",
    "/static/js/vendors-",
    ".min.js",
    "-bundle.js",
    "-bundle.min.js",
    "/polyfill",
    "/runtime.",
    "/commons.",
    "jquery",
    "lodash",
    "moment.js",
    "bootstrap",
    "react.development",
    "react.production",
]


def _is_library_url(url: str) -> bool:
    """
    Return True if *url* looks like a third-party CDN or vendored library
    resource that should be excluded from secret scanning.

    This is a fast heuristic — it checks the hostname against a known CDN
    list and the path against common vendor / dist patterns.  False negatives
    (returning False for a real library) are acceptable; false positives would
    suppress genuine secrets in first-party code, so the bar for inclusion in
    the CDN list is deliberately high (only universally-recognised CDNs).
    """
    if not url:
        return False

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        return False

    # Exact CDN hostname match
    if host in _LIBRARY_HOSTS:
        return True

    # Subdomain of a known CDN (e.g. my-org.cdn.jsdelivr.net)
    for cdn in _LIBRARY_HOSTS:
        if host.endswith("." + cdn):
            return True

    # Path-based heuristics (applies to any host, including self-hosted)
    path_lower = path.lower()
    for pattern in _LIBRARY_PATH_PATTERNS:
        if pattern in path_lower:
            return True

    return False


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def load_rules(rules_path: Optional[str] = None) -> List[SecretRule]:
    """Load detection rules from YAML file."""
    if rules_path is None:
        # Find the rules file — prefer the largest one (most rules)
        _base = Path(__file__).parent
        candidates = [
            _base / "rules" / "secrets.yaml",
            _base.parent / "rules" / "secrets.yaml",
            _base.parent.parent / "rules" / "secrets.yaml",
            _base.parent.parent.parent / "rules" / "secrets.yaml",
        ]
        existing = [p for p in candidates if p.exists()]
        if existing:
            # Pick the file with most content (most rules)
            rules_path = max(existing, key=lambda p: p.stat().st_size)
        else:
            rules_path = candidates[0]

    try:
        with open(rules_path) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("Rules file not found: %s", rules_path)
        return []
    except yaml.YAMLError as e:
        logger.error("Failed to parse rules file: %s", e)
        return []

    rules = []
    for raw in data.get("rules", []):
        try:
            compiled = re.compile(raw["pattern"])
            rules.append(SecretRule(
                id          = raw["id"],
                name        = raw["name"],
                category    = raw["category"],
                pattern     = compiled,
                severity    = raw["severity"],
                confidence  = float(raw["confidence"]),
                description = raw["description"],
                remediation = raw["remediation"],
                fp_notes    = raw.get("fp_notes", ""),
                min_length  = int(raw.get("min_length", 0)),
            ))
        except re.error as e:
            logger.warning("Invalid regex in rule %s: %s", raw.get("id"), e)

    logger.info("Loaded %d secret detection rules", len(rules))
    return rules


# Pattern to detect process.env.SECRET_NAME references
_RE_ENV_NAME = re.compile(
    r'process\.env\.([A-Z][A-Z0-9_]{2,})',
)

# ENV_NAME finding rule_id constant
_ENV_NAME_RULE_ID = "ENV_NAME"


def _decode_b64_chunks(content: str) -> List[Tuple[str, int]]:
    """
    Extract and decode base64 chunks from JS content.
    Returns list of (decoded_text, original_position) tuples.
    Only attempts chunks that are likely encoded secrets (length >= 32, valid b64).
    """
    results = []
    # Match quoted base64-looking strings of sufficient length
    b64_pattern = re.compile(r'["\x27`]([A-Za-z0-9+/]{32,}={0,2})["\x27`]')
    for m in b64_pattern.finditer(content):
        raw = m.group(1)
        # Must be valid base64 length
        if len(raw) % 4 not in (0, 2, 3):
            continue
        try:
            decoded = base64.b64decode(raw + "==").decode("utf-8", errors="strict")
            if decoded and len(decoded) >= 20:
                results.append((decoded, m.start()))
        except Exception:
            pass
    return results


class SecretScanner:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules = load_rules(rules_path)

    def _scan_content(
        self,
        content: str,
        file_url: str,
        source_page: str,
        findings: List[Finding],
        seen: Dict[str, Finding],
        pos_offset: int = 0,
    ) -> None:
        """Inner scan loop: run all rules against content."""
        for rule in self.rules:
            for match in rule.pattern.finditer(content):
                raw_value = match.group(0)
                # If there's a capture group, prefer it (more specific)
                if match.lastindex and match.lastindex >= 1:
                    try:
                        cap = match.group(1)
                        if cap:
                            raw_value = cap
                    except IndexError:
                        pass

                # Apply min_length filter
                if rule.min_length and len(raw_value) < rule.min_length:
                    continue

                # Check for false positives
                is_fp, fp_reason = _is_likely_fp(raw_value)

                confidence = rule.confidence
                status     = "candidate"

                if is_fp:
                    confidence = min(confidence * 0.3, 0.3)
                    status     = "likely_false_positive"
                elif confidence >= 0.85:
                    status = "likely_secret"

                redacted = Finding.redact(raw_value)
                sha256   = hashlib.sha256(f"{rule.id}:{raw_value}".encode()).hexdigest()
                actual_pos = match.start() + pos_offset
                context  = _get_context(content, match.start())
                line_no  = _get_line_number(content, match.start())

                finding_id = Finding.make_id(rule.id, raw_value, file_url)

                # Deduplication: same rule + value across files
                if sha256 in seen:
                    seen[sha256].occurrences.append(f"{file_url}:{line_no}")
                    continue

                finding = Finding(
                    id                  = finding_id,
                    rule_id             = rule.id,
                    title               = rule.name,
                    category            = rule.category,
                    severity            = rule.severity,
                    confidence          = round(confidence, 2),
                    file_url            = file_url,
                    source_page         = source_page,
                    line_number         = line_no,
                    column              = match.start() - content.rfind("\n", 0, match.start()),
                    matched_value       = raw_value,
                    redacted_value      = redacted,
                    sha256              = sha256,
                    context             = context,
                    description         = rule.description,
                    impact              = "",
                    remediation         = rule.remediation,
                    false_positive_notes = fp_reason or rule.fp_notes,
                    status              = status,
                    occurrences         = [f"{file_url}:{line_no}"],
                )

                seen[sha256] = finding
                findings.append(finding)

    def scan(self, content: str, file_url: str, source_page: str = "") -> List[Finding]:
        """
        Scan JavaScript content for secrets.
        Returns a list of Finding objects, deduplicated by value+rule.
        """
        findings: List[Finding] = []
        seen: Dict[str, Finding] = {}  # sha256 -> Finding

        # Primary scan on raw content
        self._scan_content(content, file_url, source_page, findings, seen)

        # Base64 decode layer: try to decode embedded b64 blobs and re-scan
        for decoded_text, orig_pos in _decode_b64_chunks(content):
            self._scan_content(decoded_text, file_url, source_page, findings, seen, pos_offset=orig_pos)

        # ENV_NAME detection: flag process.env.SECRET_NAME references
        for match in _RE_ENV_NAME.finditer(content):
            env_name = match.group(1)
            sha256 = hashlib.sha256(f"{_ENV_NAME_RULE_ID}:{env_name}".encode()).hexdigest()
            if sha256 in seen:
                continue
            line_no = _get_line_number(content, match.start())
            context = _get_context(content, match.start())
            finding_id = Finding.make_id(_ENV_NAME_RULE_ID, env_name, file_url)
            finding = Finding(
                id                  = finding_id,
                rule_id             = _ENV_NAME_RULE_ID,
                title               = "Environment Variable Reference",
                category            = "ENV",
                severity            = "INFO",
                confidence          = 0.7,
                file_url            = file_url,
                source_page         = source_page,
                line_number         = line_no,
                column              = match.start() - content.rfind("\n", 0, match.start()),
                matched_value       = env_name,
                redacted_value      = env_name,
                sha256              = sha256,
                context             = context,
                description         = f"Secret loaded from environment variable: {env_name}",
                impact              = "",
                remediation         = "Verify this environment variable is not accidentally exposed at runtime.",
                false_positive_notes = "process.env references are common and often intentional.",
                status              = "candidate",
                occurrences         = [f"{file_url}:{line_no}"],
            )
            seen[sha256] = finding
            findings.append(finding)

        return findings
