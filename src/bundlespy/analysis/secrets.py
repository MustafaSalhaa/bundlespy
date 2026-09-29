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
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

import yaml

from ..storage.models import Finding

logger = logging.getLogger("bundlespy.analysis.secrets")

# Word/phrase indicators: any of these appearing ANYWHERE in the matched value
# almost certainly means it is a placeholder.  Real secrets never contain
# human-readable words like "example" or "changeme".
FP_INDICATORS = [
    "example", "placeholder", "your-key", "your_key", "insert_key",
    "api_key_here", "changeme", "replace_me", "todo", "fixme", "dummy",
    "fake", "test_key", "sample", "demo", "enter_your", "<your",
    "your-api", "your_secret",
]

# Sequential / repetitive patterns that should be caught by entropy checks.
# These are NOT used for substring matching against real keys — a Stripe key
# like sk_live_...1234567890 should not be suppressed just because those
# digits happen to appear somewhere in the key.
# (Kept here as documentation; the entropy + unique-char checks in
# _is_likely_fp() already reject values that ARE these patterns.)


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
    min_entropy: float = 0.0  # per-rule entropy floor; 0.0 = use global default


def _shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random = more likely real."""
    if not value:
        return 0.0
    freq = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    length = len(value)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _is_likely_fp(value: str, min_entropy: float = 2.0) -> Tuple[bool, str]:
    """Check if a matched value looks like a placeholder or example."""
    lower = value.lower()
    for indicator in FP_INDICATORS:
        if indicator in lower:
            return True, f"contains placeholder indicator '{indicator}'"

    # Entropy check: caller can pass a higher threshold for generic rules
    entropy = _shannon_entropy(value)
    if len(value) > 8 and entropy < min_entropy:
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


# Regex for stripping single-line JS comments before scanning.
# We only strip // comments - block comments are left because they sometimes
# contain real secrets embedded in code that's been temporarily commented out.
_RE_LINE_COMMENT = re.compile(r'(?m)(?:^|\s)//[^\n]*')


def _strip_line_comments(content: str) -> Tuple[str, List[int]]:
    """
    Strip single-line JS/TS comments and return cleaned content plus a
    position mapping so line numbers can be recovered.
    Returns (stripped_content, list_of_original_newline_positions).
    """
    # Instead of truly removing chars (which shifts all positions), replace
    # comment text with spaces to preserve offsets exactly.
    result = list(content)
    for m in _RE_LINE_COMMENT.finditer(content):
        start = m.start()
        # Preserve the leading whitespace/newline char before //
        slash_pos = content.index("//", start)
        for i in range(slash_pos, m.end()):
            result[i] = " "
    return "".join(result)


# Known secret prefixes that indicate a partial match (prefix without the rest).
# If we see these concatenated with a variable (e.g. "sk_live_" + someVar)
# we flag it as a partial secret indicator.
_PARTIAL_SECRET_PREFIXES = [
    ("sk_live_",     "STRIPE_SECRET_KEY",   "Stripe live secret key prefix"),
    ("sk_test_",     "STRIPE_TEST_SECRET",  "Stripe test secret key prefix"),
    ("pk_live_",     "STRIPE_PUB_KEY",      "Stripe live publishable key prefix"),
    ("AKIA",         "AWS_ACCESS_KEY",      "AWS access key prefix"),
    ("AIza",         "FIREBASE_API_KEY",    "Firebase API key prefix"),
    ("gsk_",         "GROQ_API_KEY",        "Groq API key prefix"),
    ("lin_api_",     "LINEAR_API_KEY",      "Linear API key prefix"),
    ("dp.st.",       "DOPPLER_TOKEN",       "Doppler service token prefix"),
    ("vercel_blob_rw_", "VERCEL_BLOB_TOKEN","Vercel Blob token prefix"),
    ("ghp_",         "GITHUB_TOKEN",        "GitHub personal access token prefix"),
    ("gho_",         "GITHUB_TOKEN",        "GitHub OAuth token prefix"),
    ("ghr_",         "GITHUB_TOKEN",        "GitHub refresh token prefix"),
    ("github_pat_",  "GITHUB_FINE_GRAINED", "GitHub fine-grained PAT prefix"),
    ("re_",          "RESEND_API_KEY",      "Resend API key prefix"),
    ("pk.eyJ1",      "MAPBOX_ACCESS_TOKEN", "Mapbox public token prefix"),
    ("sk.eyJ1",      "MAPBOX_SECRET_TOKEN", "Mapbox secret token prefix"),
]

# Pattern: prefix followed by concatenation with a variable (not a string literal)
_RE_CONCAT = re.compile(
    r'["\x27`]({prefix})["\x27`]\s*\+\s*(?:[A-Za-z_$][A-Za-z0-9_$]*|`\$\{{)'
)


def _find_partial_secrets(content: str, file_url: str, source_page: str) -> List[Finding]:
    """
    Detect secrets split across string concatenation or template literals.
    Example: const key = "sk_live_" + apiSecretVar;
    Flags these as INFO-level partial secret indicators.
    """
    findings: List[Finding] = []
    seen: Set[str] = set()

    for prefix, rule_id, description in _PARTIAL_SECRET_PREFIXES:
        pattern = re.compile(
            r'["\x27`](' + re.escape(prefix) + r')["\x27`]\s*\+\s*'
            r'(?:[A-Za-z_$][A-Za-z0-9_$]*|\$\{[^}]+\})'
        )
        for m in pattern.finditer(content):
            dedup_key = f"PARTIAL:{rule_id}:{m.group(1)}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            line_no = _get_line_number(content, m.start())
            context = _get_context(content, m.start())
            finding_id = Finding.make_id(f"PARTIAL_{rule_id}", prefix, file_url)

            findings.append(Finding(
                id                   = finding_id,
                rule_id              = f"PARTIAL_{rule_id}",
                title                = f"Partial Secret: {description}",
                category             = "Partial",
                severity             = "INFO",
                confidence           = 0.60,
                file_url             = file_url,
                source_page          = source_page,
                line_number          = line_no,
                column               = m.start() - content.rfind("\n", 0, m.start()),
                matched_value        = prefix,
                redacted_value       = prefix,
                sha256               = hashlib.sha256(f"PARTIAL_{rule_id}:{prefix}:{file_url}".encode()).hexdigest(),
                context              = context,
                description          = f"Secret prefix '{prefix}' found concatenated with a variable - full secret assembled at runtime.",
                impact               = "",
                remediation          = "Trace the variable to find the full secret. Runtime-assembled secrets are still secrets.",
                false_positive_notes = "Prefix concatenation is deliberate obfuscation in some cases.",
                confidence_label     = "candidate",
                occurrences          = [f"{file_url}:{line_no}"],
            ))

    return findings


_SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _severity_score(finding: Finding) -> float:
    """
    Composite score combining severity, confidence, and validation status.
    Higher = more urgent to review.
    Used for sorting findings by priority.
    """
    sev  = _SEVERITY_ORDER.get(finding.severity, 1)
    conf = finding.confidence
    # Boost confirmed_live findings, penalize likely_false_positive
    label_boost = {
        "likely_secret":         1.2,
        "candidate":             1.0,
        "likely_false_positive": 0.3,
    }.get(finding.confidence_label, 1.0)
    return sev * conf * label_boost


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
                min_entropy = float(raw.get("min_entropy", 0.0)),
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

    @staticmethod
    def severity_score(finding: Finding) -> float:
        """Composite priority score for a finding. Higher = review first."""
        return _severity_score(finding)

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

                # Check for false positives - use per-rule entropy floor when set
                _entropy_floor = rule.min_entropy if rule.min_entropy > 0.0 else 2.0
                is_fp, fp_reason = _is_likely_fp(raw_value, min_entropy=_entropy_floor)

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
                    id                   = finding_id,
                    rule_id              = rule.id,
                    title                = rule.name,
                    category             = rule.category,
                    severity             = rule.severity,
                    confidence           = round(confidence, 2),
                    file_url             = file_url,
                    source_page          = source_page,
                    line_number          = line_no,
                    column               = match.start() - content.rfind("\n", 0, match.start()),
                    matched_value        = raw_value,
                    redacted_value       = redacted,
                    sha256               = sha256,
                    context              = context,
                    description          = rule.description,
                    impact               = "",
                    remediation          = rule.remediation,
                    false_positive_notes = fp_reason or rule.fp_notes,
                    confidence_label     = status,
                    occurrences          = [f"{file_url}:{line_no}"],
                )

                seen[sha256] = finding
                findings.append(finding)

    def scan(self, content: str, file_url: str, source_page: str = "") -> List[Finding]:
        """
        Scan JavaScript content for secrets.
        Returns a list of Finding objects, deduplicated by value+rule,
        sorted by severity score (most critical first).
        """
        findings: List[Finding] = []
        seen: Dict[str, Finding] = {}  # sha256 -> Finding

        # Strip single-line comments before scanning to avoid flagging
        # secrets that were commented out (reduces noise, not blind spots -
        # commented-out secrets are still findings but get lower confidence).
        # We keep original content for line number accuracy since stripping
        # replaces comment text with spaces rather than removing it.
        stripped = _strip_line_comments(content)

        # Primary scan on comment-stripped content
        self._scan_content(stripped, file_url, source_page, findings, seen)

        # Lower confidence on findings that only matched inside a comment
        # (match is in stripped spaces, meaning the original had a comment there)
        # This is implicitly handled - stripping replaces with spaces so patterns
        # requiring non-space chars won't match in stripped comment regions.

        # Base64 decode layer: try to decode embedded b64 blobs and re-scan
        for decoded_text, orig_pos in _decode_b64_chunks(content):
            self._scan_content(decoded_text, file_url, source_page, findings, seen, pos_offset=orig_pos)

        # Partial secret detection: "sk_live_" + someVar patterns
        for partial_finding in _find_partial_secrets(content, file_url, source_page):
            sha = partial_finding.sha256
            if sha not in seen:
                seen[sha] = partial_finding
                findings.append(partial_finding)

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
                id                   = finding_id,
                rule_id              = _ENV_NAME_RULE_ID,
                title                = "Environment Variable Reference",
                category             = "ENV",
                severity             = "INFO",
                confidence           = 0.7,
                file_url             = file_url,
                source_page          = source_page,
                line_number          = line_no,
                column               = match.start() - content.rfind("\n", 0, match.start()),
                matched_value        = env_name,
                redacted_value       = env_name,
                sha256               = sha256,
                context              = context,
                description          = f"Secret loaded from environment variable: {env_name}",
                impact               = "",
                remediation          = "Verify this environment variable is not accidentally exposed at runtime.",
                false_positive_notes = "process.env references are common and often intentional.",
                confidence_label     = "candidate",
                occurrences          = [f"{file_url}:{line_no}"],
            )
            seen[sha256] = finding
            findings.append(finding)

        # Sort by severity score: CRITICAL confirmed_live first, INFO FP last
        findings.sort(key=_severity_score, reverse=True)
        return findings
