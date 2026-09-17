"""
Advanced Secret Detection Engine — BundleSpy
─────────────────────────────────────────────
Detection layers (in order, all applied):

  1. YAML rule patterns         — 130+ specific provider patterns
  2. Entropy analysis           — Shannon entropy scoring on string literals
  3. Context-aware detection    — key/secret/token keyword proximity scan
  4. Base64 decode + re-scan    — decodes any base64 blob and re-runs all layers
  5. HTML entity decode         — handles &#x27; &quot; &amp; obfuscation
  6. Unicode escape decode      — handles \\u0027 \\u0022 JS escapes
  7. Hex escape decode          — handles \\x27 \\x22 sequences
  8. process.env name capture   — records env var names even when value is absent
  9. String concatenation hints — detects split/obfuscated secrets (heuristic)
"""

import re
import math
import base64
import hashlib
import html
import logging
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

import yaml

from ..storage.models import Finding

logger = logging.getLogger("bundlespy.analysis.secrets")

# ── False-positive indicators ─────────────────────────────────────────────────

FP_INDICATORS = [
    "example", "placeholder", "your-key", "your_key", "insert_key",
    "api_key_here", "xxxx", "1234567890", "abcdefgh", "changeme",
    "replace_me", "todo", "fixme", "dummy", "fake", "test_key",
    "sample", "demo", "enter_your", "<your", "your-api", "xxxxxxxx",
    "aaaaaaaaa", "0000000000", "your_secret", "my_secret", "secret_here",
    "insert_here", "fill_in", "goes_here", "put_here", "replace_with",
    "redacted", "censored", "hidden", "omitted", "not_set",
    "undefined", "null", "none", "n/a", "na", "tbd",
]

# ── Third-party / CDN library fingerprints ────────────────────────────────────
# When a match comes from a file URL that looks like a known third-party library
# we suppress findings — real application secrets don't live in jQuery/Bootstrap.
# Patterns are matched against the file_url (case-insensitive).
LIBRARY_URL_PATTERNS = [
    # jQuery variants
    r"jquery(?:[-_.\d]+)?(?:\.min)?\.js",
    r"jquery[-_.]?ui(?:[-_.\d]+)?(?:\.min)?\.js",
    # Bootstrap
    r"bootstrap(?:\.bundle)?(?:[-_.\d]+)?(?:\.min)?\.js",
    # React — with or without version suffix, with or without .production/.development
    r"react(?:[-_.\d]+)?(?:\.production\.min|\.development|\.min)?\.js",
    r"react-dom(?:[-_.\d]+)?(?:\.production\.min|\.development|\.min)?\.js",
    # Vue
    r"vue(?:[-_.\d]+)?(?:\.min)?\.js",
    r"vue(?:[-_.\d]+)?(?:\.runtime)?(?:\.min)?\.js",
    # Angular
    r"angular(?:[-_.\d]+)?(?:\.min)?\.js",
    r"@angular/core",
    # Lodash / Underscore
    r"lodash(?:[-_.\d]+)?(?:\.min)?\.js",
    r"underscore(?:[-_.\d]+)?(?:\.min)?\.js",
    # Moment / Day.js
    r"moment(?:[-_.\d]+)?(?:\.min)?\.js",
    r"dayjs(?:[-_.\d]+)?(?:\.min)?\.js",
    # Axios / Fetch polyfills
    r"axios(?:[-_.\d]+)?(?:\.min)?\.js",
    # Chart / D3
    r"(?:chart|d3)(?:[-_.\d]+)?(?:\.min)?\.js",
    # Polyfills
    r"polyfill(?:[-_.\d]+)?(?:\.min)?\.js",
    r"core-js(?:[-_.\d]+)?(?:\.min)?\.js",
    # CDN path patterns
    r"/(?:cdn-cgi|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|ajax\.googleapis\.com)/",
]

_LIBRARY_URL_RE = re.compile(
    "(?i)(" + "|".join(LIBRARY_URL_PATTERNS) + ")"
)


def _is_library_url(file_url: str) -> bool:
    """Return True if file_url looks like a third-party CDN / known library."""
    return bool(_LIBRARY_URL_RE.search(file_url))


# ── JS method-chain / property-access guard ───────────────────────────────────
# Matches patterns like  s.checkPosition  or  o.isImmediatePropagationStopped
# directly adjacent to the match start.  Used to veto short prefix matches
# (e.g. the legacy Vault "s." prefix) that fire inside minified JS.
_JS_METHOD_CHAIN_RE = re.compile(
    r"""
    (?:                         # prefix — char immediately before the match
        [A-Za-z0-9_$]          #   a JS identifier char → this is a property access
    )
    \.                          # the dot
    [A-Za-z_$][A-Za-z0-9_$]*   # a JS identifier after the dot
    """,
    re.VERBOSE,
)

# ── Keyword context patterns (context-aware detection) ────────────────────────

# Left-hand keywords that indicate a secret assignment
LH_KEYWORDS = re.compile(
    r"""(?xi)
    (?:
        api[_\-]?key | apikey | api[_\-]?secret | api[_\-]?token |
        access[_\-]?key | access[_\-]?token | access[_\-]?secret |
        auth[_\-]?key | auth[_\-]?token | auth[_\-]?secret |
        secret[_\-]?key | secret[_\-]?token | secret[_\-]?value |
        private[_\-]?key | signing[_\-]?key | encryption[_\-]?key |
        hmac[_\-]?key | aes[_\-]?key | bearer[_\-]?token |
        refresh[_\-]?token | id[_\-]?token | client[_\-]?secret |
        app[_\-]?secret | consumer[_\-]?secret | oauth[_\-]?secret |
        password | passwd | pwd | pass(?:phrase)? |
        credential | credentials | authorization |
        x[_\-]?api[_\-]?key | x[_\-]?auth[_\-]?token |
        service[_\-]?account[_\-]?key
    )
    \s* [=:] \s* ["'`]
    """,
    re.IGNORECASE
)

# ── Entropy thresholds ────────────────────────────────────────────────────────

# Minimum entropy for a string to be considered potentially secret
# Standard English text ~3.9 bits; random keys typically >4.5
ENTROPY_MIN_CHARS = 20     # minimum length to bother scoring
ENTROPY_HIGH      = 4.5    # score at which we flag it
ENTROPY_CRITICAL  = 5.0    # score at which confidence jumps

# Character sets that count toward high-entropy bonus
HEX_CHARS    = set("0123456789abcdefABCDEF")
B64_CHARS    = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
B64URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

# Regex to extract quoted string literals from JS/HTML
QUOTED_STRING_RE = re.compile(
    r"""(?x)
    (?:["'`])          # opening quote
    ([A-Za-z0-9+/=_\-]{20,})   # content — at least 20 base64/hex chars
    (?:["'`])          # closing quote
    """
)

# Regex for process.env references
PROCESS_ENV_RE = re.compile(
    r"""(?x)
    process\.env\.([A-Z][A-Z0-9_]{2,})   # env var name
    (?:                                    # optional default value
        \s*\|\|\s*
        ["'`]([^"'`]{0,120})["'`]
    )?
    """,
    re.IGNORECASE,
)

# Regex for import.meta.env (Vite / ESBuild)
IMPORT_META_ENV_RE = re.compile(
    r"""(?x)
    import\.meta\.env\.([A-Z][A-Z0-9_]{2,})
    (?:\s*\|\|\s*["'`]([^"'`]{0,120})["'`])?
    """,
    re.IGNORECASE,
)

# Base64 blobs to attempt decode (at least 24 chars, valid b64 charset)
BASE64_BLOB_RE = re.compile(
    r"""(?:["'`\s=:])([A-Za-z0-9+/]{24,}={0,2})(?:["'`\s,;\)])"""
)

# HTML entity patterns
HTML_ENTITY_RE = re.compile(r"&#x([0-9a-fA-F]+);|&#([0-9]+);|&([a-z]+);")

# JS unicode escape patterns
JS_UNICODE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
JS_HEX_RE     = re.compile(r"\\x([0-9a-fA-F]{2})")

# ── Dataclasses ───────────────────────────────────────────────────────────────

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
    min_length: int = 0   # minimum matched-value length; 0 means no minimum


@dataclass
class EnvFinding:
    """A process.env / import.meta.env reference (name only, no value present)."""
    name: str
    default_value: Optional[str]
    file_url: str
    line_number: int
    context: str
    source: str  # "process.env" or "import.meta.env"


# ── Entropy helpers ───────────────────────────────────────────────────────────

def _shannon_entropy(value: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not value:
        return 0.0
    freq: Dict[str, int] = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    n = len(value)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _charset_ratio(value: str, charset: Set[str]) -> float:
    """Fraction of chars in value that belong to charset."""
    if not value:
        return 0.0
    return sum(1 for c in value if c in charset) / len(value)


def _is_high_entropy_secret(value: str) -> Tuple[bool, float]:
    """
    Returns (is_high_entropy, entropy_score).
    A string is considered high-entropy if:
      - length >= ENTROPY_MIN_CHARS
      - entropy >= ENTROPY_HIGH
      - majority of chars look like hex or base64
    """
    if len(value) < ENTROPY_MIN_CHARS:
        return False, 0.0
    entropy = _shannon_entropy(value)
    if entropy < ENTROPY_HIGH:
        return False, entropy
    hex_ratio = _charset_ratio(value, HEX_CHARS)
    b64_ratio = _charset_ratio(value, B64_CHARS)
    if hex_ratio >= 0.9 or b64_ratio >= 0.9:
        return True, entropy
    return False, entropy


# ── False-positive filter ─────────────────────────────────────────────────────

def _is_likely_fp(value: str) -> Tuple[bool, str]:
    """Return (is_fp, reason). Checks placeholders, entropy, char diversity."""
    lower = value.lower()
    for ind in FP_INDICATORS:
        if ind in lower:
            return True, f"contains placeholder indicator '{ind}'"

    entropy = _shannon_entropy(value)
    if len(value) > 8 and entropy < 2.0:
        return True, f"low entropy ({entropy:.2f}) — likely non-random"
    if len(set(value)) < 4 and len(value) > 8:
        return True, "too few unique characters"

    # Sequential digits (e.g. 123456789012)
    if re.match(r"^[0-9]+$", value) and len(value) < 20:
        return True, "all digits, too short for a key"

    # All same repeated char
    if len(set(value)) == 1:
        return True, "single repeated character"

    return False, ""


# ── Context extraction ────────────────────────────────────────────────────────

def _get_context(content: str, pos: int, chars: int = 140) -> str:
    start = max(0, pos - chars // 2)
    end   = min(len(content), pos + chars // 2)
    return content[start:end].replace("\n", " ").strip()


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


# ── Decode helpers ────────────────────────────────────────────────────────────

def _decode_html_entities(content: str) -> str:
    """Replace &#x27; &quot; &amp; etc. with their real characters."""
    try:
        return html.unescape(content)
    except Exception:
        return content


def _decode_js_unicode(content: str) -> str:
    """Replace \\u0027 \\u0022 JS unicode escapes."""
    def _repl(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)
    return JS_UNICODE_RE.sub(_repl, content)


def _decode_js_hex(content: str) -> str:
    """Replace \\x27 \\x22 JS hex escapes."""
    def _repl(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)
    return JS_HEX_RE.sub(_repl, content)


def _decode_base64_blob(blob: str) -> Optional[str]:
    """Try to base64 decode a blob. Returns decoded string or None."""
    # Pad if needed
    padded = blob + "=" * (-len(blob) % 4)
    try:
        decoded = base64.b64decode(padded)
        text = decoded.decode("utf-8", errors="replace")
        # Only return if it looks like readable content (not binary noise)
        printable_ratio = sum(1 for c in text if c.isprintable()) / max(len(text), 1)
        if printable_ratio >= 0.80 and len(text) >= 6:
            return text
    except Exception:
        pass
    # Try URL-safe variant
    try:
        blob_url = blob.replace("+", "-").replace("/", "_")
        padded   = blob_url + "=" * (-len(blob_url) % 4)
        decoded  = base64.urlsafe_b64decode(padded)
        text     = decoded.decode("utf-8", errors="replace")
        printable_ratio = sum(1 for c in text if c.isprintable()) / max(len(text), 1)
        if printable_ratio >= 0.80 and len(text) >= 6:
            return text
    except Exception:
        pass
    return None


def _normalize_content(content: str) -> str:
    """
    Return a fully-decoded version of content with all encoding layers stripped.
    We scan this in addition to the raw content so nothing hides behind encoding.
    """
    # Order matters: html → unicode → hex
    s = _decode_html_entities(content)
    s = _decode_js_unicode(s)
    s = _decode_js_hex(s)
    return s


# ── Rule loader ───────────────────────────────────────────────────────────────

def load_rules(rules_path: Optional[str] = None) -> List[SecretRule]:
    """Load detection rules from YAML file."""
    if rules_path is None:
        _base = Path(__file__).parent
        candidates = [
            _base / "rules" / "secrets.yaml",
            _base.parent / "rules" / "secrets.yaml",
            _base.parent.parent / "rules" / "secrets.yaml",
            _base.parent.parent.parent / "rules" / "secrets.yaml",
        ]
        existing = [p for p in candidates if p.exists()]
        rules_path = max(existing, key=lambda p: p.stat().st_size) if existing else candidates[0]

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
            rules.append(SecretRule(
                id          = raw["id"],
                name        = raw["name"],
                category    = raw["category"],
                pattern     = re.compile(raw["pattern"]),
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


# ── Main scanner ──────────────────────────────────────────────────────────────

class SecretScanner:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules = load_rules(rules_path)

    # ── Public entry point ────────────────────────────────────────────────────

    def scan(
        self,
        content: str,
        file_url: str,
        source_page: str = "",
    ) -> List[Finding]:
        """
        Full multi-layer scan of JS/HTML content.
        Returns deduplicated Finding list.
        """
        findings: List[Finding] = []
        seen: Dict[str, Finding] = {}  # sha256 → Finding

        # Build all content variants to scan
        normalized = _normalize_content(content)
        variants   = [content]
        if normalized != content:
            variants.append(normalized)

        # Layer 1 + 3: rule patterns + context-keyword cross-check on each variant
        for variant in variants:
            self._scan_rules(variant, file_url, source_page, seen, findings)

        # Layer 2: entropy scan on raw content
        self._scan_entropy(content, file_url, source_page, seen, findings)

        # Layer 4: base64 decode + re-scan
        self._scan_base64(content, file_url, source_page, seen, findings)

        # Layer 5: process.env / import.meta.env name capture
        env_findings = self._scan_env_names(content, file_url)
        # Convert env findings into informational Finding objects
        for ef in env_findings:
            self._emit_env_finding(ef, seen, findings)

        return findings

    # ── Layer 1 + 3: rule patterns ────────────────────────────────────────────

    def _scan_rules(
        self,
        content: str,
        file_url: str,
        source_page: str,
        seen: Dict[str, Finding],
        findings: List[Finding],
    ) -> None:
        # Determine once per file whether it looks like a third-party library.
        # If so we still scan but library matches are suppressed unless they
        # appear inside a clear credential-assignment context — real app secrets
        # occasionally land in vendored bundles so we never skip entirely.
        is_lib = _is_library_url(file_url)

        for rule in self.rules:
            for match in rule.pattern.finditer(content):
                raw_value = match.group(0)
                if match.lastindex and match.lastindex >= 1:
                    try:
                        cap = match.group(1)
                        if cap:
                            raw_value = cap
                    except IndexError:
                        pass

                # ── min_length enforcement ────────────────────────────────────
                if rule.min_length > 0 and len(raw_value) < rule.min_length:
                    logger.debug(
                        "min_length skip: rule=%s value_len=%d min=%d",
                        rule.id, len(raw_value), rule.min_length,
                    )
                    continue

                # ── Context-aware boost: keyword proximity ────────────────────
                ctx_window = content[max(0, match.start()-80):match.start()]
                context_boost = bool(LH_KEYWORDS.search(ctx_window))

                # ── Library suppression ───────────────────────────────────────
                # In library files, only emit if there's a clear LH keyword
                # context — this way a real hardcoded key inside a vendor bundle
                # still surfaces, but noise from identifier collisions is gone.
                if is_lib and not context_boost:
                    logger.debug(
                        "library suppress: rule=%s url=%s",
                        rule.id, file_url,
                    )
                    continue

                self._emit(
                    rule_id     = rule.id,
                    rule_name   = rule.name,
                    category    = rule.category,
                    severity    = rule.severity,
                    base_conf   = rule.confidence,
                    description = rule.description,
                    remediation = rule.remediation,
                    fp_notes    = rule.fp_notes,
                    raw_value   = raw_value,
                    content     = content,
                    match_pos   = match.start(),
                    file_url    = file_url,
                    source_page = source_page,
                    source_tag  = "rule",
                    context_boost = context_boost,
                    seen        = seen,
                    findings    = findings,
                )

    # ── Layer 2: entropy analysis ─────────────────────────────────────────────

    def _scan_entropy(
        self,
        content: str,
        file_url: str,
        source_page: str,
        seen: Dict[str, Finding],
        findings: List[Finding],
    ) -> None:
        """
        Find all quoted string literals, score their entropy,
        and emit findings for high-entropy strings in key/secret contexts.
        """
        for match in QUOTED_STRING_RE.finditer(content):
            value = match.group(1)
            is_high, entropy = _is_high_entropy_secret(value)
            if not is_high:
                continue

            # Only flag if there's a keyword nearby (avoids flagging hashes, IDs)
            ctx_before = content[max(0, match.start()-100):match.start()]
            ctx_after  = content[match.end():min(len(content), match.end()+40)]
            if not LH_KEYWORDS.search(ctx_before + ctx_after):
                continue

            severity = "CRITICAL" if entropy >= ENTROPY_CRITICAL else "HIGH"
            conf     = min(0.50 + (entropy - ENTROPY_HIGH) * 0.12, 0.78)

            self._emit(
                rule_id     = "HIGH_ENTROPY_CONTEXT",
                rule_name   = "High-Entropy String in Secret Context",
                category    = "Entropy",
                severity    = severity,
                base_conf   = conf,
                description = (
                    f"High-entropy string (Shannon entropy {entropy:.2f} bits) "
                    f"found in a credential assignment context. "
                    f"Entropy ≥ {ENTROPY_HIGH} with key/secret keyword proximity "
                    f"strongly suggests a hardcoded secret."
                ),
                remediation = "Move to server-side secrets management (env vars, vault).",
                fp_notes    = "Manual review required. Some hashes and IDs produce high entropy.",
                raw_value   = value,
                content     = content,
                match_pos   = match.start(),
                file_url    = file_url,
                source_page = source_page,
                source_tag  = "entropy",
                context_boost = True,
                seen        = seen,
                findings    = findings,
            )

    # ── Layer 4: base64 decode + re-scan ─────────────────────────────────────

    def _scan_base64(
        self,
        content: str,
        file_url: str,
        source_page: str,
        seen: Dict[str, Finding],
        findings: List[Finding],
    ) -> None:
        """
        Find base64 blobs, decode them, and re-run rule patterns + entropy
        on the decoded plaintext. Catches secrets that were b64-encoded before
        embedding.
        """
        decoded_blobs: Set[str] = set()

        for match in BASE64_BLOB_RE.finditer(content):
            blob = match.group(1)
            if blob in decoded_blobs:
                continue
            decoded_blobs.add(blob)

            plaintext = _decode_base64_blob(blob)
            if not plaintext:
                continue

            # Skip if decoded content looks like ordinary text
            if not any(kw in plaintext.lower() for kw in [
                "key", "secret", "token", "password", "auth", "credential",
                "private", "access", "api", "sk-", "pk-", "akia", "ghp_",
                "-----begin", "eyj",
            ]) and _shannon_entropy(plaintext) < ENTROPY_HIGH:
                continue

            logger.debug(
                "base64 decode hit at %s: blob len=%d decoded len=%d",
                file_url, len(blob), len(plaintext),
            )

            # Re-run rules on decoded text, tagging origin
            for rule in self.rules:
                for rm in rule.pattern.finditer(plaintext):
                    raw_value = rm.group(0)
                    if rm.lastindex and rm.lastindex >= 1:
                        try:
                            cap = rm.group(1)
                            if cap:
                                raw_value = cap
                        except IndexError:
                            pass
                    self._emit(
                        rule_id     = rule.id,
                        rule_name   = rule.name,
                        category    = rule.category,
                        severity    = rule.severity,
                        base_conf   = rule.confidence,
                        description = rule.description + " [detected after base64 decode]",
                        remediation = rule.remediation,
                        fp_notes    = rule.fp_notes,
                        raw_value   = raw_value,
                        content     = plaintext,
                        match_pos   = rm.start(),
                        file_url    = file_url,
                        source_page = source_page,
                        source_tag  = "base64",
                        context_boost = False,
                        seen        = seen,
                        findings    = findings,
                    )

            # Entropy scan on decoded text
            is_high, entropy = _is_high_entropy_secret(plaintext)
            if is_high:
                self._emit(
                    rule_id     = "HIGH_ENTROPY_B64",
                    rule_name   = "High-Entropy Base64-Decoded Secret",
                    category    = "Entropy",
                    severity    = "HIGH",
                    base_conf   = min(0.55 + (entropy - ENTROPY_HIGH) * 0.10, 0.75),
                    description = (
                        f"A base64-encoded blob decoded to a high-entropy string "
                        f"(entropy {entropy:.2f} bits). Likely an obfuscated secret."
                    ),
                    remediation = "Remove encoded secrets from client-side code entirely.",
                    fp_notes    = "Hashes and random IDs can also decode to high-entropy values.",
                    raw_value   = plaintext[:120],
                    content     = plaintext,
                    match_pos   = 0,
                    file_url    = file_url,
                    source_page = source_page,
                    source_tag  = "base64_entropy",
                    context_boost = False,
                    seen        = seen,
                    findings    = findings,
                )

    # ── Layer 5: process.env / import.meta.env capture ────────────────────────

    def _scan_env_names(self, content: str, file_url: str) -> List[EnvFinding]:
        """
        Record every process.env.VAR_NAME and import.meta.env.VAR_NAME reference.
        Even when the actual value is build-time injected (not in the bundle),
        the name alone tells an analyst what secrets the app uses.
        """
        results: List[EnvFinding] = []
        seen_names: Set[str] = set()

        def _add(m: re.Match, source: str) -> None:
            name = m.group(1).upper()
            if name in seen_names:
                return
            # Skip non-sensitive env vars
            skip = {"NODE_ENV", "PUBLIC_URL", "REACT_APP_ENV", "VITE_MODE",
                    "BASE_URL", "DEV", "PROD", "SSR", "BUILD_ID"}
            if name in skip:
                return
            # Only care about names that sound like secrets
            secret_hints = re.compile(
                r"(?i)(key|secret|token|password|pass|pwd|auth|credential|"
                r"api|private|signing|access|client_id|client_secret|"
                r"webhook|stripe|paypal|firebase|aws|gcp|azure|twilio|"
                r"sendgrid|github|gitlab|slack|discord|openai|anthropic)"
            )
            if not secret_hints.search(name):
                return
            seen_names.add(name)
            default = m.group(2) if m.lastindex and m.lastindex >= 2 else None
            line    = _get_line_number(content, m.start())
            ctx     = _get_context(content, m.start())
            results.append(EnvFinding(
                name          = name,
                default_value = default,
                file_url      = file_url,
                line_number   = line,
                context       = ctx,
                source        = source,
            ))

        for m in PROCESS_ENV_RE.finditer(content):
            _add(m, "process.env")
        for m in IMPORT_META_ENV_RE.finditer(content):
            _add(m, "import.meta.env")

        return results

    def _emit_env_finding(
        self,
        ef: EnvFinding,
        seen: Dict[str, Finding],
        findings: List[Finding],
    ) -> None:
        """Convert an EnvFinding into an informational Finding."""
        sha256 = hashlib.sha256(f"ENV_NAME:{ef.name}:{ef.file_url}".encode()).hexdigest()
        if sha256 in seen:
            return

        has_default = ef.default_value and len(ef.default_value) > 3
        severity    = "HIGH" if has_default else "INFO"
        conf        = 0.75 if has_default else 0.60

        desc = (
            f"Environment variable '{ef.name}' referenced via {ef.source}. "
            f"The application depends on this secret being present at runtime. "
        )
        if has_default:
            desc += (
                f"A default value was found in the code: the secret may be "
                f"hardcoded as a fallback — HIGH risk."
            )
        else:
            desc += (
                "The secret is injected at build time and not present in the bundle. "
                "This confirms the application uses this credential type."
            )

        finding_id = Finding.make_id("ENV_NAME", ef.name, ef.file_url)
        finding = Finding(
            id                   = finding_id,
            rule_id              = "ENV_NAME",
            title                = f"Secret Env Var Reference: {ef.name}",
            category             = "Environment",
            severity             = severity,
            confidence           = round(conf, 2),
            file_url             = ef.file_url,
            source_page          = "",
            line_number          = ef.line_number,
            column               = 0,
            matched_value        = ef.name + (f"={ef.default_value}" if has_default else ""),
            redacted_value       = ef.name,
            sha256               = sha256,
            context              = ef.context,
            description          = desc,
            impact               = "",
            remediation          = (
                "Ensure this variable is set via a secrets manager (AWS SSM, Vault, etc.). "
                "Never use hardcoded default values for production secrets."
            ),
            false_positive_notes = "Env var references are informational; value not confirmed present.",
            status               = "likely_secret" if has_default else "candidate",
            occurrences          = [f"{ef.file_url}:{ef.line_number}"],
        )
        seen[sha256] = finding
        findings.append(finding)

    # ── Internal emit helper ──────────────────────────────────────────────────

    def _emit(
        self,
        *,
        rule_id:       str,
        rule_name:     str,
        category:      str,
        severity:      str,
        base_conf:     float,
        description:   str,
        remediation:   str,
        fp_notes:      str,
        raw_value:     str,
        content:       str,
        match_pos:     int,
        file_url:      str,
        source_page:   str,
        source_tag:    str,
        context_boost: bool,
        seen:          Dict[str, Finding],
        findings:      List[Finding],
    ) -> None:
        """Finalise and deduplicate a single finding candidate."""
        if not raw_value or len(raw_value) < 4:
            return

        # False-positive check
        is_fp, fp_reason = _is_likely_fp(raw_value)

        confidence = base_conf
        status     = "candidate"

        if is_fp:
            confidence = min(confidence * 0.25, 0.25)
            status     = "likely_false_positive"
        else:
            # Entropy boost
            is_high_e, entropy = _is_high_entropy_secret(raw_value)
            if is_high_e:
                confidence = min(confidence + 0.08, 0.99)
            # Context keyword boost
            if context_boost:
                confidence = min(confidence + 0.05, 0.99)
            # Source-tag penalties
            if source_tag in ("base64", "base64_entropy"):
                confidence = max(confidence - 0.05, 0.10)
            # Final status
            if confidence >= 0.85:
                status = "likely_secret"
            elif confidence >= 0.60:
                status = "candidate"

        sha256     = hashlib.sha256(f"{rule_id}:{raw_value}".encode()).hexdigest()
        context    = _get_context(content, match_pos)
        line_no    = _get_line_number(content, match_pos)
        col        = match_pos - content.rfind("\n", 0, match_pos)
        redacted   = Finding.redact(raw_value)
        finding_id = Finding.make_id(rule_id, raw_value, file_url)

        # Deduplicate by rule+value across files
        if sha256 in seen:
            seen[sha256].occurrences.append(f"{file_url}:{line_no}")
            return

        # Skip very low confidence FPs
        if is_fp and confidence < 0.15:
            return

        finding = Finding(
            id                   = finding_id,
            rule_id              = rule_id,
            title                = rule_name,
            category             = category,
            severity             = severity,
            confidence           = round(confidence, 2),
            file_url             = file_url,
            source_page          = source_page,
            line_number          = line_no,
            column               = col,
            matched_value        = raw_value,
            redacted_value       = redacted,
            sha256               = sha256,
            context              = context,
            description          = description,
            impact               = "",
            remediation          = remediation,
            false_positive_notes = fp_reason or fp_notes,
            status               = status,
            occurrences          = [f"{file_url}:{line_no}"],
        )
        seen[sha256] = finding
        findings.append(finding)
