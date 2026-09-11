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
from dataclasses import dataclass
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
    "aaaaaaaaa", "0000000000",
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


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def load_rules(rules_path: Optional[str] = None) -> List[SecretRule]:
    """Load detection rules from YAML file."""
    if rules_path is None:
        # Look inside the installed package first
        pkg_rules = Path(__file__).parent / "rules" / "secrets.yaml"
        repo_rules = Path(__file__).parent.parent.parent / "rules" / "secrets.yaml"
        rules_path = pkg_rules if pkg_rules.exists() else repo_rules

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
            ))
        except re.error as e:
            logger.warning("Invalid regex in rule %s: %s", raw.get("id"), e)

    logger.info("Loaded %d secret detection rules", len(rules))
    return rules


class SecretScanner:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules = load_rules(rules_path)

    def scan(self, content: str, file_url: str, source_page: str = "") -> List[Finding]:
        """
        Scan JavaScript content for secrets.
        Returns a list of Finding objects, deduplicated by value+rule.
        """
        findings: List[Finding] = []
        seen: Dict[str, Finding] = {}  # sha256 -> Finding

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

        return findings
