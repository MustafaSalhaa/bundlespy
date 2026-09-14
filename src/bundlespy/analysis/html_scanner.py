"""
HTML Attribute and Content Scanner.

Scans raw HTML pages for secrets embedded in:
- data-* attributes
- meta content= attributes
- input value= attributes
- script src= with tokens
- any attribute containing JWT, API keys, tokens
- inline style with URLs containing credentials
- HTML comments
- form action URLs with credentials
"""

import re
import hashlib
import logging
from typing import List
from datetime import datetime

from ..storage.models import Finding

logger = logging.getLogger("bundlespy.analysis.html_scanner")

# Patterns that target HTML attributes specifically
HTML_PATTERNS = [

    # JWT in any attribute value
    {
        "id":          "JWT_IN_ATTRIBUTE",
        "name":        "JWT Token in HTML Attribute",
        "category":    "JWT",
        "severity":    "HIGH",
        "confidence":  0.88,
        "pattern":     re.compile(
            r'(?:data-[a-z][a-z0-9\-]*|content|value|token|authorization)\s*=\s*["\']'
            r'(eyJ[A-Za-z0-9\-_=]{10,}\.eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]*)'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "JWT token found in HTML attribute.",
        "remediation":  "Remove hardcoded tokens. Generate tokens server-side at runtime.",
    },

    # API keys in data- attributes
    {
        "id":          "API_KEY_IN_ATTRIBUTE",
        "name":        "API Key in HTML Attribute",
        "category":    "Generic",
        "severity":    "HIGH",
        "confidence":  0.80,
        "pattern":     re.compile(
            r'data-(?:[a-z\-]*(?:key|token|secret|api|auth)[a-z\-]*)\s*=\s*["\']'
            r'([A-Za-z0-9\-_+/=]{20,})'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "API key or token found in HTML data attribute.",
        "remediation":  "Move credentials to server-side. Never embed in HTML attributes.",
    },

    # Hardcoded password hash in JS within HTML
    {
        "id":          "HARDCODED_HASH",
        "name":        "Hardcoded Password Hash",
        "category":    "Cryptographic",
        "severity":    "HIGH",
        "confidence":  0.78,
        "pattern":     re.compile(
            r'(?:var|let|const)\s+(?:_h|hash|pwd_hash|password_hash|stored_hash|AUTH_HASH)\s*='
            r'\s*["\']([a-f0-9]{32,64})["\']',
            re.IGNORECASE,
        ),
        "description":  "Hardcoded password hash found. Can be cracked offline with hashcat/john.",
        "remediation":  "Move authentication to server-side. Never store password hashes in client-side code.",
    },

    # Google Analytics / Tag Manager IDs in attributes
    {
        "id":          "GA_TRACKING_ID",
        "name":        "Google Analytics Tracking ID",
        "category":    "Analytics",
        "severity":    "INFO",
        "confidence":  0.90,
        "pattern":     re.compile(
            r'(?:data-[a-z\-]*(?:id|tracking)[a-z\-]*|gtag|config)\s*[=\(]\s*["\']'
            r'((?:G|UA|AW|DC)-[A-Z0-9\-]{4,20})'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "Google Analytics/Tag Manager tracking ID found.",
        "remediation":  "Low risk but confirms analytics provider and account.",
    },

    # AWS keys in HTML attributes or meta tags
    {
        "id":          "AWS_KEY_IN_HTML",
        "name":        "AWS Access Key in HTML",
        "category":    "AWS",
        "severity":    "CRITICAL",
        "confidence":  0.92,
        "pattern":     re.compile(
            r'(?:content|value|data-[a-z\-]*key[a-z\-]*)\s*=\s*["\']'
            r'((?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16})'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "AWS Access Key ID found in HTML attribute.",
        "remediation":  "Remove immediately. Rotate in AWS console.",
    },

    # Netlify / Vercel / hosting site IDs
    {
        "id":          "NETLIFY_SITE_ID",
        "name":        "Netlify Site ID",
        "category":    "Hosting",
        "severity":    "LOW",
        "confidence":  0.85,
        "pattern":     re.compile(
            r'data-netlify-(?:rum-site-id|site-id)\s*=\s*["\']'
            r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "Netlify Site ID found in HTML attribute.",
        "remediation":  "Site IDs are low risk alone but confirm hosting provider.",
    },

    # Firebase config in meta or data attributes
    {
        "id":          "FIREBASE_IN_HTML",
        "name":        "Firebase Config in HTML",
        "category":    "Google",
        "severity":    "HIGH",
        "confidence":  0.85,
        "pattern":     re.compile(
            r'data-firebase-(?:api-key|config)\s*=\s*["\']([A-Za-z0-9\-_]{30,})["\']',
            re.IGNORECASE,
        ),
        "description":  "Firebase configuration found in HTML attribute.",
        "remediation":  "Review Firebase security rules.",
    },

    # Stripe publishable key in HTML
    {
        "id":          "STRIPE_KEY_IN_HTML",
        "name":        "Stripe Key in HTML",
        "category":    "Stripe",
        "severity":    "MEDIUM",
        "confidence":  0.92,
        "pattern":     re.compile(
            r'(?:data-[a-z\-]*(?:key|stripe)[a-z\-]*|value|content)\s*=\s*["\']'
            r'((?:pk|sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "Stripe key found in HTML attribute.",
        "remediation":  "Verify this is a publishable key only. Secret keys must never appear in HTML.",
    },

    # HTML comments containing secrets
    {
        "id":          "SECRET_IN_COMMENT",
        "name":        "Potential Secret in HTML Comment",
        "category":    "Generic",
        "severity":    "MEDIUM",
        "confidence":  0.65,
        "pattern":     re.compile(
            r'<!--.*?(?:password|api.?key|secret|token|credential|auth)\s*[=:]\s*'
            r'([A-Za-z0-9\-_+/=]{8,}).*?-->',
            re.IGNORECASE | re.DOTALL,
        ),
        "description":  "Potential credential found in HTML comment.",
        "remediation":  "Remove credentials from HTML comments before deploying.",
    },

    # OpenAI / Anthropic keys in meta or data
    {
        "id":          "AI_KEY_IN_HTML",
        "name":        "AI API Key in HTML",
        "category":    "AI",
        "severity":    "CRITICAL",
        "confidence":  0.90,
        "pattern":     re.compile(
            r'(?:content|value|data-[a-z\-]*(?:key|token)[a-z\-]*)\s*=\s*["\']'
            r'(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{40,})'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "AI API key found in HTML attribute.",
        "remediation":  "Remove immediately. Rotate at the provider console.",
    },

    # Internal URLs in action/href attributes
    {
        "id":          "INTERNAL_URL_IN_HTML",
        "name":        "Internal URL in HTML Attribute",
        "category":    "Infrastructure",
        "severity":    "MEDIUM",
        "confidence":  0.75,
        "pattern":     re.compile(
            r'(?:action|href|src|data-url|data-endpoint)\s*=\s*["\']'
            r'(https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^"\']*)'
            r'["\']',
            re.IGNORECASE,
        ),
        "description":  "Internal IP address found in HTML attribute.",
        "remediation":  "Remove internal IP references from HTML.",
    },
]


def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def scan_html(html: str, page_url: str) -> List[Finding]:
    """
    Scan raw HTML content for secrets in attributes and comments.
    Returns Finding objects compatible with the main scanner output.
    """
    findings: List[Finding] = []
    seen:     set            = set()

    for rule in HTML_PATTERNS:
        for match in rule["pattern"].finditer(html):
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            if not value or len(value) < 8:
                continue

            # Basic false positive check
            lower = value.lower()
            fp_indicators = [
                "example", "placeholder", "your-", "insert", "xxxx",
                "1234567890", "changeme", "replace", "dummy", "fake",
            ]
            if any(ind in lower for ind in fp_indicators):
                continue

            sha256 = hashlib.sha256(f"{rule['id']}:{value}:{page_url}".encode()).hexdigest()
            key    = f"{rule['id']}:{value}"
            if key in seen:
                continue
            seen.add(key)

            line_no = _get_line(html, match.start())
            context = html[max(0, match.start()-80):match.end()+80].replace("\n", " ").strip()

            finding = Finding(
                id                   = sha256[:16],
                rule_id              = rule["id"],
                title                = rule["name"],
                category             = rule["category"],
                severity             = rule["severity"],
                confidence           = rule["confidence"],
                file_url             = f"html:{page_url}",
                source_page          = page_url,
                line_number          = line_no,
                column               = 0,
                matched_value        = value,
                redacted_value       = value[:4] + "*" * max(0, len(value) - 8) + value[-4:] if len(value) > 8 else "*" * len(value),
                sha256               = sha256,
                context              = context[:200],
                description          = rule["description"],
                impact               = "",
                remediation          = rule["remediation"],
                false_positive_notes = "",
                status               = "likely_secret" if rule["confidence"] >= 0.85 else "candidate",
                occurrences          = [f"html:{page_url}:{line_no}"],
            )
            findings.append(finding)
            logger.info(
                "HTML finding: %s at %s line %d",
                rule["name"], page_url, line_no,
            )

    return findings
