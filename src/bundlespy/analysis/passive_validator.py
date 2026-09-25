"""
Stage 5: Passive Validator
══════════════════════════════════════════════════════════════════════════════

Performs lightweight, non-destructive HEAD/GET probes against the source URLs
of HIGH and CRITICAL findings to confirm:

  1. The JS file that contained the secret is still publicly reachable.
  2. The pattern (matched value prefix) is still present in the live response.

This answers the key validation question: "Is this still exploitable right now?"

Design constraints:
  - GET only on JS/source files (never on API endpoints — no state changes).
  - Respects scope, rate limits, and the existing safety.network allow-list.
  - Reads at most MAX_RESPONSE_BYTES per file.
  - Never logs or stores the actual secret value.
  - Populates finding.provenance in-place — callers see updated objects.
  - Returns a PassiveValidationReport for the terminal/JSON reporters.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

import requests
import urllib3

from ..storage.models import Finding, Provenance
from ..safety.network import validate_url
from ..utils.stealth import random_ua

urllib3.disable_warnings()
logger = logging.getLogger("bundlespy.analysis.passive_validator")

MAX_RESPONSE_BYTES = 512 * 1024   # 512 KB — enough for any JS file
PROBE_TIMEOUT      = 8             # seconds
VALIDATE_SEVERITIES = {"CRITICAL", "HIGH"}


# ── Per-probe result ──────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    """Outcome of one passive probe against a JS source file."""
    finding_id:    str
    rule_id:       str
    severity:      str
    source_url:    str           # The JS file URL probed (never the secret value)
    http_status:   int = 0
    pattern_found: bool = False  # Was the redacted prefix still present in the response?
    validation_status: str = "NOT_VALIDATED"  # CONFIRMED | UNREACHABLE | ERROR | NOT_VALIDATED
    error:         str = ""
    elapsed_ms:    int = 0

    def to_dict(self) -> dict:
        return {
            "finding_id":    self.finding_id,
            "rule_id":       self.rule_id,
            "severity":      self.severity,
            "source_url":    self.source_url,
            "http_status":   self.http_status,
            "pattern_found": self.pattern_found,
            "validation_status": self.validation_status,
            "error":         self.error,
            "elapsed_ms":    self.elapsed_ms,
        }


# ── Report ────────────────────────────────────────────────────────────────────

@dataclass
class PassiveValidationReport:
    """
    Aggregate result of passive validation for a scan.
    Surfaced in the terminal coverage section and JSON report.
    """
    probed:    int = 0
    confirmed: int = 0
    unreachable: int = 0
    not_validated: int = 0
    errors:    int = 0
    skipped:   int = 0    # Findings not in VALIDATE_SEVERITIES or out-of-scope
    probes:    List[ProbeResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "probed":     self.probed,
            "confirmed":  self.confirmed,
            "unreachable": self.unreachable,
            "not_validated": self.not_validated,
            "errors":     self.errors,
            "skipped":    self.skipped,
            "probes":     [p.to_dict() for p in self.probes],
        }


# ── Core probe logic ──────────────────────────────────────────────────────────

def _probe_source_url(
    url:      str,
    stealth:  bool  = False,
    timeout:  int   = PROBE_TIMEOUT,
) -> tuple[int, bytes, str]:
    """
    Fetch up to MAX_RESPONSE_BYTES from *url* using GET.
    Returns (http_status, body_bytes, error_string).
    Never raises — all exceptions are caught and returned as (0, b"", err).
    """
    headers = {
        "User-Agent": random_ua() if stealth else
                      "BundleSpy/1.0.0 (authorized security assessment)",
        "Accept": "*/*",
    }
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            stream=True,
        )
        body = b""
        for chunk in resp.iter_content(8192):
            body += chunk
            if len(body) >= MAX_RESPONSE_BYTES:
                break
        return resp.status_code, body, ""
    except requests.exceptions.Timeout:
        return 0, b"", "timeout"
    except requests.exceptions.ConnectionError as e:
        return 0, b"", f"connection error: {e}"
    except Exception as e:
        return 0, b"", str(e)


def _pattern_still_present(body: bytes, finding: Finding) -> bool:
    """
    Check whether the first N characters of the matched value are
    still present in the response body.

    We use the *first* 8 characters of the matched value as a probe
    pattern — enough to confirm the secret is in the file without
    logging or storing the full value.

    Returns False if the matched value is too short to probe safely.
    """
    value = getattr(finding, "matched_value", "") or ""
    if len(value) < 8:
        return False  # Too short to probe meaningfully
    prefix = value[:8].encode("utf-8", errors="replace")
    return prefix in body


def probe_finding(
    finding:  Finding,
    scope,
    stealth:  bool  = False,
    delay:    float = 0.3,
) -> ProbeResult:
    """
    Run a passive probe against the JS source file of one finding.

    Mutates finding.provenance in-place to reflect the probe result.
    Always returns a ProbeResult regardless of outcome.
    """
    probe = ProbeResult(
        finding_id = finding.id,
        rule_id    = finding.rule_id,
        severity   = finding.severity,
        source_url = finding.file_url,
    )

    # Build/retrieve provenance
    if finding.provenance is None:
        finding.provenance = Provenance.from_finding(finding)

    # Skip inline / synthetic URLs
    source_url = finding.file_url or ""
    skip_prefixes = ("inline:", "html:", "sourcemap://", "local://", "")
    if not source_url or any(source_url.startswith(pfx) for pfx in skip_prefixes if pfx):
        probe.validation_status = "NOT_VALIDATED"
        probe.error = "Inline or synthetic source — cannot probe"
        finding.provenance.validation_status = "NOT_VALIDATED"
        finding.provenance.skipped_reason    = probe.error
        return probe

    # Scope check
    if scope and not scope.in_scope(source_url):
        probe.validation_status = "NOT_VALIDATED"
        probe.error = "Source URL out of scope"
        finding.provenance.validation_status = "NOT_VALIDATED"
        finding.provenance.skipped_reason    = probe.error
        return probe

    # Safety check
    safe, reason = validate_url(source_url, check_dns=False)
    if not safe:
        probe.validation_status = "NOT_VALIDATED"
        probe.error = f"URL blocked by safety filter: {reason}"
        finding.provenance.validation_status = "NOT_VALIDATED"
        finding.provenance.skipped_reason    = probe.error
        return probe

    # Rate-limit delay
    if delay > 0:
        time.sleep(delay)

    t0 = time.monotonic()
    http_status, body, error = _probe_source_url(source_url, stealth=stealth)
    probe.elapsed_ms  = int((time.monotonic() - t0) * 1000)
    probe.http_status = http_status
    probe.error       = error

    if error:
        probe.validation_status = "ERROR"
    elif http_status == 0:
        probe.validation_status = "ERROR"
    elif http_status >= 400:
        probe.validation_status = "UNREACHABLE"
        probe.error = f"HTTP {http_status}"
    else:
        probe.pattern_found = _pattern_still_present(body, finding)
        probe.validation_status = "CONFIRMED" if probe.pattern_found else "UNREACHABLE"

    # Update provenance in-place
    finding.provenance.validation_status     = probe.validation_status
    finding.provenance.validation_http_status = probe.http_status
    finding.provenance.validation_error      = probe.error

    # Access level from HTTP status
    if http_status == 200:
        finding.provenance.access_level = "PUBLIC"
    elif http_status in (401, 403):
        finding.provenance.auth_required = True
        finding.provenance.access_level  = "AUTHENTICATED"

    logger.debug(
        "Probe %s [%s] → HTTP %d  pattern=%s  elapsed=%dms",
        finding.rule_id, finding.id[:8],
        probe.http_status, probe.pattern_found, probe.elapsed_ms,
    )
    return probe


# ── Batch runner ──────────────────────────────────────────────────────────────

def run_passive_validation(
    findings: List[Finding],
    scope,
    stealth:          bool  = False,
    rate:             float = 2.0,   # probes per second
    max_probes:       int   = 50,
    severities:       set   = None,
    delay:            float = None,  # explicit inter-probe delay (overrides rate)
) -> PassiveValidationReport:
    """
    Run passive validation against HIGH/CRITICAL findings.

    Mutates each qualifying finding's .provenance field in-place.
    Returns an aggregate PassiveValidationReport.

    Parameters
    ----------
    findings   : list of Finding objects from the scan
    scope      : ScopeEnforcer instance (or None to skip scope checks)
    stealth    : use randomised User-Agent
    rate       : maximum probes per second (default 2)
    max_probes : hard cap on total probes
    severities : which severities to probe (default CRITICAL + HIGH)
    """
    if severities is None:
        severities = VALIDATE_SEVERITIES

    report = PassiveValidationReport()
    delay  = delay if delay is not None else 1.0 / max(rate, 0.1)

    # Deduplicate by source URL — no need to re-probe the same JS file twice
    seen_urls: set = set()

    for finding in findings:
        sev = getattr(finding, "severity", "")
        if sev not in severities:
            report.skipped += 1
            continue

        if report.probed >= max_probes:
            report.skipped += 1
            continue

        source_url = finding.file_url or ""
        # Probe each source URL only once per scan — subsequent findings from
        # the same file inherit the result via their own provenance build.
        cache_key = source_url
        if cache_key in seen_urls and not source_url.startswith("inline:"):
            # Copy the probe result from the first finding with the same source
            _existing = next(
                (p for p in report.probes if p.source_url == source_url), None
            )
            if _existing and finding.provenance is None:
                finding.provenance = Provenance.from_finding(finding)
            if _existing:
                finding.provenance.validation_status      = _existing.validation_status
                finding.provenance.validation_http_status = _existing.http_status
                finding.provenance.validation_error       = _existing.error
                if _existing.http_status == 200:
                    finding.provenance.access_level = "PUBLIC"
                elif _existing.http_status in (401, 403):
                    finding.provenance.auth_required = True
                    finding.provenance.access_level  = "AUTHENTICATED"
            report.skipped += 1
            continue

        seen_urls.add(cache_key)
        probe = probe_finding(finding, scope, stealth=stealth, delay=delay)
        report.probes.append(probe)
        report.probed += 1

        vs = probe.validation_status
        if vs == "CONFIRMED":    report.confirmed   += 1
        elif vs == "UNREACHABLE": report.unreachable += 1
        elif vs == "ERROR":       report.errors      += 1
        else:                     report.not_validated += 1

    return report
