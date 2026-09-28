"""
Baseline capture and differential comparison for all active tests.
"""
import hashlib
import re
from typing import Optional, Tuple
from .models import Baseline, TestObservation

_IGNORE_HEADERS = {"date", "x-request-id", "x-trace-id", "cf-ray", "x-amzn-requestid"}

def _normalize_body(body: str) -> str:
    """Strip dynamic tokens (CSRF, timestamps, nonces) for stable comparison."""
    # Remove common CSRF token patterns
    body = re.sub(r'["\']?csrf[_-]?token["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', 'CSRF_TOKEN', body, flags=re.I)
    # Remove UUIDs
    body = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', body, flags=re.I)
    # Remove timestamps
    body = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', body)
    return body

def _body_hash(body: str) -> str:
    return hashlib.sha256(_normalize_body(body).encode("utf-8", errors="replace")).hexdigest()[:16]

def _clean_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _IGNORE_HEADERS}

def capture_baseline(fetcher, url: str, method: str = "GET", body: dict = None) -> Optional[Baseline]:
    """
    Fetch a baseline response. Returns None if unreachable.
    """
    import time
    try:
        t0 = time.monotonic()
        result = fetcher.get(url)
        elapsed = (time.monotonic() - t0) * 1000
        if result is None:
            return None
        content, status, content_type, _ = result
        if content is None:
            content = ""
        return Baseline(
            status_code=status or 0,
            content_type=content_type or "",
            content_length=len(content),
            body_hash=_body_hash(content),
            headers={},
            timing_ms=elapsed,
            redirect_chain=[],
        )
    except Exception:
        return None

def capture_observation(fetcher, url: str, method: str = "GET") -> Optional[TestObservation]:
    """
    Fetch an observation after injecting a test payload.
    Returns None if unreachable.
    """
    import time
    try:
        t0 = time.monotonic()
        result = fetcher.get(url)
        elapsed = (time.monotonic() - t0) * 1000
        if result is None:
            return None
        content, status, content_type, _ = result
        if content is None:
            content = ""
        return TestObservation(
            status_code=status or 0,
            content_type=content_type or "",
            content_length=len(content),
            body_hash=_body_hash(content),
            body_excerpt=content[:500],
            headers={},
            timing_ms=elapsed,
            redirect_chain=[],
        )
    except Exception as e:
        return TestObservation(
            status_code=0, content_type="", content_length=0,
            body_hash="", body_excerpt="", error=str(e),
        )

def differential(baseline: Baseline, observation: TestObservation) -> dict:
    """
    Compute meaningful differences between baseline and observation.
    Returns a dict of signal name -> (baseline_value, observed_value).
    """
    signals = {}
    if baseline.status_code != observation.status_code:
        signals["status_code"] = (baseline.status_code, observation.status_code)
    size_delta = abs(observation.content_length - baseline.content_length)
    if size_delta > 50:   # ignore tiny whitespace differences
        signals["content_length"] = (baseline.content_length, observation.content_length)
    if baseline.body_hash != observation.body_hash:
        signals["body_changed"] = (baseline.body_hash, observation.body_hash)
    timing_delta = observation.timing_ms - baseline.timing_ms
    if timing_delta > 3000:   # 3s+ timing anomaly
        signals["timing_anomaly_ms"] = (baseline.timing_ms, observation.timing_ms)
    return signals
