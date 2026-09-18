"""
BundleSpy URL Normalizer — spec section 5.

Centralised URL normalization, decoding, comparison,
extraction from arbitrary text, and safe content decoding.
"""

import re
import logging
from typing import List, Optional
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    urlencode,
    parse_qsl,
    quote,
    unquote,
    unquote_plus,
)

logger = logging.getLogger("bundlespy.url_normalizer")

# Default ports that should be stripped
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Regex for URL extraction from arbitrary text
_URL_RE = re.compile(
    r'https?://[^\s"\'<>\]\[)(\\]+',
    re.IGNORECASE,
)

# Relative paths starting with / but not // (protocol-relative)
_REL_PATH_RE = re.compile(
    r'(?<![:\w])(/(?:[a-zA-Z0-9_.~!$&\'()*+,;=:@%-][a-zA-Z0-9_.~!$&\'()*+,;=:@/%-]*)?)',
)

# Schemes to always filter out from extracted URLs
_FILTER_SCHEMES = {"data", "blob", "javascript", "mailto", "tel", "vbscript"}


# ─────────────────────────────────────────────────────────────────────────────

def normalize_url(url: str, base: str = "") -> Optional[str]:
    """
    Normalize *url*, optionally resolved against *base*.

    Returns the canonical URL string, or None on any error.
    """
    try:
        if not url or not isinstance(url, str):
            return None

        url = url.strip()
        if not url:
            return None

        # Resolve relative URL against base
        if base:
            url = urljoin(base, url)

        parsed = urlparse(url)

        # Must have a recognised scheme
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return None

        # Lowercase host
        host = (parsed.hostname or "").lower()
        if not host:
            return None

        # Strip default ports
        port = parsed.port
        if port and _DEFAULT_PORTS.get(scheme) == port:
            port = None

        netloc = host
        if port:
            netloc = f"{host}:{port}"

        # Normalise path — resolve ../  ./  and collapse //
        path = parsed.path or "/"
        # Replace multiple consecutive slashes
        path = re.sub(r"//+", "/", path)
        # Resolve . and .. segments
        parts: List[str] = []
        for seg in path.split("/"):
            if seg == "..":
                if parts:
                    parts.pop()
            elif seg == ".":
                pass
            else:
                parts.append(seg)
        path = "/".join(parts) or "/"

        # Remove trailing slash unless it is the root
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Percent-encode non-ASCII characters in path
        try:
            path = quote(unquote(path), safe="/:@!$&'()*+,;=%-")
        except Exception:
            pass

        # Sort query params alphabetically
        query = ""
        if parsed.query:
            try:
                params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
                query = urlencode(params)
            except Exception:
                query = parsed.query

        # Strip fragment entirely
        fragment = ""

        return urlunparse((scheme, netloc, path, "", query, fragment))

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────

def decode_url(url: str) -> str:
    """
    Return the best human-readable decoded form of *url*.

    Handles:
    - Standard percent-encoding  (%2F, %2f, %20, …)
    - Plus-sign encoding in query strings (+  →  space)
    - Double encoding (%2520 → %20 → space)
    """
    if not url or not isinstance(url, str):
        return url or ""

    try:
        # First pass: decode double-encoded sequences (%25XX → %XX)
        partially = unquote(url)
        # Second pass: fully decode the result
        fully = unquote_plus(partially)
        return fully
    except Exception:
        return url


# ─────────────────────────────────────────────────────────────────────────────

def is_same_resource(url1: str, url2: str) -> bool:
    """
    Return True if *url1* and *url2* refer to the same resource
    after normalization.

    Handles different query-param ordering, equivalent ports, etc.
    """
    n1 = normalize_url(url1)
    n2 = normalize_url(url2)
    if n1 is None or n2 is None:
        return False
    return n1 == n2


# ─────────────────────────────────────────────────────────────────────────────

def extract_urls_from_text(text: str, base: str = "") -> List[str]:
    """
    Extract and normalise URLs from arbitrary text (JS source, HTML, etc.).

    Matches:
    - Absolute  https?://…  URLs
    - Relative paths starting with /  (but not  // protocol-relative)

    Returns a deduplicated, normalised list.  Filters out data: and blob: URIs.
    """
    if not text or not isinstance(text, str):
        return []

    seen: set = set()
    result: List[str] = []

    def _accept(raw: str) -> None:
        # Strip trailing punctuation that is unlikely to be part of a URL
        raw = raw.rstrip(".,;:\"')}]>\\")
        if not raw:
            return

        # Filter disallowed schemes
        scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):.*', raw)
        if scheme_match:
            if scheme_match.group(1).lower() in _FILTER_SCHEMES:
                return

        normalized = normalize_url(raw, base=base)
        if not normalized:
            return
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    # Absolute URLs
    for m in _URL_RE.finditer(text):
        _accept(m.group(0))

    # Relative paths (only when a base is provided so they can be resolved)
    if base:
        for m in _REL_PATH_RE.finditer(text):
            candidate = m.group(1)
            # Skip if it looks like it was already captured as part of an absolute URL
            start = m.start()
            if start > 0 and text[start - 1] in (":", "/"):
                continue
            _accept(candidate)

    return result


# ─────────────────────────────────────────────────────────────────────────────

def safe_decode_content(raw: bytes, declared_charset: str = "") -> str:
    """
    Decode *raw* bytes to a string, never raising an exception.

    Strategy (in order):
    1. Declared charset from Content-Type header.
    2. chardet auto-detection (if chardet is installed).
    3. UTF-8 with errors=replace.
    4. latin-1 (always succeeds for any byte sequence).
    """
    if not raw:
        return ""

    # 1. Declared charset
    if declared_charset:
        try:
            return raw.decode(declared_charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            pass

    # 2. chardet
    try:
        import chardet  # type: ignore
        detected = chardet.detect(raw)
        enc = detected.get("encoding") if detected else None
        if enc:
            try:
                return raw.decode(enc, errors="replace")
            except (LookupError, UnicodeDecodeError):
                pass
    except ImportError:
        pass
    except Exception:
        pass

    # 3. UTF-8 with replacement
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        pass

    # 4. latin-1 — always works
    try:
        return raw.decode("latin-1", errors="replace")
    except Exception:
        return ""
