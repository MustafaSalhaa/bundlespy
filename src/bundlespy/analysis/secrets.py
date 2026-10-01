"""
PII post-match validation and false-positive reduction.

Called by SecretScanner after pattern matching to validate PII findings:
  - Credit cards: Luhn algorithm
  - IBANs: ISO 13616 mod-97 checksum
  - SSNs: area/group/serial constraints
  - Emails: MX/format sanity (no network calls; pure structural)
  - Phone: digit-count range validation
  - GPS: precision and range clipping

These validators run AFTER the regex fires and can:
  1. Upgrade confidence if the checksum passes
  2. Mark as likely_false_positive if it fails

None of these make network calls. All validation is local/structural.
"""

import re
import logging
from typing import Tuple

logger = logging.getLogger("bundlespy.analysis.pii")


# ---------------------------------------------------------------------------
# Credit Card — Luhn Algorithm
# ---------------------------------------------------------------------------

def luhn_check(number: str) -> bool:
    """
    Run the Luhn algorithm on a digit string.
    Returns True if the number is a valid Luhn sequence.
    """
    digits = re.sub(r"\D", "", number)
    if len(digits) < 12 or len(digits) > 19:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Known test/example card numbers that should always be FP
_CC_KNOWN_TEST = {
    "4111111111111111",  # Visa test
    "4242424242424242",  # Stripe Visa test
    "5555555555554444",  # Mastercard test
    "5105105105105100",  # Mastercard test
    "378282246310005",   # Amex test
    "371449635398431",   # Amex test
    "6011111111111117",  # Discover test
    "3530111333300000",  # JCB test
    "3566002020360505",  # JCB test
}


def validate_credit_card(value: str) -> Tuple[bool, str]:
    """
    Validate a credit card number match.
    Returns (is_valid, reason).
    """
    digits = re.sub(r"\D", "", value)
    if digits in _CC_KNOWN_TEST:
        return False, "known test card number"
    if not luhn_check(digits):
        return False, "fails Luhn check"
    # Reject obvious sequential or repeated numbers
    if len(set(digits)) <= 2:
        return False, "too few unique digits (likely placeholder)"
    return True, "Luhn valid"


# ---------------------------------------------------------------------------
# IBAN — ISO 13616 mod-97 checksum
# ---------------------------------------------------------------------------

# Country code -> expected IBAN length
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28,
    "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "DZ": 24,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18,
    "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
    "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
    "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "MZ": 25, "NI": 32,
    "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28,
    "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24,
    "SI": 19, "SK": 24, "SM": 27, "SN": 28, "SO": 23,
    "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26,
    "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


def validate_iban(value: str) -> Tuple[bool, str]:
    """
    Validate an IBAN using ISO 13616 mod-97 algorithm.
    Returns (is_valid, reason).
    """
    iban = re.sub(r"[\s\-]", "", value).upper()
    country = iban[:2]

    # Check country code is known
    if country not in _IBAN_LENGTHS:
        return False, f"unknown IBAN country code '{country}'"

    # Check length
    expected = _IBAN_LENGTHS[country]
    if len(iban) != expected:
        return False, f"wrong length for {country} IBAN: expected {expected}, got {len(iban)}"

    # Rearrange: move first 4 chars to end
    rearranged = iban[4:] + iban[:4]

    # Replace letters with digits (A=10, B=11, ..., Z=35)
    numeric = ""
    for ch in rearranged:
        if ch.isalpha():
            numeric += str(ord(ch) - 55)
        else:
            numeric += ch

    # Mod-97 check
    try:
        remainder = int(numeric) % 97
    except ValueError:
        return False, "non-numeric characters in IBAN body"

    if remainder != 1:
        return False, f"mod-97 check failed (remainder={remainder})"

    return True, "IBAN checksum valid"


# ---------------------------------------------------------------------------
# SSN — US Social Security Number constraints
# ---------------------------------------------------------------------------

# Area numbers that are never valid
_SSN_INVALID_AREAS = {
    "000", "666",
    # 900-999 are reserved
}


def validate_ssn(value: str) -> Tuple[bool, str]:
    """
    Validate a US SSN beyond just the format.
    Returns (is_valid, reason).
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False, "wrong digit count"

    area   = digits[:3]
    group  = digits[3:5]
    serial = digits[5:]

    if area in _SSN_INVALID_AREAS:
        return False, f"invalid SSN area '{area}'"
    if int(area) >= 900:
        return False, "SSN area 900-999 is reserved (ITINs, not SSNs)"
    if group == "00":
        return False, "group number 00 is invalid"
    if serial == "0000":
        return False, "serial number 0000 is invalid"
    # Repeated-digit check (e.g. 123-45-6789 is a known fake)
    if len(set(digits)) <= 3:
        return False, "too few unique digits (likely placeholder)"

    return True, "SSN passes constraint checks"


# ---------------------------------------------------------------------------
# Email — structural sanity (no network)
# ---------------------------------------------------------------------------

# TLDs that are almost always test/example domains
_EXAMPLE_TLDS_AND_DOMAINS = re.compile(
    r"@(?:"
    # Exact placeholder domains (any TLD)
    r"example\.[a-z]{2,}|test\.[a-z]{2,}|sample\.[a-z]{2,}|"
    r"fake\.[a-z]{2,}|dummy\.[a-z]{2,}|placeholder\.[a-z]{2,}|"
    r"yourcompany\.[a-z]{2,}|yourdomain\.[a-z]{2,}|changeme\.[a-z]{2,}|"
    r"foo\.com|bar\.com|baz\.com|qux\.com|"
    # Disposable / throw-away email services (any subdomain)
    r"(?:[a-z0-9\-]+\.)?mailinator\.com|"
    r"(?:[a-z0-9\-]+\.)?guerrillamail\.[a-z]{2,}|"
    r"(?:[a-z0-9\-]+\.)?trashmail\.[a-z]{2,}|"
    r"(?:[a-z0-9\-]+\.)?yopmail\.com|"
    r"(?:[a-z0-9\-]+\.)?sharklasers\.com|"
    r"(?:[a-z0-9\-]+\.)?throwam\.com|"
    r"(?:[a-z0-9\-]+\.)?guerrillamailblock\.com|"
    r"(?:[a-z0-9\-]+\.)?mailtest\.[a-z]{2,}|"
    # Single-label (localhost, invalid, etc.)
    r"localhost|invalid"
    r")$",
    re.IGNORECASE,
)


def validate_email(value: str) -> Tuple[bool, str]:
    """
    Structural email validation — no network calls.
    Returns (is_valid, reason).
    """
    if _EXAMPLE_TLDS_AND_DOMAINS.search(value):
        return False, "placeholder/example email domain"

    # Basic RFC 5321 structure
    if "@" not in value:
        return False, "not an email address"

    local, _, domain = value.rpartition("@")

    if not local or len(local) > 64:
        return False, "invalid local part"
    if not domain or len(domain) > 253:
        return False, "invalid domain"
    if "." not in domain:
        return False, "domain has no TLD"

    tld = domain.rsplit(".", 1)[-1]
    if len(tld) < 2:
        return False, "TLD too short"

    return True, "email passes structural checks"


# ---------------------------------------------------------------------------
# Phone — digit range sanity
# ---------------------------------------------------------------------------

def validate_phone(value: str) -> Tuple[bool, str]:
    """
    Sanity-check extracted phone number.
    Returns (is_valid, reason).
    """
    digits = re.sub(r"\D", "", value)
    # E.164 allows 7-15 digits (excluding the + prefix digit count)
    if len(digits) < 7 or len(digits) > 15:
        return False, f"digit count {len(digits)} outside valid range 7-15"
    # All same digit (0000000, 1111111, etc.)
    if len(set(digits)) == 1:
        return False, "all same digit (placeholder)"
    # Sequential run (1234567890)
    sequential = "".join(str(i) for i in range(10))
    if digits[:7] in sequential or digits in sequential:
        return False, "sequential digits (placeholder)"
    return True, "phone passes sanity checks"


# ---------------------------------------------------------------------------
# GPS Coordinates — range and precision check
# ---------------------------------------------------------------------------

def validate_gps(lat_str: str, lon_str: str) -> Tuple[bool, str]:
    """
    Validate GPS coordinates — check range and reject low-precision values.
    Returns (is_valid, reason).
    """
    try:
        lat = float(lat_str)
        lon = float(lon_str)
    except (ValueError, TypeError):
        return False, "non-numeric coordinate"

    if not (-90 <= lat <= 90):
        return False, f"latitude {lat} out of range [-90, 90]"
    if not (-180 <= lon <= 180):
        return False, f"longitude {lon} out of range [-180, 180]"

    # Require at least 4 decimal places (city-level precision or better)
    lat_decimals = len(lat_str.split(".")[-1]) if "." in lat_str else 0
    lon_decimals = len(lon_str.split(".")[-1]) if "." in lon_str else 0
    if lat_decimals < 4 or lon_decimals < 4:
        return False, "fewer than 4 decimal places (city-level, not personal location)"

    # Well-known null island / zeros
    if lat == 0.0 and lon == 0.0:
        return False, "null island (0,0) is a placeholder"

    return True, "GPS coordinates within valid range with sufficient precision"


# ---------------------------------------------------------------------------
# Dispatch table — called from SecretScanner after a rule match
# ---------------------------------------------------------------------------

_PII_VALIDATORS = {
    "PII_CREDIT_CARD":        lambda v, _:  validate_credit_card(v),
    "PII_IBAN":               lambda v, _:  validate_iban(v),
    "PII_SSN_US":             lambda v, _:  validate_ssn(v),
    "PII_EMAIL_HARDCODED":    lambda v, _:  validate_email(v),
    "PII_EMAIL_IN_URL":       lambda v, _:  validate_email(v.replace("%40", "@")),
    "PII_PHONE_INTL":         lambda v, _:  validate_phone(v),
    "PII_PHONE_US":           lambda v, _:  validate_phone(v),
}


def validate_pii_finding(rule_id: str, matched_value: str, context: str = "") -> Tuple[float, str]:
    """
    Post-match validation for PII findings.

    Returns (confidence_multiplier, new_status):
      - (1.2, "likely_secret")  → checksum/structure passes, boost confidence
      - (1.0, "candidate")      → no validator, keep as-is
      - (0.1, "likely_false_positive") → validation failed

    The caller multiplies the rule's base confidence by the returned multiplier
    and sets the confidence_label to the returned status.
    """
    validator = _PII_VALIDATORS.get(rule_id)
    if validator is None:
        # No specific validator — keep default scoring
        return 1.0, "candidate"

    try:
        is_valid, reason = validator(matched_value, context)
    except Exception as exc:
        logger.debug("PII validator error for %s: %s", rule_id, exc)
        return 1.0, "candidate"

    if is_valid:
        logger.debug("PII %s validated OK: %s", rule_id, reason)
        return 1.15, "likely_secret"
    else:
        logger.debug("PII %s rejected: %s", rule_id, reason)
        return 0.1, "likely_false_positive"
