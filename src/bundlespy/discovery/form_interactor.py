"""
BundleSpy Form Interaction Engine — Tier 1 + Tier 2.

Tier 1 (always active when --headless is on):
    - GET forms only
    - Search / filter / query fields only
    - Safe dummy values (never PII, never real data)
    - Zero state mutation — we never submit anything that persists server-side
    - Runs silently on every page, no flag required

Tier 2 (opt-in with --forms):
    - POST forms included, after intent classification
    - Safe intents only: search, filter, newsletter signup, contact, login
    - Never touch payment, checkout, delete, transfer, account-close forms
    - Never fill fields classified as destructive (amount, account number, IBAN…)
    - Pre-submission warning printed to terminal
    - Clears all filled fields after interaction regardless of outcome

Design principles:
    - Every classification returns an explicit verdict enum — no ambiguous booleans
    - All Playwright calls are wrapped in try/except — a broken form never crashes the crawl
    - Field classifiers run on name + id + placeholder + autocomplete + aria-label (priority order)
    - Form classifiers run on action URL + method + id + class + data-form-type + legend text
    - No external dependencies — pure Python + Playwright
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("bundlespy.discovery.form_interactor")


# ── Enums ─────────────────────────────────────────────────────────────────────

class Tier(Enum):
    """Which tier activated this interaction."""
    ONE = auto()    # GET forms, search/filter only — always on
    TWO = auto()    # POST forms, classified safe — --forms flag


class FormVerdict(Enum):
    """Classification result for a form."""
    TIER1_SAFE    = auto()   # GET form with search/filter fields — always interact
    TIER2_SAFE    = auto()   # POST form with safe intent — interact only in Tier 2
    SKIP_DESTRUCTIVE = auto()  # Form context indicates payment/delete/account operations
    SKIP_METHOD   = auto()   # Method is POST and Tier 2 is not enabled
    SKIP_NO_FIELDS = auto()  # No interactable fields matched our classifiers


class FieldVerdict(Enum):
    """Classification result for a single input field."""
    SEARCH        = auto()   # search/q/query/find/keyword — always fill
    FILTER        = auto()   # filter/sort/category — always fill
    EMAIL_SAFE    = auto()   # email field in a safe context (newsletter, contact, search)
    USERNAME_SAFE = auto()   # username/login field — fill only in Tier 2 safe login forms
    TEXT_SAFE     = auto()   # generic text field with a safe name — fill in Tier 2 only
    SKIP_SENSITIVE = auto()  # amount, card, account, password, SSN etc — NEVER fill
    SKIP_UNKNOWN  = auto()   # unrecognised field — skip to be safe


class FormIntent(Enum):
    """Classified intent of a POST form."""
    SEARCH        = auto()   # Search / filter / catalog browse
    CONTACT       = auto()   # Contact form / support ticket / feedback
    NEWSLETTER    = auto()   # Email subscription
    LOGIN         = auto()   # Authentication — safe because we have credentials
    REGISTRATION  = auto()   # Sign-up — mild risk, allowed with dummy values
    DESTRUCTIVE   = auto()   # Delete / cancel / account operations — NEVER touch
    PAYMENT       = auto()   # Payment / checkout — NEVER touch
    UNKNOWN       = auto()   # Unclassified — skip in Tier 2


# ── Safe dummy values ─────────────────────────────────────────────────────────

# ── Gap 7: Smart field-aware fill values ──────────────────────────────────────
#
# Equivalent to -'s FormFillSuggestions() — values are chosen per
# field *type* (HTML input type + autocomplete + name token) to produce the
# most realistic-looking value that will actually pass client-side validation
# without carrying any real PII or triggering real server actions.
#
# All values are obviously fake:
#   - email domain is .invalid (RFC 2606 reserved — never resolves)
#   - phone numbers are all-zeros or clearly not real
#   - names, companies, and addresses use "Test" prefix
#   - numeric fields use minimal real-looking values (e.g. "21" for age)
#
# Lookup priority in _smart_fill_value():
#   1. HTML autocomplete attribute value
#   2. HTML input type attribute
#   3. Field name/id token fuzzy match
#   4. Generic text fallback

SAFE_VALUES: Dict[str, str] = {
    # ── Search / filter ───────────────────────────────────────────────────────
    "search":           "test",
    "q":                "test",
    "query":            "test",
    "find":             "test",
    "keyword":          "test",
    "keywords":         "test",
    "term":             "test",
    "filter":           "all",
    "sort":             "asc",
    "category":         "all",
    "tag":              "test",
    "type":             "all",
    # ── Contact / newsletter ──────────────────────────────────────────────────
    "name":             "Test User",
    "fullname":         "Test User",
    "full_name":        "Test User",
    "first_name":       "Test",
    "last_name":        "User",
    "given_name":       "Test",
    "family_name":      "User",
    "subject":          "Test inquiry",
    "message":          "This is a test message.",
    "comment":          "test comment",
    "feedback":         "test feedback",
    "description":      "test description",
    "body":             "test body text",
    "content":          "test content",
    "note":             "test note",
    "notes":            "test notes",
    # ── Location / address ────────────────────────────────────────────────────
    "address":          "1 Test Street",
    "address1":         "1 Test Street",
    "address2":         "Suite 100",
    "street":           "1 Test Street",
    "city":             "Test City",
    "state":            "CA",
    "province":         "ON",
    "region":           "Test Region",
    "zip":              "00000",
    "zipcode":          "00000",
    "postal":           "00000",
    "postal_code":      "00000",
    "postcode":         "00000",
    "country":          "US",
    # ── Organisation / professional ───────────────────────────────────────────
    "company":          "Test Company",
    "organization":     "Test Org",
    "organisation":     "Test Org",
    "org":              "Test Org",
    "job_title":        "Tester",
    "title":            "Tester",
    "position":         "Tester",
    "department":       "QA",
    # ── Auth (Tier 2 only) ────────────────────────────────────────────────────
    "username":         "testuser",
    "user_name":        "testuser",
    "user":             "testuser",
    "login":            "testuser",
    "handle":           "testuser",
    "email":            "probe@bundlespy.invalid",
    "e_mail":           "probe@bundlespy.invalid",
    "mail":             "probe@bundlespy.invalid",
    # ── URLs / web ────────────────────────────────────────────────────────────
    "url":              "https://example.invalid",
    "website":          "https://example.invalid",
    "homepage":         "https://example.invalid",
    "link":             "https://example.invalid",
    # ── Phone / fax ───────────────────────────────────────────────────────────
    "phone":            "0000000000",
    "tel":              "0000000000",
    "mobile":           "0000000000",
    "fax":              "0000000000",
    "telephone":        "0000000000",
    "cellphone":        "0000000000",
    # ── Numeric ───────────────────────────────────────────────────────────────
    "age":              "21",
    "quantity":         "1",
    "qty":              "1",
    "count":            "1",
    "number":           "1",
    "num":              "1",
    "amount_safe":      "1",   # generic numeric (NOT financial amount — that's blocked)
    "_number":          "1",
    # ── Dates ─────────────────────────────────────────────────────────────────
    "date":             "2000-01-01",
    "birth_date":       "2000-01-01",
    "dob":              "2000-01-01",
    "birthday":         "2000-01-01",
    "start_date":       "2000-01-01",
    "end_date":         "2000-12-31",
    # ── Generic fallbacks ─────────────────────────────────────────────────────
    "_text":            "test",
}

# Autocomplete attribute → fill value mapping.
# The HTML autocomplete spec defines these token values:
# https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#attr-fe-autocomplete
_AUTOCOMPLETE_FILL: Dict[str, str] = {
    # Names
    "name":               SAFE_VALUES["name"],
    "given-name":         SAFE_VALUES["given_name"],
    "family-name":        SAFE_VALUES["family_name"],
    "additional-name":    "M",
    "nickname":           "testuser",
    "honorific-prefix":   "Mr",
    "honorific-suffix":   "Jr",
    # Contact
    "email":              SAFE_VALUES["email"],
    "tel":                SAFE_VALUES["tel"],
    "tel-national":       SAFE_VALUES["tel"],
    "tel-local":          SAFE_VALUES["tel"],
    # Address
    "street-address":     SAFE_VALUES["address"],
    "address-line1":      SAFE_VALUES["address1"],
    "address-line2":      SAFE_VALUES["address2"],
    "address-level1":     SAFE_VALUES["state"],
    "address-level2":     SAFE_VALUES["city"],
    "address-level3":     SAFE_VALUES["city"],
    "postal-code":        SAFE_VALUES["postal_code"],
    "country":            SAFE_VALUES["country"],
    "country-name":       "United States",
    # Organisation
    "organization":       SAFE_VALUES["organization"],
    "organization-title": SAFE_VALUES["job_title"],
    # Auth (username only — we never fill password)
    "username":           SAFE_VALUES["username"],
    # Web
    "url":                SAFE_VALUES["url"],
    # Dates
    "bday":               SAFE_VALUES["birth_date"],
    "bday-day":           "1",
    "bday-month":         "1",
    "bday-year":          "2000",
    # Search
    "search":             SAFE_VALUES["search"],
    # Sex / gender — harmless demographic field on some forms
    "sex":                "other",
}

# HTML input type → fill value mapping.
# Used when autocomplete isn't set and name-token matching doesn't match.
_INPUT_TYPE_FILL: Dict[str, str] = {
    "text":           SAFE_VALUES["_text"],
    "search":         SAFE_VALUES["search"],
    "email":          SAFE_VALUES["email"],
    "url":            SAFE_VALUES["url"],
    "tel":            SAFE_VALUES["tel"],
    "number":         SAFE_VALUES["_number"],
    "date":           SAFE_VALUES["date"],
    "month":          "2000-01",
    "week":           "2000-W01",
    "time":           "00:00",
    "datetime-local": "2000-01-01T00:00",
    "textarea":       SAFE_VALUES["message"],
}


def _smart_fill_value(el, itype: str) -> str:
    """
    Gap 7: --style smart fill value selection.

    Priority chain (first match wins):
      1. HTML `autocomplete` attribute — the browser's own semantic hint
      2. HTML `type` attribute — email/url/tel/number/date have defined formats
      3. Fuzzy match on name + id + placeholder + aria-label token
      4. Generic text fallback: "test"

    Returns a fill value that:
      - Passes basic client-side format validation (type=email needs @, etc.)
      - Is obviously fake (domain .invalid, all-zero phone, "Test" names)
      - Never contains real PII
    """
    # 1. autocomplete attribute → most specific semantic hint
    try:
        ac = (el.get_attribute("autocomplete") or "").strip().lower()
        # Strip "section-foo " prefix and "shipping " / "billing " modifiers
        ac_tokens = ac.split()
        for tok in reversed(ac_tokens):
            if tok in _AUTOCOMPLETE_FILL:
                return _AUTOCOMPLETE_FILL[tok]
    except Exception:
        pass

    # 2. HTML input type — ONLY for semantically specific types that imply a
    #    format constraint (email needs @, url needs scheme, etc.).
    #    Generic types (text, textarea, number) defer to token matching below
    #    so that a field named "first_name" with type="text" still gets "Test"
    #    rather than the bland "test" fallback.
    _SPECIFIC_INPUT_TYPES: Set[str] = {
        "email", "url", "tel", "date", "month", "week",
        "time", "datetime-local", "search",
    }
    type_val = itype.strip().lower()
    if type_val in _SPECIFIC_INPUT_TYPES and type_val in _INPUT_TYPE_FILL:
        return _INPUT_TYPE_FILL[type_val]

    # 3. Token fuzzy match (name + id + placeholder + aria-label)
    #    Runs for ALL types — including generic text/number/textarea.
    try:
        token = _field_token(el)  # function defined below — forward ref is fine

        # Substring matches that must run BEFORE key-scan because they are
        # more specific than a short key that would fire too broadly.
        # e.g. "first_name" contains "first" → given_name, not "name" → Test User
        if any(x in token for x in ("first", "given")):
            return SAFE_VALUES["given_name"]
        if any(x in token for x in ("last", "family", "surname")):
            return SAFE_VALUES["family_name"]
        if "birth" in token or "dob" in token:
            return SAFE_VALUES["birth_date"]
        if "zip" in token or "postal" in token or "postcode" in token:
            return SAFE_VALUES["postal_code"]
        if "street" in token or "addr" in token:
            return SAFE_VALUES["address"]
        if "city" in token or "town" in token:
            return SAFE_VALUES["city"]
        if "country" in token:
            return SAFE_VALUES["country"]
        if "company" in token or "employer" in token:
            return SAFE_VALUES["company"]
        if "org" in token and "organi" not in token:
            # "org" alone or "org_name" → company; but "organization" has its own key below
            return SAFE_VALUES["company"]
        if "job" in token or "position" in token or "role" in token:
            return SAFE_VALUES["job_title"]
        if "age" in token:
            return SAFE_VALUES["age"]
        if "qty" in token or "quantity" in token:
            return SAFE_VALUES["quantity"]
        if "username" in token or "user_name" in token or "userid" in token:
            return SAFE_VALUES["username"]

        # Exact key match — now runs after the high-specificity checks above
        for key in SAFE_VALUES:
            if key.startswith("_"):
                continue
            if key in token:
                return SAFE_VALUES[key]
    except Exception:
        pass

    # 4. Type-based fallback — now only reached when token matching found nothing.
    #    For text/number/textarea, this is the final safety net before the
    #    ultimate generic fallback.
    if type_val in _INPUT_TYPE_FILL:
        return _INPUT_TYPE_FILL[type_val]

    # 5. Ultimate generic fallback
    return SAFE_VALUES["_text"]


# ── Classification patterns ───────────────────────────────────────────────────

# Field name fragments that indicate safe search/filter fields (Tier 1 allowed)
_FIELD_SEARCH_PATTERNS: Tuple[str, ...] = (
    "search", "q", "query", "find", "keyword", "keywords", "term",
    "filter", "sort", "order", "category", "tag", "type", "genre",
    "lookup", "seek", "browse",
)

# Field name fragments allowed only in Tier 2 safe forms
_FIELD_TEXT_SAFE_PATTERNS: Tuple[str, ...] = (
    "name", "fullname", "full_name", "first", "last",
    "subject", "message", "comment", "feedback", "body",
    "address", "city", "zip", "postal", "country",
    "company", "org", "website", "url",
    "phone", "tel", "mobile",
)

# Username / email patterns — Tier 2 safe login / registration forms
_FIELD_USERNAME_PATTERNS: Tuple[str, ...] = (
    "username", "user_name", "login", "userid", "user",
    "email", "e_mail", "mail", "handle",
)

# Patterns that ALWAYS mean skip — sensitive / financial / destructive
_FIELD_SKIP_PATTERNS: Tuple[str, ...] = (
    "password", "passwd", "pass", "pwd", "secret", "pin",
    "card", "credit", "debit", "cvv", "cvc", "expiry", "expiration",
    "account", "iban", "routing", "swift", "bic",
    "ssn", "social", "tax", "ein",
    "amount", "price", "cost", "total", "payment",
    "delete", "remove", "confirm_delete", "destroy",
    "transfer", "withdraw", "send_money",
    "otp", "mfa", "totp", "2fa", "verification_code",
    "captcha", "recaptcha",
)

# Form action URL fragments that mean skip always
_FORM_ACTION_SKIP: Tuple[str, ...] = (
    "/payment", "/checkout", "/billing", "/purchase", "/order",
    "/delete", "/remove", "/transfer", "/withdraw", "/send",
    "/admin", "/api/v1/delete", "/api/v2/delete",
    "/account/close", "/account/cancel", "/account/delete",
    "/unsubscribe/confirm",
)

# Form context keywords that mean DESTRUCTIVE
_FORM_CONTEXT_DESTRUCTIVE: Tuple[str, ...] = (
    "payment", "checkout", "billing", "credit", "card",
    "purchase", "buy", "transaction", "stripe",
    "paypal", "braintree", "adyen", "square", "invoice",
    "delete", "remove", "cancel_account", "close_account",
    "terminate", "destroy", "wipe", "deactivate",
    "transfer", "withdraw", "wire",
)

# Form context keywords that indicate SEARCH intent
_FORM_CONTEXT_SEARCH: Tuple[str, ...] = (
    "search", "find", "filter", "browse", "catalog", "explore",
    "lookup", "query", "list", "directory",
)

# Form context keywords that indicate CONTACT/NEWSLETTER/FEEDBACK
_FORM_CONTEXT_CONTACT: Tuple[str, ...] = (
    "contact", "support", "help", "feedback", "report",
    "subscribe", "newsletter", "mailing", "signup", "sign-up",
    "inquiry", "enquiry", "question", "suggest",
)

# Form context keywords that indicate LOGIN intent
_FORM_CONTEXT_LOGIN: Tuple[str, ...] = (
    "login", "log-in", "signin", "sign-in", "auth", "authenticate",
    "logon", "log-on", "session",
)

# Form context keywords that indicate REGISTRATION intent
_FORM_CONTEXT_REGISTRATION: Tuple[str, ...] = (
    "register", "registration", "signup", "sign-up", "create_account",
    "new_account", "join", "enroll",
)

# Button text that means "submit this form for real" — never click in Tier 1 or Tier 2
_SUBMIT_BLACKLIST: Tuple[str, ...] = (
    "place order", "buy now", "pay now", "checkout",
    "confirm order", "submit order", "complete purchase",
    "make payment", "send payment", "transfer funds",
    "delete account", "close account", "cancel account",
    "deactivate", "destroy", "wipe",
    "confirm delete", "yes, delete",
)

# Button text that is safe to click (next-step navigation, not submission)
_NEXT_BTN_PATTERNS: Tuple[str, ...] = (
    "next", "continue", "proceed", "forward", "step",
    "go →", "→", ">", "advance",
)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class FieldResult:
    """Result of classifying one input field."""
    verdict:    FieldVerdict
    fill_value: Optional[str] = None  # None means skip


@dataclass
class FormResult:
    """Result of classifying one form."""
    verdict:    FormVerdict
    intent:     FormIntent      = FormIntent.UNKNOWN
    tier:       Optional[Tier]  = None
    field_count: int            = 0
    filled_count: int           = 0
    routes_found: List[str]     = field(default_factory=list)


@dataclass
class PageFormReport:
    """Aggregated results for all forms on one page."""
    url:         str
    forms_found: int             = 0
    forms_interacted: int        = 0
    forms_skipped: int           = 0
    new_routes:  List[str]       = field(default_factory=list)
    results:     List[FormResult] = field(default_factory=list)


# ── Classifier helpers ────────────────────────────────────────────────────────

def _field_token(el) -> str:
    """
    Build a normalised token string for a field element by joining
    name, id, placeholder, autocomplete, aria-label.
    Lowercase, spaces collapsed.
    """
    parts = []
    for attr in ("name", "id", "placeholder", "autocomplete", "aria-label"):
        try:
            v = el.get_attribute(attr)
            if v:
                parts.append(v.lower())
        except Exception:
            pass
    return " ".join(parts)


def _form_context_token(form_el) -> str:
    """
    Build a context string for a form element from action, id, class,
    data-form-type, name, aria-label, and the text of its first <legend>.
    """
    parts = []
    for attr in ("action", "id", "class", "name", "data-form-type", "aria-label"):
        try:
            v = form_el.get_attribute(attr)
            if v:
                parts.append(v.lower())
        except Exception:
            pass
    # Pull legend text
    try:
        legend = form_el.query_selector("legend")
        if legend:
            t = legend.inner_text()
            if t:
                parts.append(t.lower())
    except Exception:
        pass
    return " ".join(parts)


def classify_field(el, form_intent: FormIntent, tier2_enabled: bool) -> FieldResult:
    """
    Classify one input/textarea element and decide what value to fill (if any).

    Rules (applied in strict priority order):
      1. If field token matches any skip pattern → SKIP_SENSITIVE, no fill
      2. If field matches search/filter patterns → SEARCH/FILTER, fill "test"
      3. If tier2_enabled and form is a safe POST intent:
           - email / username fields → EMAIL_SAFE / USERNAME_SAFE
           - text/url/tel fields with safe name → TEXT_SAFE
      4. Otherwise → SKIP_UNKNOWN
    """
    token = _field_token(el)

    # Priority 1: never fill sensitive fields
    if any(p in token for p in _FIELD_SKIP_PATTERNS):
        return FieldResult(FieldVerdict.SKIP_SENSITIVE)

    # Priority 2: search/filter — always safe regardless of tier or form intent
    if any(p in token for p in _FIELD_SEARCH_PATTERNS):
        fill_key = next((p for p in _FIELD_SEARCH_PATTERNS if p in token), "search")
        fill_val = SAFE_VALUES.get(fill_key, SAFE_VALUES["search"])
        return FieldResult(FieldVerdict.SEARCH, fill_value=fill_val)

    # Priority 3: Tier 2 safe form fields
    if tier2_enabled and form_intent in (
        FormIntent.SEARCH, FormIntent.CONTACT,
        FormIntent.NEWSLETTER, FormIntent.LOGIN, FormIntent.REGISTRATION,
    ):
        # Email
        if any(p in token for p in ("email", "e_mail", "mail")):
            # Only fill email with clearly fake probe address
            return FieldResult(FieldVerdict.EMAIL_SAFE, fill_value=SAFE_VALUES["email"])

        # Username (but not in combination with password check — we already skip passwords above)
        if any(p in token for p in _FIELD_USERNAME_PATTERNS):
            return FieldResult(FieldVerdict.USERNAME_SAFE, fill_value=SAFE_VALUES["username"])

        # Generic safe text fields
        if any(p in token for p in _FIELD_TEXT_SAFE_PATTERNS):
            fill_key = next((p for p in _FIELD_TEXT_SAFE_PATTERNS if p in token), None)
            fill_val = SAFE_VALUES.get(fill_key, SAFE_VALUES["_text"])
            return FieldResult(FieldVerdict.TEXT_SAFE, fill_value=fill_val)

    return FieldResult(FieldVerdict.SKIP_UNKNOWN)


def classify_form(form_el, tier2_enabled: bool) -> Tuple[FormVerdict, FormIntent]:
    """
    Classify a form element and return (FormVerdict, FormIntent).

    Steps:
      1. Extract method (GET/POST/other)
      2. Check action URL for skip patterns
      3. Build context token and check for destructive patterns
      4. Classify intent from context
      5. Apply tier gating:
           GET  → TIER1_SAFE if intent is not destructive
           POST → TIER2_SAFE if tier2_enabled and intent is safe
                  SKIP_METHOD if tier2_enabled is False
                  SKIP_DESTRUCTIVE if intent is destructive
    """
    # Method
    try:
        method = (form_el.get_attribute("method") or "get").strip().upper()
    except Exception:
        method = "GET"
    if method not in ("GET", "POST"):
        method = "GET"  # treat non-standard as GET (safe default)

    # Action URL check
    try:
        action = (form_el.get_attribute("action") or "").lower()
    except Exception:
        action = ""
    if any(frag in action for frag in _FORM_ACTION_SKIP):
        return FormVerdict.SKIP_DESTRUCTIVE, FormIntent.DESTRUCTIVE

    # Context token
    ctx = _form_context_token(form_el)

    # Check destructive context
    if any(kw in ctx for kw in _FORM_CONTEXT_DESTRUCTIVE):
        return FormVerdict.SKIP_DESTRUCTIVE, FormIntent.DESTRUCTIVE

    # Classify intent
    intent = _classify_intent(ctx, form_el)

    if intent == FormIntent.DESTRUCTIVE:
        return FormVerdict.SKIP_DESTRUCTIVE, intent
    if intent == FormIntent.PAYMENT:
        return FormVerdict.SKIP_DESTRUCTIVE, intent

    # Tier gating
    if method == "GET":
        return FormVerdict.TIER1_SAFE, intent

    # POST below this point
    if not tier2_enabled:
        return FormVerdict.SKIP_METHOD, intent

    # POST + Tier 2 enabled
    if intent in (
        FormIntent.SEARCH, FormIntent.CONTACT,
        FormIntent.NEWSLETTER, FormIntent.LOGIN, FormIntent.REGISTRATION,
    ):
        return FormVerdict.TIER2_SAFE, intent

    # POST with UNKNOWN intent → skip (be conservative)
    return FormVerdict.SKIP_DESTRUCTIVE, FormIntent.UNKNOWN


def _classify_intent(ctx: str, form_el) -> FormIntent:
    """
    Determine the likely intent of a form from its context token.
    Priority: destructive > payment > login > registration > search > contact/newsletter > unknown.
    """
    # Destructive
    if any(kw in ctx for kw in (
        "delete", "remove", "cancel", "terminate", "deactivate",
        "destroy", "wipe", "close account", "close_account",
    )):
        return FormIntent.DESTRUCTIVE

    # Payment
    if any(kw in ctx for kw in (
        "payment", "checkout", "billing", "credit", "card",
        "purchase", "buy", "transaction", "stripe",
        "paypal", "braintree", "adyen", "square",
    )):
        return FormIntent.PAYMENT

    # Login (check before registration — "login" beats "register")
    if any(kw in ctx for kw in _FORM_CONTEXT_LOGIN):
        return FormIntent.LOGIN

    # Registration
    if any(kw in ctx for kw in _FORM_CONTEXT_REGISTRATION):
        return FormIntent.REGISTRATION

    # Search
    if any(kw in ctx for kw in _FORM_CONTEXT_SEARCH):
        return FormIntent.SEARCH

    # Contact / newsletter
    if any(kw in ctx for kw in _FORM_CONTEXT_CONTACT):
        return FormIntent.CONTACT

    # Fallback: inspect actual fields to guess intent
    return _intent_from_fields(form_el)


def _intent_from_fields(form_el) -> FormIntent:
    """
    Secondary intent inference: look at field names when the form context
    itself didn't yield a clear intent.
    """
    try:
        inputs = form_el.query_selector_all("input, textarea, select")
    except Exception:
        return FormIntent.UNKNOWN

    tokens = []
    for inp in inputs[:10]:
        try:
            t = _field_token(inp)
            if t:
                tokens.append(t)
        except Exception:
            pass

    combined = " ".join(tokens)

    # Password field alone implies login or registration — NOT safe to fill
    has_password = any(p in combined for p in ("password", "passwd", "pwd"))
    has_email    = any(p in combined for p in ("email", "mail"))
    has_search   = any(p in combined for p in _FIELD_SEARCH_PATTERNS)
    has_message  = any(p in combined for p in ("message", "comment", "body", "feedback"))

    if has_password and has_email:
        return FormIntent.LOGIN       # classic login form
    if has_password and not has_email:
        return FormIntent.REGISTRATION  # registration usually has email + password
    if has_search:
        return FormIntent.SEARCH
    if has_email and has_message:
        return FormIntent.CONTACT
    if has_email and not has_password:
        return FormIntent.NEWSLETTER  # email-only = subscribe

    return FormIntent.UNKNOWN


# ── FormInteractor ────────────────────────────────────────────────────────────

class FormInteractor:
    """
    Stateless form interaction engine.

    Call interact_page() on every page visit.
    It runs Tier 1 automatically; Tier 2 only when tier2_enabled=True.

    No mutable state is stored here — all state is on the caller's engine.
    The engine passes a PageStabilizer so we can wait for JS reactions
    without coupling to the engine's internals.
    """

    MAX_FORMS     = 8    # max forms to process per page
    MAX_FIELDS    = 10   # max fields to fill per form
    MAX_STEPS     = 4    # max wizard steps per form

    # Selectors for modal/dialog detection
    MODAL_SELECTORS = (
        "[role='dialog']:not([hidden])",
        "[aria-modal='true']:not([hidden])",
        ".modal:not(.hidden):not(.d-none)",
        ".dialog:not(.hidden)",
    )

    # Selectors for "next step" navigation buttons (not submit)
    NEXT_BTN_SELECTORS = (
        "[data-action='next']",
        "[data-step='next']",
        "button.next", "button.continue",
        "a.next", "a.continue",
        "button[type='button']",
        "button:not([type='submit'])",
    )

    def __init__(self, tier2_enabled: bool = False):
        self.tier2_enabled = tier2_enabled

    def interact_page(
        self,
        page,
        stabilizer,
        source_url: str = "",
    ) -> PageFormReport:
        """
        Discover and interact with all forms on the current page.

        Returns a PageFormReport with interaction counts and any new routes
        discovered via form submission (GET forms that navigate on submit).
        """
        report = PageFormReport(url=source_url)

        try:
            forms = page.query_selector_all("form")
        except Exception:
            return report

        # Cap at MAX_FORMS — we don't want to spend forever on a page
        forms = forms[: self.MAX_FORMS]
        report.forms_found = len(forms)

        for form in forms:
            result = self._interact_form(page, form, stabilizer, source_url)
            report.results.append(result)
            if result.verdict in (FormVerdict.TIER1_SAFE, FormVerdict.TIER2_SAFE):
                report.forms_interacted += 1
                report.new_routes.extend(result.routes_found)
            else:
                report.forms_skipped += 1

        return report

    # ── Private form-level logic ──────────────────────────────────────────────

    def _interact_form(
        self,
        page,
        form_el,
        stabilizer,
        source_url: str,
    ) -> FormResult:
        """
        Classify and interact with one form.
        Returns FormResult with the verdict and stats.
        """
        verdict, intent = classify_form(form_el, self.tier2_enabled)
        result = FormResult(verdict=verdict, intent=intent)

        if verdict not in (FormVerdict.TIER1_SAFE, FormVerdict.TIER2_SAFE):
            logger.debug(
                "form skip [%s] intent=%s url=%s",
                verdict.name, intent.name, source_url
            )
            return result

        tier = Tier.ONE if verdict == FormVerdict.TIER1_SAFE else Tier.TWO
        result.tier = tier

        logger.debug(
            "form interact [Tier %s] method=%s intent=%s url=%s",
            "1" if tier == Tier.ONE else "2",
            "GET" if verdict == FormVerdict.TIER1_SAFE else "POST",
            intent.name,
            source_url,
        )

        # Multi-step wizard loop
        for _step in range(self.MAX_STEPS):
            filled  = self._fill_fields(form_el, intent, stabilizer)
            selects = self._fill_selects(form_el, stabilizer)
            result.field_count   += filled[0]  + selects[0]
            result.filled_count  += filled[1] + selects[1]

            if (filled[1] + selects[1]) == 0 and _step > 0:
                break  # No new fields appeared — wizard is done

            # Tab through to trigger conditional reveals
            try:
                page.keyboard.press("Tab")
                stabilizer.wait_after_interaction(max_ms=300)
            except Exception:
                pass

            # For GET forms: submit via keyboard (Enter) and capture nav URL
            if verdict == FormVerdict.TIER1_SAFE and _step == 0:
                new_routes = self._try_submit_get(page, form_el, stabilizer, source_url)
                result.routes_found.extend(new_routes)

            # For Tier 2 POST forms that are CONTACT/NEWSLETTER/SEARCH:
            # Do NOT submit — just fill the fields to trigger JS reactions.
            # We only click Next/Continue to advance wizard steps.
            advanced = self._try_advance_wizard(form_el, stabilizer)
            if not advanced:
                break

            # Check for modals that appeared after a wizard step
            self._handle_modals(page, intent, stabilizer)

        # Always clear what we touched — leave no trace
        self._clear_fields(form_el)

        return result

    def _fill_fields(
        self,
        form_el,
        intent: FormIntent,
        stabilizer,
    ) -> Tuple[int, int]:
        """
        Fill visible, enabled fields in this form that pass classification.
        Handles text/email/url/tel/number/textarea via .fill(), and
        checkbox/radio via .click() (correct DOM interaction for those types).
        Returns (fields_seen, fields_filled).
        """
        seen   = 0
        filled = 0

        # ── Text-like inputs + textarea ───────────────────────────────────────
        try:
            inputs = form_el.query_selector_all(
                "input:not([type='hidden']):not([type='submit'])"
                ":not([type='button']):not([type='image']),"
                "textarea"
            )[: self.MAX_FIELDS]
        except Exception:
            inputs = []

        for inp in inputs:
            try:
                if not inp.is_visible() or not inp.is_enabled():
                    continue

                itype = (inp.get_attribute("type") or "text").strip().lower()

                # Checkbox / radio: use .click() — .fill() does nothing on these
                if itype in ("checkbox", "radio"):
                    token = _field_token(inp)
                    # Never click sensitive / destructive fields
                    if any(p in token for p in _FIELD_SKIP_PATTERNS):
                        continue
                    # Only click if unchecked (avoid toggling something already on)
                    try:
                        if inp.is_checked():
                            continue
                        seen += 1
                        inp.scroll_into_view_if_needed(timeout=300)
                        inp.click(timeout=500)
                        stabilizer.wait_after_interaction(max_ms=200)
                        filled += 1
                    except Exception as e:
                        logger.debug("%s click error: %s", itype, e)
                    continue

                # Skip non-text input types we never want to fill
                if itype in ("file", "date", "datetime-local", "time", "color",
                             "range", "week", "month"):
                    continue

                seen += 1
                field_res = classify_field(inp, intent, self.tier2_enabled)

                if field_res.verdict in (
                    FieldVerdict.SKIP_SENSITIVE, FieldVerdict.SKIP_UNKNOWN
                ):
                    continue

                # Gap 7: Smart fill value — type+autocomplete+token-aware.
                fill_val = _smart_fill_value(inp, itype)

                # Sanity fallback: field_res.fill_value is still valid when set
                if not fill_val:
                    fill_val = field_res.fill_value or SAFE_VALUES["_text"]

                try:
                    inp.scroll_into_view_if_needed(timeout=300)
                    inp.click(timeout=500)
                    inp.fill(fill_val, timeout=500)
                    stabilizer.wait_after_interaction(max_ms=250)
                    filled += 1
                except Exception as e:
                    logger.debug("field fill error (%s): %s", fill_val, e)

            except Exception:
                pass

        return seen, filled

    def _fill_selects(
        self,
        form_el,
        stabilizer,
    ) -> Tuple[int, int]:
        """
        Handle <select> elements by enumerating real <option> values and
        picking the first non-empty, non-disabled, non-placeholder option.

        Uses select_option(value=...) — not fill() — which is the correct
        Playwright API for <select> elements. .fill() silently does nothing.

        Returns (selects_seen, selects_filled).
        """
        seen   = 0
        filled = 0

        try:
            selects = form_el.query_selector_all("select")[: self.MAX_FIELDS]
        except Exception:
            return 0, 0

        for sel_el in selects:
            try:
                if not sel_el.is_visible() or not sel_el.is_enabled():
                    continue

                # Skip selects whose name/id token looks sensitive
                token = _field_token(sel_el)
                if any(p in token for p in _FIELD_SKIP_PATTERNS):
                    continue

                seen += 1

                # Walk <option> children to find a real value
                try:
                    options = sel_el.query_selector_all("option")
                except Exception:
                    options = []

                picked = None
                for opt in options:
                    try:
                        opt_value = opt.get_attribute("value") or ""
                        opt_text  = (opt.inner_text() or "").strip()
                        disabled  = opt.get_attribute("disabled")

                        if disabled is not None:
                            continue

                        # Skip empty / placeholder options (value="" or text is
                        # a generic placeholder like "Select...", "Choose...", "--")
                        if not opt_value and not opt_text:
                            continue

                        text_lower = opt_text.lower()
                        if text_lower in (
                            "", "select", "choose", "pick", "--", "---",
                            "please select", "please choose", "select one",
                            "select an option", "choose an option",
                        ):
                            continue

                        # Prefer a non-empty value attribute; fall back to text
                        picked = opt_value if opt_value else opt_text
                        break
                    except Exception:
                        continue

                if not picked:
                    # No real option found — fall back to index 1 (skip index 0,
                    # which is almost always the placeholder)
                    if len(options) > 1:
                        try:
                            picked = options[1].get_attribute("value") or (
                                options[1].inner_text() or ""
                            ).strip()
                        except Exception:
                            pass

                if not picked:
                    continue

                # Select by value first; if that fails, try by label text
                try:
                    sel_el.scroll_into_view_if_needed(timeout=300)
                    try:
                        sel_el.select_option(value=picked, timeout=500)
                    except Exception:
                        sel_el.select_option(label=picked, timeout=500)
                    stabilizer.wait_after_interaction(max_ms=200)
                    filled += 1
                except Exception as e:
                    logger.debug("select fill error (value=%s): %s", picked, e)

            except Exception:
                pass

        return seen, filled

    def _try_submit_get(
        self,
        page,
        form_el,
        stabilizer,
        source_url: str,
    ) -> List[str]:
        """
        For GET forms: trigger form submission and capture the resulting URL.
        We press Enter (not click Submit) to be respectful of page state.

        Only captures the URL if it stays within the same origin.
        Always navigates back to source_url afterward.
        """
        new_routes: List[str] = []
        original_url = source_url

        try:
            # Find the first filled text input and press Enter
            inp = form_el.query_selector(
                "input[type='search'], input[type='text'], input[name='q'], "
                "input[name='search'], input[name='query']"
            )
            if not inp or not inp.is_visible():
                return new_routes

            inp.press("Enter", timeout=500)
            stabilizer.wait_after_interaction(max_ms=1200)

            current = page.url
            if current and current != original_url:
                parsed_orig    = urlparse(original_url)
                parsed_current = urlparse(current)

                # Only accept same-origin navigations
                if (parsed_orig.scheme == parsed_current.scheme and
                        parsed_orig.netloc == parsed_current.netloc):
                    route = parsed_current.path or "/"
                    if route != "/":
                        new_routes.append(route)
                        logger.debug(
                            "GET form submit captured route: %s → %s",
                            original_url, route,
                        )

            # Navigate back so the rest of the crawl runs on the original page
            try:
                page.go_back(timeout=3000, wait_until="domcontentloaded")
                stabilizer.wait_after_interaction(max_ms=800)
            except Exception:
                try:
                    page.goto(original_url, timeout=5000, wait_until="domcontentloaded")
                    stabilizer.wait_after_interaction(max_ms=800)
                except Exception:
                    pass

        except Exception as e:
            logger.debug("GET form submit error: %s", e)

        return new_routes

    def _try_advance_wizard(self, form_el, stabilizer) -> bool:
        """
        Look for Next/Continue/Proceed buttons inside this form and click one.
        Returns True if a button was clicked (wizard advanced), False otherwise.

        Strictly skips any button whose text matches the submit blacklist.
        """
        for sel in self.NEXT_BTN_SELECTORS:
            try:
                buttons = form_el.query_selector_all(sel)[: 4]
                for btn in buttons:
                    try:
                        if not btn.is_visible() or not btn.is_enabled():
                            continue
                        btn_text = (btn.inner_text() or "").lower().strip()

                        # Hard blacklist — never click
                        if any(w in btn_text for w in _SUBMIT_BLACKLIST):
                            continue

                        # Only click navigation buttons, not submit buttons
                        if not any(w in btn_text for w in _NEXT_BTN_PATTERNS):
                            continue

                        btn.scroll_into_view_if_needed(timeout=300)
                        btn.click(timeout=600)
                        stabilizer.wait_after_interaction(max_ms=900)
                        return True

                    except Exception:
                        pass
            except Exception:
                pass

        return False

    def _handle_modals(self, page, intent: FormIntent, stabilizer) -> None:
        """
        If a modal/dialog appeared after a wizard step, interact with its
        safe inputs (search/filter only) and then close it.
        """
        for modal_sel in self.MODAL_SELECTORS:
            try:
                modal = page.query_selector(modal_sel)
                if not modal or not modal.is_visible():
                    continue

                # Only fill search/filter fields inside modals — never more
                for inp in modal.query_selector_all(
                    "input:not([type='hidden']):not([type='submit']),textarea"
                )[: 4]:
                    try:
                        if not inp.is_visible() or not inp.is_enabled():
                            continue
                        token = _field_token(inp)
                        if not any(p in token for p in _FIELD_SEARCH_PATTERNS):
                            continue
                        itype = (inp.get_attribute("type") or "text").lower()
                        if itype not in ("text", "search"):
                            continue
                        inp.fill(SAFE_VALUES["search"], timeout=400)
                        stabilizer.wait_after_interaction(max_ms=250)
                    except Exception:
                        pass

                # Close the modal so it doesn't interfere with the rest of the page
                for close_sel in (
                    "[aria-label='Close']",
                    "[aria-label='close']",
                    "[data-dismiss='modal']",
                    "[data-bs-dismiss='modal']",
                    "button.close",
                    ".modal-header button",
                    ".modal-close",
                    "[data-modal-close]",
                ):
                    try:
                        close_btn = modal.query_selector(close_sel)
                        if close_btn and close_btn.is_visible():
                            close_btn.click(timeout=500)
                            stabilizer.wait_after_interaction(max_ms=500)
                            break
                    except Exception:
                        pass

            except Exception:
                pass

    def _clear_fields(self, form_el) -> None:
        """
        Clear all visible text-type inputs in the form after interacting.
        Also unchecks any checkboxes we may have clicked, and resets selects
        back to their first option. Leaves no data behind in the page state.
        """
        # ── Text-like inputs ──────────────────────────────────────────────────
        try:
            inputs = form_el.query_selector_all(
                "input:not([type='hidden'])"
                ":not([type='radio'])"
                ":not([type='checkbox'])"
                ":not([type='submit'])"
                ":not([type='button'])"
            )[: self.MAX_FIELDS]
            for inp in inputs:
                try:
                    if inp.is_visible():
                        inp.fill("", timeout=300)
                except Exception:
                    pass
        except Exception:
            pass

        # ── Checkboxes — uncheck any we clicked ──────────────────────────────
        try:
            checkboxes = form_el.query_selector_all(
                "input[type='checkbox']"
            )[: self.MAX_FIELDS]
            for cb in checkboxes:
                try:
                    if cb.is_visible() and cb.is_checked():
                        cb.click(timeout=300)
                except Exception:
                    pass
        except Exception:
            pass

        # ── Selects — reset to first option ──────────────────────────────────
        try:
            selects = form_el.query_selector_all("select")[: self.MAX_FIELDS]
            for sel_el in selects:
                try:
                    if not sel_el.is_visible():
                        continue
                    options = sel_el.query_selector_all("option")
                    if options:
                        first_val = options[0].get_attribute("value") or ""
                        sel_el.select_option(value=first_val, timeout=300)
                except Exception:
                    pass
        except Exception:
            pass
