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

# Values we fill into specific field types.
# They are designed to be recognisably fake and never trigger real server actions.
SAFE_VALUES: Dict[str, str] = {
    # Search/filter
    "search":   "test",
    "q":        "test",
    "query":    "test",
    "find":     "test",
    "keyword":  "test",
    "keywords": "test",
    "term":     "test",
    "filter":   "all",
    "sort":     "asc",
    "category": "all",
    "tag":      "test",
    "type":     "all",
    # Contact / newsletter
    "name":     "Test User",
    "fullname": "Test User",
    "subject":  "Test",
    "message":  "test",
    "comment":  "test",
    "feedback": "test",
    # Auth (Tier 2 login forms only)
    "username": "testuser",
    "user":     "testuser",
    "login":    "testuser",
    "email":    "probe@bundlespy.invalid",
    # Generic text fallback for Tier 2
    "_text":    "test",
    # URL field
    "url":      "https://example.invalid",
    "website":  "https://example.invalid",
    # Number field
    "_number":  "1",
    # Phone (Tier 2 contact forms only — clearly fake)
    "phone":    "0000000000",
    "tel":      "0000000000",
    "mobile":   "0000000000",
}


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
            filled = self._fill_fields(form_el, intent, stabilizer)
            result.field_count   += filled[0]
            result.filled_count  += filled[1]

            if filled[1] == 0 and _step > 0:
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
        Returns (fields_seen, fields_filled).
        """
        seen   = 0
        filled = 0

        try:
            inputs = form_el.query_selector_all(
                "input:not([type='hidden']):not([type='submit'])"
                ":not([type='radio']):not([type='checkbox'])"
                ":not([type='button']):not([type='image']),"
                "textarea"
            )[: self.MAX_FIELDS]
        except Exception:
            return 0, 0

        for inp in inputs:
            try:
                if not inp.is_visible() or not inp.is_enabled():
                    continue

                itype = (inp.get_attribute("type") or "text").strip().lower()

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

                # Number fields: use "1" as fill value
                if itype == "number":
                    fill_val = SAFE_VALUES["_number"]
                elif itype in ("url",):
                    fill_val = SAFE_VALUES["url"]
                elif itype in ("tel",):
                    fill_val = SAFE_VALUES["tel"]
                else:
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
        Leaves no data behind in the page state.
        """
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
