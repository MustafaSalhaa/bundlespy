"""
BundleSpy Auto-Login Engine

Headless form-based login with:
- Smart field detection (username/password/email/CSRF)
- Multi-step form support
- Post-login session capture (cookies + localStorage tokens)
- Auth verification after login
- Detailed result reporting for terminal and HTML
"""

import logging
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("bundlespy.discovery.autologin")


# ── Field name heuristics ─────────────────────────────────────────────────────

USERNAME_NAMES = {
    "username", "user", "login", "email", "mail", "uname",
    "user_name", "user-name", "userid", "user_id",
    "account", "identifier", "handle", "loginid",
    # common autocomplete values
    "email", "username", "current-password",
}

PASSWORD_NAMES = {
    "password", "pass", "passwd", "pwd", "secret",
    "password1", "pass1", "current_password", "user_password",
    "current-password",
}

CSRF_NAMES = {
    "_token", "csrf", "csrf_token", "csrfmiddlewaretoken",
    "_csrf", "xsrf", "authenticity_token", "__requestverificationtoken",
    "x-csrf-token", "xsrf-token",
}

MFA_NAMES = {
    "otp", "mfa", "totp", "code", "verification_code",
    "two_factor", "2fa", "token", "one_time_password",
}

# Keywords in aria-label / placeholder that signal username or password
_USERNAME_HINTS = {"username", "user name", "email", "e-mail", "login", "account", "identifier"}
_PASSWORD_HINTS = {"password", "pass", "passphrase", "secret"}


def _field_type(name: str, input_type: str, aria_label: str = "", placeholder: str = "", autocomplete: str = "") -> Optional[str]:
    """
    Classify an input field.
    Checks name/id, then input type, then aria-label, placeholder, autocomplete.
    Returns 'username', 'password', 'csrf', 'mfa', or None.
    """
    n  = (name or "").lower().replace("-", "_")
    t  = (input_type or "text").lower()
    al = (aria_label or "").lower()
    ph = (placeholder or "").lower()
    ac = (autocomplete or "").lower()

    # type=password is unambiguous
    if t == "password":
        return "password"

    # name/id match
    if n in PASSWORD_NAMES:
        return "password"
    if n in USERNAME_NAMES or t == "email":
        return "username"
    if n in CSRF_NAMES or t == "hidden":
        return "csrf"
    if n in MFA_NAMES:
        return "mfa"

    # autocomplete attribute - very reliable signal (React/Vue often set this)
    if ac in ("current-password", "new-password"):
        return "password"
    if ac in ("username", "email"):
        return "username"

    # aria-label / placeholder fallback - covers React controlled components
    # that render <input aria-label="Email" /> with no name attribute
    for hint in _PASSWORD_HINTS:
        if hint in al or hint in ph:
            return "password"
    for hint in _USERNAME_HINTS:
        if hint in al or hint in ph:
            return "username"

    return None


def _find_login_form(page):
    """
    Find the best login form on the page.
    Returns (form_element, field_map) or (None, {}).
    field_map: {'username': el, 'password': el, 'submit': el, 'csrf': el}
    """
    best_form = None
    best_fields = {}
    best_score = 0

    try:
        forms = page.query_selector_all("form")
    except Exception:
        return None, {}

    for form in forms:
        try:
            fields = {"username": None, "password": None, "submit": None, "csrf": None}
            score = 0

            # Check form action/id/class for login hints
            form_ctx = (
                (form.get_attribute("action") or "") +
                (form.get_attribute("id") or "") +
                (form.get_attribute("class") or "")
            ).lower()

            if any(k in form_ctx for k in ["login", "signin", "sign-in", "auth", "session"]):
                score += 3

            # Scan inputs
            inputs = form.query_selector_all("input, button[type='submit'], button:not([type])")
            for inp in inputs:
                try:
                    itype  = (inp.get_attribute("type") or "text").lower()
                    iname  = (inp.get_attribute("name") or inp.get_attribute("id") or "")
                    iac    = (inp.get_attribute("autocomplete") or "")
                    iph    = (inp.get_attribute("placeholder") or "")
                    ial    = (inp.get_attribute("aria-label") or "")
                    kind   = _field_type(iname, itype, aria_label=ial, placeholder=iph, autocomplete=iac)

                    if kind == "password":
                        fields["password"] = inp
                        score += 5
                    elif kind == "username":
                        fields["username"] = inp
                        score += 3
                    elif kind == "csrf":
                        fields["csrf"] = inp
                    elif itype in ("submit", "button") or inp.tag_name() == "button":
                        fields["submit"] = inp
                        score += 1
                except Exception:
                    pass

            # Must have at least a password field to be a real login form
            if fields["password"] and score > best_score:
                best_score = score
                best_form = form
                best_fields = fields

        except Exception:
            continue

    return best_form, best_fields


def _find_formless_login(page):
    """
    Fallback for pages with no <form> tag - find bare password input + submit button.
    Covers React/Vue/Angular SPAs that render login UI without a <form> wrapper.
    Returns field_map dict (same shape as _find_login_form's second return value).
    """
    try:
        pw = page.query_selector("input[type='password']")
        if not pw:
            return {}

        # Submit button - prioritize visible buttons near the password field
        submit = (
            page.query_selector("button[type='submit']") or
            page.query_selector("input[type='submit']") or
            page.query_selector("button[onclick]") or
            page.query_selector("button:not([type='button']):not([type='reset'])") or
            page.query_selector("input[type='button']")
        )

        # Username: prefer email, then aria-labeled text inputs
        username = (
            page.query_selector("input[type='email']") or
            page.query_selector("input[autocomplete='username']") or
            page.query_selector("input[autocomplete='email']") or
            page.query_selector("input[type='text'][name*='user']") or
            page.query_selector("input[type='text'][name*='email']") or
            page.query_selector("input[type='text'][aria-label*='ser']") or
            page.query_selector("input[type='text'][aria-label*='mail']") or
            page.query_selector("input[type='text'][placeholder*='ser']") or
            page.query_selector("input[type='text'][placeholder*='mail']") or
            page.query_selector("input[type='text']")
        )
        return {
            "username": username,
            "password": pw,
            "submit":   submit,
            "csrf":     None,
        }
    except Exception:
        return {}


def _capture_session(page, domain: str) -> dict:
    """
    Capture all session material after login:
    - Browser cookies
    - localStorage tokens
    - sessionStorage tokens
    Returns dict with 'cookies', 'local_storage', 'session_storage', 'cookie_string'
    """
    result = {
        "cookies": [],
        "local_storage": {},
        "session_storage": {},
        "cookie_string": "",
        "token_keys": [],
    }

    # Browser cookies
    try:
        browser_cookies = page.context.cookies()
        result["cookies"] = browser_cookies
        # Build cookie string (name=value; name2=value2)
        parts = []
        for c in browser_cookies:
            if domain in c.get("domain", ""):
                parts.append(f"{c['name']}={c['value']}")
        result["cookie_string"] = "; ".join(parts)
    except Exception as e:
        logger.debug("Cookie capture failed: %s", e)

    # localStorage — look for tokens, JWTs, API keys
    try:
        ls = page.evaluate("""() => {
            const out = {};
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                out[k] = localStorage.getItem(k);
            }
            return out;
        }""")
        if ls:
            result["local_storage"] = ls
            # Flag keys that look like tokens
            token_hints = {"token", "jwt", "auth", "session", "access", "bearer", "key", "secret"}
            result["token_keys"] = [
                k for k in ls
                if any(h in k.lower() for h in token_hints)
            ]
    except Exception as e:
        logger.debug("localStorage capture failed: %s", e)

    # sessionStorage
    try:
        ss = page.evaluate("""() => {
            const out = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                out[k] = sessionStorage.getItem(k);
            }
            return out;
        }""")
        if ss:
            result["session_storage"] = ss
            token_hints = {"token", "jwt", "auth", "session", "access", "bearer", "key", "secret"}
            for k in ss:
                if any(h in k.lower() for h in token_hints):
                    if k not in result["token_keys"]:
                        result["token_keys"].append(k)
    except Exception as e:
        logger.debug("sessionStorage capture failed: %s", e)

    return result


def _is_still_on_login(page, login_url: str) -> bool:
    """Check if we're still on (or redirected back to) the login page after submit."""
    current = page.url.lower()
    login_lower = login_url.lower()
    # Same URL or login-like path
    if current == login_lower:
        return True
    path = urlparse(current).path.lower()
    return any(k in path for k in ["/login", "/signin", "/sign-in", "/auth/login"])


def _detect_error_message(page) -> Optional[str]:
    """Try to detect a visible login error message on the page."""
    error_selectors = [
        ".error", ".alert-danger", ".alert-error", ".login-error",
        "[role='alert']", ".invalid-feedback", ".form-error",
        ".message.error", ".notification.error", "#error-message",
        ".error-message", ".auth-error",
    ]
    for sel in error_selectors:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                text = el.inner_text().strip()
                if text:
                    return text[:200]
        except Exception:
            pass
    return None


def auto_login(
    page,
    login_url: str,
    username: str,
    password: str,
    timeout: int = 15,
) -> dict:
    """
    Attempt to log in via headless browser form submission.

    Args:
        page: Playwright page object (already has cookies/headers if any)
        login_url: URL of the login page
        username: Username or email to use
        password: Password to use
        timeout: Per-action timeout in seconds

    Returns dict:
        success          bool
        method           str  (form_submit / no_form_found / navigation_error)
        login_url        str
        final_url        str
        status           int
        username_field   str  (field name used)
        password_field   str  (field name used)
        cookie_string    str  (ready to pass to --cookie)
        cookies          list
        local_storage    dict
        session_storage  dict
        token_keys       list  (localStorage/sessionStorage keys that look like tokens)
        error_message    str  (page error text if login failed)
        error            str  (internal error if exception)
        steps            list  (what happened, for reporting)
    """
    result = {
        "success":        False,
        "method":         "unknown",
        "login_url":      login_url,
        "final_url":      login_url,
        "status":         0,
        "username_field": "",
        "password_field": "",
        "cookie_string":  "",
        "cookies":        [],
        "local_storage":  {},
        "session_storage": {},
        "token_keys":     [],
        "error_message":  "",
        "error":          "",
        "steps":          [],
    }

    domain = urlparse(login_url).netloc.split(":")[0]
    t_ms = timeout * 1000

    def step(msg):
        logger.info("AutoLogin: %s", msg)
        result["steps"].append(msg)

    try:
        # Step 1: Navigate to login page
        step(f"Navigating to {login_url}")
        resp = page.goto(login_url, timeout=t_ms, wait_until="domcontentloaded")
        if resp:
            result["status"] = resp.status

        # Wait for framework
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass

        # Step 2: Find login form
        step("Scanning page for login form")
        form, fields = _find_login_form(page)

        if not form:
            # Try waiting a bit — SPA may render form after JS loads
            try:
                page.wait_for_selector("input[type='password']", timeout=5000)
                form, fields = _find_login_form(page)
            except Exception:
                pass

        if not fields.get("password"):
            # Formless fallback — bare password input with no <form> wrapper
            fields = _find_formless_login(page)
            if fields.get("password"):
                step("No <form> found — using formless input detection")
                result["method"] = "formless"
            else:
                result["method"] = "no_form_found"
                result["error"]  = "No login form with a password field found on page"
                step("No login form found")
                return result

        # Get field names for reporting
        u_field = fields.get("username")
        p_field = fields.get("password")
        result["username_field"] = (
            u_field.get_attribute("name") or
            u_field.get_attribute("id") or "unknown"
        ) if u_field else "not_found"
        result["password_field"] = (
            p_field.get_attribute("name") or
            p_field.get_attribute("id") or "unknown"
        )

        step(f"Found login form — username field: '{result['username_field']}', password field: '{result['password_field']}'")

        # Step 3: Fill username
        if u_field:
            try:
                u_field.click(timeout=t_ms)
                u_field.fill("", timeout=t_ms)
                u_field.type(username, delay=30)
                step(f"Filled username: {username}")
            except Exception as e:
                step(f"Username fill warning: {e}")

        # Step 4: Fill password
        try:
            p_field.click(timeout=t_ms)
            p_field.fill("", timeout=t_ms)
            p_field.type(password, delay=30)
            step("Filled password (redacted)")
        except Exception as e:
            result["error"] = f"Password fill failed: {e}"
            step(f"Password fill error: {e}")
            return result

        # Step 5: Submit — try submit button first, then Enter key
        submit_btn = fields.get("submit")
        pre_submit_url = page.url

        if submit_btn:
            try:
                step("Clicking submit button")
                submit_btn.click(timeout=t_ms)
            except Exception:
                # Fallback: Enter on password field
                step("Submit button click failed — pressing Enter")
                try:
                    p_field.press("Enter")
                except Exception as e2:
                    result["error"] = f"Submit failed: {e2}"
                    return result
        else:
            step("No submit button found — pressing Enter on password field")
            try:
                p_field.press("Enter")
            except Exception as e:
                result["error"] = f"Enter key failed: {e}"
                return result

        if result["method"] != "formless":
            result["method"] = "form_submit"

        # Step 6: Wait for navigation / response
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass

        result["final_url"] = page.url

        # Step 7: Verify login outcome
        # Three success signals checked in order:
        #   1. URL changed away from login page (most reliable)
        #   2. Password field gone from DOM (SPA in-place render)
        #   3. Success indicator visible in DOM (dashboard/welcome/avatar elements)
        # Failure: still on login page + error message visible

        final_url_changed = result["final_url"] != pre_submit_url

        if final_url_changed and not _is_still_on_login(page, login_url):
            result["success"] = True
            step(f"Login successful - redirected to {result['final_url']}")
        else:
            # SPA check: password field removed from DOM = successful JS auth
            pw_gone = False
            try:
                pw_gone = not page.is_visible("input[type='password']")
            except Exception:
                pass

            # Success indicator: elements that typically appear after login
            # (nav avatar, dashboard header, account menu, logout link)
            spa_success = False
            if not pw_gone:
                _success_selectors = [
                    "[data-testid*='avatar']", "[data-testid*='account']",
                    "[aria-label*='account']", "[aria-label*='profile']",
                    ".user-menu", ".account-menu", "#user-nav", "#account-nav",
                    "a[href*='/logout']", "a[href*='/signout']", "a[href*='/log-out']",
                    ".dashboard", "#dashboard", "[class*='dashboard']",
                    "[class*='welcome']", "[class*='logged-in']",
                ]
                for sel in _success_selectors:
                    try:
                        if page.query_selector(sel) and page.is_visible(sel):
                            spa_success = True
                            step(f"Login successful - success indicator visible: {sel}")
                            break
                    except Exception:
                        pass

            if pw_gone:
                result["success"] = True
                step("Login successful - password field no longer visible (SPA auth)")
            elif spa_success:
                result["success"] = True
            else:
                error_msg = _detect_error_message(page)
                result["success"]       = False
                result["error_message"] = error_msg or "Still on login page after submit — check credentials"
                step(f"Login failed - {result['error_message']}")

        # Step 8: Capture session regardless (partial capture on failure is useful)
        step("Capturing session cookies and storage")
        session = _capture_session(page, domain)
        result["cookie_string"]  = session["cookie_string"]
        result["cookies"]        = session["cookies"]
        result["local_storage"]  = session["local_storage"]
        result["session_storage"] = session["session_storage"]
        result["token_keys"]     = session["token_keys"]

        if session["cookie_string"]:
            step(f"Captured {len(session['cookies'])} cookies")
        if session["token_keys"]:
            step(f"Found tokens in storage: {', '.join(session['token_keys'])}")

    except Exception as e:
        result["error"]  = str(e)
        result["method"] = "navigation_error"
        step(f"Exception: {e}")
        logger.debug("AutoLogin exception", exc_info=True)

    return result


def build_login_spec(username: str, password: str, login_url: str = "") -> str:
    """
    Build a --login compatible spec string from separate --username / --password flags.
    login_url is optional - if not provided, the target URL is used (cli.py handles that).
    """
    parts = []
    if login_url:
        parts.append(f"url={login_url}")
    parts.append(f"user={username}")
    parts.append(f"pass={password}")
    return ",".join(parts)


def parse_login_arg(login_str: str) -> dict:
    """
    Parse --login argument string into components.

    Formats supported:
      url=https://example.com/login,user=admin,pass=secret123
      https://example.com/login,user=admin,pass=secret123
      user=admin,pass=secret123   (uses target URL as login URL)

    Returns dict with keys: url, username, password, valid, error
    """
    result = {"url": "", "username": "", "password": "", "valid": False, "error": ""}

    if not login_str:
        result["error"] = "Empty --login value"
        return result

    # Split on comma but be careful about URLs containing commas
    # Use key=value parsing
    parts = {}
    # Try to parse key=value pairs
    # First check if there's a url= key or a bare URL
    remaining = login_str.strip()

    # Extract url= first (may contain commas in query strings)
    url_match = re.search(r'url=([^,]+(?:,[^=,]+(?:,[^=,]+)*)*?)(?:,(?:user|pass|username|password)=|$)', remaining)
    if url_match:
        parts["url"] = url_match.group(1).strip()
        remaining = remaining.replace(f"url={parts['url']}", "").strip(",").strip()
    elif remaining.startswith("http"):
        # Bare URL as first token
        tokens = remaining.split(",")
        parts["url"] = tokens[0].strip()
        remaining = ",".join(tokens[1:])

    # Parse remaining key=value pairs
    for token in remaining.split(","):
        token = token.strip()
        if "=" in token:
            k, _, v = token.partition("=")
            parts[k.strip().lower()] = v.strip()

    result["url"]      = parts.get("url", "")
    result["username"] = parts.get("user", parts.get("username", parts.get("email", "")))
    result["password"] = parts.get("pass", parts.get("password", ""))

    if not result["password"]:
        result["error"] = "Missing pass= in --login"
        return result

    result["valid"] = True
    return result
