"""
theme.py - Color and styling constants for BundleSpy terminal UI.

Exports: A, USE_COLOR, SEVERITY_COLOR, SEVERITY_LABEL, STATUS_COLOR
"""
from __future__ import annotations

import os
import sys

# ---------------------------------------------------------------------------
# Color toggle
# ---------------------------------------------------------------------------

USE_COLOR: bool = (
    os.environ.get("NO_COLOR") is None
    and os.environ.get("BUNDLESPY_NO_COLOR") is None
    and sys.stdout.isatty()
)


def _c(code: str) -> str:
    """Return ANSI escape if color is enabled, else empty string."""
    return f"\033[{code}m" if USE_COLOR else ""


# ---------------------------------------------------------------------------
# ANSI attribute namespace  (access as  A.GREEN, A.BOLD, etc.)
# ---------------------------------------------------------------------------

class _Attrs:
    # Reset
    RESET      = _c("0")

    # Styles
    BOLD       = _c("1")
    DIM        = _c("2")
    ITALIC     = _c("3")
    UNDERLINE  = _c("4")

    # Standard foreground colors
    BLACK      = _c("30")
    RED        = _c("31")
    GREEN      = _c("32")
    YELLOW     = _c("33")
    BLUE       = _c("34")
    MAGENTA    = _c("35")
    CYAN       = _c("36")
    WHITE      = _c("37")

    # Bright foreground colors
    BRIGHT_BLACK   = _c("90")   # grey
    BRIGHT_RED     = _c("91")
    BRIGHT_GREEN   = _c("92")
    BRIGHT_YELLOW  = _c("93")
    BRIGHT_BLUE    = _c("94")
    BRIGHT_MAGENTA = _c("95")
    BRIGHT_CYAN    = _c("96")
    BRIGHT_WHITE   = _c("97")

    # Background colors
    BG_BLACK   = _c("40")
    BG_RED     = _c("41")
    BG_GREEN   = _c("42")
    BG_YELLOW  = _c("43")
    BG_BLUE    = _c("44")
    BG_MAGENTA = _c("45")
    BG_CYAN    = _c("46")
    BG_WHITE   = _c("47")

    # Bright backgrounds
    BG_BRIGHT_RED    = _c("101")
    BG_BRIGHT_GREEN  = _c("102")
    BG_BRIGHT_YELLOW = _c("103")

    # Compound helpers (bold + color)
    B_RED     = _c("1;31")
    B_GREEN   = _c("1;32")
    B_YELLOW  = _c("1;33")
    B_BLUE    = _c("1;34")
    B_MAGENTA = _c("1;35")
    B_CYAN    = _c("1;36")
    B_WHITE   = _c("1;37")

    B_BRIGHT_RED    = _c("1;91")
    B_BRIGHT_GREEN  = _c("1;92")
    B_BRIGHT_YELLOW = _c("1;93")
    B_BRIGHT_CYAN   = _c("1;96")
    B_BRIGHT_WHITE  = _c("1;97")

    # Orange approximation (256-color)
    ORANGE         = _c("38;5;208") if USE_COLOR else ""
    BOLD_ORANGE    = _c("1;38;5;208") if USE_COLOR else ""

    # Gradient greens for banner (bright -> mid -> dim)
    BANNER_GREEN_1 = _c("1;92")   # bright green
    BANNER_GREEN_2 = _c("32")     # normal green
    BANNER_GREEN_3 = _c("2;32")   # dim green

    # Aliases used across the codebase
    GREY = _c("90")
    GRAY = _c("90")


A = _Attrs()


# ---------------------------------------------------------------------------
# Severity color map
# Maps severity string -> ANSI prefix  (used by printer + renderer)
# ---------------------------------------------------------------------------

SEVERITY_COLOR: dict[str, str] = {
    "critical" : A.B_BRIGHT_RED,
    "high"     : A.BOLD_ORANGE,
    "medium"   : A.B_YELLOW,
    "low"      : A.B_BLUE,
    "info"     : A.GREY,
    # uppercase variants
    "CRITICAL" : A.B_BRIGHT_RED,
    "HIGH"     : A.BOLD_ORANGE,
    "MEDIUM"   : A.B_YELLOW,
    "LOW"      : A.B_BLUE,
    "INFO"     : A.GREY,
}

# Severity dot colors (just the color, no bold) for inline use
SEVERITY_DOT_COLOR: dict[str, str] = {
    "critical" : A.BRIGHT_RED,
    "high"     : A.ORANGE,
    "medium"   : A.YELLOW,
    "low"      : A.BLUE,
    "info"     : A.GREY,
}

# Human-readable labels (uppercase, fixed width for alignment)
SEVERITY_LABEL: dict[str, str] = {
    "critical" : "CRITICAL",
    "high"     : "HIGH    ",
    "medium"   : "MEDIUM  ",
    "low"      : "LOW     ",
    "info"     : "INFO    ",
    "CRITICAL" : "CRITICAL",
    "HIGH"     : "HIGH    ",
    "MEDIUM"   : "MEDIUM  ",
    "LOW"      : "LOW     ",
    "INFO"     : "INFO    ",
}

# Status colors for validation states
STATUS_COLOR: dict[str, str] = {
    "confirmed"       : A.B_BRIGHT_RED,
    "likely_secret"   : A.B_RED,
    "possible_secret" : A.B_YELLOW,
    "unlikely"        : A.GREY,
    "unknown"         : A.WHITE,
    "valid"           : A.B_BRIGHT_RED,
    "invalid"         : A.GREY,
    "error"           : A.YELLOW,
    "skipped"         : A.DIM,
}

# Section accent colors (used by renderer._section)
SECTION_COLOR: dict[str, str] = {
    "findings"    : A.B_BRIGHT_RED,
    "secrets"     : A.B_BRIGHT_RED,
    "endpoints"   : A.B_BLUE,
    "discovery"   : A.B_CYAN,
    "sourcemaps"  : A.B_YELLOW,
    "subdomains"  : A.B_GREEN,
    "default"     : A.B_WHITE,
}
