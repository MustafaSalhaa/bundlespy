"""
Theme — centralized colors, symbols, severity styling.
Respects NO_COLOR env var and non-TTY environments automatically.
"""

import os
import sys


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


USE_COLOR = _use_color()


class _Noop:
    def __getattr__(self, _): return ""


class _Ansi:
    # Foreground
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    PURPLE  = "\033[95m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    # Style
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


if USE_COLOR:
    A = _Ansi()
else:
    A = _Noop()


SEVERITY_COLOR = {
    "CRITICAL": A.RED    + A.BOLD,
    "HIGH":     A.ORANGE + A.BOLD,
    "MEDIUM":   A.YELLOW,
    "LOW":      A.BLUE,
    "INFO":     A.GREY,
}

SEVERITY_LABEL = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]    ",
    "MEDIUM":   "[MEDIUM]  ",
    "LOW":      "[LOW]     ",
    "INFO":     "[INFO]    ",
}

STATUS_COLOR = {
    "likely_secret":         A.RED,
    "validated":             A.RED + A.BOLD,
    "candidate":             A.YELLOW,
    "likely_false_positive": A.GREY,
}
