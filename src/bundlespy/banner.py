"""
banner.py - ASCII art banner for BundleSpy.

Exports: print_banner(no_color=False)
"""

from .theme import A, USE_COLOR
from .renderer import _p, _w, _vis_len, _pad

# ---------------------------------------------------------------------------
# ASCII art definition
# Each entry: (line_text, gradient_tier)  tier 0=brightest, 1=mid, 2=dim
# ---------------------------------------------------------------------------

_ASCII_ROWS = [
    ("  ██████╗ ██╗   ██╗███╗   ██╗██████╗ ██╗     ███████╗",  0),
    ("  ██╔══██╗██║   ██║████╗  ██║██╔══██╗██║     ██╔════╝",  0),
    ("  ██████╔╝██║   ██║██╔██╗ ██║██║  ██║██║     █████╗  ",  1),
    ("  ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██║     ██╔══╝  ",  1),
    ("  ██████╔╝╚██████╔╝██║ ╚████║██████╔╝███████╗███████╗",  2),
    ("  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝", 2),
]

_ASCII_SPY = [
    ("  ███████╗██████╗ ██╗   ██╗", 0),
    ("  ██╔════╝██╔══██╗╚██╗ ██╔╝", 0),
    ("  ███████╗██████╔╝ ╚████╔╝ ", 1),
    ("  ╚════██║██╔═══╝   ╚██╔╝  ", 1),
    ("  ███████║██║        ██║   ", 2),
    ("  ╚══════╝╚═╝        ╚═╝   ", 2),
]

_GRADIENT = [
    A.BANNER_GREEN_1,  # tier 0 - bright
    A.BANNER_GREEN_2,  # tier 1 - normal
    A.BANNER_GREEN_3,  # tier 2 - dim
]

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

_META = {
    "Author"  : "BundleSpy Team",
    "Version" : "2.0.0",
    "GitHub"  : "github.com/bundlespy/bundlespy",
    "PyPI"    : "pypi.org/project/bundlespy",
}

_TAGLINE = "JavaScript Bundle Reconnaissance Framework"


def _meta_box(no_color: bool) -> None:
    """Render a thin single-line box around the metadata block."""
    c = (lambda s: "") if no_color else (lambda s: s)
    w = _w()
    inner_w = min(w - 4, 58)  # box inner width

    tl, tr, bl, br, h, v = "┌", "┐", "└", "┘", "─", "│"
    ml, mr = "├", "┤"

    box_color = c(A.BRIGHT_BLACK)
    key_color = c(A.GREY)
    val_color = c(A.BRIGHT_WHITE)
    reset     = c(A.RESET)

    def _row(key: str, val: str) -> str:
        content = f"{key_color}{key:<8}{reset}  {val_color}{val}{reset}"
        # pad to inner_w visible chars
        vis = len(key) + 2 + len(val)
        pad = max(0, inner_w - vis) * " "
        return f"  {box_color}{v}{reset}  {key_color}{key:<8}{reset}  {val_color}{val}{reset}{pad}  {box_color}{v}{reset}"

    _p(f"  {box_color}{tl}{h * (inner_w + 4)}{tr}{reset}")
    for key, val in _META.items():
        _p(_row(key, val))
    _p(f"  {box_color}{ml}{h * (inner_w + 4)}{mr}{reset}")
    # Tagline row
    tag_pad = max(0, inner_w - len(_TAGLINE)) * " "
    _p(f"  {box_color}{v}{reset}  {c(A.DIM)}{_TAGLINE}{tag_pad}{reset}  {box_color}{v}{reset}")
    _p(f"  {box_color}{bl}{h * (inner_w + 4)}{br}{reset}")


def print_banner(no_color: bool = False) -> None:
    """
    Print the BundleSpy ASCII art banner with metadata box.

    Parameters
    ----------
    no_color : bool
        Force plain output (no ANSI codes) regardless of environment.
    """
    c = (lambda s: "") if no_color else (lambda s: s)
    reset = c(A.RESET)

    _p("")
    # ASCII art with gradient
    for line, tier in _ASCII_ROWS:
        color = c(_GRADIENT[tier])
        _p(f"{color}{line}{reset}")

    _p("")

    # SPY sub-text in brighter green, right-aligned relative to BUNDLE block
    for line, tier in _ASCII_SPY:
        color = c(_GRADIENT[max(0, tier - 1)])  # one tier brighter for SPY
        _p(f"  {color}{line.strip():<30}{reset}")

    _p("")

    # Metadata box
    _meta_box(no_color)

    # Warning line
    _p("")
    warn_color = c(A.B_BRIGHT_RED)
    _p(f"  {warn_color}[ ! ]  AUTHORIZED USE ONLY  -  Unauthorized scanning is illegal{reset}")
    _p("")
