"""
renderer.py - Low-level rendering primitives for BundleSpy terminal UI.

Exports: term_width, divider, section, kv, truncate, truncate_url,
         severity_badge, redact, bullet, indent_block, two_col_table,
         count_table, severity_table, progress_bar
"""
from __future__ import annotations

import os
import shutil
import re

from .theme import A, USE_COLOR, SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_DOT_COLOR

# ---------------------------------------------------------------------------
# Terminal width helpers
# ---------------------------------------------------------------------------

def term_width() -> int:
    """Return current terminal width, clamped to a sane range."""
    try:
        return max(60, min(shutil.get_terminal_size((80, 24)).columns, 110))
    except Exception:
        return 100


def _w() -> int:
    """Shorthand for current terminal width."""
    return term_width()


def _p(text: str = "") -> None:
    """Print a line (single point of output for easy mock/redirect)."""
    print(text)


def _vis_len(s: str) -> int:
    """Return visible character length of a string, stripping ANSI codes."""
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def _pad(s: str, width: int, fill: str = " ") -> str:
    """Pad string to visible width using fill character."""
    vis = _vis_len(s)
    diff = width - vis
    if diff <= 0:
        return s
    return s + fill * diff


# ---------------------------------------------------------------------------
# Box-drawing character sets
# ---------------------------------------------------------------------------

# Double-line box (used for major containers: header, summary)
D = {
    "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝",
    "h": "═",  "v": "║",  "ml": "╠", "mr": "╣",
}

# Single-line box (used for sections, finding cards)
S = {
    "tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
    "h": "─",  "v": "│",  "ml": "├", "mr": "┤",
}


# ---------------------------------------------------------------------------
# Core drawing helpers
# ---------------------------------------------------------------------------

def _hline_d(width: int, color: str = "") -> str:
    """Double-line horizontal rule, full width."""
    return color + D["h"] * width + A.RESET


def _hline_s(width: int, color: str = "") -> str:
    """Single-line horizontal rule, full width."""
    return color + S["h"] * width + A.RESET


def _box_top_d(width: int, color: str = "") -> str:
    inner = D["h"] * (width - 2)
    return color + D["tl"] + inner + D["tr"] + A.RESET


def _box_bot_d(width: int, color: str = "") -> str:
    inner = D["h"] * (width - 2)
    return color + D["bl"] + inner + D["br"] + A.RESET


def _box_mid_d(width: int, color: str = "") -> str:
    inner = D["h"] * (width - 2)
    return color + D["ml"] + inner + D["mr"] + A.RESET


def _box_row_d(content: str, width: int, color: str = "") -> str:
    """Single row inside a double-line box, padded to width."""
    inner_w = width - 4  # 2 for borders + 2 for spaces
    padded = _pad(content, inner_w)
    return color + D["v"] + A.RESET + "  " + padded + "  " + color + D["v"] + A.RESET


def _box_top_s(width: int, color: str = "") -> str:
    inner = S["h"] * (width - 2)
    return color + S["tl"] + inner + S["tr"] + A.RESET


def _box_bot_s(width: int, color: str = "") -> str:
    inner = S["h"] * (width - 2)
    return color + S["bl"] + inner + S["br"] + A.RESET


def _box_mid_s(width: int, color: str = "") -> str:
    inner = S["h"] * (width - 2)
    return color + S["ml"] + inner + S["mr"] + A.RESET


def _box_row_s(content: str, width: int, color: str = "") -> str:
    """Single row inside a single-line box, padded to width."""
    inner_w = width - 4
    padded = _pad(content, inner_w)
    return color + S["v"] + A.RESET + "  " + padded + "  " + color + S["v"] + A.RESET


# ---------------------------------------------------------------------------
# Public primitives
# ---------------------------------------------------------------------------

def divider(char: str = S["h"], color: str = "") -> None:
    """Print a full-width horizontal divider."""
    w = _w()
    _p((color or A.BRIGHT_BLACK) + char * w + A.RESET)


def section(title: str, count: str = "", color: str = "") -> None:
    """
    Print a modern section header.

    Renders:
      ┌─[ TITLE ]──────────────────────────── count ──┐

    Parameters
    ----------
    title : str
        Section name (displayed uppercase).
    count : str
        Optional count or annotation shown right-aligned.
    color : str
        ANSI color prefix for the header chrome.
    """
    w = _w()
    c = color or A.B_WHITE
    title_upper = title.upper()
    label_part = f"[ {title_upper} ]"
    # Compose: tl + h + label_part + h*fill + count_part + tr
    if count:
        count_part = f" {count} "
    else:
        count_part = ""

    prefix = S["h"] + label_part + S["h"]
    suffix = count_part + S["h"]
    # Available fill between prefix and suffix
    fill_len = w - 2 - len(prefix) - len(suffix)
    fill = S["h"] * max(0, fill_len)
    line = (
        c + S["tl"] + S["h"] + label_part + S["h"]
        + fill
        + (A.RESET + A.DIM + count_part + c if count_part else "")
        + S["h"] + S["tr"] + A.RESET
    )
    _p("")
    _p(line)


def kv(label: str, value: str, label_width: int = 10) -> None:
    """Print a key-value pair with aligned label."""
    lbl = (A.GREY + label.upper().ljust(label_width) + A.RESET)
    _p(f"  {lbl}  {value}")


def truncate(text: str, max_len: int = 80, suffix: str = "...") -> str:
    """Truncate text to max_len visible characters."""
    if len(text) <= max_len:
        return text
    return text[: max_len - len(suffix)] + suffix


def truncate_url(url: str, max_len: int = 60) -> str:
    """
    Truncate a URL intelligently, preserving the scheme+host and tail.
    Example: https://example.com/.../very-long-path/file.js
    """
    if len(url) <= max_len:
        return url
    # Try to keep scheme+host
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    tail_len = max_len - len(base) - 5  # 5 for "/.../"
    if tail_len < 6:
        return truncate(url, max_len)
    tail = parsed.path[-tail_len:] if len(parsed.path) > tail_len else parsed.path
    return base + "/.../" + tail.lstrip("/")


def severity_badge(severity: str) -> str:
    """
    Return a colored severity badge string.
    Example: A.B_RED + "● HIGH" + A.RESET
    """
    sev = severity.lower()
    dot_color = SEVERITY_DOT_COLOR.get(sev, A.WHITE)
    label_color = SEVERITY_COLOR.get(sev, A.WHITE)
    label = SEVERITY_LABEL.get(sev, severity.upper().ljust(8))
    return dot_color + "●" + A.RESET + " " + label_color + label.strip() + A.RESET


def redact(value: str, show: int = 4, char: str = "•") -> str:
    """
    Redact sensitive string, showing only leading/trailing chars.
    Example:  AKIA + 12 bullets + XXYZ
    """
    if len(value) <= show * 2:
        return char * len(value)
    head = value[:show]
    tail = value[-show:]
    mid = char * min(12, max(4, len(value) - show * 2))
    return head + mid + tail


def bullet(text: str, level: int = 0, color: str = "") -> None:
    """Print a bullet line with optional indent level."""
    markers = ["•", "·", "-"]
    marker = markers[min(level, len(markers) - 1)]
    indent = "  " + "    " * level
    c = color or (A.GREY if level > 0 else A.WHITE)
    _p(f"{indent}{c}{marker}{A.RESET}  {text}")


def indent_block(lines: list[str], indent: int = 4) -> None:
    """Print each line indented by `indent` spaces."""
    pad = " " * indent
    for line in lines:
        _p(pad + line)


def two_col_table(rows: list[tuple[str, str]], col1_width: int = 24) -> None:
    """
    Print a two-column table without borders.
    rows: list of (label, value) tuples
    """
    for label, value in rows:
        lbl = (A.GREY + label.ljust(col1_width) + A.RESET)
        _p(f"  {lbl}  {value}")


def count_table(items: dict[str, int], columns: int = 3) -> None:
    """
    Print a count summary table.
    items: dict of label -> count
    columns: how many columns across
    """
    pairs = list(items.items())
    if not pairs:
        return
    col_w = (_w() - 4) // columns
    row = ""
    col = 0
    for label, count in pairs:
        cell = f"{A.BRIGHT_WHITE}{str(count).rjust(5)}{A.RESET}  {A.GREY}{label}{A.RESET}"
        row += _pad(cell, col_w)
        col += 1
        if col >= columns:
            _p("  " + row)
            row = ""
            col = 0
    if row:
        _p("  " + row)


def severity_table(counts: dict[str, int]) -> None:
    """
    Print colored severity count blocks.
    counts: dict of severity_key -> int
    """
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        n = counts.get(sev, counts.get(sev.upper(), 0))
        if n == 0:
            continue
        dot_c = SEVERITY_DOT_COLOR.get(sev, A.WHITE)
        lbl_c = SEVERITY_COLOR.get(sev, A.WHITE)
        label = SEVERITY_LABEL.get(sev, sev.upper()).ljust(10)
        blocks = dot_c + "██" + A.RESET
        _p(f"  {blocks}  {lbl_c}{label}{A.RESET}  {A.BRIGHT_WHITE}{n}{A.RESET}")


def progress_bar(
    current: int,
    total: int,
    width: int = 40,
    label: str = "",
    show_pct: bool = True,
) -> str:
    """
    Return a styled progress bar string.

      ━━━━━━━━━━━━━━━━━━━━░░░░░░░░░░  47%  [9/20]

    Parameters
    ----------
    current : int
    total : int
    width : int   visible bar width in characters
    label : str   optional trailing label
    show_pct : bool
    """
    if total <= 0:
        pct = 0.0
    else:
        pct = min(1.0, current / total)

    filled = int(pct * width)
    empty = width - filled

    bar_filled = A.CYAN + "━" * filled + A.RESET
    bar_empty  = A.BRIGHT_BLACK + "░" * empty + A.RESET

    parts = ["  ", bar_filled, bar_empty]
    if show_pct:
        parts.append(f"  {A.BRIGHT_WHITE}{int(pct * 100):3d}%{A.RESET}")
    if total > 0:
        parts.append(f"  {A.GREY}[{current}/{total}]{A.RESET}")
    if label:
        parts.append(f"  {label}")

    return "".join(parts)
