"""
Core renderer — terminal width, dividers, headers, tables, truncation.
Everything goes through here so layout is consistent everywhere.
"""

import os
import shutil
from typing import List, Optional, Tuple

from .theme import A


def term_width() -> int:
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def _w() -> int:
    return min(term_width(), 100)


def divider(char: str = "─", color: str = "") -> str:
    rst = A.RESET if color else ""
    return f"{color}{char * _w()}{rst}"


def section(title: str, subtitle: str = "") -> str:
    sub = f"  {A.GREY}{subtitle}{A.RESET}" if subtitle else ""
    return f"\n{A.BOLD}{A.WHITE}{title}{A.RESET}{sub}\n{A.GREY}{divider()}{A.RESET}"


def kv(label: str, value: str, label_width: int = 16, value_color: str = "") -> str:
    rst = A.RESET if value_color else ""
    padded = label.ljust(label_width)
    return f"  {A.GREY}{padded}{A.RESET}  {value_color}{value}{rst}"


def truncate(text: str, max_len: int = 80, placeholder: str = "...") -> str:
    if len(text) <= max_len:
        return text
    keep = max_len - len(placeholder)
    return text[:keep] + placeholder


def truncate_url(url: str, max_len: int = None) -> str:
    if max_len is None:
        max_len = _w() - 10
    return truncate(url, max_len)


def severity_badge(severity: str) -> str:
    from .theme import SEVERITY_COLOR, SEVERITY_LABEL
    color = SEVERITY_COLOR.get(severity, "")
    label = SEVERITY_LABEL.get(severity, f"[{severity}]")
    return f"{color}{label}{A.RESET}"


def redact(value: str) -> str:
    """Always redact secrets in terminal output."""
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    last4 = value[-4:]
    dots  = "•" * min(16, len(value) - 4)
    return f"{dots}{last4}"


def bullet(text: str, indent: int = 2, marker: str = "  ") -> str:
    return f"{' ' * indent}{A.GREY}{marker}{A.RESET}{text}"


def indent_block(lines: List[str], indent: int = 4) -> str:
    prefix = " " * indent
    return "\n".join(prefix + line for line in lines)


def two_col_table(
    rows:        List[Tuple[str, str]],
    col1_width:  int  = 24,
    indent:      int  = 2,
    label_color: str  = "",
    value_color: str  = "",
) -> str:
    out = []
    for label, value in rows:
        lc  = label_color or A.GREY
        vc  = value_color or A.WHITE
        pad = label.ljust(col1_width)
        out.append(f"{' ' * indent}{lc}{pad}{A.RESET}  {vc}{value}{A.RESET}")
    return "\n".join(out)


def count_table(
    rows:   List[Tuple[str, int]],
    indent: int = 2,
    col_w:  int = 20,
) -> str:
    out = []
    for label, count in rows:
        pad  = label.ljust(col_w)
        cstr = str(count).rjust(6)
        out.append(f"{' ' * indent}{A.GREY}{pad}{A.RESET}  {A.WHITE}{cstr}{A.RESET}")
    return "\n".join(out)


def severity_table(counts: dict) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    from .theme import SEVERITY_COLOR
    lines = []
    for sev in order:
        n = counts.get(sev, 0)
        if n == 0:
            continue
        color = SEVERITY_COLOR.get(sev, "")
        label = sev.ljust(10)
        lines.append(f"  {color}{label}{A.RESET}  {A.WHITE}{str(n).rjust(5)}{A.RESET}")
    return "\n".join(lines) if lines else f"  {A.GREY}none{A.RESET}"


def progress_bar(current: int, total: int, width: int = 24) -> str:
    if total == 0:
        return "[-]"
    pct   = current / total
    filled = int(width * pct)
    bar   = "█" * filled + "░" * (width - filled)
    return f"{A.CYAN}[{bar}]{A.RESET}  {int(pct * 100):3d}%  {current}/{total}"
