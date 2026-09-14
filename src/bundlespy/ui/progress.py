"""
Real-time progress renderer for BundleSpy.
Updates a single line in-place — no terminal spam.
"""

import sys
import time
import threading
import shutil
from typing import Optional


def _w() -> int:
    try:
        return min(shutil.get_terminal_size((80, 24)).columns, 110)
    except Exception:
        return 80


class LiveProgress:
    """
    Single-line live progress updater.
    Shows a spinner + current stat counts while the scan runs.
    Updates in-place using carriage return.
    """

    SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label: str = "Scanning"):
        self.label    = label
        self.pages    = 0
        self.js       = 0
        self.findings = 0
        self.endpoints = 0
        self._running  = False
        self._thread:  Optional[threading.Thread] = None
        self._idx      = 0
        self._start    = time.monotonic()

    def update(self, pages: int = None, js: int = None,
               findings: int = None, endpoints: int = None) -> None:
        if pages    is not None: self.pages     = pages
        if js       is not None: self.js        = js
        if findings is not None: self.findings  = findings
        if endpoints is not None: self.endpoints = endpoints

    def _render(self) -> str:
        from .theme import A
        spin    = self.SPINNERS[self._idx % len(self.SPINNERS)]
        elapsed = time.monotonic() - self._start
        parts   = []
        if self.pages:
            parts.append(f"{self.pages} pages")
        if self.js:
            parts.append(f"{self.js} JS")
        if self.endpoints:
            parts.append(f"{self.endpoints} endpoints")
        if self.findings:
            parts.append(f"{A.RED}{self.findings} findings{A.RESET}")
        stats   = "  ".join(parts) if parts else "starting..."
        elapsed_str = f"{elapsed:.0f}s"
        line    = f"  {A.CYAN}{spin}{A.RESET}  {self.label}  {A.GREY}{stats}  {elapsed_str}{A.RESET}"
        # Truncate to terminal width
        max_w = _w() - 2
        if len(line) > max_w:
            line = line[:max_w]
        return line

    def _loop(self) -> None:
        import os
        is_tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        while self._running:
            if is_tty:
                line = self._render()
                sys.stdout.write(f"\r{line}")
                sys.stdout.flush()
            self._idx += 1
            time.sleep(0.1)

    def start(self) -> None:
        if not sys.stdout.isatty():
            return
        self._running = True
        self._start   = time.monotonic()
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self, final_line: str = "") -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        if sys.stdout.isatty():
            # Clear the progress line
            sys.stdout.write(f"\r{' ' * (_w())}\r")
            sys.stdout.flush()
        if final_line:
            print(final_line)


class ScanProgress:
    """
    Higher-level scan progress tracker.
    Shows crawl progress and updates as pages/JS are discovered.
    """

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._live: Optional[LiveProgress] = None

    def start_crawl(self) -> None:
        if self.quiet:
            return
        self._live = LiveProgress("Crawling")
        self._live.start()

    def update_crawl(self, pages: int, js: int) -> None:
        if self._live:
            self._live.update(pages=pages, js=js)

    def finish_crawl(self, pages: int, js: int) -> None:
        from .theme import A
        if self._live:
            self._live.stop()
        if not self.quiet:
            detail = f"{pages} pages  {js} JS files"
            print(f"  {A.GREEN}✓{A.RESET}  Crawl complete  {A.GREY}{detail}{A.RESET}")

    def start_analysis(self) -> None:
        if self.quiet:
            return
        self._live = LiveProgress("Analyzing")
        self._live.start()

    def update_analysis(self, findings: int = 0, endpoints: int = 0) -> None:
        if self._live:
            self._live.update(findings=findings, endpoints=endpoints)

    def finish_analysis(self, findings: int, endpoints: int, infra: int) -> None:
        from .theme import A
        if self._live:
            self._live.stop()
        if not self.quiet:
            detail = f"{findings} findings  {endpoints} endpoints  {infra} infrastructure"
            print(f"  {A.GREEN}✓{A.RESET}  Analysis complete  {A.GREY}{detail}{A.RESET}")
