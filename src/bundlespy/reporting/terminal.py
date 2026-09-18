"""
Terminal report entry point.
Delegates all rendering to the UI layer (ui/printer.py).

This file is a thin pass-through - all logic lives in printer.py.
"""

from __future__ import annotations

from ..storage.models import ScanResult
from ..ui.printer import print_report as _printer_print_report


def print_report(
    result:             ScanResult,
    show_sensitive:     bool  = True,
    no_color:           bool  = False,
    min_severity:       str   = "INFO",
    extras:             dict  = None,
    validation_results: list  = None,
    graphql_schemas:    list  = None,
    subdomains:         list  = None,
    report_paths:       dict  = None,
    verbose:            bool  = False,
) -> None:
    """Entry point for terminal report. Delegates to ui.printer.print_report."""
    _printer_print_report(
        result             = result,
        show_sensitive     = show_sensitive,
        no_color           = no_color,
        min_severity       = min_severity,
        extras             = extras,
        validation_results = validation_results,
        graphql_schemas    = graphql_schemas,
        subdomains         = subdomains,
        report_paths       = report_paths,
        verbose            = verbose,
    )
