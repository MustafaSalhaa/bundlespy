"""
Terminal report entry point.
Delegates all rendering to the UI layer.
"""

from ..storage.models import ScanResult
from ..ui.printer import (
    print_js_inventory, print_findings, print_endpoints,
    print_infrastructure, print_subdomains, print_summary,
    print_source_maps, print_webpack, print_passive,
    print_headless, print_graphql, print_secret_analysis,
    print_attack_surface, print_coverage, _print_libraries,
)


def print_report(
    result:             ScanResult,
    show_sensitive:     bool  = True,   # kept for API compat, terminal always redacts
    no_color:           bool  = False,
    min_severity:       str   = "INFO",
    extras:             dict  = None,
    validation_results: list  = None,
    graphql_schemas:    list  = None,
    subdomains:         list  = None,
    report_paths:       dict  = None,
    verbose:            bool  = False,
) -> None:
    extras = extras or {}

    print_js_inventory(result.js_files, verbose=verbose,
                        per_file_stats=extras.get('per_file_stats') if extras else None)

    # Feature summaries
    if extras.get("source_map_details"):
        d = extras["source_map_details"]
        print_source_maps(
            discovered=d.get("discovered", 0),
            valid=d.get("valid", 0),
            recovered=d.get("recovered", 0),
            sources=d.get("sources", 0),
            details=d.get("items", []),
        )
    if extras.get("chunk_stats"):
        c = extras["chunk_stats"]
        print_webpack(
            runtime=c.get("runtime", False),
            discovered=c.get("discovered", 0),
            downloaded=c.get("downloaded", 0),
            endpoints=c.get("endpoints", 0),
            findings=c.get("findings", 0),
        )
    if extras.get("passive_stats"):
        p = extras["passive_stats"]
        print_passive(
            source=p.get("source", "Wayback + CommonCrawl"),
            urls=p.get("urls", 0),
            js=p.get("js", 0),
            unique=p.get("unique", 0),
            new=p.get("new", 0),
        )
    if extras.get("headless_stats"):
        h = extras["headless_stats"]
        print_headless(
            pages=h.get("pages", 0),
            js=h.get("js", 0),
            xhr=h.get("xhr", 0),
            fetch=h.get("fetch", 0),
            ws=h.get("ws", 0),
            routes=h.get("routes", 0),
            endpoints=h.get("endpoints", 0),
            workers=h.get("workers", 0),
            timings=h.get("timings"),
        )

    print_secret_analysis(result.findings)
    print_findings(result.findings, verbose=verbose)
    print_endpoints(result.endpoints, validation_results=validation_results, verbose=verbose)

    if graphql_schemas:
        print_graphql(graphql_schemas)

    print_infrastructure(result.infrastructure)

    if subdomains:
        print_subdomains(subdomains)

    # Vulnerable libraries
    if extras.get("lib_findings"):
        _print_libraries(extras["lib_findings"])

    # Attack surface
    surface = extras.get("attack_surface")
    if surface:
        print_attack_surface(surface)

    # Coverage and blind spots
    coverage = extras.get("coverage")
    if coverage:
        print_coverage(coverage)

    print_summary(result, extras=extras, report_paths=report_paths)
