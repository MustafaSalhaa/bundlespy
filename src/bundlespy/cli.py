"""
BundleSpy CLI — clean, automation-friendly, no interactive prompts.
"""

import sys
import os
import argparse
import logging
from datetime import datetime
from pathlib import Path

from .config import BundleSpyConfig, CrawlerConfig, ScopeConfig, ReportingConfig
from .config import PROJECT_NAME, PROJECT_VERSION, AUTHOR_NAME, GITHUB_URL
from .safety.network import validate_url
from .crawler.fetcher import Fetcher
from .crawler.scope import ScopeChecker
from .crawler.crawler import Crawler
from .analysis.secrets import SecretScanner
from .analysis.endpoints import extract_endpoints
from .analysis.infrastructure import extract_infrastructure
from .analysis.jwt import find_jwts
from .storage.models import ScanResult, Finding, Endpoint, InfrastructureItem, JSFile
from .reporting.terminal import print_report
from .reporting.json_report import generate as generate_json
from .reporting.html_report import generate as generate_html
from .reporting.csv_report import generate as generate_csv
from .reporting.burp_export import generate_burp_xml, generate_url_list
from .ui.printer import (
    print_header, phase, phase_done, phase_warn, phase_error,
    print_discovery,
)
from .ui.theme import A


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bundlespy",
        description="BundleSpy — JavaScript Intelligence and Secret Exposure Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
examples:
  bundlespy scan https://example.com
  bundlespy scan https://example.com --source-maps --chunks --validate
  bundlespy scan https://example.com --passive --format html --output ./reports/
  bundlespy scan https://example.com --headless --stealth
  bundlespy scan https://example.com --graphql --harvest-subs
  bundlespy scan https://example.com --format html,json,burp --output ./reports/
  bundlespy local ./dist/
  bundlespy demo
""",
    )

    sub = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Scan a target URL")
    scan.add_argument("target")

    # Crawl
    scan.add_argument("--depth",       type=int, default=2)
    scan.add_argument("--max-pages",   type=int, default=100)
    scan.add_argument("--max-js",      type=int, default=200)
    scan.add_argument("--rate",        type=int, default=2)
    scan.add_argument("--timeout",     type=int, default=10)
    scan.add_argument("--common-paths",action="store_true")
    scan.add_argument("--subdomains",  action="store_true")
    scan.add_argument("--exclude",     nargs="+", default=[])

    # Features
    scan.add_argument("--source-maps",    action="store_true")
    scan.add_argument("--chunks",         action="store_true")
    scan.add_argument("--passive",        action="store_true")
    scan.add_argument("--headless",       action="store_true")
    scan.add_argument("--validate",       action="store_true")
    scan.add_argument("--graphql",        action="store_true")
    scan.add_argument("--harvest-subs",   action="store_true")
    scan.add_argument("--validate-secrets", action="store_true")
    scan.add_argument("--stealth",        action="store_true")

    # Output
    scan.add_argument("--format", default="terminal")
    scan.add_argument("--output", default="")
    scan.add_argument("-v", "--verbose",  action="store_true")
    scan.add_argument("-vv","--debug",    action="store_true")
    scan.add_argument("-q", "--quiet",    action="store_true")
    scan.add_argument("--no-color",       action="store_true")
    scan.add_argument("--json",           action="store_true", help="JSON output only")
    scan.add_argument("--csv",            action="store_true", help="CSV output only")

    # ── local ─────────────────────────────────────────────────────────────────
    local = sub.add_parser("local", help="Scan local JS files")
    local.add_argument("path")
    local.add_argument("--format",   default="terminal")
    local.add_argument("--output",   default="")
    local.add_argument("-v", "--verbose", action="store_true")
    local.add_argument("--no-color", action="store_true")

    # ── demo ──────────────────────────────────────────────────────────────────
    sub.add_parser("demo", help="Run offline demo")

    return parser


def _setup_logging(verbose: bool, debug: bool, quiet: bool) -> None:
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="  %(message)s",
    )


def _write_reports(
    result:    ScanResult,
    formats:   list,
    output_dir: str,
    started:   datetime,
) -> dict:
    """Write file reports. Returns dict of format -> path."""
    ts      = started.strftime("%Y%m%d_%H%M%S")
    paths   = {}

    if "json" in formats:
        out = generate_json(result)
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"bundlespy_{ts}.json"
        p.write_text(out)
        paths["json"] = str(p)

    if "html" in formats:
        out = generate_html(result)
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"bundlespy_{ts}.html"
        p.write_text(out)
        paths["html"] = str(p)

    if "csv" in formats:
        out = generate_csv(result)
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"bundlespy_{ts}.csv"
        p.write_text(out)
        paths["csv"] = str(p)

    if "burp" in formats:
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p1  = Path(d) / f"bundlespy_{ts}_burp.xml"
        p2  = Path(d) / f"bundlespy_{ts}_urls.txt"
        p1.write_text(generate_burp_xml(result))
        p2.write_text(generate_url_list(result))
        paths["burp-xml"]  = str(p1)
        paths["burp-urls"] = str(p2)

    return paths


def _analyze(js_files: list, scanner: SecretScanner) -> tuple:
    findings   = []
    endpoints  = []
    infra      = []
    for js in js_files:
        findings.extend(scanner.scan(js.content, js.url, js.source_page))
        endpoints.extend(extract_endpoints(js.content, js.url))
        infra.extend(extract_infrastructure(js.content, js.url))
    return findings, endpoints, infra


def run_scan(args) -> int:
    # Handle --json / --csv shortcuts
    if args.json:
        args.format = "json"
        args.quiet  = True
    if args.csv:
        args.format = "csv"
        args.quiet  = True

    _setup_logging(args.verbose, getattr(args, "debug", False), args.quiet)

    # Apply NO_COLOR
    if args.no_color or os.environ.get("NO_COLOR"):
        os.environ["NO_COLOR"] = "1"

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Safety check — fail cleanly, no prompt
    safe, reason = validate_url(target, check_dns=False)
    if not safe:
        phase_error(f"Target blocked by safety policy: {reason}")
        return 2

    formats = [f.strip() for f in args.format.split(",")]
    started = datetime.utcnow()
    extras  = {}

    if not args.quiet:
        mode = "Passive" if args.passive else ("Headless" if args.headless else "Active")
        if args.stealth:
            mode += " + Stealth"
        scope_label = "Subdomains included" if args.subdomains else "Strict"
        print_header(target, mode=mode, scope=scope_label, version=PROJECT_VERSION, author=AUTHOR_NAME)

    fetcher = Fetcher(
        timeout=args.timeout,
        requests_per_second=args.rate,
        stealth=args.stealth,
    )
    scope = ScopeChecker(
        target_url=target,
        same_origin=True,
        subdomains=args.subdomains,
        exclude=args.exclude,
    )

    all_js: list = []
    errors: list = []

    # ── Active crawl ──────────────────────────────────────────────────────────
    if not args.passive:
        if not args.quiet:
            phase("Crawling target")
        crawler = Crawler(
            target_url=target, fetcher=fetcher, scope=scope,
            max_depth=args.depth, max_pages=args.max_pages,
            max_js_files=args.max_js, common_paths=args.common_paths,
        )
        try:
            crawler.crawl()
        except KeyboardInterrupt:
            phase_warn("Scan interrupted by user")
            return 0

        errors.extend(crawler.errors)
        all_js.extend(crawler.js_files)

        for script_content, source_page in crawler.inline_scripts:
            import hashlib
            all_js.append(JSFile(
                url="inline:" + source_page, source_page=source_page,
                status_code=200, content_type="text/javascript",
                size_bytes=len(script_content), sha256="",
                content=script_content,
            ))

        if not args.quiet:
            phase_done("Crawl complete",
                f"{crawler.pages_crawled} pages  {len(crawler.js_files)} JS files")

    # ── Passive ───────────────────────────────────────────────────────────────
    if args.passive:
        if not args.quiet:
            phase("Collecting from web archives")
        from .discovery.passive import collect_passive_js_urls
        passive_urls = collect_passive_js_urls(target)
        new_js = 0
        seen   = set()
        for url in passive_urls[:args.max_js]:
            if url in seen or not scope.in_scope(url):
                continue
            seen.add(url)
            content, status, ct, sha256 = fetcher.get(url)
            if content and status in range(200, 300):
                from datetime import datetime as dt
                all_js.append(JSFile(
                    url=url, source_page=target, status_code=status,
                    content_type=ct, size_bytes=len(content),
                    sha256=sha256, content=content, discovered_at=dt.utcnow(),
                ))
                new_js += 1
        extras["passive_stats"] = {
            "source": "Wayback Machine + CommonCrawl",
            "urls": len(passive_urls), "js": new_js,
            "unique": new_js, "new": new_js,
        }
        if not args.quiet:
            phase_done("Passive collection", f"{len(passive_urls)} archive URLs  {new_js} JS assets")

    # ── Headless ──────────────────────────────────────────────────────────────
    if args.headless:
        if not args.quiet:
            phase("Launching advanced headless browser")
        from .discovery.headless import collect_headless_full
        # Pass crawler's already-seen JS URLs so headless doesn't re-fetch them
        crawler_seen = getattr(crawler if not args.passive else None, "visited_js", set()) or set()
        headless_result = collect_headless_full(target, scope,
                                                stealth=args.stealth,
                                                timeout=args.timeout,
                                                max_pages=args.max_pages,
                                                external_seen=crawler_seen)
        headless_files    = headless_result.get("js_files", [])
        headless_endpoints = headless_result.get("endpoints", [])
        headless_stats    = headless_result.get("stats", {})

        all_js.extend(headless_files)

        # Add network-intercepted endpoints directly
        if headless_endpoints:
            all_endpoints_extra = headless_endpoints
        else:
            all_endpoints_extra = []

        extras["headless_stats"] = {
            "pages":     headless_stats.get("pages", 0),
            "js":        len(headless_files),
            "xhr":       headless_stats.get("xhr", 0),
            "fetch":     headless_stats.get("fetch", 0),
            "ws":        headless_stats.get("ws", 0),
            "routes":    headless_stats.get("routes", 0),
            "endpoints": headless_stats.get("endpoints", 0),
        }
        if not args.quiet:
            phase_done("Browser discovery",
                f"{headless_stats.get('pages',0)} pages  "
                f"{len(headless_files)} JS  "
                f"{headless_stats.get('xhr',0)+headless_stats.get('fetch',0)} API calls  "
                f"{headless_stats.get('ws',0)} WS  "
                f"{headless_stats.get('routes',0)} routes"
            )

    # ── Source maps ───────────────────────────────────────────────────────────
    sm_details = {"discovered": 0, "valid": 0, "recovered": 0, "sources": 0, "items": []}
    if args.source_maps:
        if not args.quiet:
            phase("Analyzing source maps")
        from .discovery.source_maps import process_js_file
        recovered_files = []
        for js_file in list(all_js):
            result = process_js_file(js_file, fetcher, scope)
            if result:
                sm_details["discovered"] += 1
                if result.recovered_files:
                    sm_details["valid"]     += 1
                    sm_details["recovered"] += 1
                    sm_details["sources"]   += len(result.recovered_files)
                    sm_details["items"].append({
                        "js":      js_file.url.split("/")[-1],
                        "map":     result.map_url.split("/")[-1] if not result.map_url.startswith("data:") else "inline",
                        "sources": len(result.recovered_files),
                    })
                    recovered_files.extend(result.recovered_files)
        all_js.extend(recovered_files)
        extras["source_map_details"] = sm_details
        extras["recovered_sources"]  = len(recovered_files)
        if not args.quiet:
            phase_done("Source map analysis",
                f"{sm_details['discovered']} maps  {len(recovered_files)} sources recovered")

    # ── Webpack chunks ────────────────────────────────────────────────────────
    chunk_stats = {"runtime": False, "discovered": 0, "downloaded": 0}
    if args.chunks:
        if not args.quiet:
            phase("Discovering webpack chunks")
        from .discovery.webpack_chunks import fetch_chunks, detect_webpack
        seen_chunk_urls = {js.url for js in all_js}
        chunk_files     = []
        for js_file in list(all_js):
            if detect_webpack(js_file.content):
                chunk_stats["runtime"] = True
            chunks = fetch_chunks(js_file, fetcher, scope, seen_chunk_urls)
            chunk_files.extend(chunks)
        all_js.extend(chunk_files)
        chunk_stats["discovered"] = len(chunk_files)
        chunk_stats["downloaded"] = len(chunk_files)
        extras["chunk_stats"]  = chunk_stats
        extras["chunks_found"] = len(chunk_files)
        if not args.quiet:
            phase_done("Chunk discovery", f"{len(chunk_files)} chunks")

    # ── Analysis ──────────────────────────────────────────────────────────────
    if not args.quiet:
        phase("Analyzing JavaScript")
    scanner = SecretScanner()
    all_findings, all_endpoints, all_infra = _analyze(all_js, scanner)

    # Merge headless-intercepted endpoints (real network calls, high confidence)
    if args.headless and "all_endpoints_extra" in dir():
        seen_ep_keys = {ep.url.rstrip("/").lower().split("?")[0] for ep in all_endpoints}
        for ep in all_endpoints_extra:
            key = ep.url.rstrip("/").lower().split("?")[0]
            if key not in seen_ep_keys:
                seen_ep_keys.add(key)
                all_endpoints.append(ep)
    if not args.quiet:
        phase_done("Analysis complete",
            f"{len(all_findings)} findings  {len(all_endpoints)} endpoints  {len(all_infra)} infrastructure")

    # Update chunk stats with findings
    if args.chunks:
        chunk_stats["findings"]  = len([f for f in all_findings if any(c.technology == "webpack-chunk" for c in all_js if c.url == f.file_url)])
        chunk_stats["endpoints"] = len([e for e in all_endpoints if any(c.technology == "webpack-chunk" for c in all_js if c.url == e.source_file)])

    # ── Subdomain harvesting ──────────────────────────────────────────────────
    subdomains = []
    if args.harvest_subs:
        if not args.quiet:
            phase("Harvesting subdomains")
        from .discovery.subdomains import harvest_subdomains
        subdomains = harvest_subdomains(
            target,
            [js.content for js in all_js],
            [ep.url for ep in all_endpoints],
        )
        extras["subdomains"] = len(subdomains)
        if not args.quiet:
            phase_done("Subdomain harvest", f"{len(subdomains)} subdomains")

    # ── Endpoint validation ───────────────────────────────────────────────────
    validation_results = []
    if args.validate and all_endpoints:
        if not args.quiet:
            phase(f"Validating {len(all_endpoints)} endpoints")
        from .analysis.endpoint_validator import validate_endpoints
        validation_results = validate_endpoints(
            all_endpoints, target, scope,
            stealth=args.stealth, rate=max(1, args.rate // 2),
        )
        interesting = sum(1 for r in validation_results if r.interesting)
        if not args.quiet:
            phase_done("Endpoint validation", f"{interesting} interesting")

    # ── GraphQL ───────────────────────────────────────────────────────────────
    graphql_schemas = []
    if args.graphql and all_endpoints:
        if not args.quiet:
            phase("GraphQL introspection")
        from .analysis.graphql import find_graphql_endpoints, introspect
        gql_urls = find_graphql_endpoints(all_endpoints)
        for gql_url in gql_urls:
            schema = introspect(gql_url, stealth=args.stealth)
            if schema:
                graphql_schemas.append(schema)
        total_ops = sum(len(s.queries) + len(s.mutations) for s in graphql_schemas if not s.error)
        extras["graphql_queries"] = total_ops
        if not args.quiet:
            phase_done("GraphQL", f"{len(gql_urls)} endpoints  {total_ops} operations")

    # ── Secret validation ─────────────────────────────────────────────────────
    if args.validate_secrets and all_findings:
        if not args.quiet:
            phase("Validating secrets")
        from .analysis.secret_validator import validate_finding
        validated = 0
        for finding in all_findings:
            if finding.status == "likely_false_positive":
                continue
            vr = validate_finding(finding.rule_id, finding.matched_value)
            if vr and vr.valid:
                finding.status      = "validated"
                finding.description += f" | VALIDATED: {vr.detail}"
                validated += 1
        if not args.quiet:
            phase_done("Secret validation", f"{validated} confirmed active")

    # ── Build result ──────────────────────────────────────────────────────────
    finished = datetime.utcnow()
    result = ScanResult(
        target_url     = target,
        started_at     = started,
        finished_at    = finished,
        pages_crawled  = getattr(crawler if not args.passive else None, "pages_crawled", 0) or 0,
        js_files       = all_js,
        findings       = all_findings,
        endpoints      = all_endpoints,
        infrastructure = all_infra,
        errors         = errors,
    )

    # ── Reports ───────────────────────────────────────────────────────────────
    file_paths = {}
    file_formats = [f for f in formats if f != "terminal"]
    if file_formats:
        file_paths = _write_reports(result, file_formats, args.output, started)

    if "terminal" in formats and not args.quiet:
        print_report(
            result,
            verbose             = args.verbose,
            no_color            = args.no_color,
            extras              = extras,
            validation_results  = validation_results,
            graphql_schemas     = graphql_schemas,
            subdomains          = subdomains,
            report_paths        = file_paths,
        )
    elif args.quiet and file_paths:
        for fmt, path in file_paths.items():
            print(path)

    critical = [f for f in all_findings
                if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    return 1 if critical else 0


def run_local(args) -> int:
    _setup_logging(args.verbose, False, False)
    if args.no_color or os.environ.get("NO_COLOR"):
        os.environ["NO_COLOR"] = "1"

    path = args.path
    if not args.verbose:
        from .ui.printer import phase
        phase(f"Local scan: {path}")

    from .discovery.local_scanner import load_local_files
    js_files = load_local_files(path)

    if not js_files:
        phase_error("No JavaScript files found.")
        return 0

    scanner = SecretScanner()
    all_findings, all_endpoints, all_infra = _analyze(js_files, scanner)

    started  = datetime.utcnow()
    finished = datetime.utcnow()

    result = ScanResult(
        target_url=f"local://{path}", started_at=started, finished_at=finished,
        pages_crawled=0, js_files=js_files,
        findings=all_findings, endpoints=all_endpoints,
        infrastructure=all_infra, errors=[],
    )

    extras = {"local_path": path}
    formats = [f.strip() for f in args.format.split(",")]
    file_paths = {}
    file_formats = [f for f in formats if f != "terminal"]
    if file_formats:
        file_paths = _write_reports(result, file_formats, args.output, started)

    if "terminal" in formats:
        print_report(
            result,
            verbose=args.verbose,
            no_color=args.no_color,
            report_paths=file_paths,
        )

    critical = [f for f in all_findings
                if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    return 1 if critical else 0


def run_demo() -> int:
    from .storage.models import JSFile, Finding, Endpoint, InfrastructureItem, ScanResult
    import hashlib

    fake_js = JSFile(
        url="https://demo.example.com/static/js/main.8f31ab.chunk.js",
        source_page="https://demo.example.com/",
        status_code=200, content_type="application/javascript",
        size_bytes=42000, sha256=hashlib.sha256(b"fake").hexdigest(),
        content="", technology="React",
    )

    fake_findings = [
        Finding(
            id="demo001", rule_id="AWS_ACCESS_KEY", title="AWS Access Key ID",
            category="AWS", severity="CRITICAL", confidence=0.96,
            file_url=fake_js.url, source_page=fake_js.source_page,
            line_number=18291, column=12,
            matched_value="AKIAIOSFODNN7REALKEY",
            redacted_value="AKIA***************EY",
            sha256="abc123",
            context="const awsKey = 'AKIAIOSFODNN7REALKEY'",
            description="AWS Access Key ID found in JavaScript bundle.",
            impact="", remediation="Remove from client-side code. Rotate in AWS console.",
            false_positive_notes="", status="likely_secret",
            occurrences=["main.8f31ab.chunk.js:18291"],
        ),
        Finding(
            id="demo002", rule_id="JWT_TOKEN", title="JSON Web Token",
            category="JWT", severity="HIGH", confidence=0.89,
            file_url=fake_js.url, source_page=fake_js.source_page,
            line_number=1882, column=22,
            matched_value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SIGFAKE",
            redacted_value="eyJhbGci...FAKE",
            sha256="def456",
            context="const token = 'eyJhbGciOi...'",
            description="JWT token hardcoded in JavaScript.",
            impact="", remediation="Remove hardcoded tokens. Use runtime authentication.",
            false_positive_notes="", status="likely_secret",
            occurrences=["main.8f31ab.chunk.js:1882"],
        ),
        Finding(
            id="demo003", rule_id="GENERIC_API_KEY", title="Generic API Key",
            category="Generic", severity="MEDIUM", confidence=0.70,
            file_url=fake_js.url, source_page=fake_js.source_page,
            line_number=3441, column=4,
            matched_value="api_key_placeholder_do_not_use",
            redacted_value="api_key_plac...use",
            sha256="ghi789",
            context="const config = { api_key: 'placeholder' }",
            description="Generic API key assignment.",
            impact="", remediation="Move to environment variables.",
            false_positive_notes="contains placeholder indicator", status="likely_false_positive",
            occurrences=["main.8f31ab.chunk.js:3441"],
        ),
    ]

    fake_endpoints = [
        Endpoint(url="/api/v1/users",    path="/api/v1/users",    method="GET",  category="API",
                 source_file=fake_js.url, line_number=512, confidence=0.80),
        Endpoint(url="/api/auth/login",  path="/api/auth/login",  method="POST", category="AUTH",
                 source_file=fake_js.url, line_number=623, confidence=0.85),
        Endpoint(url="/admin/dashboard", path="/admin/dashboard", method="GET",  category="ADMIN",
                 source_file=fake_js.url, line_number=891, confidence=0.75),
        Endpoint(url="/graphql",         path="/graphql",         method="POST", category="GRAPHQL",
                 source_file=fake_js.url, line_number=1024, confidence=0.90),
        Endpoint(url="/api/v1/config",   path="/api/v1/config",   method="GET",  category="API",
                 source_file=fake_js.url, line_number=1201, confidence=0.78),
    ]

    fake_infra = [
        InfrastructureItem(
            value="192.168.1.50", classification="PRIVATE_IP",
            source_file=fake_js.url, line_number=912, confidence=0.92, action="report_only",
        ),
    ]

    started = datetime.utcnow()
    result  = ScanResult(
        target_url="https://demo.example.com",
        started_at=started, finished_at=datetime.utcnow(),
        pages_crawled=31, js_files=[fake_js],
        findings=fake_findings, endpoints=fake_endpoints,
        infrastructure=fake_infra, errors=[],
    )

    print_header(
        "https://demo.example.com",
        mode="Demo (offline)",
        scope="Strict",
        version=PROJECT_VERSION,
        author=AUTHOR_NAME,
    )

    print_report(
        result,
        verbose=True,
        extras={
            "source_map_details": {"discovered": 2, "valid": 2, "recovered": 2, "sources": 31, "items": [
                {"js": "main.8f31ab.chunk.js", "map": "main.8f31ab.chunk.js.map", "sources": 31},
            ]},
            "chunk_stats": {"runtime": True, "discovered": 8, "downloaded": 8, "endpoints": 14, "findings": 1},
            "passive_stats": {"source": "Wayback Machine", "urls": 142, "js": 23, "unique": 19, "new": 4},
        },
        subdomains=["api.example.com", "staging.example.com", "admin.example.com"],
    )
    return 0


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "scan":
        sys.exit(run_scan(args))
    elif args.command == "local":
        sys.exit(run_local(args))
    elif args.command == "demo":
        sys.exit(run_demo())
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
