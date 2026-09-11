"""
BundleSpy CLI entry point.
"""

import sys
import os
import argparse
import logging
import json
from datetime import datetime
from pathlib import Path

from .config import BundleSpyConfig, CrawlerConfig, ScopeConfig, ReportingConfig
from .banner import print_banner
from .safety.authorization import require_authorization
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bundlespy",
        description="BundleSpy - JavaScript Intelligence and Secret Exposure Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  bundlespy scan https://example.com
  bundlespy scan https://example.com --depth 2 --source-maps --chunks
  bundlespy scan https://example.com --passive --format html --output ./reports/
  bundlespy scan https://example.com --headless --stealth
  bundlespy scan https://example.com --validate --graphql
  bundlespy scan https://example.com --format html,json,burp --output ./reports/
  bundlespy local ./dist/
  bundlespy demo
""",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── scan command ──────────────────────────────────────────────────────────
    scan = subparsers.add_parser("scan", help="Scan a target URL")
    scan.add_argument("target", help="Target URL (e.g. https://example.com)")

    # Crawl options
    scan.add_argument("--depth",         type=int, default=2,   help="Crawl depth (default: 2)")
    scan.add_argument("--max-pages",     type=int, default=100, help="Max pages to crawl (default: 100)")
    scan.add_argument("--max-js",        type=int, default=200, help="Max JS files to fetch (default: 200)")
    scan.add_argument("--concurrency",   type=int, default=4,   help="Concurrent requests (default: 4)")
    scan.add_argument("--rate",          type=int, default=2,   help="Requests per second (default: 2)")
    scan.add_argument("--timeout",       type=int, default=10,  help="Request timeout seconds (default: 10)")
    scan.add_argument("--common-paths",  action="store_true",   help="Try common JS paths like /app.js, /main.js")
    scan.add_argument("--subdomains",    action="store_true",   help="Include subdomains in scope")
    scan.add_argument("--exclude",       nargs="+", default=[], help="Exclude hostnames from scope")

    # Feature flags
    scan.add_argument("--source-maps",   action="store_true",   help="Download and analyze source maps")
    scan.add_argument("--chunks",        action="store_true",   help="Discover and scan webpack/Vite chunks")
    scan.add_argument("--passive",       action="store_true",   help="Passive mode - collect JS from Wayback Machine/CommonCrawl")
    scan.add_argument("--headless",      action="store_true",   help="Use headless Chromium browser (requires playwright)")
    scan.add_argument("--validate",      action="store_true",   help="Validate discovered endpoints with safe GET/HEAD requests")
    scan.add_argument("--graphql",       action="store_true",   help="Run GraphQL introspection on detected endpoints")
    scan.add_argument("--harvest-subs",  action="store_true",   help="Passively harvest subdomains from JS and CT logs")
    scan.add_argument("--validate-secrets", action="store_true",help="Validate detected secrets against provider APIs (read-only)")
    scan.add_argument("--stealth",       action="store_true",   help="Stealth mode - UA rotation, jitter, browser headers")

    # Output
    scan.add_argument("--format",        default="terminal",    help="Output formats: terminal,json,html,csv,burp (comma-separated)")
    scan.add_argument("--output",        default="",            help="Output directory for report files")
    scan.add_argument("--show-sensitive",action="store_true", default=True, help="Show full secret values in output")

    # Misc
    scan.add_argument("--verbose",       action="store_true",   help="Verbose logging")
    scan.add_argument("--quiet",         action="store_true",   help="Suppress non-essential output")
    scan.add_argument("--no-color",      action="store_true",   help="Disable colored output")
    scan.add_argument("--yes",           action="store_true",   help="Skip authorization prompt (CI use)")

    # ── local command ─────────────────────────────────────────────────────────
    local = subparsers.add_parser("local", help="Scan local JS files without crawling")
    local.add_argument("path",           help="Local directory or file to scan")
    local.add_argument("--source-maps",  action="store_true",  help="Also analyze .map files in the directory")
    local.add_argument("--format",       default="terminal",   help="Output formats: terminal,json,html,csv (comma-separated)")
    local.add_argument("--output",       default="",           help="Output directory for report files")
    local.add_argument("--show-sensitive", action="store_true", default=True, help="Show full secret values")
    local.add_argument("--verbose",      action="store_true",  help="Verbose logging")
    local.add_argument("--no-color",     action="store_true",  help="Disable colored output")

    # ── demo command ──────────────────────────────────────────────────────────
    subparsers.add_parser("demo", help="Run offline demo with synthetic data")

    return parser


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(level=level, format="  [%(levelname)s] %(name)s: %(message)s")


def _write_reports(result: ScanResult, formats: list, output_dir: str,
                   show_sensitive: bool, started: datetime) -> None:
    ts = started.strftime("%Y%m%d_%H%M%S")

    if "json" in formats:
        out = generate_json(result, show_sensitive=show_sensitive)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            p = Path(output_dir) / f"bundlespy_{ts}.json"
            p.write_text(out)
            print(f"\n  [+] JSON report saved to {p}")
        else:
            print(out)

    if "html" in formats:
        out = generate_html(result, show_sensitive=show_sensitive)
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"bundlespy_{ts}.html"
        p.write_text(out)
        print(f"\n  [+] HTML report saved to {p}")

    if "csv" in formats:
        out = generate_csv(result, show_sensitive=show_sensitive)
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"bundlespy_{ts}.csv"
        p.write_text(out)
        print(f"\n  [+] CSV report saved to {p}")

    if "burp" in formats:
        xml_out  = generate_burp_xml(result)
        url_out  = generate_url_list(result)
        d        = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p1 = Path(d) / f"bundlespy_{ts}_burp.xml"
        p2 = Path(d) / f"bundlespy_{ts}_urls.txt"
        p1.write_text(xml_out)
        p2.write_text(url_out)
        print(f"\n  [+] Burp XML saved to {p1}")
        print(f"  [+] URL list saved to {p2}")


def _analyze_js_files(js_files: list, secret_scanner) -> tuple:
    """Run all analyzers on a list of JSFile objects."""
    all_findings    = []
    all_endpoints   = []
    all_infra       = []

    for js_file in js_files:
        content = js_file.content
        all_findings.extend(secret_scanner.scan(content, js_file.url, js_file.source_page))
        all_endpoints.extend(extract_endpoints(content, js_file.url))
        all_infra.extend(extract_infrastructure(content, js_file.url))

    return all_findings, all_endpoints, all_infra


def run_scan(args) -> int:
    _setup_logging(args.verbose, args.quiet)

    if not args.no_color:
        print_banner()
    else:
        print_banner(no_color=True)

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    safe, reason = validate_url(target, check_dns=False)
    if not safe:
        print(f"\n  [ERROR] Target URL is not safe to scan: {reason}\n")
        return 2

    if not require_authorization(target, skip=args.yes):
        return 0

    started = datetime.utcnow()
    errors  = []

    fetcher = Fetcher(
        timeout=args.timeout,
        requests_per_second=args.rate,
        stealth=args.stealth,
    )
    scope = ScopeChecker(
        target_url  = target,
        same_origin = True,
        subdomains  = args.subdomains,
        exclude     = args.exclude,
    )

    if args.stealth:
        print(f"  \033[93m[*] Stealth mode - UA rotation, jitter delays, browser headers\033[0m")

    print(f"  Scanning: {target}")
    print(f"  Depth: {args.depth} | Max pages: {args.max_pages} | Max JS: {args.max_js}")
    print(f"  Rate: {args.rate} req/s | Timeout: {args.timeout}s\n")

    # ── Active crawl ──────────────────────────────────────────────────────────
    all_js: list = []

    if not args.passive:
        crawler = Crawler(
            target_url   = target,
            fetcher      = fetcher,
            scope        = scope,
            max_depth    = args.depth,
            max_pages    = args.max_pages,
            max_js_files = args.max_js,
            common_paths = args.common_paths,
        )
        try:
            crawler.crawl()
        except KeyboardInterrupt:
            print("\n  Scan interrupted.")
            return 0

        errors.extend(crawler.errors)
        all_js.extend(crawler.js_files)

        # Inline scripts
        for script_content, source_page in crawler.inline_scripts:
            import hashlib
            inline = JSFile(
                url="inline:" + source_page, source_page=source_page,
                status_code=200, content_type="text/javascript",
                size_bytes=len(script_content), sha256="",
                content=script_content,
            )
            all_js.append(inline)

    # ── Passive mode ──────────────────────────────────────────────────────────
    if args.passive:
        print("  [*] Passive mode - collecting from Wayback Machine and CommonCrawl...")
        from .discovery.passive import collect_passive_js_urls
        passive_urls = collect_passive_js_urls(target)
        print(f"  [*] Found {len(passive_urls)} historical JS URLs")
        extras["passive_urls"] = len(passive_urls)

        seen_passive = set()
        for url in passive_urls[:args.max_js]:
            if url in seen_passive:
                continue
            seen_passive.add(url)
            if not scope.in_scope(url):
                continue
            content, status, ct, sha256 = fetcher.get(url)
            if content and status in range(200, 300):
                from datetime import datetime as dt
                import hashlib as hl
                js = JSFile(
                    url=url, source_page=target, status_code=status,
                    content_type=ct, size_bytes=len(content),
                    sha256=sha256, content=content,
                    discovered_at=dt.utcnow(),
                )
                all_js.append(js)

    # ── Headless browser ──────────────────────────────────────────────────────
    if args.headless:
        print("  [*] Headless browser mode - launching Chromium...")
        from .discovery.headless import collect_headless_js
        headless_files = collect_headless_js(target, scope, stealth=args.stealth)
        print(f"  [*] Headless captured {len(headless_files)} JS files")
        extras["headless_files"] = len(headless_files)
        all_js.extend(headless_files)

    # ── Source maps ───────────────────────────────────────────────────────────
    if args.source_maps:
        print("  [*] Analyzing source maps...")
        from .discovery.source_maps import process_js_file, try_predictable_map_paths
        recovered_files = []
        for js_file in list(all_js):
            result = process_js_file(js_file, fetcher, scope)
            if result and result.recovered_files:
                print(f"  [+] Source map: recovered {len(result.recovered_files)} files from {js_file.url}")
                recovered_files.extend(result.recovered_files)
        all_js.extend(recovered_files)
        print(f"  [*] Total recovered source files: {len(recovered_files)}")
        extras["recovered_sources"] = len(recovered_files)

    # ── Webpack chunks ────────────────────────────────────────────────────────
    if args.chunks:
        print("  [*] Discovering webpack/Vite chunks...")
        from .discovery.webpack_chunks import fetch_chunks
        seen_chunk_urls = {js.url for js in all_js}
        chunk_files = []
        for js_file in list(all_js):
            chunks = fetch_chunks(js_file, fetcher, scope, seen_chunk_urls)
            chunk_files.extend(chunks)
        all_js.extend(chunk_files)
        print(f"  [*] Discovered {len(chunk_files)} additional chunks")
        extras["chunks_found"] = len(chunk_files)

    # ── Track extras for terminal output ─────────────────────────────────────
    extras = {}

    # ── Analysis ──────────────────────────────────────────────────────────────
    secret_scanner = SecretScanner()
    all_findings, all_endpoints, all_infra = _analyze_js_files(all_js, secret_scanner)

    # ── Subdomain harvesting ──────────────────────────────────────────────────
    subdomains = []
    if args.harvest_subs:
        print("  [*] Harvesting subdomains...")
        from .discovery.subdomains import harvest_subdomains
        js_contents   = [js.content for js in all_js]
        discovered_urls = [ep.url for ep in all_endpoints]
        subdomains    = harvest_subdomains(target, js_contents, discovered_urls)
        print(f"  [*] Found {len(subdomains)} subdomains")
        extras["subdomains"] = len(subdomains)
        for sub in subdomains[:20]:
            print(f"      {sub}")

    # ── Endpoint validation ───────────────────────────────────────────────────
    validation_results = []
    if args.validate and all_endpoints:
        print(f"  [*] Validating {len(all_endpoints)} endpoints...")
        from .analysis.endpoint_validator import validate_endpoints
        validation_results = validate_endpoints(
            all_endpoints, target, scope,
            stealth=args.stealth, rate=max(1, args.rate // 2),
        )
        interesting = [r for r in validation_results if r.interesting]
        print(f"  [*] {len(interesting)} interesting endpoints found")

    # ── GraphQL introspection ─────────────────────────────────────────────────
    graphql_schemas = []
    if args.graphql and all_endpoints:
        from .analysis.graphql import find_graphql_endpoints, introspect
        gql_urls = find_graphql_endpoints(all_endpoints)
        if gql_urls:
            print(f"  [*] Running GraphQL introspection on {len(gql_urls)} endpoint(s)...")
            for gql_url in gql_urls:
                schema = introspect(gql_url, stealth=args.stealth)
                if schema and not schema.error:
                    graphql_schemas.append(schema)
                    print(f"  [+] GraphQL schema: {len(schema.queries)} queries, {len(schema.mutations)} mutations")
                    if schema.sensitive_fields:
                        print(f"  [!] Sensitive fields: {', '.join(schema.sensitive_fields[:5])}")

    # ── Secret validation ─────────────────────────────────────────────────────
    if args.validate_secrets and all_findings:
        from .analysis.secret_validator import validate_finding
        validated_count = 0
        for finding in all_findings:
            if finding.status == "likely_false_positive":
                continue
            vresult = validate_finding(finding.rule_id, finding.matched_value)
            if vresult and vresult.valid:
                finding.status = "validated"
                finding.description += f" | VALIDATED: {vresult.detail}"
                validated_count += 1
        if validated_count:
            print(f"  \033[91m[!!] {validated_count} secrets VALIDATED as active\033[0m")

    # ── Build result ──────────────────────────────────────────────────────────
    finished = datetime.utcnow()
    result   = ScanResult(
        target_url    = target,
        started_at    = started,
        finished_at   = finished,
        pages_crawled = getattr(crawler, "pages_crawled", 0) if not args.passive else 0,
        js_files      = [js for js in all_js if not js.url.startswith("sourcemap://")],
        findings      = all_findings,
        endpoints     = all_endpoints,
        infrastructure = all_infra,
        errors        = errors,
    )

    # ── Reports ───────────────────────────────────────────────────────────────
    formats = [f.strip() for f in args.format.split(",")]

    if "terminal" in formats:
        print_report(
            result,
            show_sensitive      = args.show_sensitive,
            no_color            = args.no_color,
            extras              = extras,
            validation_results  = validation_results,
            graphql_schemas     = graphql_schemas,
            subdomains          = subdomains,
        )

    _write_reports(result, formats, args.output, args.show_sensitive, started)

    # ── Exit code ─────────────────────────────────────────────────────────────
    critical = [f for f in all_findings
                if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    return 1 if critical else 0


def run_local(args) -> int:
    _setup_logging(args.verbose, False)

    if not args.no_color:
        print_banner()
    else:
        print_banner(no_color=True)

    path = args.path
    print(f"  Local scan: {path}\n")

    from .discovery.local_scanner import load_local_files
    js_files = load_local_files(path)

    if not js_files:
        print("  No JS files found.")
        return 0

    print(f"  Loaded {len(js_files)} file(s)\n")

    secret_scanner = SecretScanner()
    all_findings, all_endpoints, all_infra = _analyze_js_files(js_files, secret_scanner)

    started  = datetime.utcnow()
    finished = datetime.utcnow()

    result = ScanResult(
        target_url     = f"local://{path}",
        started_at     = started,
        finished_at    = finished,
        pages_crawled  = 0,
        js_files       = js_files,
        findings       = all_findings,
        endpoints      = all_endpoints,
        infrastructure = all_infra,
        errors         = [],
    )

    formats = [f.strip() for f in args.format.split(",")]
    if "terminal" in formats:
        print_report(
            result,
            show_sensitive      = args.show_sensitive,
            no_color            = args.no_color,
            extras              = extras,
            validation_results  = validation_results,
            graphql_schemas     = graphql_schemas,
            subdomains          = subdomains,
        )

    _write_reports(result, formats, args.output, args.show_sensitive, started)

    critical = [f for f in all_findings
                if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    return 1 if critical else 0


def run_demo() -> int:
    print_banner()
    print("  Running in DEMO mode - no network requests will be made.\n")
    print("  This demonstrates what BundleSpy output looks like on a real target.\n")
    print(f"  {'─' * 60}")

    from .storage.models import JSFile, Finding, Endpoint, InfrastructureItem, ScanResult
    import hashlib

    fake_js = JSFile(
        url="https://demo.example.com/static/js/main.chunk.js",
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
            matched_value="AKIAIOSFODNN7EXAMPLE",
            redacted_value="AKIA************PLE",
            sha256="abc123", context="const awsKey = 'AKIAIOSFODNN7EXAMPLE'",
            description="AWS Access Key ID found in JavaScript bundle.",
            impact="", remediation="Remove from client-side code. Rotate in AWS console.",
            false_positive_notes="", status="likely_secret",
            occurrences=["main.chunk.js:18291"],
        ),
        Finding(
            id="demo002", rule_id="JWT_TOKEN", title="JSON Web Token",
            category="JWT", severity="HIGH", confidence=0.89,
            file_url=fake_js.url, source_page=fake_js.source_page,
            line_number=1882, column=22,
            matched_value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.FAKE",
            redacted_value="eyJhbGci...REDACTED",
            sha256="def456", context="const token = 'eyJhbGciOi...'",
            description="JWT token hardcoded in JavaScript.",
            impact="", remediation="Remove hardcoded tokens. Use runtime authentication.",
            false_positive_notes="", status="likely_secret",
            occurrences=["main.chunk.js:1882"],
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
    ]

    fake_infra = [
        InfrastructureItem(
            value="http://192.168.1.50/api", classification="PRIVATE_IP",
            source_file=fake_js.url, line_number=912, confidence=0.92, action="report_only",
        ),
    ]

    result = ScanResult(
        target_url="https://demo.example.com (DEMO MODE)",
        started_at=datetime.utcnow(), finished_at=datetime.utcnow(),
        pages_crawled=42, js_files=[fake_js],
        findings=fake_findings, endpoints=fake_endpoints,
        infrastructure=fake_infra, errors=[],
    )

    print_report(result)
    print("  This was demo mode. No real requests were made.\n")
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
