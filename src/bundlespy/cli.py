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
from .storage.models import ScanResult, Finding, Endpoint, InfrastructureItem
from .reporting.terminal import print_report
from .reporting.json_report import generate as generate_json
from .reporting.html_report import generate as generate_html
from .reporting.csv_report import generate as generate_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bundlespy",
        description="BundleSpy - JavaScript Intelligence and Secret Exposure Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  bundlespy scan https://example.com
  bundlespy scan https://example.com --depth 2 --max-js 100
  bundlespy scan https://example.com --format json --output ./reports/
  bundlespy scan https://example.com --show-sensitive --verbose
  bundlespy demo
""",
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan = subparsers.add_parser("scan", help="Scan a target")
    scan.add_argument("target", help="Target URL (e.g. https://example.com)")
    scan.add_argument("--depth",         type=int, default=2,     help="Crawl depth (default: 2)")
    scan.add_argument("--max-pages",     type=int, default=100,   help="Max pages to crawl (default: 100)")
    scan.add_argument("--max-js",        type=int, default=200,   help="Max JS files to fetch (default: 200)")
    scan.add_argument("--concurrency",   type=int, default=4,     help="Concurrent requests (default: 4)")
    scan.add_argument("--rate",          type=int, default=2,     help="Requests per second (default: 2)")
    scan.add_argument("--timeout",       type=int, default=10,    help="Request timeout seconds (default: 10)")
    scan.add_argument("--common-paths",  action="store_true",     help="Try common JS paths like /app.js, /main.js")
    scan.add_argument("--subdomains",    action="store_true",     help="Include subdomains in scope")
    scan.add_argument("--exclude",       nargs="+", default=[],   help="Exclude hostnames from scope")
    scan.add_argument("--format",        default="terminal",       help="Output format: terminal,json (default: terminal)")
    scan.add_argument("--output",        default="",              help="Output directory for reports")
    scan.add_argument("--show-sensitive",action="store_true",     help="Show full secret values in output (use carefully)")
    scan.add_argument("--verbose",       action="store_true",     help="Verbose logging")
    scan.add_argument("--quiet",         action="store_true",     help="Suppress non-essential output")
    scan.add_argument("--no-color",      action="store_true",     help="Disable colored output")
    scan.add_argument("--yes",           action="store_true",     help="Skip authorization prompt (CI use)")
    scan.add_argument("--stealth",       action="store_true",     help="Stealth mode - random UA rotation, realistic headers, jitter delays")

    # demo command
    subparsers.add_parser("demo", help="Run offline demo with fake data")

    return parser


def run_scan(args) -> int:
    """Execute a full scan and return exit code."""
    # Setup logging
    log_level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="  [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.no_color:
        print_banner()
    else:
        print_banner(no_color=True)

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Validate target URL
    safe, reason = validate_url(target, check_dns=False)
    if not safe:
        print(f"\n  [ERROR] Target URL is not safe to scan: {reason}\n")
        return 2

    # Authorization check
    if not require_authorization(target, skip=args.yes):
        return 0

    started = datetime.utcnow()
    errors  = []

    # Setup components
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
    crawler = Crawler(
        target_url    = target,
        fetcher       = fetcher,
        scope         = scope,
        max_depth     = args.depth,
        max_pages     = args.max_pages,
        max_js_files  = args.max_js,
        common_paths  = args.common_paths,
    )

    if args.stealth:
        print(f"  {chr(27)}[93m[*] Stealth mode enabled - UA rotation, jitter delays, browser headers{chr(27)}[0m")
    print(f"  Scanning: {target}")
    print(f"  Depth: {args.depth} | Max pages: {args.max_pages} | Max JS: {args.max_js}")
    print(f"  Rate: {args.rate} req/s | Timeout: {args.timeout}s\n")

    # Crawl
    try:
        crawler.crawl()
    except KeyboardInterrupt:
        print("\n  Scan interrupted by user.")
        return 0

    errors.extend(crawler.errors)

    # Analyze
    secret_scanner = SecretScanner()
    all_findings:    list = []
    all_endpoints:   list = []
    all_infra:       list = []

    all_js = list(crawler.js_files)

    # Also analyze inline scripts
    for script_content, source_page in crawler.inline_scripts:
        from .storage.models import JSFile
        from datetime import datetime as dt
        inline_file = JSFile(
            url="inline:" + source_page,
            source_page=source_page,
            status_code=200,
            content_type="text/javascript",
            size_bytes=len(script_content),
            sha256="",
            content=script_content,
        )
        all_js.append(inline_file)

    for js_file in all_js:
        content = js_file.content

        findings = secret_scanner.scan(content, js_file.url, js_file.source_page)
        all_findings.extend(findings)

        endpoints = extract_endpoints(content, js_file.url)
        all_endpoints.extend(endpoints)

        infra = extract_infrastructure(content, js_file.url)
        all_infra.extend(infra)

    finished = datetime.utcnow()

    result = ScanResult(
        target_url      = target,
        started_at      = started,
        finished_at     = finished,
        pages_crawled   = crawler.pages_crawled,
        js_files        = crawler.js_files,
        findings        = all_findings,
        endpoints       = all_endpoints,
        infrastructure  = all_infra,
        errors          = errors,
    )

    # Report
    formats = [f.strip() for f in args.format.split(",")]

    if "terminal" in formats:
        print_report(
            result,
            show_sensitive = args.show_sensitive,
            no_color       = args.no_color,
        )

    if "json" in formats:
        json_output = generate_json(result, show_sensitive=args.show_sensitive)
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            ts      = started.strftime("%Y%m%d_%H%M%S")
            outfile = Path(args.output) / f"bundlespy_{ts}.json"
            outfile.write_text(json_output)
            print(f"\n  [+] JSON report saved to {outfile}")
        else:
            print(json_output)

    if "html" in formats:
        html_output = generate_html(result, show_sensitive=args.show_sensitive)
        os.makedirs(args.output or "./bundlespy-reports", exist_ok=True)
        ts      = started.strftime("%Y%m%d_%H%M%S")
        outfile = Path(args.output or "./bundlespy-reports") / f"bundlespy_{ts}.html"
        outfile.write_text(html_output)
        print(f"\n  [+] HTML report saved to {outfile}")

    if "csv" in formats:
        csv_output = generate_csv(result, show_sensitive=args.show_sensitive)
        os.makedirs(args.output or "./bundlespy-reports", exist_ok=True)
        ts      = started.strftime("%Y%m%d_%H%M%S")
        outfile = Path(args.output or "./bundlespy-reports") / f"bundlespy_{ts}.csv"
        outfile.write_text(csv_output)
        print(f"\n  [+] CSV report saved to {outfile}")

    # Exit code based on findings
    critical = [f for f in all_findings if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    high     = [f for f in all_findings if f.severity == "HIGH"     and f.status != "likely_false_positive"]

    if critical:
        return 1
    return 0


def run_demo() -> int:
    """Offline demo mode with synthetic fake data."""
    print_banner()
    print("  Running in DEMO mode - no network requests will be made.\n")
    print("  This demonstrates what BundleSpy output looks like on a real target.\n")
    print(f"  {'─' * 60}")

    from .storage.models import JSFile, Finding, Endpoint, InfrastructureItem, ScanResult
    import hashlib

    fake_js = JSFile(
        url="https://demo.example.com/static/js/main.chunk.js",
        source_page="https://demo.example.com/",
        status_code=200,
        content_type="application/javascript",
        size_bytes=42000,
        sha256=hashlib.sha256(b"fake").hexdigest(),
        content="",
        technology="React",
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
            impact="Unauthorized AWS API access.",
            remediation="Remove from client-side code. Rotate in AWS console.",
            false_positive_notes="",
            status="likely_secret",
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
            impact="Token exposure may allow impersonation.",
            remediation="Remove hardcoded tokens. Use runtime authentication.",
            false_positive_notes="",
            status="likely_secret",
            occurrences=["main.chunk.js:1882"],
        ),
        Finding(
            id="demo003", rule_id="S3_BUCKET_URL", title="AWS S3 Bucket URL",
            category="Cloud Storage", severity="MEDIUM", confidence=0.88,
            file_url=fake_js.url, source_page=fake_js.source_page,
            line_number=44, column=8,
            matched_value="https://s3.amazonaws.com/demo-company-prod-backup/",
            redacted_value="https://s3.amazonaws.com/demo-company-prod-backup/",
            sha256="ghi789", context="const backupUrl = 'https://s3.amazonaws.com/demo...'",
            description="S3 bucket URL found. Check access permissions.",
            impact="Publicly accessible bucket may expose sensitive data.",
            remediation="Review bucket ACL. Enable S3 Block Public Access.",
            false_positive_notes="",
            status="candidate",
            occurrences=["main.chunk.js:44"],
        ),
    ]

    fake_endpoints = [
        Endpoint(url="/api/v1/users", path="/api/v1/users", method="GET", category="API",
                 source_file=fake_js.url, line_number=512, confidence=0.80),
        Endpoint(url="/api/auth/login", path="/api/auth/login", method="POST", category="AUTH",
                 source_file=fake_js.url, line_number=623, confidence=0.85),
        Endpoint(url="/admin/dashboard", path="/admin/dashboard", method="GET", category="ADMIN",
                 source_file=fake_js.url, line_number=891, confidence=0.75),
        Endpoint(url="/graphql", path="/graphql", method="POST", category="GRAPHQL",
                 source_file=fake_js.url, line_number=1024, confidence=0.90),
    ]

    fake_infra = [
        InfrastructureItem(
            value="http://192.168.1.50/api",
            classification="PRIVATE_IP",
            source_file=fake_js.url, line_number=912,
            confidence=0.92, action="report_only",
        ),
        InfrastructureItem(
            value="https://api-staging.demo.internal",
            classification="INTERNAL_HOSTNAME",
            source_file=fake_js.url, line_number=445,
            confidence=0.85, action="report_only",
        ),
    ]

    result = ScanResult(
        target_url      = "https://demo.example.com (DEMO MODE)",
        started_at      = datetime.utcnow(),
        finished_at     = datetime.utcnow(),
        pages_crawled   = 42,
        js_files        = [fake_js],
        findings        = fake_findings,
        endpoints       = fake_endpoints,
        infrastructure  = fake_infra,
        errors          = [],
    )

    print_report(result)
    print("  This was demo mode. No real requests were made.\n")
    return 0


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "scan":
        sys.exit(run_scan(args))
    elif args.command == "demo":
        sys.exit(run_demo())
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
