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
from .analysis.ast_endpoints import extract_all_endpoints
from .analysis.endpoint_intel import extract_endpoint_intelligence
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

    # -- scan -------------------------------------------------------------
    scan = sub.add_parser("scan", help="Scan a target URL")
    scan.add_argument("target")

    # Crawl
    scan.add_argument("--depth",       type=int, default=5)
    scan.add_argument("--max-pages",   type=int, default=500)
    scan.add_argument("--max-js",      type=int, default=1000)
    scan.add_argument("--rate",        type=int, default=3)
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
    scan.add_argument("--interact",       action="store_true", help="Enable full page interaction in headless mode (slower but finds more lazy JS)")
    scan.add_argument("--workers",        type=int, default=3, help="Concurrent headless browser workers (default: 3)")

    # Cache
    scan.add_argument("--no-cache",    action="store_true", help="Disable cache reads (re-fetch everything; still writes to cache)")
    scan.add_argument("--clear-cache", action="store_true", help="Wipe the local HTTP cache before scanning")
    scan.add_argument("--cache-dir",   default="", metavar="PATH", help="Override the cache directory (default: ~/.cache/bundlespy/http)")

    scan.add_argument("--cookie",         default="",  help="Session cookie to include in all requests")
    scan.add_argument("--header",         action="append", default=[], metavar="NAME:VALUE",
                      help="Extra header to include in all requests (can use multiple times)")

    # Output
    scan.add_argument("--format", default="terminal")
    scan.add_argument("--output", default="")
    scan.add_argument("--report-name", default="", metavar="NAME",
                      help="Custom filename stem for report files (e.g. client-webapp-2026)")
    scan.add_argument("-v", "--verbose",  action="store_true")
    scan.add_argument("-vv","--debug",    action="store_true")
    scan.add_argument("-q", "--quiet",    action="store_true")
    scan.add_argument("--no-color",       action="store_true")
    scan.add_argument("--json",           action="store_true", help="JSON output only")
    scan.add_argument("--csv",            action="store_true", help="CSV output only")
    scan.add_argument("--show-fp",        action="store_true", help="Show likely false positives in output")
    scan.add_argument("--silent",         action="store_true", help="Findings only - no progress, no headers")

    # -- local ------------------------------------------------------------
    local = sub.add_parser("local", help="Scan local JS files")
    local.add_argument("path")
    local.add_argument("--format",   default="terminal")
    local.add_argument("--output",   default="")
    local.add_argument("-v", "--verbose", action="store_true")
    local.add_argument("--no-color", action="store_true")

    # -- demo -------------------------------------------------------------
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
    # Strip any extension the user may have added - we add the right one
    for ext in (".html", ".json", ".csv", ".xml", ".txt"):
        if stem.lower().endswith(ext):
            stem = stem[:-len(ext)]
    paths   = {}

    if "json" in formats:
        out = generate_json(result)
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
    inline_analyzed_hashes: set = None,
    fetcher=None,
    scope=None,
) -> tuple:
    """
    Analyze JS files for secrets, endpoints, and infrastructure.

    Content-hash dedup: if two JSFile objects have identical sha256,
    analyze the content only once but attribute findings/endpoints
    to ALL file URLs that share that content (provenance preserved).

    Static-to-runtime endpoint correlation: same canonical URL seen in
    both static JS and runtime interception -> one entity, higher confidence.

    Workers and dynamic imports are fetched and analyzed when fetcher/scope
    are supplied. GraphQL operations are extracted and returned separately.
    """
    from .analysis.ast_endpoints import (
        extract_workers, extract_dynamic_imports, extract_graphql_operations,
    )
    from urllib.parse import urljoin

    findings:      list = []
    endpoints:     list = []
    infra:         list = []
    graphql_ops:   list = []
    seen_finds:    set  = set()
    seen_eps:      set  = set()

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

    # Set of sha256 hashes already processed by the inline analyzer (avoid double-counting)
    _inline_analyzed = inline_analyzed_hashes or set()

    # Track worker/dynamic-import URLs already fetched to avoid loops
    _fetched_extra: set = set()

    def _add_ep(ep, source_type: str = "static") -> bool:
        key = ep.url.rstrip("/").lower().split("?")[0]
        if key not in seen_eps:
            seen_eps.add(key)
            ep.source_type = source_type
            endpoints.append(ep)
            return True
        return False

    # Analyze each unique content once; attribute to all occurrences
    def _process(primary_js: "JSFile", all_urls: list) -> None:
        # Skip files already fully analyzed inline during headless session.
        # The inline analyzer already recorded their findings/endpoints on the engine.
        # We only skip the content analysis; infrastructure detection still runs
        # because inline analysis stores infra back as api_calls, not infra items.
        if primary_js.sha256 and primary_js.sha256 in _inline_analyzed:
            return
        if getattr(primary_js, "_inline_analyzed", False):
            return

        content = primary_js.content

        # Secret detection - scan once against primary URL
        for f in scanner.scan(content, primary_js.url, primary_js.source_page):
            if f.sha256 not in seen_finds:
                seen_finds.add(f.sha256)
                # Record all occurrence URLs in the finding
                if len(all_urls) > 1:
                    f.occurrences = [f"{u}:{f.line_number}" for u in all_urls]
                findings.append(f)

        # Endpoint extraction - deduplicate by canonical key
        for ep in extract_all_endpoints(content, primary_js.url):
            _add_ep(ep, "static")

        for ep in extract_endpoints(content, primary_js.url):
            _add_ep(ep, "static")

        # GraphQL operations - extracted from every JS file, deduplicated by op_type:name
        for op in extract_graphql_operations(content, primary_js.url):
            key = f"{op.op_type}:{op.name}"
            if not any(f"{o.op_type}:{o.name}" == key for o in graphql_ops):
                graphql_ops.append(op)

        # Workers - fetch and analyze inline when fetcher is available.
        # extract_workers() covers new Worker(), SharedWorker, sw.register, importScripts.
        if fetcher and scope:
            _process_workers(content, primary_js.url)
            _process_dynamic_imports(content, primary_js.url)

        # Infrastructure detection
        infra.extend(extract_infrastructure(content, primary_js.url))

    def _fetch_and_analyze(url: str, source_page: str) -> None:
        """Fetch one extra JS file (worker/dynamic-import) and run _process on it."""
        norm = url.rstrip("?#")
        if norm in _fetched_extra:
            return
        _fetched_extra.add(norm)
        try:
            content, status, ct, sha256 = fetcher.get(url)
        except Exception:
            return
        if not content or status not in range(200, 300):
            return
        # Deduplicate by content hash
        if sha256 and sha256 in content_groups:
            return  # already analyzed as part of main set
        from .storage.models import JSFile as _JSFile
        extra_js = _JSFile(
            url=url, source_page=source_page, status_code=status,
            content_type=ct, size_bytes=len(content), sha256=sha256,
            content=content,
        )
        # Register in content_groups so subsequent duplicates are skipped
        if sha256:
            if sha256 in content_groups:
                content_groups[sha256].append(extra_js)
                return
            content_groups[sha256] = [extra_js]
        _process(extra_js, [url])

    def _process_workers(content: str, file_url: str) -> None:
        """Extract worker URLs and analyze their content."""
        for w in extract_workers(content, file_url):
            wurl = w.url
            if not wurl or wurl.startswith("blob:") or wurl.startswith("data:"):
                continue
            # Resolve relative URLs against the file that references them
            if not wurl.startswith("http"):
                wurl = urljoin(file_url, wurl)
            if scope and not scope.in_scope(wurl):
                continue
            _fetch_and_analyze(wurl, file_url)

    def _process_dynamic_imports(content: str, file_url: str) -> None:
        """Extract dynamic import() / require() URLs and analyze them."""
        for di in extract_dynamic_imports(content, file_url):
            durl = di.url
            if not durl or durl.startswith("blob:") or durl.startswith("data:"):
                continue
            # Skip template-literal placeholders that could not be resolved
            if "${" in durl:
                continue
            if not durl.startswith("http"):
                durl = urljoin(file_url, durl)
            if scope and not scope.in_scope(durl):
                continue
            _fetch_and_analyze(durl, file_url)

    # Snapshot keys before iteration - _process() may add new entries to
    # content_groups via _fetch_and_analyze() (workers, dynamic imports).
    # Iterate a copy so the dict can grow without raising RuntimeError.
    processed: set = set()

    def _process_all() -> None:
        """Process all unprocessed content groups, including ones added mid-run."""
        changed = True
        while changed:
            changed = False
            for sha, group in list(content_groups.items()):
                if sha in processed:
                    continue
                processed.add(sha)
                changed = True
                _process(group[0], [js.url for js in group])

    _process_all()

    for js in no_hash:
        _process(js, [js.url])

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

    # Normalize URL - fix common input mistakes
    # Collapse duplicate schemes: https://https://x -> https://x
    while re.match(r'^https?://https?://', target):
        target = re.sub(r'^https?://(https?://)', r'\1', target)
    # Add scheme if completely missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Safety check - fail cleanly, no prompt
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
        if args.cookie or args.header:
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

    # -- HTTP cache -------------------------------------------------------
    from .crawler.cache import FetchCache
    from pathlib import Path as _Path
    _cache_path = _Path(args.cache_dir) if getattr(args, "cache_dir", "") else None
    _fetch_cache = FetchCache(
        path=_cache_path,
        disabled=getattr(args, "no_cache", False),
    )
    if getattr(args, "clear_cache", False):
        _cleared = _fetch_cache.clear()
        if not args.quiet:
            phase_done("Cache cleared", f"{_cleared} entries removed")
    else:
        # Evict stale entries in background - fast, no network
        try:
            _fetch_cache.evict_expired()
        except Exception:
            pass
    extras["cache"] = _fetch_cache

    fetcher = Fetcher(
        timeout=args.timeout,
        requests_per_second=args.rate,
        stealth=args.stealth,
        extra_headers=extra_headers,
        cache=_fetch_cache,
    )
    scope = ScopeChecker(
        target_url=target,
        same_origin=True,
        subdomains=args.subdomains,
        exclude=args.exclude,
    )

    all_js: list = []
    errors: list = []

    # -- Active crawl -----------------------------------------------------
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

        # Surface technology-stack intelligence from HTTP response headers.
        # Server:, X-Powered-By:, Via:, CSP, etc. are collected by the crawler
        # and stored as InfrastructureItem objects for the final report.
        _observed_headers = getattr(crawler, "observed_headers", [])
        if _observed_headers:
            from .storage.models import InfrastructureItem as _InfraItem
            _header_infra = []
            _seen_hdr_vals: set = set()
            for _hdr_entry in _observed_headers:
                _page_url = _hdr_entry.get("url", target)
                for _key, _label in [
                    ("server",           "HTTP Server"),
                    ("x_powered_by",     "X-Powered-By"),
                    ("via",              "Via Proxy"),
                    ("x_generator",      "Generator"),
                    ("x_aspnet_version", "ASP.NET Version"),
                    ("x_aspnetmvc_version", "ASP.NET MVC"),
                    ("x_drupal_cache",   "Drupal CMS"),
                    ("x_wp_total",       "WordPress REST"),
                ]:
                    _val = _hdr_entry.get(_key, "")
                    if _val and _val not in _seen_hdr_vals:
                        _seen_hdr_vals.add(_val)
                        _header_infra.append(_InfraItem(
                            value          = f"{_label}: {_val}",
                            classification = "TECHNOLOGY_DISCLOSURE",
                            source_file    = f"http-header:{_page_url}",
                            line_number    = 0,
                            confidence     = 0.99,
                            action         = "report_only",
                        ))
            extras["header_infra"] = _header_infra

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

    # -- Passive intelligence collection ----------------------------------
    # Runs on every scan (active, headless, or passive mode).
    # Collects robots.txt, sitemaps, well-known paths, response headers, CSP,
    # OpenAPI schemas, and meta-tag intelligence - all without exploitation.
    try:
        from .discovery.intelligence import run_intelligence_collection
        if not args.quiet:
            phase("Collecting passive intelligence")
        _html_content = getattr(crawler, "homepage_html", "") if crawler else ""
        _intel_result = run_intelligence_collection(
            target_url   = target,
            fetcher      = fetcher,
            scope        = scope,
            html_content = _html_content,
        )
        extras["intelligence"] = _intel_result
        # Feed sitemap-discovered URLs into scope for the rest of the scan
        if _intel_result.sitemap_urls:
            for _su in _intel_result.sitemap_urls:
                if scope.in_scope(_su) and _su not in {js.source_page for js in all_js}:
                    pass  # URLs handed to coverage; JS fetch happens via crawler only
        if not args.quiet:
            _intel_summary = (
                f"{len(_intel_result.sitemap_urls)} sitemap URLs  "
                f"{len(_intel_result.technologies)} tech detected  "
                f"{len(_intel_result.interesting_headers)} header flags"
            )
            phase_done("Passive intelligence", _intel_summary)
    except Exception as _ie:
        import logging as _ilog
        _ilog.getLogger("bundlespy.cli").warning("Intelligence collection failed: %s", _ie)

    # -- Passive ----------------------------------------------------------
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

    # -- Headless ---------------------------------------------------------
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
                # Only relative paths - these are frontend routes
                if _ep.url.startswith("/") and not _ep.url.startswith("//"):
                    # Skip API paths - we want page routes not API endpoints
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

        # Pre-seed headless dedup with content hashes from crawler JS files.
        # This prevents headless from counting a file it sees again (same content,
        # possibly same or different URL) as a new unique JS asset.
        _crawler_js_hashes = {js.sha256 for js in all_js if js.sha256}

        headless_result = collect_headless_full(
            target, scope,
            stealth       = args.stealth,
            timeout       = args.timeout,
            max_pages     = args.max_pages,
            external_seen = crawler_seen,
            seed_urls     = all_seed_urls,
            interact      = getattr(args, "interact", False),
            workers       = getattr(args, "workers", 3),
            cookies       = _playwright_cookies,
            extra_headers = extra_headers,
            seen_hashes   = _crawler_js_hashes,
        )
        headless_files     = headless_result.get("js_files", [])
        # Tag all browser-captured files so the inventory can distinguish them
        for _hf in headless_files:
            if not getattr(_hf, "source_type", ""):
                _hf.source_type = "browser"
        headless_endpoints = headless_result.get("endpoints", [])
        headless_stats     = headless_result.get("stats", {})

        # Store auth result - used for mode label correction and report
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

        extras["headless_stats"] = {
            "pages":     headless_stats.get("pages", 0),
            "js":        len(headless_files),
            "xhr":       headless_stats.get("xhr", 0),
            "fetch":     headless_stats.get("fetch", 0),
            "ws":        headless_stats.get("ws", 0),
            "routes":    headless_stats.get("routes", 0),
            "endpoints": headless_stats.get("endpoints", 0),
            "workers":   headless_stats.get("workers", 0),
            "timings":   headless_stats.get("timings", {}),
        }
        if not args.quiet:
            phase_done("Browser discovery",
                f"{headless_stats.get('pages',0)} pages  "
                f"{len(headless_files)} JS  "
                f"{headless_stats.get('xhr',0)+headless_stats.get('fetch',0)} API calls  "
                f"{headless_stats.get('ws',0)} WS  "
                f"{headless_stats.get('routes',0)} routes"
            )

    # -- Source maps ------------------------------------------------------
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

    # -- Webpack chunks ---------------------------------------------------
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

    # -- Analysis ---------------------------------------------------------
    if not args.quiet:
        phase("Analyzing JavaScript")
    import time as _time
    import logging as _logging
    _logger = _logging.getLogger("bundlespy.cli")
    _t_analysis = _time.monotonic()
    scanner = SecretScanner()
    # Pass hashes already analyzed inline by the headless engine so _analyze()
    # skips those files and avoids double-counting findings/endpoints.
    _headless_analyzed_hashes = locals().get("headless_result", {}).get("analyzed_hashes", set()) if "headless_result" in locals() else set()
    all_findings, all_endpoints, all_infra, _graphql_ops = _analyze(
        all_js, scanner,
        inline_analyzed_hashes=_headless_analyzed_hashes,
        fetcher=fetcher,
        scope=scope,
    )
    _analysis_ms = int((_time.monotonic() - _t_analysis) * 1000)
    _logger.info("JS analysis took %dms for %d files", _analysis_ms, len(all_js))

    # Store extracted GraphQL operations for the report.
    # These are statically extracted operation names (query/mutation/subscription)
    # from JS source - distinct from GraphQL introspection schemas.
    extras["graphql_operations"] = _graphql_ops
    if _graphql_ops and not args.quiet:
        _gql_queries = sum(1 for op in _graphql_ops if op.op_type == "query")
        _gql_muts    = sum(1 for op in _graphql_ops if op.op_type == "mutation")
        _gql_subs    = sum(1 for op in _graphql_ops if op.op_type == "subscription")
        _logger.info(
            "GraphQL operations extracted: %d queries, %d mutations, %d subscriptions",
            _gql_queries, _gql_muts, _gql_subs,
        )

    # Merge HTTP header infrastructure items (technology disclosure from Server:, X-Powered-By:, etc.)
    _header_infra = extras.pop("header_infra", [])
    if _header_infra:
        all_infra.extend(_header_infra)

    # Re-categorize UNKNOWN endpoints using full classifier
    from .analysis.endpoints import _categorize_path as _recat
    from urllib.parse import urlparse as _uprc
    for _ep in all_endpoints:
        if _ep.category in ("UNKNOWN", ""):
            _ep_path = _uprc(_ep.url).path or _ep.url
            _ep.category = _recat(_ep_path)

    # Merge HTML attribute findings BEFORE building per-file stats
    # so html: findings are visible to the stats builder
    html_findings_from_crawler = locals().get("html_findings_from_crawler", [])
    seen_html = {f.sha256 for f in all_findings}
    for f in html_findings_from_crawler:
        if f.sha256 not in seen_html:
            seen_html.add(f.sha256)
            all_findings.append(f)

    # Per-file analysis breakdown - prove every file was analyzed
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

    # Per-file stats - run each extractor on each file individually
    # HTML attribute findings (html: prefix) are PAGE-level, not script-level
    # They are shown separately - we do NOT assign them to inline scripts
    from .analysis.endpoint_intel import extract_endpoint_intelligence as _ep_intel
    from .analysis.ast_endpoints import extract_all_endpoints as _ast_ep

    # Per-file stats - map already-computed findings/endpoints back to each file
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

    # HTML attribute findings - completely separate section, never merged into inline JS
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
        from .analysis.endpoints import _categorize_path as _cat_path
        seen_ep_keys = {ep.url.rstrip("/").lower().split("?")[0] for ep in all_endpoints}
        for ep in all_endpoints_extra:
            key = ep.url.rstrip("/").lower().split("?")[0]
            if key not in seen_ep_keys:
                seen_ep_keys.add(key)
                # Re-categorize UNKNOWN endpoints using full classifier
                if ep.category in ("UNKNOWN", ""):
                    from urllib.parse import urlparse as _upep
                    _ep_path = _upep(ep.url).path or ep.url
                    ep.category = _cat_path(_ep_path)
                all_endpoints.append(ep)

        # Static-to-runtime correlation: same canonical URL seen in static JS and
        # real network traffic -> upgrade to source_type="correlated", boost confidence.
        # Only run when we have real runtime endpoints to correlate against.
        if all_endpoints_extra:
            from .analysis.endpoints import correlate_endpoints as _correlate
            _static_eps  = [ep for ep in all_endpoints if getattr(ep, "source_type", "static") == "static"]
            _runtime_eps = [ep for ep in all_endpoints if getattr(ep, "source_type", "runtime") == "runtime"]
            if _static_eps and _runtime_eps:
                _correlated = _correlate(_static_eps, _runtime_eps)
                # Replace static+runtime portion of all_endpoints with correlated set;
                # keep crawled-page routes and any other source_type entries intact.
                _other_eps = [ep for ep in all_endpoints
                              if getattr(ep, "source_type", "static") not in ("static", "runtime")]
                all_endpoints = _other_eps + _correlated

    if not args.quiet:
        phase_done("Analysis complete",
            f"{len(all_findings)} findings  {len(all_endpoints)} endpoints  {len(all_infra)} infrastructure")

    # Deduplicate findings by rule + value - same secret on multiple pages
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

    # Remove bare target root from endpoints - it's not an API endpoint
    _target_base = target.rstrip("/").lower()
    all_endpoints = [
        ep for ep in all_endpoints
        if ep.url.rstrip("/").lower() not in (_target_base, _target_base + "/")
        and not (ep.url.rstrip("/").lower() == _target_base and ep.method == "UNKNOWN")
    ]

    # Final endpoint dedup - keep parameterized endpoints distinct
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

    # -- Attack surface analysis ------------------------------------------
    from .analysis.attack_surface import analyze_attack_surface
    attack_surface = analyze_attack_surface(all_endpoints)
    extras["attack_surface"] = attack_surface

    # -- Vulnerable library detection -------------------------------------
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

    # -- Subdomain harvesting ---------------------------------------------
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

    # -- Endpoint validation ----------------------------------------------
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

    # -- GraphQL ----------------------------------------------------------
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

    # -- Secret validation ------------------------------------------------
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

    # -- Build result -----------------------------------------------------
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

    # -- Attack surface graph ---------------------------------------------
    # Build the relationship graph from the completed scan result.
    # This is O(n) and adds no network I/O - pure in-memory assembly.
    try:
        from .storage.graph import AttackSurfaceGraph
        result.graph = AttackSurfaceGraph.from_scan_result(result)
        extras["graph"] = result.graph
    except Exception as _ge:
        import logging as _gl
        _gl.getLogger("bundlespy.cli").warning("Graph build failed: %s", _ge)

    # -- Coverage metrics -------------------------------------------------
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
    )
    extras["coverage"] = coverage

    # -- Cache stats ------------------------------------------------------
    _cache_summary = _fetch_cache.summary()
    extras["cache_stats"] = _cache_summary
    if not args.quiet and (_cache_summary["hits"] > 0 or _cache_summary["revalidated"] > 0):
        _saved_mb = _cache_summary["saved_bytes"] / 1_048_576
        phase_done(
            "Cache",
            f"{_cache_summary['hits']} hits  "
            f"{_cache_summary['revalidated']} revalidated  "
            f"{_cache_summary['misses']} misses  "
            f"{_saved_mb:.1f} MB saved",
        )

    # -- Reports ----------------------------------------------------------
    file_paths = {}
    file_formats = [f for f in formats if f != "terminal"]
    if file_formats:
        file_paths = _write_reports(result, file_formats, args.output, started,
                                    report_name=getattr(args, "report_name", ""),
                                    extras=extras, validation_results=validation_results,
                                    graphql_schemas=graphql_schemas, subdomains=subdomains)

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
        )
    elif getattr(args, "silent", False):
        # Silent mode - print only findings, one per line
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
        file_paths = _write_reports(result, file_formats, args.output, started,
                                    report_name=getattr(args, "report_name", ""),
                                    extras=extras)

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
