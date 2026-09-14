# BundleSpy

JavaScript Intelligence and Secret Exposure Scanner for authorized penetration testing and security assessments.

BundleSpy crawls a target web application, collects JavaScript files, and analyzes them for exposed secrets, hardcoded credentials, internal API endpoints, private IP addresses, cloud storage references, and infrastructure details. It goes beyond basic crawling - recovering original source from source maps, discovering hidden webpack chunks, pulling historical JS from web archives, intercepting real browser network traffic, and validating findings against provider APIs.

---

## Why it exists

Modern web applications serve large JavaScript bundles that often contain more than intended: AWS keys accidentally left in environment configs, internal API routes baked into React builds, Firebase tokens, database URLs from development environments, staging hostnames, and JWT tokens hardcoded during testing.

These don't require authentication to find - they're sitting in files the browser downloads on every visit. BundleSpy automates that discovery and goes deeper than a standard crawler by recovering original source code, finding lazy-loaded chunks, intercepting real network traffic via a full browser engine, and pulling historical versions from web archives.

---

## What it finds

- AWS, Azure, Google Cloud, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid credentials
- JWT tokens - decoded locally, algorithm and expiry checked
- Hardcoded passwords and generic API keys
- Private key headers (RSA, EC, OpenSSH)
- Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
- AWS S3, Azure Blob, and Google Cloud Storage URLs
- Internal API endpoints and application routes
- Private IP addresses and internal hostnames
- Staging and development environment references
- GraphQL schemas, queries, mutations, and sensitive fields
- Subdomains from JS content and Certificate Transparency logs
- Historical JS secrets from Wayback Machine and CommonCrawl
- Real XHR, fetch, and WebSocket calls intercepted from a live browser session

---

## Safety model

BundleSpy is built around one principle: discover and analyze, do not exploit.

Network safety is not optional. The tool blocks all requests to:
- Private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Loopback (127.x, ::1)
- Link-local and cloud metadata endpoints (169.254.169.254)
- Internal hostnames (.local, .internal, .corp, .lan)
- Non-HTTP schemes (file://, ftp://, gopher://, etc.)

DNS resolution is checked before every request to prevent DNS rebinding attacks. Destructive HTTP methods (POST, PUT, DELETE) are never sent automatically.

---

## Installation

```bash
# Recommended
pipx install bundlespy

# Or from source
git clone https://github.com/MustafaSalhaa/bundlespy.git
cd bundlespy
pip install -e . --break-system-packages --no-build-isolation
```

**For headless browser mode (optional):**
```bash
pip install playwright --break-system-packages
playwright install chromium
```

---

## Quick start

```bash
# Offline demo - see what output looks like
bundlespy demo

# Basic scan
bundlespy scan https://example.com

# Full scan with all features
bundlespy scan https://example.com --source-maps --chunks --validate --graphql --format html,json --output ./reports/

# Advanced headless scan - visits every page, intercepts all network traffic
bundlespy scan https://example.com --headless --max-pages 9999

# Passive mode - zero requests to target
bundlespy scan https://example.com --passive --format html --output ./reports/

# Scan local JS files
bundlespy local ./dist/
```

---

## Commands

### `bundlespy scan`

Active scan against a live target.

```bash
bundlespy scan https://example.com [options]
```

### `bundlespy local`

Scan local JS/TS files without any network requests. Useful for CI/CD and pre-deployment secret scanning.

```bash
bundlespy local ./dist/
bundlespy local ./build/ --format html --output ./reports/
```

### `bundlespy demo`

Offline demo with synthetic data. No network requests.

```bash
bundlespy demo
```

---

## All options

```
Crawl:
  --depth N           Crawl depth (default: 2)
  --max-pages N       Max pages to crawl, also controls headless page limit (default: 100)
  --max-js N          Max JS files to fetch (default: 200)
  --rate N            Requests per second (default: 2)
  --timeout N         Request timeout in seconds (default: 10)
  --common-paths      Try common JS paths like /app.js, /main.js
  --subdomains        Include subdomains in scope
  --exclude HOST      Exclude hostnames from scope

Features:
  --source-maps       Download and analyze source maps to recover original source code
  --chunks            Discover and scan webpack/Vite lazy-loaded chunks
  --passive           Pull historical JS from Wayback Machine and CommonCrawl (no target requests)
  --headless          Advanced headless browser - multi-page, network-intercepting, interaction-aware
  --validate          Probe discovered endpoints with safe GET/HEAD requests
  --graphql           Run GraphQL introspection on detected endpoints
  --harvest-subs      Collect subdomains from JS content and CT logs
  --validate-secrets  Validate detected secrets against provider APIs (read-only)
  --stealth           WAF evasion - UA rotation, jitter delays, full browser headers

Output:
  --format FORMATS    terminal, json, html, csv, burp (comma-separated, default: terminal)
  --output DIR        Directory for report files
  -v, --verbose       Show detailed discovery information
  -q, --quiet         Findings and errors only
  --no-color          Disable ANSI colors

Other:
  --yes               Skip authorization prompt (for CI/CD use)
```

---

## Feature details

### Source map exploitation (`--source-maps`)

Many production apps ship with source maps that expose the full original source code - comments, internal routes, developer notes, and everything the minifier removed. BundleSpy detects `.map` file references, downloads them safely, recovers the original source files, and feeds them through the secret and endpoint analyzers.

```bash
bundlespy scan https://example.com --source-maps
```

### Webpack chunk discovery (`--chunks`)

Modern React/Angular/Vue apps split into dozens or hundreds of lazy-loaded chunks. A normal crawler only sees the initial bundle. BundleSpy parses webpack and Vite runtime manifests to enumerate all chunk IDs, then fetches and analyzes each one automatically.

```bash
bundlespy scan https://example.com --chunks
```

### Passive mode (`--passive`)

Pulls historical JS URLs from Wayback Machine and CommonCrawl without making any direct requests to the target. Old JS files from 1-2 years ago often contain credentials that are still valid. Zero noise on the target.

```bash
bundlespy scan https://example.com --passive
```

Note: passive mode skips the active crawler entirely. Run a separate active scan if you want both.

### Headless browser (`--headless`)

BundleSpy's headless engine goes beyond basic browser automation. It does not just visit the root page and stop.

What it does:
- Visits every discovered route across the full application
- Intercepts all XHR, fetch, and WebSocket calls at the network level in real time
- Extracts routes from React Router, Vue Router, Angular Router, and Next.js
- Fills forms intelligently with test values to trigger validation and autocomplete API calls
- Scrolls pages to capture lazy-loaded and infinite-scroll content
- Captures dynamically injected webpack chunks that a static crawler never sees
- All intercepted API calls become high-confidence endpoints (0.95) in the report

```bash
pip install playwright && playwright install chromium

# Standard headless scan
bundlespy scan https://example.com --headless

# No page limit - crawl everything the browser finds
bundlespy scan https://example.com --headless --max-pages 9999

# Combine with stealth for WAF-protected targets
bundlespy scan https://example.com --headless --stealth
```

### Endpoint validation (`--validate`)

After discovering endpoints from JS content, BundleSpy probes each one with a safe GET or HEAD request and reports status codes, content types, and interesting findings. Never makes POST, PUT, or DELETE requests. Rate limited and scope enforced.

```bash
bundlespy scan https://example.com --validate
```

### GraphQL introspection (`--graphql`)

When GraphQL endpoints are detected, BundleSpy runs a safe introspection query to map the full schema - types, queries, mutations, and fields. Flags sensitive field names like `password`, `token`, `ssn`, and `credit_card`.

```bash
bundlespy scan https://example.com --graphql
```

### Subdomain harvesting (`--harvest-subs`)

Passively collects subdomains from JS file content, discovered URLs, and Certificate Transparency logs via crt.sh. No DNS brute-forcing. No active probing.

```bash
bundlespy scan https://example.com --harvest-subs
```

### Secret validation (`--validate-secrets`)

For high-confidence findings, optionally validates secrets against provider APIs using read-only requests. Supported providers: GitHub, Stripe, Slack, SendGrid. Never logs or displays secret values. Clearly distinguishes `detected` from `validated`.

```bash
bundlespy scan https://example.com --validate-secrets
```

### Stealth mode (`--stealth`)

Rotates through 22 real browser User-Agents (Chrome, Firefox, Safari, Edge, Brave, Opera, mobile), sends full browser header sets including Sec-Fetch and Sec-CH-UA headers, adds random jitter to request delays, and spoofs Referer headers to match the target origin.

```bash
bundlespy scan https://example.com --stealth
bundlespy scan https://example.com --headless --stealth
```

Does not bypass TLS fingerprinting (JA3) used by advanced WAFs like Cloudflare in high security mode.

### Burp Suite export (`--format burp`)

Exports discovered endpoints and JS file URLs into Burp Suite sitemap XML format and a plain URL list for immediate use in manual testing.

```bash
bundlespy scan https://example.com --format html,json,burp --output ./reports/
```

---

## Output formats

- **terminal** - clean professional output with severity hierarchy and redacted values. Default.
- **json** - structured output with all findings, endpoints, infrastructure, and JS inventory.
- **html** - standalone self-contained report. No external dependencies, works offline.
- **csv** - one row per finding, ready for Excel or a bug tracker.
- **burp** - Burp Suite sitemap XML and plain URL list.

Combine formats:
```bash
bundlespy scan https://example.com --format terminal,html,json,csv,burp --output ./reports/
```

---

## Detection engine

Rules live in `rules/secrets.yaml`. 35 rules covering:
AWS, Azure, Google Cloud, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, JWT, RSA keys, database connection strings, cloud storage URLs, internal IPs, internal hostnames, and more.

Each finding gets a confidence score (0.0 to 1.0) and a status:
- `likely_secret` - high confidence, strong signals
- `candidate` - matched pattern, needs manual review
- `likely_false_positive` - low confidence, placeholder indicators present
- `validated` - confirmed active via provider API (when `--validate-secrets` is used)

---

## Running tests

```bash
cd bundlespy
pytest tests/unit/ -v
```

44 tests covering network safety, SSRF protection, secret detection, entropy scoring, false positive detection, and redaction.

---

## Use cases

**Bug bounty JS recon** - run against in-scope targets after subdomain enumeration. Use `--passive` first for zero noise, then `--headless --source-maps --chunks` for full coverage.

**External penetration test** - run early in an engagement. JS files reveal internal API structure, staging environments, and credentials left from development. `--headless --max-pages 9999` maps the full API surface.

**API discovery** - use endpoint intelligence output to map the application's API surface before manual testing. `--graphql` maps the full GraphQL schema automatically. `--headless` intercepts real API calls the frontend makes.

**Cloud exposure** - S3 bucket names, Azure blob URLs, and Firebase configs appear frequently in frontend bundles.

**CI/CD pre-deployment scanning** - use `bundlespy local ./dist/` to catch secrets before they go live.

**Passive recon** - use `--passive` to collect historical JS without touching the target at all.

---

## Architecture

```
src/bundlespy/
- cli.py                    CLI - scan, local, demo commands
- config.py                 Configuration and defaults
- banner.py                 ASCII banner
- safety/
  - network.py              SSRF protection, IP blocking, URL validation
  - authorization.py        Authorization confirmation prompt
- crawler/
  - crawler.py              Bounded, rate-limited page and JS crawler
  - fetcher.py              Safe HTTP client with stealth support
  - scope.py                Scope enforcement
- discovery/
  - html.py                 JS URL and link extraction from HTML
  - source_maps.py          Source map detection and recovery
  - webpack_chunks.py       Webpack/Vite chunk enumeration
  - passive.py              Wayback Machine and CommonCrawl collection
  - headless.py             Advanced headless browser engine
  - subdomains.py           Passive subdomain harvesting
  - local_scanner.py        Local file system scanning
- analysis/
  - secrets.py              35-rule secret detection engine
  - endpoints.py            API path and URL extractor
  - infrastructure.py       Private IP and internal hostname detection
  - jwt.py                  Local JWT decode and analysis
  - endpoint_validator.py   Safe endpoint probing
  - graphql.py              GraphQL introspection
  - secret_validator.py     Provider API validation
- reporting/
  - terminal.py             Professional terminal output
  - json_report.py          JSON export
  - html_report.py          Standalone HTML report
  - csv_report.py           CSV export
  - burp_export.py          Burp Suite XML and URL list
- ui/
  - theme.py                Color system, severity colors, NO_COLOR support
  - renderer.py             Terminal width, dividers, tables, truncation
  - printer.py              All terminal output - findings, endpoints, summary
- utils/
  - stealth.py              UA rotation, browser headers, jitter delays
- storage/models.py         All data models
- rules/secrets.yaml        Detection rules

rules/
- secrets.yaml              35 detection rules
```

---

## Known limitations

- Headless mode does not bypass TLS fingerprinting (JA3) - Cloudflare high security mode will block it
- Passive mode may return empty results for new or low-traffic domains
- Secret detection confidence depends on code context - always verify findings manually
- Endpoint extraction from heavily obfuscated bundles may miss some paths
- `--passive` skips the active crawler entirely - run separately if you want both

---

## Stealth and WAF evasion

```bash
bundlespy scan https://example.com --stealth
```

Stealth mode enables:
- Rotation through 22 real browser User-Agents
- Full browser header sets (Accept, Accept-Language, Sec-Fetch, Sec-CH-UA)
- Random jitter on request delays instead of a fixed rate
- Referrer spoofing to match the target origin

This covers most WAF fingerprinting based on headers and request patterns. It does not bypass TLS fingerprinting (JA3) used by Cloudflare in high security mode.

---

## Authorized use only

BundleSpy is for systems you own or have explicit written authorization to test:
- Your own web applications
- Authorized penetration testing engagements
- Approved bug bounty programs (within stated scope)
- Internal security reviews
- CI/CD pre-deployment scanning on your own builds

You are responsible for ensuring your use complies with applicable laws, contracts, and program rules.

---

## License

MIT

---

## Author

Mustafa Salha
Penetration Tester, Abu Dhabi, UAE
GitHub: https://github.com/MustafaSalhaa
PyPI: https://pypi.org/project/bundlespy
