[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/) [![License MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE) [![PyPI](https://img.shields.io/pypi/v/bundlespy)](https://pypi.org/project/bundlespy) [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20kali-lightgrey)](https://www.kali.org/)

```
██████╗ ██╗   ██╗███╗   ██╗██████╗ ██╗     ███████╗███████╗██████╗ ██╗   ██╗
██╔══██╗██║   ██║████╗  ██║██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝
██████╔╝██║   ██║██╔██╗ ██║██║  ██║██║     █████╗  ███████╗██████╔╝ ╚████╔╝ 
██╔══██╗██║   ██║██║╚██╗██║██║  ██║██║     ██╔══╝  ╚════██║██╔═══╝   ╚██╔╝  
██████╔╝╚██████╔╝██║ ╚████║██████╔╝███████╗███████╗███████║██║        ██║   
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝        ╚═╝   
```

**JavaScript attack surface scanner for authorized penetration testing**

BundleSpy crawls a target web application, collects JavaScript files, and extracts secrets, endpoints, credentials, and infrastructure details that developers accidentally left in the code. It goes beyond a standard crawler by recovering original source from source maps, discovering hidden webpack chunks, pulling historical JS from web archives, intercepting real browser network traffic, and validating findings against provider APIs.

---

## What it finds

| What | Examples |
|------|---------|
| Cloud credentials | AWS keys, Azure secrets, GCP tokens, GitHub tokens, GitLab tokens |
| Payment and messaging | Stripe keys, Slack tokens, Twilio, SendGrid |
| JWT tokens | Decoded locally - algorithm, expiry, claims |
| Private keys | RSA, EC, OpenSSH |
| Database strings | PostgreSQL, MySQL, MongoDB, Redis connection URLs |
| Cloud storage | S3 bucket URLs, Azure Blob, Google Cloud Storage |
| API endpoints | Internal routes, admin paths, hidden API surfaces |
| Infrastructure | Private IPs, internal hostnames, staging environments |
| GraphQL | Full schema via introspection - queries, mutations, sensitive fields |
| Subdomains | Extracted from JS content and CT logs via crt.sh |
| Historical secrets | Old JS from Wayback Machine and CommonCrawl |
| Live traffic | XHR, fetch, WebSocket calls intercepted from real browser session |

> 📸 **[SCREENSHOT: Run `bundlespy scan https://example.com` and capture the full terminal output - banner, discovery phase, findings list, and summary. Dark terminal background.]**

---

## Installation

### Recommended

```bash
pipx install bundlespy
```

### From source (Kali Linux)

```bash
git clone https://github.com/MustafaSalhaa/bundlespy.git
cd bundlespy
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

> **Kali Linux note:** The system Python is externally managed (PEP 668). Always use a venv - plain `pip install` will fail.

### Headless browser support (optional)

```bash
pip install playwright
playwright install chromium
```

---

## Quick start

```bash
# Basic scan
bundlespy scan https://example.com

# Full scan with all features
bundlespy scan https://example.com --source-maps --chunks --validate --graphql --format html,json --output ./reports/

# Headless - visits every page, intercepts all network traffic
bundlespy scan https://example.com --headless --max-pages 9999

# Passive - zero requests to target, pulls from web archives
bundlespy scan https://example.com --passive --format html --output ./reports/

# Authenticated scan - post-login JS surface
bundlespy scan https://app.example.com \
  --cookie "session=abc123" \
  --headless --source-maps --chunks --validate --graphql \
  --format html --output ./reports/

# Scan local build before deployment
bundlespy local ./dist/

# Offline demo
bundlespy demo
```

---

## Features

### Source map recovery (`--source-maps`)

Many production apps ship with source maps that expose full original source - comments, internal routes, dev notes, everything the minifier stripped. BundleSpy detects `.map` references, downloads them, recovers the original files, and feeds them through the secret and endpoint analyzers.

> 📸 **[SCREENSHOT: Source map recovery output showing list of recovered files and a secret found in original source]**

### Webpack chunk discovery (`--chunks`)

React, Angular, and Vue apps split code into dozens or hundreds of lazy-loaded chunks. A normal crawler only sees the initial bundle. BundleSpy parses webpack and Vite runtime manifests to enumerate all chunk IDs, then fetches and analyzes each one.

> 📸 **[SCREENSHOT: Chunk discovery showing chunk IDs enumerated and JS files fetched]**

### Passive mode (`--passive`)

Pulls historical JS URLs from Wayback Machine and CommonCrawl without making any direct requests to the target. JS files from 1-2 years ago often contain credentials that are still valid today. Zero noise on the target.

> 📸 **[SCREENSHOT: Passive mode output showing archive URLs collected and any findings]**

### Headless browser (`--headless`)

Full Playwright-based browser engine. Visits every discovered route. Intercepts XHR, fetch, and WebSocket calls at the network level in real time. Fills forms with test values to trigger API calls. Scrolls for lazy and infinite-scroll content. All intercepted calls become high-confidence endpoints (0.95).

```bash
pip install playwright && playwright install chromium
bundlespy scan https://example.com --headless --max-pages 9999
```

> 📸 **[SCREENSHOT: Headless scan output - pages visited counter, intercepted network calls, endpoints discovered]**

### Async fetching (`--concurrency N`)

AsyncFetcher fires up to N parallel requests using aiohttp and asyncio (default: 10). Up to 10x faster than sequential fetching on JS-heavy targets. Bounded by semaphore, rate-limited, and SSRF-protected - no unbounded parallelism.

### Secret validation (`--validate-secrets`)

For high-confidence findings, validates against provider APIs using read-only requests. Supported: GitHub, Stripe, Slack, SendGrid. Never logs or displays secret values. Clearly distinguishes `detected` from `validated`.

### GraphQL introspection (`--graphql`)

When GraphQL endpoints are detected, runs a safe introspection query to map the full schema - types, queries, mutations, fields. Flags sensitive field names like `password`, `token`, `ssn`, `credit_card`.

### Stealth mode (`--stealth`)

Rotates through 22 real browser User-Agents (Chrome, Firefox, Safari, Edge, Brave, Opera, mobile). Sends full browser header sets including Sec-Fetch and Sec-CH-UA. Adds random jitter to request delays. Spoofs Referer headers to match the target origin.

> **Note:** does not bypass TLS fingerprinting (JA3). Cloudflare high security mode will still block it.

### Authenticated scanning (`--cookie`, `--header`)

Scan as a logged-in user to reach post-login JS bundles containing internal API routes, admin endpoints, and staging references.

```bash
# Get your session cookie from DevTools - Application tab - Cookies
bundlespy scan https://app.example.com \
  --cookie "session=abc123; csrf=xyz" \
  --header "Authorization: Bearer eyJ..."
```

### Burp Suite export (`--format burp`)

Exports discovered endpoints and JS URLs into Burp Suite sitemap XML and a plain URL list for immediate use in manual testing.

---

## Safety model

BundleSpy is built around one principle: discover and analyze, never exploit.

All requests are blocked to:
- Private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Loopback (127.x, ::1)
- Link-local and cloud metadata endpoints (169.254.169.254)
- Internal hostnames (.local, .internal, .corp, .lan)
- Non-HTTP schemes (file://, ftp://, gopher://)

DNS resolution is checked before every request to prevent DNS rebinding. POST, PUT, and DELETE are never sent automatically. Destructive UI actions are blocked in headless mode (delete, purchase, payment flows, account changes, password resets). Concurrency is bounded by semaphore. Response size is capped at 10MB.

---

## All options

**Crawl**

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 2 | Crawl depth |
| `--max-pages N` | 100 | Max pages to crawl (also controls headless page limit) |
| `--max-js N` | 200 | Max JS files to fetch |
| `--rate N` | 2 | Requests per second |
| `--concurrency N` | 10 | Concurrent async HTTP requests |
| `--timeout N` | 10 | Request timeout in seconds |
| `--common-paths` | off | Try common JS paths (/app.js, /main.js, etc.) |
| `--subdomains` | off | Include subdomains in scope |
| `--exclude HOST` | - | Exclude hostnames from scope |

**Features**

| Flag | Default | Description |
|------|---------|-------------|
| `--source-maps` | off | Download and analyze source maps |
| `--chunks` | off | Discover and scan webpack/Vite lazy chunks |
| `--passive` | off | Pull historical JS from web archives (zero target requests) |
| `--headless` | off | Advanced headless browser with network interception |
| `--validate` | off | Probe discovered endpoints with safe GET/HEAD |
| `--graphql` | off | Run GraphQL introspection on detected endpoints |
| `--harvest-subs` | off | Collect subdomains from JS content and CT logs |
| `--validate-secrets` | off | Validate secrets against provider APIs (read-only) |
| `--stealth` | off | WAF evasion - UA rotation, jitter, full browser headers |
| `--cookie VALUE` | - | Session cookie for authenticated scanning |
| `--header KEY:VALUE` | - | Custom header (repeatable) |

**Output**

| Flag | Default | Description |
|------|---------|-------------|
| `--format FORMATS` | terminal | terminal, json, html, csv, burp (comma-separated) |
| `--output DIR` | - | Directory for report files |
| `-v` | off | Verbose - show detailed discovery info |
| `-q` | off | Quiet - findings and errors only |
| `--no-color` | off | Disable ANSI colors |

**Other**

| Flag | Default | Description |
|------|---------|-------------|
| `--yes` | off | Skip authorization prompt (for CI/CD) |

---

## Output formats

- `terminal` - clean output with severity hierarchy and redacted values (default)
- `json` - structured output with all findings, endpoints, infrastructure, JS inventory
- `html` - standalone self-contained report, no external dependencies, works offline
- `csv` - one row per finding, ready for Excel or a bug tracker
- `burp` - Burp Suite sitemap XML and plain URL list

> 📸 **[SCREENSHOT: HTML report opened in browser - show the findings dashboard with severity breakdown and one finding expanded]**

---

## Use cases

**Bug bounty JS recon**

Run after subdomain enumeration. Use `--passive` first for zero noise, then `--headless --source-maps --chunks` for full coverage.

**External penetration test**

Run early in the engagement. JS files reveal internal API structure, staging environments, and credentials left from development. `--headless --max-pages 9999` maps the full API surface.

**API discovery**

Combine `--validate` and `--graphql` to map the full API before manual testing. `--headless` intercepts real calls the frontend makes.

**CI/CD pre-deployment**

`bundlespy local ./dist/` catches secrets before they go live. No network requests, fast, fits in any pipeline.

---

## Detection engine

Rules live in `rules/secrets.yaml`. 35 rules covering AWS, Azure, Google Cloud, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, JWT, RSA keys, database connection strings, cloud storage URLs, internal IPs, and internal hostnames.

Each finding gets a confidence score (0.0 to 1.0) and one of four statuses:

- `likely_secret` - high confidence, strong signals
- `candidate` - matched pattern, needs manual review
- `likely_false_positive` - low confidence, placeholder indicators present
- `validated` - confirmed active via provider API (requires `--validate-secrets`)

---

## Running tests

```bash
cd bundlespy
pytest tests/unit/ -v
```

44 tests covering network safety, SSRF protection, secret detection, entropy scoring, false positive filtering, async fetching, and redaction.

---

## Architecture

```
src/bundlespy/
- cli.py                    CLI entry point
- config.py                 Configuration and defaults
- banner.py                 ASCII banner
- safety/
  - network.py              SSRF protection, IP blocking, URL validation
  - authorization.py        Authorization confirmation prompt
- crawler/
  - crawler.py              Bounded, rate-limited page and JS crawler
  - fetcher.py              Sync and async HTTP clients with stealth support
  - scope.py                Scope enforcement
- discovery/
  - html.py                 JS URL and link extraction from HTML
  - source_maps.py          Source map detection and recovery
  - webpack_chunks.py       Webpack/Vite chunk enumeration
  - passive.py              Wayback Machine and CommonCrawl collection
  - headless.py             Advanced headless browser engine
  - subdomains.py           Passive subdomain harvesting
  - local_scanner.py        Local file system scanning
  - registry.py             JS file registry and deduplication
- analysis/
  - secrets.py              35-rule secret detection engine
  - endpoints.py            API path and URL extractor
  - infrastructure.py       Private IP and internal hostname detection
  - jwt.py                  Local JWT decode and analysis
  - endpoint_validator.py   Safe endpoint probing
  - graphql.py              GraphQL introspection
  - secret_validator.py     Provider API validation
- reporting/
  - terminal.py             Terminal output
  - json_report.py          JSON export
  - html_report.py          Standalone HTML report
  - csv_report.py           CSV export
  - burp_export.py          Burp Suite XML and URL list
- ui/
  - theme.py                Color system, severity colors
  - renderer.py             Terminal width, dividers, tables
  - printer.py              All terminal output logic
- utils/
  - stealth.py              UA rotation, browser headers, jitter
  - url_normalizer.py       URL deduplication and normalization
- storage/models.py         All data models
- rules/secrets.yaml        35 detection rules
```

---

## Known limitations

- Headless does not bypass TLS fingerprinting (JA3) - Cloudflare high security mode will block it
- Passive mode may return empty results for new or low-traffic domains
- Secret detection depends on code context - always verify findings manually
- Endpoint extraction from heavily obfuscated bundles may miss some paths
- `--passive` skips the active crawler entirely - run a separate scan if you want both

---

## Authorized use

BundleSpy is for systems you own or have explicit written authorization to test:

- Your own web applications
- Authorized penetration testing engagements
- Approved bug bounty programs (within stated scope)
- Internal security reviews
- CI/CD pre-deployment scanning on your own builds

You are responsible for compliance with applicable laws, contracts, and program rules.

---

**Author:** Mustafa Salha - Penetration Tester, Abu Dhabi, UAE
**GitHub:** https://github.com/MustafaSalhaa
**PyPI:** https://pypi.org/project/bundlespy
**License:** MIT

---
