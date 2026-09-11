# BundleSpy

JavaScript Intelligence and Secret Exposure Scanner for authorized penetration testing and security assessments.

BundleSpy crawls a target web application, collects JavaScript files, and analyzes them for exposed secrets, hardcoded credentials, internal API endpoints, private IP addresses, cloud storage references, and infrastructure details that can inform a security assessment.

It is a passive reconnaissance tool. It reads publicly served JavaScript - it does not exploit anything, authenticate anywhere, or touch internal systems.

---

## Why it exists

Modern web applications serve large JavaScript bundles that often contain more than intended: AWS keys accidentally left in environment configs, internal API routes baked into React builds, Firebase tokens, database URLs from development environments, staging hostnames, and JWT tokens hardcoded during testing.

These don't require authentication to find - they're sitting in files the browser downloads on every visit. The problem is that hunting through dozens of minified 2MB bundles manually takes hours. BundleSpy automates that.

---

## What it finds

- AWS, Azure, Google Cloud, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid credentials
- JWT tokens (decoded locally - algorithm, claims, expiry checked without sending anywhere)
- Hardcoded passwords and generic API keys
- Private key headers (RSA, EC, OpenSSH)
- Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
- AWS S3, Azure Blob, and Google Cloud Storage URLs
- Internal API endpoints and application routes
- Private IP addresses (10.x, 172.16-31.x, 192.168.x)
- Internal hostnames (.local, .internal, .corp, .lan)
- Staging and development environment references
- Cloud metadata endpoint references

---

## Safety model

BundleSpy is built around one principle: discover and analyze, do not exploit.

Before any scan begins, the tool requires explicit authorization confirmation. This is enforced at runtime, not buried in documentation.

Network safety is not optional. The tool blocks all requests to:
- Private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Loopback (127.x, ::1)
- Link-local and cloud metadata endpoints (169.254.169.254)
- Internal hostnames (.local, .internal, .corp, .lan)
- Non-HTTP schemes (file://, ftp://, gopher://, etc.)

DNS resolution is checked before every request to prevent DNS rebinding attacks where a public-looking hostname resolves to a private IP.

URLs discovered inside JavaScript are classified and reported as intelligence. They are never automatically requested.

Rate limiting, concurrency limits, crawl depth, page count, JS file count, and response size are all configurable and conservative by default.

---

## Installation

```bash
pipx install bundlespy
```

If you don't have pipx:
```bash
sudo apt install pipx
pipx install bundlespy
```
Or
```bash
git clone https://github.com/MustafaSalhaa/bundlespy.git
cd bundlespy
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

**Requirements:** Python 3.8+, `requests`, `pyyaml`, `urllib3`

---

## Quick start

```bash
# Run offline demo first to see what output looks like
python3 -m bundlespy.cli demo

# Scan a target (will prompt for authorization confirmation)
python3 -m bundlespy.cli scan https://example.com

# If installed as a package
bundlespy scan https://example.com
```

---

## Examples

**Basic scan with terminal output:**
```bash
bundlespy scan https://example.com
```

**Deeper crawl with more JS files:**
```bash
bundlespy scan https://example.com --depth 3 --max-pages 200 --max-js 300
```

**Generate HTML and JSON reports:**
```bash
bundlespy scan https://example.com --format html,json --output ./reports/
```

**Include subdomains in scope:**
```bash
bundlespy scan https://example.com --subdomains
```

**Try common JS paths like /app.js, /main.js:**
```bash
bundlespy scan https://example.com --common-paths
```

**Skip authorization prompt for CI pipelines:**
```bash
bundlespy scan https://staging.example.com --yes --format json --output ./reports/
```

**Show full secret values in output (use carefully):**
```bash
bundlespy scan https://example.com --show-sensitive
```

**Conservative scan - slow and polite:**
```bash
bundlespy scan https://example.com --rate 1 --concurrency 2 --timeout 15
```

---

## CLI reference

```
bundlespy scan <target> [options]

Options:
  --depth N          Crawl depth (default: 2)
  --max-pages N      Max pages to crawl (default: 100)
  --max-js N         Max JS files to fetch (default: 200)
  --concurrency N    Concurrent requests (default: 4)
  --rate N           Requests per second (default: 2)
  --timeout N        Request timeout in seconds (default: 10)
  --common-paths     Try common JS paths (/app.js, /main.js, etc.)
  --subdomains       Include subdomains in scope
  --exclude HOST     Exclude hostnames from scope (repeatable)
  --format FORMATS   Output formats: terminal,json,html,csv (comma-separated)
  --output DIR       Output directory for report files
  --show-sensitive   Show full secret values (use with caution)
  --verbose          Verbose logging
  --quiet            Suppress non-essential output
  --no-color         Disable colored terminal output
  --yes              Skip authorization prompt (for CI use)

bundlespy demo          Run offline demo with synthetic data
```

---

## Output formats

**Terminal** - color-coded findings with redacted values printed directly. Default.

**JSON** (`--format json`) - structured output with all findings, endpoints, infrastructure, and JS inventory. Suitable for parsing and integration into other tools.

**HTML** (`--format html`) - standalone self-contained report with navigation, stats dashboard, and full finding details. No external dependencies - works offline. Good for sharing with clients or teams.

**CSV** (`--format csv`) - one row per finding, easy to open in Excel or import into a tracker.

Combine formats: `--format terminal,html,json`

---

## Stealth Mode

By default BundleSpy identifies itself with its own User-Agent. If you are scanning a target protected by a WAF and want to reduce detection, use `--stealth`:

```bash
bundlespy scan https://example.com --stealth
```

What stealth mode does:

- Rotates through 45 real browser User-Agents (Chrome, Firefox, Safari, Edge, Brave, Opera, mobile browsers)
- Sends full browser header sets including Accept, Accept-Language, Sec-Fetch, and Sec-CH-UA headers
- Adds random jitter to delays between requests instead of a fixed rate
- Rotates the User-Agent periodically during the scan
- Spoofs Referer headers to match the target origin

This covers most WAF fingerprinting techniques based on headers and request patterns. It does not bypass TLS fingerprinting (JA3) used by advanced WAFs like Cloudflare in high security mode - that requires a different approach at the TLS stack level.

Use stealth mode on authorized targets only.

## Output example

```
+------------------------------------------------------------------+
|        BundleSpy - JavaScript Intelligence & Secret Scanner        |
|               Authorized Security Assessments Only               |
+------------------------------------------------------------------+
  Author  : Mustafa Salha
  Version : 1.0.0

  Scanning: https://example.com
  Depth: 2 | Max pages: 100 | Max JS: 200
  Rate: 2 req/s | Timeout: 10s

  [CRITICAL] AWS Access Key ID
  File       : /static/js/main.chunk.js
  Line       : 18291
  Confidence : 96%
  Status     : likely_secret
  Value      : AKIA************789
  Context    : ...const awsKey = 'AKIA...'
  Fix        : Remove from client-side code. Rotate in AWS console.

  [HIGH] JSON Web Token
  File       : /assets/app.js
  Line       : 1882
  Confidence : 89%
  Value      : eyJhbGci...REDACTED

  ENDPOINTS (146)
  [AUTH]     /api/auth/login
  [ADMIN]    /admin/dashboard
  [GRAPHQL]  /graphql
  [API]      /api/v1/users

  INFRASTRUCTURE INTELLIGENCE
  [PRIVATE_IP]        http://192.168.1.50/api
  [INTERNAL_HOSTNAME] https://api.internal/v2
```

---

## Detection engine

Rules live in `rules/secrets.yaml`. Each rule has a pattern, severity, base confidence score, description, remediation, and false positive guidance.

The engine combines multiple signals to score each candidate:

- Pattern match against the rule regex
- Shannon entropy of the matched value (low entropy = likely placeholder)
- Surrounding variable name and context
- Known placeholder indicators ("example", "your-key", "changeme", etc.)
- Repeated character detection

Every finding gets a confidence score (0.0 to 1.0) and a status:

- `likely_secret` - high confidence, strong signals
- `candidate` - matched the pattern, needs manual review
- `likely_false_positive` - low confidence, placeholder indicators present

Severity and confidence are separate. A HIGH severity finding with LOW confidence still gets reported but is clearly marked. Nothing is suppressed silently.

---

## False positives

The tool will produce false positives. That is expected and by design - it is better to flag something that turns out to be a placeholder than to miss a real secret.

Ways to reduce noise:

- Filter by status: focus on `likely_secret` first, review `candidate` second
- Filter by confidence: `>= 0.80` cuts most placeholders
- Check the FP note on each finding - it explains why confidence was reduced

Common false positives:

- Example keys in documentation strings
- Test values with "example", "placeholder", or "changeme" in the value
- UUIDs that match broad patterns
- CSS color values that happen to look like hex keys

---

## Adding custom rules

Edit `rules/secrets.yaml` to add your own patterns. Each rule needs:

```yaml
- id: MY_RULE
  name: My Custom Pattern
  category: Custom
  pattern: 'my-regex-pattern-here'
  severity: HIGH
  confidence: 0.80
  description: What this detects.
  remediation: How to fix it.
  fp_notes: Common false positives to watch for.
```

Rules are loaded at startup. No rebuild needed.

---

## Running tests

```bash
pip install pytest
pytest tests/unit/ -v
```

44 tests covering network safety (IP blocking, URL validation, scope enforcement, SSRF protections) and the secret detection engine (pattern matching, entropy scoring, false positive detection, redaction).

---

## Use cases

**Bug bounty recon** - run against in-scope targets after subdomain enumeration to find exposed JS bundles. Large React/Angular/Vue apps are the best targets - they bundle everything into a few large files that are easy to miss manually.

**External penetration test** - run early in an engagement as part of passive recon. JS files often reveal internal API structure, staging environments, and occasionally real credentials left from development.

**API discovery** - use the endpoint intelligence output to map the application's API surface before starting manual testing. Saves significant time compared to manually reading minified bundles.

**Cloud exposure** - S3 bucket names, Azure blob URLs, and Firebase configs appear frequently in frontend bundles. BundleSpy flags these for follow-up access checks.

**Source map analysis** - when `--common-paths` is enabled, BundleSpy looks for `.map` files that can expose original un-minified source code including comments, internal routes, and developer notes.

---

## Architecture

```
src/bundlespy/
- cli.py                CLI entry point, scan orchestration
- config.py             Configuration dataclasses and defaults
- banner.py             CLI banner
- safety/
  - network.py          IP blocking, URL validation, DNS rebinding protection
  - authorization.py    Authorization confirmation prompt
- crawler/
  - crawler.py          Bounded, rate-limited page and JS crawler
  - fetcher.py          Safe HTTP client with retries and size limits
  - scope.py            Scope enforcement
- discovery/
  - html.py             JS URL and link extraction from HTML
- analysis/
  - secrets.py          Rule-based secret detection with confidence scoring
  - endpoints.py        API path and URL extractor
  - infrastructure.py   Private IP and internal hostname detection
  - jwt.py              Local JWT decode and analysis
- reporting/
  - terminal.py         Color-coded terminal output
  - json_report.py      JSON export
  - html_report.py      Standalone HTML report
  - csv_report.py       CSV export
- storage/
  - models.py           All data models (Finding, JSFile, Endpoint, etc.)

rules/
- secrets.yaml          Detection rules - edit to customize
```

---

## Authorized use only

BundleSpy is for systems you own or have explicit written authorization to test. This includes:

- Your own web applications
- Authorized penetration testing engagements
- Approved bug bounty programs (within stated scope)
- Internal security reviews

You are responsible for ensuring your use complies with applicable laws, contracts, and program rules. The tool enforces safe defaults but safe defaults are not a substitute for authorization.

---

## License

MIT

---

## Author

Mustafa Salha
Penetration Tester | Abu Dhabi, UAE
GitHub: https://github.com/MustafaSalhaa
