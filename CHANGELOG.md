# Changelog

---

## 1.0.2 - 2026-09-14

### Added

- Advanced headless browser engine (complete rewrite of headless mode)
  - Multi-page crawling across the full application, not just root
  - Real-time XHR, fetch, and WebSocket interception at the network level
  - Route extraction from React Router, Vue Router, Angular Router, Next.js
  - Intelligent form filling to trigger API calls and validation callbacks
  - Scroll and lazy-load handling for infinite-scroll content
  - All intercepted network calls become high-confidence endpoints (0.95)
  - Configurable page limit via `--max-pages` (default 100, set 9999 for unlimited)
- Source map exploitation (`--source-maps`) - recovers original unminified source code
- Webpack and Vite chunk discovery (`--chunks`) - enumerates all lazy-loaded bundles
- Passive mode (`--passive`) - collects historical JS from Wayback Machine and CommonCrawl
- Endpoint validation (`--validate`) - probes endpoints with safe GET/HEAD requests
- GraphQL introspection (`--graphql`) - maps full schema, queries, mutations, sensitive fields
- Subdomain harvesting (`--harvest-subs`) - CT logs via crt.sh, JS content, discovered URLs
- Secret validation (`--validate-secrets`) - confirms active secrets via provider APIs (GitHub, Stripe, Slack, SendGrid)
- Stealth mode (`--stealth`) - 22 UA rotation, full browser headers, jitter delays, referrer spoofing
- Burp Suite export (`--format burp`) - sitemap XML and plain URL list
- Local scan mode (`bundlespy local ./dist/`) - CI/CD pre-deployment scanning
- New terminal UI layer (`ui/theme.py`, `ui/renderer.py`, `ui/printer.py`)
  - Clean professional output with no emojis
  - Severity hierarchy, information density, consistent alignment
  - NO_COLOR and non-TTY support
  - Auto-adapts to terminal width
- All feature results now shown in terminal output with dedicated sections
- File output is fully optional - terminal is the default

### Changed

- CLI no longer shows interactive authorization prompt - automation-friendly by default
- Headless mode now visits multiple pages instead of just the root
- Endpoint deduplication is now global across all analyzed JS files
- Social media, documentation, and CDN domains filtered from endpoint results
- Storage and static asset paths filtered from endpoint results
- 404 errors from `--common-paths` no longer logged as scan errors
- Terminal output completely redesigned - no boxes, no emojis, clean hierarchy

### Fixed

- `INTERNAL_HOSTNAME` rule false positives on JS property access (`this.int`, `e.local`)
- `BASIC_AUTH_URL` rule false positives on normal URLs containing `:` and `@`
- Rules file path resolution now works correctly in all install locations
- Duplicate endpoints from multiple inline scripts on the same page
- Secrets detection broken when rules file path resolved incorrectly

---

## 1.0.1 - 2026-09-11

### Fixed

- Rules file path resolution on non-standard install locations
- CI workflow references to old package name
- Source map path detection on installed packages

---

## 1.0.0 - 2026-09-11

### Added

- Controlled HTML crawler with depth, page, and JS file limits
- Safe HTTP client with rate limiting, retries, and size limits
- Scope enforcement (same-origin, subdomain, exclusion list)
- Network safety layer blocking private IPs, loopback, link-local, and cloud metadata endpoints
- DNS rebinding protection via pre-request hostname resolution
- 35-rule secret detection engine covering AWS, Azure, Google, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, JWT, RSA keys, database connection strings, cloud storage URLs, internal IPs, and internal hostnames
- Shannon entropy scoring and placeholder detection for false positive reduction
- Local JWT decode and analysis (algorithm, claims, expiry, algorithm risk)
- Endpoint extraction (API paths, GraphQL, WebSocket, auth routes, admin routes)
- Infrastructure intelligence (private IPs, internal hostnames, staging/dev environments)
- Technology fingerprinting (React, Vue, Angular, Next.js, Webpack, Vite)
- Terminal report with color-coded severity and redacted values
- JSON, HTML (standalone), and CSV reports
- Offline demo mode
- 44 unit tests covering safety, detection, and redaction
