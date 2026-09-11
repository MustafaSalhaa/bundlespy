# Changelog

## 1.0.0 - 2026-09-11

Initial release.

### Features

- Controlled HTML crawler with depth, page, and JS file limits
- Safe HTTP client with rate limiting, retries, and size limits
- Scope enforcement (same-origin, subdomain, exclusion list)
- Network safety layer blocking private IPs, loopback, link-local, and cloud metadata endpoints
- DNS rebinding protection via pre-request hostname resolution
- Authorization confirmation prompt before every scan
- 35-rule secret detection engine covering AWS, Azure, Google, GitHub, GitLab, Stripe, Slack,
  Twilio, SendGrid, JWT, RSA keys, database connection strings, cloud storage URLs,
  internal IPs, and internal hostnames
- Shannon entropy scoring and placeholder detection for false positive reduction
- Local JWT decode and analysis (algorithm, claims, expiry, algorithm risk)
- Endpoint extraction (API paths, GraphQL, WebSocket, auth routes, admin routes)
- Infrastructure intelligence (private IPs, internal hostnames, staging/dev environments)
- Technology fingerprinting (React, Vue, Angular, Next.js, Webpack, Vite)
- Terminal report with color-coded severity and redacted values
- JSON report
- HTML report (standalone, no external dependencies)
- CSV report
- Offline demo mode
- 44 unit tests covering safety, detection, and redaction
