# Security Policy

## Scope

This document covers the security of BundleSpy itself as a tool - not the targets it scans.

## Reporting a vulnerability in BundleSpy

If you find a security issue in BundleSpy - for example, an SSRF bypass, a way to make the scanner
request private network resources, a regex DoS, or credential leakage through logging - please
report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Contact: Mustafa Salha via GitHub (https://github.com/MustafaSalhaa)

Include:
- Description of the issue
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

## Known design decisions

**Private network blocking is defense-in-depth, not the only control.**
The tool blocks private IPs at the HTTP layer. This does not make it safe to run
against untrusted targets in environments where the scanner host has privileged
network access to internal systems.

**DNS resolution is checked but not guaranteed.**
The DNS rebinding protection checks addresses at request time, but short TTLs can
still theoretically allow a rebinding attack between the check and the connection.
Do not run BundleSpy on a host that has unrestricted access to sensitive internal networks.

**Secrets found by BundleSpy are not validated.**
The tool never contacts AWS, GitHub, or any other provider to check if a credential is valid.
Treat all findings as potential until manually verified.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
