"""
Network safety layer.
Blocks private IPs, loopback, link-local, cloud metadata endpoints,
and dangerous URL schemes before any request is made.

This is the most critical safety module in BundleSpy.
It must be called before every outbound request.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


ALLOWED_SCHEMES = {"http", "https"}

# RFC 1918 private ranges + loopback + link-local + cloud metadata
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # private
    ipaddress.ip_network("172.16.0.0/12"),    # private
    ipaddress.ip_network("192.168.0.0/16"),   # private
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / IMDS
    ipaddress.ip_network("0.0.0.0/8"),        # unspecified
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # documentation
    ipaddress.ip_network("203.0.113.0/24"),   # documentation
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"),
]

BLOCKED_NETWORKS_V6 = [
    ipaddress.ip_network("::1/128"),           # loopback
    ipaddress.ip_network("fc00::/7"),          # unique local
    ipaddress.ip_network("fe80::/10"),         # link-local
    ipaddress.ip_network("::/128"),            # unspecified
]

# Cloud metadata endpoints - never contact these
BLOCKED_HOSTNAMES = {
    "169.254.169.254",       # AWS / Azure / GCP IMDS
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
    "localhost",
    "localhost.localdomain",
}


def is_ip_blocked(ip_str: str) -> bool:
    """Returns True if the resolved IP falls in a blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return any(addr in net for net in BLOCKED_NETWORKS)
        else:
            return any(addr in net for net in BLOCKED_NETWORKS_V6)
    except ValueError:
        return True  # unparseable = blocked


def is_hostname_blocked(hostname: str) -> bool:
    """Check if a hostname is on the explicit blocklist."""
    return hostname.lower().strip() in BLOCKED_HOSTNAMES


def resolve_and_check(hostname: str) -> Tuple[bool, str]:
    """
    Resolve hostname to IP and check if it's in a blocked range.
    This prevents DNS rebinding attacks where a public-looking hostname
    resolves to a private IP.

    Returns (is_safe, reason).
    """
    if is_hostname_blocked(hostname):
        return False, f"hostname '{hostname}' is on the blocked list"

    try:
        results = socket.getaddrinfo(hostname, None)
        for result in results:
            ip = result[4][0]
            if is_ip_blocked(ip):
                return False, f"hostname '{hostname}' resolved to blocked IP {ip}"
        return True, ""
    except socket.gaierror as e:
        # DNS resolution failure - treat as blocked to be safe
        return False, f"DNS resolution failed for '{hostname}': {e}"


def validate_url(url: str, check_dns: bool = False) -> Tuple[bool, str]:
    """
    Full URL safety validation.

    Returns (is_safe, reason).
    """
    if not url or not url.strip():
        return False, "empty URL"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"URL parse error: {e}"

    # Scheme check - only http and https
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"scheme '{parsed.scheme}' is not allowed (only http/https)"

    hostname = parsed.hostname
    if not hostname:
        return False, "no hostname in URL"

    # Strip IPv6 brackets
    hostname = hostname.strip("[]")

    if is_hostname_blocked(hostname):
        return False, f"hostname '{hostname}' is blocked"

    # Check if hostname is a raw IP
    try:
        addr = ipaddress.ip_address(hostname)
        if is_ip_blocked(str(addr)):
            return False, f"IP address {hostname} is in a blocked range"
        return True, ""
    except ValueError:
        pass  # not a raw IP, it's a hostname

    # Optional DNS resolution check (slower but safer against rebinding)
    if check_dns:
        safe, reason = resolve_and_check(hostname)
        if not safe:
            return False, reason

    return True, ""


def classify_url(url: str) -> str:
    """
    Classify a URL found inside JavaScript without requesting it.
    Used to categorize intelligence findings.
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip("[]")

        if not hostname:
            return "RELATIVE"

        if hostname in BLOCKED_HOSTNAMES or hostname == "localhost":
            return "LOOPBACK"

        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_loopback or str(addr) == "0.0.0.0":
                return "LOOPBACK"
            if addr.is_link_local:
                return "LINK_LOCAL"
            if addr.is_private:
                return "PRIVATE_IP"
            return "PUBLIC_IP"
        except ValueError:
            pass  # hostname, not IP

        lower = hostname.lower()
        if any(lower.endswith(s) for s in [".local", ".internal", ".corp", ".lan", ".intranet"]):
            return "INTERNAL_HOSTNAME"
        if any(k in lower for k in ["staging", "stage", "stg"]):
            return "STAGING"
        if any(k in lower for k in ["dev", "develop", "development", "test", "sandbox"]):
            return "DEVELOPMENT"
        if "169.254.169.254" in hostname:
            return "CLOUD_METADATA"

        return "PUBLIC"

    except Exception:
        return "UNKNOWN"
