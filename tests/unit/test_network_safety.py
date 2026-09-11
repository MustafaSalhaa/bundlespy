"""Unit tests for the network safety layer."""

import pytest
import sys
sys.path.insert(0, "/home/claude/bundlespy/src")

from bundlespy.safety.network import (
    is_ip_blocked, validate_url, classify_url, is_hostname_blocked
)


class TestIPBlocking:
    def test_loopback_blocked(self):
        assert is_ip_blocked("127.0.0.1")
        assert is_ip_blocked("127.0.0.2")

    def test_private_10_blocked(self):
        assert is_ip_blocked("10.0.0.1")
        assert is_ip_blocked("10.255.255.255")

    def test_private_172_blocked(self):
        assert is_ip_blocked("172.16.0.1")
        assert is_ip_blocked("172.31.255.255")

    def test_private_192_blocked(self):
        assert is_ip_blocked("192.168.0.1")
        assert is_ip_blocked("192.168.255.255")

    def test_link_local_blocked(self):
        assert is_ip_blocked("169.254.169.254")  # cloud metadata
        assert is_ip_blocked("169.254.0.1")

    def test_public_ip_allowed(self):
        assert not is_ip_blocked("8.8.8.8")
        assert not is_ip_blocked("1.1.1.1")
        assert not is_ip_blocked("93.184.216.34")

    def test_ipv6_loopback_blocked(self):
        assert is_ip_blocked("::1")

    def test_ipv6_link_local_blocked(self):
        assert is_ip_blocked("fe80::1")


class TestURLValidation:
    def test_valid_https_allowed(self):
        safe, _ = validate_url("https://example.com")
        assert safe

    def test_valid_http_allowed(self):
        safe, _ = validate_url("http://example.com")
        assert safe

    def test_file_scheme_blocked(self):
        safe, _ = validate_url("file:///etc/passwd")
        assert not safe

    def test_ftp_scheme_blocked(self):
        safe, _ = validate_url("ftp://example.com")
        assert not safe

    def test_gopher_blocked(self):
        safe, _ = validate_url("gopher://evil.com")
        assert not safe

    def test_localhost_blocked(self):
        safe, _ = validate_url("http://localhost/admin")
        assert not safe

    def test_raw_private_ip_blocked(self):
        safe, _ = validate_url("http://192.168.1.1/")
        assert not safe

    def test_raw_loopback_blocked(self):
        safe, _ = validate_url("http://127.0.0.1/")
        assert not safe

    def test_cloud_metadata_blocked(self):
        safe, _ = validate_url("http://169.254.169.254/latest/meta-data/")
        assert not safe

    def test_empty_url_blocked(self):
        safe, _ = validate_url("")
        assert not safe

    def test_no_hostname_blocked(self):
        safe, _ = validate_url("https://")
        assert not safe


class TestURLClassification:
    def test_private_ip_classified(self):
        assert classify_url("http://192.168.1.50/api") == "PRIVATE_IP"
        assert classify_url("http://10.0.0.1/") == "PRIVATE_IP"

    def test_loopback_classified(self):
        assert classify_url("http://127.0.0.1/") == "LOOPBACK"
        assert classify_url("http://localhost/") == "LOOPBACK"

    def test_internal_hostname_classified(self):
        assert classify_url("http://api.internal/v1") == "INTERNAL_HOSTNAME"
        assert classify_url("http://server.local/") == "INTERNAL_HOSTNAME"
        assert classify_url("http://db.corp/") == "INTERNAL_HOSTNAME"

    def test_staging_classified(self):
        assert classify_url("https://api-staging.example.com") == "STAGING"

    def test_dev_classified(self):
        assert classify_url("https://dev.example.com") == "DEVELOPMENT"

    def test_public_classified(self):
        result = classify_url("https://api.example.com")
        assert result == "PUBLIC"

    def test_cloud_metadata_classified(self):
        # 169.254.x.x is blocked before IP classification - reported as blocked
        result = classify_url("http://169.254.169.254/latest/")
        assert result in ("LINK_LOCAL", "LOOPBACK")  # both indicate blocked


class TestHostnameBlocking:
    def test_localhost_blocked(self):
        assert is_hostname_blocked("localhost")

    def test_metadata_blocked(self):
        assert is_hostname_blocked("169.254.169.254")
        assert is_hostname_blocked("metadata.google.internal")

    def test_real_hostname_allowed(self):
        assert not is_hostname_blocked("example.com")
        assert not is_hostname_blocked("api.github.com")
