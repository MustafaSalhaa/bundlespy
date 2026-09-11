"""Unit tests for the secret detection engine."""

import pytest
import sys
sys.path.insert(0, "/home/claude/bundlespy/src")

from bundlespy.analysis.secrets import SecretScanner, _shannon_entropy, _is_likely_fp


class TestEntropy:
    def test_low_entropy_string(self):
        assert _shannon_entropy("aaaaaaaaaa") < 1.0

    def test_high_entropy_string(self):
        assert _shannon_entropy("aB3$xZ9!mQ2@") > 3.0

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0


class TestFalsePositiveDetection:
    def test_example_placeholder(self):
        is_fp, reason = _is_likely_fp("AKIAEXAMPLE123456789")
        assert is_fp

    def test_your_key_placeholder(self):
        is_fp, reason = _is_likely_fp("your-api-key-here")
        assert is_fp

    def test_repeated_chars(self):
        is_fp, reason = _is_likely_fp("xxxxxxxxxxxxxxxxxxxx")
        assert is_fp

    def test_real_looking_key(self):
        is_fp, reason = _is_likely_fp("AKIAIOSFODNN7REALKEY")
        assert not is_fp


class TestSecretScanner:
    def setup_method(self):
        self.scanner = SecretScanner(
            rules_path="/home/claude/bundlespy/rules/secrets.yaml"
        )

    def test_aws_key_detected(self):
        js = "const key = 'AKIAIOSFODNN7REALKEY';"
        findings = self.scanner.scan(js, "https://example.com/app.js")
        aws = [f for f in findings if f.rule_id == "AWS_ACCESS_KEY"]
        assert len(aws) >= 1

    def test_github_token_detected(self):
        js = "const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';"
        findings = self.scanner.scan(js, "https://example.com/app.js")
        gh = [f for f in findings if f.rule_id == "GITHUB_TOKEN"]
        assert len(gh) >= 1

    def test_stripe_secret_detected(self):
        js = "const stripe = 'sk_live_abcdefghijklmnopqrstuvwx';"
        findings = self.scanner.scan(js, "https://example.com/app.js")
        stripe = [f for f in findings if f.rule_id == "STRIPE_SECRET_KEY"]
        assert len(stripe) >= 1

    def test_google_api_key_detected(self):
        js = "const apiKey = 'AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567';"
        findings = self.scanner.scan(js, "https://example.com/app.js")
        google = [f for f in findings if f.rule_id == "GOOGLE_API_KEY"]
        assert len(google) >= 1

    def test_pem_key_detected(self):
        js = "const pem = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...\\n-----END RSA PRIVATE KEY-----';"
        findings = self.scanner.scan(js, "https://example.com/app.js")
        pem = [f for f in findings if f.rule_id == "RSA_PRIVATE_KEY"]
        assert len(pem) >= 1

    def test_empty_js_no_findings(self):
        findings = self.scanner.scan("", "https://example.com/empty.js")
        assert findings == []

    def test_normal_js_no_false_positives(self):
        js = """
        function greet(name) {
            return 'Hello, ' + name;
        }
        const version = '1.0.0';
        const debug = false;
        """
        findings = self.scanner.scan(js, "https://example.com/app.js")
        # Only check for high-confidence findings to reduce noise
        high_conf = [f for f in findings if f.confidence > 0.7 and f.status != "likely_false_positive"]
        assert len(high_conf) == 0

    def test_redaction_works(self):
        from bundlespy.storage.models import Finding
        value    = "AKIAIOSFODNN7REALKEY"
        redacted = Finding.redact(value)
        assert "AKIA" in redacted
        assert redacted != value
        assert "*" in redacted
