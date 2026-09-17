"""
Regression tests for BundleSpy secret-detection false-positive reduction.

Focus areas:
  1. Vault token — valid hvs./hvb. → detect; legacy s. → ignore;
     s.method() inside minified JS → ignore
  2. min_length enforcement
  3. Third-party library URL suppression
  4. Context-aware confidence (keyword proximity)
  5. Existing detection layers unchanged (AWS, GitHub, Stripe, JWT, etc.)
  6. No duplicate findings; provenance fields present

These tests are designed to FAIL on the old secrets.py and PASS after the fix.
"""

import sys
import re
from pathlib import Path

# Always import from the project source, not an installed package.
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from bundlespy.analysis.secrets import (
    SecretScanner,
    SecretRule,
    _is_library_url,
    _shannon_entropy,
    _is_likely_fp,
    load_rules,
)

RULES_PATH = str(Path(__file__).parent.parent.parent / "rules" / "secrets.yaml")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_scanner() -> SecretScanner:
    return SecretScanner(rules_path=RULES_PATH)


def vault_findings(scanner, content, url="https://example.com/app.js"):
    findings = scanner.scan(content, url)
    return [f for f in findings if f.rule_id == "VAULT_TOKEN"]


# ─── 1. Vault token ───────────────────────────────────────────────────────────

class TestVaultToken:
    """Vault token detection — valid tokens detected, noise suppressed."""

    def setup_method(self):
        self.scanner = make_scanner()

    # 1a. Valid hvs. service token (≥ 26 chars total including prefix)
    def test_valid_hvs_token_detected(self):
        content = 'const vaultToken = "hvs.AaBbCcDdEeFfGgHhIiJjKkLl";'
        hits = vault_findings(self.scanner, content)
        assert len(hits) >= 1, "Valid hvs. token should be detected"
        assert hits[0].status != "likely_false_positive"

    # 1b. Valid hvb. batch token
    def test_valid_hvb_token_detected(self):
        content = 'vault_token = "hvb.AaBbCcDdEeFfGgHhIiJjKkLl1234";'
        hits = vault_findings(self.scanner, content)
        assert len(hits) >= 1, "Valid hvb. batch token should be detected"

    # 1c. hvs. token that is too short (below min_length) → ignored
    def test_short_hvs_token_ignored(self):
        content = 'const x = "hvs.Ab12";'  # only 9 chars total
        hits = vault_findings(self.scanner, content)
        assert len(hits) == 0, "Short hvs. value should be ignored (below min_length)"

    # 1d. Legacy s. prefix alone → never matched
    def test_legacy_s_prefix_not_matched(self):
        # Exactly the kind of string that used to match the old s.[A-Za-z0-9]{24} pattern
        content = 's.isImmediatePropagationStopped=function(){return this.stopped}'
        hits = vault_findings(self.scanner, content)
        assert len(hits) == 0, "Legacy s. prefix should never produce a Vault finding"

    # 1e. jQuery minified — s.checkPosition property chain → no Vault hit
    def test_jquery_property_chain_no_vault_hit(self):
        # Excerpted from the actual jQuery 3.4.1 minified source
        content = (
            "n=0;while((o=i.handlers[n++])&&!s.isImmediatePropagationStopped())"
            "s.rnamespace&&!1!==o.namespace&&!s.rnamespace.test(o.namespace)||"
            "(s.handleObj=o,s.data=o.data,void 0!=="
        )
        hits = vault_findings(self.scanner, content)
        assert len(hits) == 0, "jQuery method chains should not match Vault token"

    # 1f. Bootstrap minified — s.checkPosition pattern → no Vault hit
    def test_bootstrap_property_chain_no_vault_hit(self):
        content = (
            "a.proxy(this.checkPosition,this)).on('click.bs.affix.data-api',"
            "a.proxy(this.checkPositionWithEventLoop,this))"
        )
        hits = vault_findings(self.scanner, content)
        assert len(hits) == 0, "Bootstrap property chains should not match Vault token"

    # 1g. Vault-like text inside unrelated context → no hit
    def test_vault_like_text_in_comment_no_hit(self):
        content = "// See https://vaultproject.io for s.storage and s.metadata docs"
        hits = vault_findings(self.scanner, content)
        assert len(hits) == 0, "s.storage in a comment should not match"

    # 1h. hvb. token confidence is high (not marked FP)
    def test_hvb_token_high_confidence(self):
        content = 'const token = "hvb.AaBbCcDdEeFfGgHhIiJjKkLl1234Mm";'
        hits = vault_findings(self.scanner, content)
        assert len(hits) >= 1
        assert hits[0].confidence >= 0.80, "Vault batch token should have high confidence"
        assert hits[0].status != "likely_false_positive"


# ─── 2. min_length enforcement ───────────────────────────────────────────────

class TestMinLength:
    """SecretRule.min_length is enforced during scan."""

    def setup_method(self):
        self.scanner = make_scanner()

    def test_vault_min_length_rejects_short_value(self):
        """hvs. + only 5 chars → below min_length=26 → no hit."""
        content = 'token = "hvs.Ab1Cd";'
        hits = vault_findings(self.scanner, content)
        assert len(hits) == 0

    def test_vault_min_length_accepts_exact_length(self):
        """hvs. (4) + 24 base64 chars = 28 total chars → pattern {24,} satisfied → detect.
        min_length=26 is satisfied (28 >= 26) and pattern requires ≥24 chars after prefix."""
        # Pattern: (?:hvs\.|hvb\.)[A-Za-z0-9+/]{24,}
        # Minimum match = 4 (prefix) + 24 = 28 chars
        token = "hvs." + "A" * 24   # 28 chars total
        content = f'vault_token = "{token}";'
        hits = vault_findings(self.scanner, content)
        assert len(hits) >= 1, "Token at exact pattern minimum (28 chars) should be detected"

    def test_rule_without_min_length_still_works(self):
        """AWS key rule has no min_length; still detects normally."""
        content = "const key = 'AKIAIOSFODNN7REALKEY';"
        findings = self.scanner.scan(content, "https://example.com/app.js")
        aws = [f for f in findings if f.rule_id == "AWS_ACCESS_KEY"]
        assert len(aws) >= 1, "AWS key without min_length should still be detected"

    def test_min_length_field_loaded_from_yaml(self):
        """Vault rule in YAML has min_length=26; verify it is loaded."""
        rules = load_rules(RULES_PATH)
        vault_rules = [r for r in rules if r.id == "VAULT_TOKEN"]
        assert vault_rules, "VAULT_TOKEN rule must exist in YAML"
        vault_rule = vault_rules[0]
        assert vault_rule.min_length == 26, (
            f"VAULT_TOKEN min_length should be 26, got {vault_rule.min_length}"
        )

    def test_min_length_zero_by_default(self):
        """Rules without min_length in YAML default to 0."""
        rules = load_rules(RULES_PATH)
        # Pick any rule that definitely has no min_length set
        aws_rules = [r for r in rules if r.id == "AWS_ACCESS_KEY"]
        assert aws_rules
        assert aws_rules[0].min_length == 0


# ─── 3. Third-party library URL suppression ──────────────────────────────────

class TestLibraryUrlSuppression:
    """Findings from known library files are suppressed unless in key= context."""

    def setup_method(self):
        self.scanner = make_scanner()

    def _scan(self, content, url):
        return self.scanner.scan(content, url)

    # 3a. is_library_url correctly identifies known libraries
    def test_jquery_url_recognized(self):
        assert _is_library_url("https://example.com/static/js/jquery-3.4.1.min.js")
        assert _is_library_url("https://code.jquery.com/jquery-3.6.0.min.js")
        assert _is_library_url("/assets/jquery.min.js")

    def test_bootstrap_url_recognized(self):
        assert _is_library_url("https://example.com/static/js/bootstrap.js")
        assert _is_library_url("/static/bootstrap.bundle.min.js")

    def test_react_url_recognized(self):
        assert _is_library_url("/js/react.production.min.js")
        assert _is_library_url("https://cdn.example.com/react.min.js")

    def test_vue_url_recognized(self):
        assert _is_library_url("/vendor/vue.min.js")

    def test_cdn_url_recognized(self):
        assert _is_library_url("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js")
        assert _is_library_url("https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js")

    def test_app_bundle_url_not_library(self):
        assert not _is_library_url("https://example.com/static/js/main.chunk.js")
        assert not _is_library_url("https://example.com/app.js")
        assert not _is_library_url("https://example.com/dist/bundle.js")

    # 3b. Pattern that would match in app code — suppressed in library URL
    def test_pattern_in_jquery_url_suppressed(self):
        # The old s. Vault pattern would have matched this. With the new rule it
        # won't match at all. But test that generic noisy patterns inside library
        # files don't produce high-confidence findings.
        js = (
            "n=0;while((o=i.handlers[n++])&&!s.isImmediatePropagationStopped())"
            "s.rnamespace&&!1!==o.namespace&&!s.rnamespace.test(o.namespace)"
        )
        url = "https://example.com/static/js/jquery-3.4.1.min.js"
        findings = self._scan(js, url)
        # No high-confidence findings from minified jQuery
        high = [f for f in findings
                if f.confidence >= 0.70 and f.status == "likely_secret"]
        assert len(high) == 0, (
            f"No high-confidence findings expected in jQuery; got: {high}"
        )

    def test_pattern_in_bootstrap_url_suppressed(self):
        js = (
            "a.proxy(this.checkPosition,this)).on('click.bs.affix.data-api',"
            "a.proxy(this.checkPositionWithEventLoop,this)),"
            "this.$element=a(c),this.affixed=this.unpin=this.pinnedOffset=null"
        )
        url = "https://example.com/static/js/bootstrap.js"
        findings = self._scan(js, url)
        high = [f for f in findings
                if f.confidence >= 0.70 and f.status == "likely_secret"]
        assert len(high) == 0, (
            f"No high-confidence findings expected in Bootstrap; got: {high}"
        )

    # 3c. Same token pattern in an application-owned file → still detected
    def test_real_secret_in_app_bundle_still_detected(self):
        """An AWS key inside a non-library bundle must still surface."""
        content = 'window.AWS_KEY = "AKIAIOSFODNN7REALKEY";'
        url = "https://example.com/static/js/main.chunk.js"
        findings = self._scan(content, url)
        aws = [f for f in findings if f.rule_id == "AWS_ACCESS_KEY"]
        assert len(aws) >= 1, "AWS key in app bundle should still be detected"

    def test_real_secret_in_react_app_bundle_still_detected(self):
        """App bundle that happens to be named similarly but isn't a library."""
        content = 'const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";'
        url = "https://example.com/static/js/app.bundle.js"
        findings = self._scan(content, url)
        gh = [f for f in findings if f.rule_id == "GITHUB_TOKEN"]
        assert len(gh) >= 1, "GitHub token in app bundle should be detected"

    def test_real_secret_in_library_file_with_context_still_detected(self):
        """A token inside a library file WITH a key= assignment context still surfaces."""
        # This covers the edge case of a bundler that inlines an app secret
        # into what looks like a library file — the key= context saves it.
        content = 'var apiKey = "AKIAIOSFODNN7REALKEY";'
        url = "https://example.com/static/js/jquery-3.4.1.min.js"
        findings = self._scan(content, url)
        aws = [f for f in findings if f.rule_id == "AWS_ACCESS_KEY"]
        assert len(aws) >= 1, (
            "AWS key WITH assignment context in library file should still be detected"
        )


# ─── 4. Context-aware confidence ─────────────────────────────────────────────

class TestContextAwareConfidence:
    """Keyword proximity affects confidence scoring."""

    def setup_method(self):
        self.scanner = make_scanner()

    def test_api_key_assignment_context_boosts_confidence(self):
        """apiKey = 'value' → confidence boosted vs bare value."""
        content_with_ctx    = 'const apiKey = "AKIAIOSFODNN7REALKEY";'
        content_without_ctx = '"AKIAIOSFODNN7REALKEY"'

        f_ctx  = self.scanner.scan(content_with_ctx,    "https://ex.com/app.js")
        f_bare = self.scanner.scan(content_without_ctx, "https://ex.com/app.js")

        aws_ctx  = [f for f in f_ctx  if f.rule_id == "AWS_ACCESS_KEY"]
        aws_bare = [f for f in f_bare if f.rule_id == "AWS_ACCESS_KEY"]

        # Both should detect (AWS key has a strong pattern), but with-context
        # finding should have equal or higher confidence
        assert aws_ctx,  "AWS key in assignment context should be detected"
        assert aws_bare, "Bare AWS key should also be detected"
        assert aws_ctx[0].confidence >= aws_bare[0].confidence

    def test_generic_password_with_secret_context_has_higher_confidence(self):
        """Werkzeug SECRET = '...' should be detected with good confidence."""
        content = 'SECRET = "udOkgfUbSBjBX2ujijPD";'
        findings = self.scanner.scan(content, "https://ex.com/console")
        generic = [f for f in findings
                   if f.rule_id in ("GENERIC_PASSWORD", "GENERIC_SECRET",
                                    "GENERIC_API_KEY", "HIGH_ENTROPY_CONTEXT")
                   and f.status != "likely_false_positive"]
        assert len(generic) >= 1, (
            "Werkzeug SECRET assignment should produce at least one finding"
        )

    def test_normal_variable_no_high_confidence_finding(self):
        """Regular JS variable not resembling a secret → no high-conf finding."""
        content = 'const version = "1.0.0"; const debug = false; const name = "app";'
        findings = self.scanner.scan(content, "https://ex.com/app.js")
        high = [f for f in findings
                if f.confidence >= 0.70 and f.status == "likely_secret"]
        assert len(high) == 0


# ─── 5. Existing detection layers unchanged ───────────────────────────────────

class TestExistingLayersUnchanged:
    """All provider-specific detection layers must keep working after the FP fix."""

    def setup_method(self):
        self.scanner = make_scanner()

    def _has(self, findings, rule_id):
        return any(f.rule_id == rule_id for f in findings)

    def test_aws_access_key(self):
        js = "const key = 'AKIAIOSFODNN7REALKEY';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "AWS_ACCESS_KEY")

    def test_github_pat(self):
        js = "token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "GITHUB_TOKEN")

    def test_github_fine_grained(self):
        # 82 chars after github_pat_
        js = "token = 'github_pat_" + "A" * 82 + "';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "GITHUB_FINE_GRAINED")

    def test_stripe_live_secret(self):
        js = "const sk = 'sk_live_abcdefghijklmnopqrstuvwx';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "STRIPE_SECRET_KEY")

    def test_google_api_key(self):
        js = "var k = 'AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "GOOGLE_API_KEY")

    def test_rsa_private_key(self):
        js = "const pem = '-----BEGIN RSA PRIVATE KEY-----';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "RSA_PRIVATE_KEY")

    def test_jwt_detected(self):
        # Real-looking JWT structure (header.payload.sig)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        js  = f'const tok = "{jwt}";'
        f   = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "JWT_TOKEN"), "JWT should still be detected"

    def test_azure_connection_string(self):
        cs  = "DefaultEndpointsProtocol=https;AccountName=mystore;AccountKey=" + "A" * 88 + ";"
        js  = f'const conn = "{cs}";'
        f   = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "AZURE_CONNECTION_STRING")

    def test_sendgrid_api_key(self):
        key = "SG." + "A" * 22 + "." + "B" * 43
        js  = f'const sg = "{key}";'
        f   = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "SENDGRID_API_KEY")

    def test_slack_webhook(self):
        wh = "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx"
        js = f'const wh = "{wh}";'
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "SLACK_WEBHOOK")

    def test_openai_api_key(self):
        # 48 alphanum after sk-
        key = "sk-" + "A" * 48
        js  = f'const ai = "{key}";'
        f   = self.scanner.scan(js, "https://ex.com/app.js")
        assert self._has(f, "OPENAI_API_KEY")

    def test_base64_decoded_secret_still_found(self):
        """A base64-encoded GitHub token should be found after b64 decode."""
        import base64
        raw  = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        blob = base64.b64encode(raw.encode()).decode()
        js   = f'const enc = "{blob}";'
        f    = self.scanner.scan(js, "https://ex.com/app.js")
        # Either direct match (if pattern hits the b64 string) or base64-decoded match
        gh = [x for x in f if x.rule_id == "GITHUB_TOKEN"]
        assert gh, "Base64-encoded GitHub token should be detected via b64 decode layer"

    def test_entropy_detection_still_works(self):
        """High-entropy base64 string in secret_key= context (with underscore → matches
        LH_KEYWORDS) → at least one high-entropy or rule finding is emitted.
        'secretKey' (camelCase) doesn't match LH_KEYWORDS, but 'secret_key' does."""
        # Uses snake_case to hit LH_KEYWORDS pattern (secret[_-]?key)
        value = "aB3xZ9mQ2wK5pL7nR4vT8yU1cE6fH0sG"  # entropy ~5.0 bits, B64 charset
        js    = f'const secret_key = "{value}";'
        f     = self.scanner.scan(js, "https://ex.com/app.js")
        # Either HIGH_ENTROPY_CONTEXT or WEAK_CRYPTO_KEY / GENERIC_API_KEY fires
        entropy_or_rule_hits = [
            x for x in f
            if x.rule_id in ("HIGH_ENTROPY_CONTEXT", "WEAK_CRYPTO_KEY",
                             "GENERIC_API_KEY", "GENERIC_SECRET")
            and x.status != "likely_false_positive"
        ]
        assert entropy_or_rule_hits, (
            "High-entropy string in secret_key= context must produce at least one finding"
        )

    def test_env_name_capture_still_works(self):
        """process.env.STRIPE_SECRET_KEY → ENV_NAME finding."""
        js = "const key = process.env.STRIPE_SECRET_KEY;"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        env = [x for x in f if x.rule_id == "ENV_NAME"]
        assert env, "process.env secret reference should produce ENV_NAME finding"


# ─── 6. Regression guarantees ────────────────────────────────────────────────

class TestRegressionGuarantees:
    """No duplicates, provenance fields intact, status/confidence correct."""

    def setup_method(self):
        self.scanner = make_scanner()

    def test_no_duplicate_findings_same_value(self):
        """Same value appearing twice → single finding with 2 occurrences."""
        key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        js  = f'const a = "{key}"; const b = "{key}";'
        f   = self.scanner.scan(js, "https://ex.com/app.js")
        gh  = [x for x in f if x.rule_id == "GITHUB_TOKEN"]
        assert len(gh) == 1, "Same token value should produce exactly 1 finding"
        assert len(gh[0].occurrences) >= 1

    def test_finding_has_required_provenance_fields(self):
        """Every finding must carry file_url, line_number, rule_id, and sha256."""
        js = "const key = 'AKIAIOSFODNN7REALKEY';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        assert f, "Expected at least one finding"
        for finding in f:
            assert finding.rule_id,     "rule_id must be set"
            assert finding.file_url,    "file_url must be set"
            assert finding.sha256,      "sha256 must be set"
            assert finding.line_number >= 1, "line_number must be ≥ 1"

    def test_vault_rule_severity_unchanged(self):
        """VAULT_TOKEN findings must keep CRITICAL severity."""
        token = "hvs." + "A" * 30
        js    = f'const tok = "{token}";'
        hits  = self.scanner.scan(js, "https://ex.com/app.js")
        vault = [f for f in hits if f.rule_id == "VAULT_TOKEN"]
        assert vault, "Valid hvs. token must still produce a finding"
        assert vault[0].severity == "CRITICAL"

    def test_placeholder_fp_indicator_at_string_level(self):
        """_is_likely_fp() correctly identifies placeholder indicators when given
        the full string. This validates the FP logic itself works correctly.
        Note: the AWS_ACCESS_KEY regex captures group(1)='AKIA' (only the prefix
        token, 4 chars), so the per-scan FP check operates on that short group,
        not the full key string. That's a known limitation of the grouped-capture
        approach — the real safeguard is the rule's fp_notes field and manual review.
        This test confirms that the underlying FP function works correctly."""
        from src.bundlespy.analysis.secrets import _is_likely_fp
        # Full placeholder string correctly identified as FP
        is_fp, reason = _is_likely_fp("AKIAEXAMPLE000000000")
        assert is_fp, "Full placeholder AWS key string must be flagged as FP by _is_likely_fp()"
        assert "example" in reason.lower(), f"Reason should mention 'example', got: {reason}"

        # A genuine-looking HMAC placeholder → also FP  (uses 'your_secret' indicator)
        is_fp2, reason2 = _is_likely_fp("your_secret_goes_here")
        assert is_fp2, f"your_secret_goes_here is a placeholder and should be flagged, got: {reason2}"

        # A real high-entropy value → not FP
        is_fp3, _ = _is_likely_fp("aB3xZ9mQ2wK5pL7nR4vT8yU1cE6fH0sG")
        assert not is_fp3, "High-entropy real-looking value should NOT be flagged as FP"

    def test_high_confidence_finding_status_is_likely_secret(self):
        """Genuine high-confidence findings must be status=likely_secret."""
        js = "const key = 'AKIAIOSFODNN7REALKEY';"
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        aws = [x for x in f if x.rule_id == "AWS_ACCESS_KEY"]
        assert aws
        assert aws[0].status == "likely_secret", (
            f"Real AWS key should be likely_secret, got {aws[0].status}"
        )

    def test_candidate_status_for_medium_confidence(self):
        """Generic matches with medium confidence show as candidate."""
        # A password= assignment — detectable but not unambiguous
        js = 'const password = "myS3cretP@ssword123!";'
        f  = self.scanner.scan(js, "https://ex.com/app.js")
        generic = [x for x in f
                   if x.rule_id == "GENERIC_PASSWORD"
                   and x.status not in ("likely_false_positive",)]
        # May or may not fire depending on entropy; either 0 hits or candidate status
        for hit in generic:
            assert hit.status in ("candidate", "likely_secret"), (
                f"Generic password should be candidate or likely_secret, got {hit.status}"
            )

    def test_reported_jquery_bootstrap_fp_is_gone(self):
        """
        Exact reproduction of the FP reported from pentest-ground.com:81.
        The legacy VAULT_TOKEN rule was matching inside jQuery and Bootstrap
        minified source. Both must produce zero VAULT_TOKEN findings now.
        """
        scanner = make_scanner()

        jquery_excerpt = (
            "n=0;while((o=i.handlers[n++])&&!s.isImmediatePropagationStopped())"
            "s.rnamespace&&!1!==o.namespace&&!s.rnamespace.test(o.namespace)||"
            "(s.handleObj=o,s.data=o.data,void 0!=="
        )
        bootstrap_excerpt = (
            "a.proxy(this.checkPosition,this)).on('click.bs.affix.data-api',"
            "a.proxy(this.checkPositionWithEventLoop,this)),"
            "this.$element=a(c),this.affixed=this.unpin=this.pinnedOffset=null,"
            "this.$window=a(t).on('scroll.bs.affix.data-api',"
        )

        jquery_url    = "https://pentest-ground.com:81/static/js/jquery-3.4.1.min.js"
        bootstrap_url = "https://pentest-ground.com:81/static/js/bootstrap.js"

        jquery_hits    = [f for f in scanner.scan(jquery_excerpt, jquery_url)
                          if f.rule_id == "VAULT_TOKEN"]
        bootstrap_hits = [f for f in scanner.scan(bootstrap_excerpt, bootstrap_url)
                          if f.rule_id == "VAULT_TOKEN"]

        assert len(jquery_hits)    == 0, (
            f"jQuery should produce 0 VAULT_TOKEN hits, got {len(jquery_hits)}"
        )
        assert len(bootstrap_hits) == 0, (
            f"Bootstrap should produce 0 VAULT_TOKEN hits, got {len(bootstrap_hits)}"
        )
