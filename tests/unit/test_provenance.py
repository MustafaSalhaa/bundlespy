"""
Stage 5: Provenance model, coverage ledger, and passive validator unit tests.

All tests are offline — no network I/O, no disk I/O beyond imports.
Tests use synthetic fixtures built in-memory.
"""

import hashlib
import sys
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

sys.path.insert(0, "src")

from bundlespy.storage.models import (
    Provenance, Finding, Endpoint, JSFile, ScanResult, InfrastructureItem,
)
from bundlespy.analysis.coverage import (
    build_coverage_ledger, CoverageLedger, ProvenanceSummary,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _finding(
    rule_id: str = "STRIPE_SECRET_KEY",
    severity: str = "CRITICAL",
    file_url: str = "https://app.com/main.js",
    source_page: str = "https://app.com/",
    line_number: int = 42,
    status: str = "likely_secret",
    matched_value: str = "sk_live_ABCD1234567890",
) -> Finding:
    fid = Finding.make_id(rule_id, matched_value, file_url)
    return Finding(
        id               = fid,
        rule_id          = rule_id,
        title            = "Stripe Secret Key",
        category         = "CREDENTIAL",
        severity         = severity,
        confidence       = 0.95,
        file_url         = file_url,
        source_page      = source_page,
        line_number      = line_number,
        column           = 0,
        matched_value    = matched_value,
        redacted_value   = "sk_l****4567890",
        sha256           = hashlib.sha256(matched_value.encode()).hexdigest(),
        context          = "const key = 'sk_live_ABCD1234567890';",
        description      = "Stripe live secret key detected.",
        impact           = "Full payment API access.",
        remediation      = "Rotate immediately.",
        false_positive_notes = "",
        status           = status,
    )


def _endpoint(
    url:         str   = "https://app.com/api/v1/users",
    method:      str   = "GET",
    category:    str   = "API",
    source_file: str   = "https://app.com/main.js",
    line_number: int   = 10,
    confidence:  float = 0.9,
    auth_context: str  = "",
    source_type: str   = "static",
) -> Endpoint:
    from urllib.parse import urlparse
    p = urlparse(url)
    ep = Endpoint(
        url          = url,
        path         = p.path,
        method       = method,
        category     = category,
        source_file  = source_file,
        line_number  = line_number,
        confidence   = confidence,
        auth_context = auth_context,
        source_type  = source_type,
    )
    return ep


# ── Provenance dataclass ───────────────────────────────────────────────────────

class TestProvenance:
    def test_defaults(self):
        p = Provenance()
        assert p.source == "static"
        assert p.validation_status == "NOT_VALIDATED"
        assert p.auth_required is None
        assert p.access_level == "UNKNOWN"
        assert p.skipped_reason == ""

    def test_to_dict_keys(self):
        p = Provenance(
            source            = "runtime",
            discovered_in     = "https://app.com/main.js",
            line_number       = 17,
            observed_at       = "https://app.com/dashboard",
            correlation       = "static+runtime",
            validation_status = "CONFIRMED",
            validation_http_status = 200,
            auth_required     = False,
            access_level      = "PUBLIC",
        )
        d = p.to_dict()
        assert d["source"] == "runtime"
        assert d["discovered_in"] == "https://app.com/main.js"
        assert d["line_number"] == 17
        assert d["validation_status"] == "CONFIRMED"
        assert d["validation_http_status"] == 200
        assert d["auth_required"] is False
        assert d["access_level"] == "PUBLIC"

    def test_from_finding_static(self):
        f = _finding()
        p = Provenance.from_finding(f)
        assert p.source == "static"
        assert p.discovered_in == f.file_url
        assert p.line_number == 42
        assert p.observed_at == f.source_page

    def test_from_endpoint_static(self):
        ep = _endpoint()
        p = Provenance.from_endpoint(ep)
        assert p.source == "static"
        assert p.discovered_in == ep.source_file
        assert p.line_number == ep.line_number

    def test_from_endpoint_authenticated(self):
        ep = _endpoint(auth_context="Bearer")
        p = Provenance.from_endpoint(ep)
        assert p.auth_required is True
        assert p.access_level == "AUTHENTICATED"

    def test_from_endpoint_no_auth(self):
        ep = _endpoint(auth_context="")
        p = Provenance.from_endpoint(ep)
        assert p.auth_required is None
        assert p.access_level == "UNKNOWN"

    def test_from_endpoint_correlated(self):
        ep = _endpoint(source_type="correlated")
        p = Provenance.from_endpoint(ep)
        assert p.source == "correlated"
        assert p.correlation == "static+runtime"

    def test_finding_provenance_field_default_none(self):
        f = _finding()
        assert f.provenance is None

    def test_endpoint_provenance_field_default_none(self):
        ep = _endpoint()
        assert ep.provenance is None

    def test_provenance_round_trip(self):
        p = Provenance(
            source="runtime",
            discovered_in="https://a.com/a.js",
            validation_status="CONFIRMED",
            validation_http_status=200,
        )
        d = p.to_dict()
        assert d["source"] == "runtime"
        assert d["validation_status"] == "CONFIRMED"
        assert d["validation_http_status"] == 200


# ── Coverage ledger ────────────────────────────────────────────────────────────

class TestCoverageLedger:
    def test_empty(self):
        ledger = build_coverage_ledger([], [])
        assert ledger.findings.total == 0
        assert ledger.endpoints.total == 0
        assert ledger.high_critical_total == 0

    def test_single_finding_static(self):
        f = _finding(severity="CRITICAL")
        ledger = build_coverage_ledger([f], [])
        fs = ledger.findings
        assert fs.total == 1
        assert fs.from_static == 1
        assert fs.not_validated == 1
        assert fs.unknown_access == 1
        assert ledger.high_critical_total == 1
        assert ledger.high_critical_probed == 0

    def test_finding_with_provenance_confirmed(self):
        f = _finding(severity="HIGH")
        f.provenance = Provenance(
            source              = "static",
            validation_status   = "CONFIRMED",
            validation_http_status = 200,
            access_level        = "PUBLIC",
        )
        ledger = build_coverage_ledger([f], [])
        fs = ledger.findings
        assert fs.confirmed == 1
        assert fs.public == 1
        assert fs.not_validated == 0
        assert ledger.high_critical_probed == 1
        assert ledger.high_critical_confirmed == 1

    def test_finding_with_provenance_unreachable(self):
        f = _finding(severity="HIGH")
        f.provenance = Provenance(
            validation_status = "UNREACHABLE",
            access_level      = "UNKNOWN",
        )
        ledger = build_coverage_ledger([f], [])
        fs = ledger.findings
        assert fs.unreachable == 1
        assert fs.confirmed == 0

    def test_multiple_findings_mixed_severities(self):
        f1 = _finding(severity="CRITICAL", matched_value="sk_live_111")
        f2 = _finding(severity="MEDIUM",   matched_value="sk_live_222")
        f3 = _finding(severity="HIGH",     matched_value="sk_live_333")
        ledger = build_coverage_ledger([f1, f2, f3], [])
        assert ledger.findings.total == 3
        assert ledger.high_critical_total == 2  # CRITICAL + HIGH only

    def test_endpoint_counts(self):
        ep1 = _endpoint(url="https://app.com/api/1", source_type="static")
        ep2 = _endpoint(url="https://app.com/api/2", source_type="runtime")
        ep3 = _endpoint(url="https://app.com/api/3", source_type="correlated")
        ledger = build_coverage_ledger([], [ep1, ep2, ep3])
        eps = ledger.endpoints
        assert eps.total == 3
        assert eps.from_static == 1
        assert eps.from_runtime == 1
        assert eps.from_correlated == 1

    def test_endpoint_auth_context(self):
        ep = _endpoint(auth_context="Bearer")
        ledger = build_coverage_ledger([], [ep])
        assert ledger.endpoints.auth_required == 1
        assert ledger.endpoints.public == 0

    def test_to_dict_structure(self):
        f  = _finding()
        ep = _endpoint()
        ledger = build_coverage_ledger([f], [ep])
        d = ledger.to_dict()
        assert "findings" in d
        assert "endpoints" in d
        assert "high_critical" in d
        assert "by_source" in d["findings"]
        assert "by_validation" in d["findings"]
        assert "by_access" in d["findings"]

    def test_runtime_finding_source_count(self):
        f = _finding()
        f.provenance = Provenance(source="runtime")
        ledger = build_coverage_ledger([f], [])
        assert ledger.findings.from_runtime == 1
        assert ledger.findings.from_static == 0

    def test_passive_finding_source_count(self):
        f = _finding()
        f.provenance = Provenance(source="passive")
        ledger = build_coverage_ledger([f], [])
        assert ledger.findings.from_passive == 1


# ── Passive validator (mocked HTTP) ───────────────────────────────────────────

class TestPassiveValidator:
    """
    All HTTP is mocked — no actual network requests.
    """

    def _make_scope(self, in_scope=True):
        scope = MagicMock()
        scope.in_scope.return_value = in_scope
        return scope

    def test_skip_low_severity(self):
        from bundlespy.analysis.passive_validator import run_passive_validation
        f = _finding(severity="LOW")
        scope = self._make_scope()
        report = run_passive_validation([f], scope)
        assert report.probed == 0
        assert report.skipped == 1

    def test_skip_medium_severity(self):
        from bundlespy.analysis.passive_validator import run_passive_validation
        f = _finding(severity="MEDIUM")
        scope = self._make_scope()
        report = run_passive_validation([f], scope)
        assert report.probed == 0
        assert report.skipped == 1

    def test_skip_out_of_scope(self):
        from bundlespy.analysis.passive_validator import run_passive_validation
        f = _finding(severity="CRITICAL")
        scope = self._make_scope(in_scope=False)
        report = run_passive_validation([f], scope)
        assert report.probed == 1  # Attempted but skipped by scope inside probe_finding
        assert report.not_validated == 1

    def test_skip_inline_url(self):
        from bundlespy.analysis.passive_validator import run_passive_validation
        f = _finding(severity="CRITICAL", file_url="inline:https://app.com/#script-1-abc")
        scope = self._make_scope()
        report = run_passive_validation([f], scope)
        assert report.probed == 1
        assert report.not_validated == 1

    @patch("bundlespy.analysis.passive_validator._probe_source_url")
    def test_confirmed_when_pattern_present(self, mock_probe):
        from bundlespy.analysis.passive_validator import run_passive_validation
        # The first 8 chars of matched_value should appear in the response body
        mv = "sk_live_ABCD1234567890"
        body = f"var k = '{mv}';".encode()
        mock_probe.return_value = (200, body, "")

        f     = _finding(severity="CRITICAL", matched_value=mv)
        scope = self._make_scope()
        report = run_passive_validation([f], scope, delay=0)

        assert report.probed == 1
        assert report.confirmed == 1
        assert f.provenance is not None
        assert f.provenance.validation_status == "CONFIRMED"
        assert f.provenance.access_level == "PUBLIC"

    @patch("bundlespy.analysis.passive_validator._probe_source_url")
    def test_unreachable_when_pattern_absent(self, mock_probe):
        from bundlespy.analysis.passive_validator import run_passive_validation
        mv = "sk_live_ABCD1234567890"
        body = b"console.log('no secrets here');"
        mock_probe.return_value = (200, body, "")

        f     = _finding(severity="HIGH", matched_value=mv)
        scope = self._make_scope()
        report = run_passive_validation([f], scope, delay=0)

        assert report.probed == 1
        assert report.unreachable == 1
        assert f.provenance.validation_status == "UNREACHABLE"

    @patch("bundlespy.analysis.passive_validator._probe_source_url")
    def test_unreachable_on_404(self, mock_probe):
        from bundlespy.analysis.passive_validator import run_passive_validation
        mock_probe.return_value = (404, b"", "")

        f     = _finding(severity="CRITICAL")
        scope = self._make_scope()
        report = run_passive_validation([f], scope, delay=0)

        assert report.unreachable == 1
        assert f.provenance.validation_status == "UNREACHABLE"

    @patch("bundlespy.analysis.passive_validator._probe_source_url")
    def test_error_on_exception(self, mock_probe):
        from bundlespy.analysis.passive_validator import run_passive_validation
        mock_probe.return_value = (0, b"", "connection refused")

        f     = _finding(severity="CRITICAL")
        scope = self._make_scope()
        report = run_passive_validation([f], scope, delay=0)

        assert report.errors == 1
        assert f.provenance.validation_status == "ERROR"

    @patch("bundlespy.analysis.passive_validator._probe_source_url")
    def test_deduplication_same_source_url(self, mock_probe):
        """Two findings from the same JS file should probe the URL only once."""
        from bundlespy.analysis.passive_validator import run_passive_validation
        mv   = "sk_live_ABCD1234567890"
        body = f"var k = '{mv}';".encode()
        mock_probe.return_value = (200, body, "")

        f1 = _finding(severity="CRITICAL", matched_value=mv, rule_id="STRIPE_SECRET_KEY")
        f2 = _finding(severity="HIGH",     matched_value=mv, rule_id="OTHER_RULE",
                      file_url="https://app.com/main.js")  # same JS file

        scope  = self._make_scope()
        report = run_passive_validation([f1, f2], scope, delay=0)

        # URL probed only once (f2 reuses the result)
        assert mock_probe.call_count == 1
        assert report.probed == 1
        assert report.skipped == 1

    @patch("bundlespy.analysis.passive_validator._probe_source_url")
    def test_max_probes_limit(self, mock_probe):
        from bundlespy.analysis.passive_validator import run_passive_validation
        mv   = "sk_live_ABCD1234567890"
        mock_probe.return_value = (200, f"var k = '{mv}';".encode(), "")

        # 10 findings each from a unique JS file — cap at 3
        findings = [
            _finding(
                severity="CRITICAL",
                matched_value=mv,
                file_url=f"https://app.com/chunk{i}.js",
            )
            for i in range(10)
        ]
        scope  = self._make_scope()
        report = run_passive_validation(findings, scope, delay=0, max_probes=3)

        assert report.probed == 3
        assert report.skipped == 7

    def test_to_dict_passive_report(self):
        from bundlespy.analysis.passive_validator import PassiveValidationReport, ProbeResult
        report = PassiveValidationReport(
            probed=2, confirmed=1, unreachable=1,
            probes=[
                ProbeResult(
                    finding_id="abc", rule_id="R1", severity="CRITICAL",
                    source_url="https://a.com/a.js",
                    http_status=200, pattern_found=True,
                    validation_status="CONFIRMED",
                ),
            ],
        )
        d = report.to_dict()
        assert d["probed"] == 2
        assert d["confirmed"] == 1
        assert len(d["probes"]) == 1
        assert d["probes"][0]["pattern_found"] is True


# ── JSON report provenance integration ────────────────────────────────────────

class TestJSONReportProvenance:
    def _scan_result(self) -> ScanResult:
        return ScanResult(
            target_url    = "https://app.com",
            started_at    = datetime.utcnow(),
            finished_at   = datetime.utcnow(),
            pages_crawled = 1,
            js_files      = [],
            findings      = [_finding()],
            endpoints     = [_endpoint()],
            infrastructure = [],
            errors        = [],
        )

    def test_findings_have_provenance_key(self):
        import json
        from bundlespy.reporting.json_report import generate
        result = self._scan_result()
        out    = generate(result)
        data   = json.loads(out)
        assert "provenance" in data["findings"][0]

    def test_endpoints_have_provenance_key(self):
        import json
        from bundlespy.reporting.json_report import generate
        result = self._scan_result()
        out    = generate(result)
        data   = json.loads(out)
        assert "provenance" in data["endpoints"][0]

    def test_provenance_source_field(self):
        import json
        from bundlespy.reporting.json_report import generate
        result = self._scan_result()
        out    = generate(result)
        data   = json.loads(out)
        prov = data["findings"][0]["provenance"]
        assert "source" in prov
        assert prov["source"] in ("static", "runtime", "correlated", "passive")

    def test_coverage_ledger_in_json(self):
        import json
        from bundlespy.reporting.json_report import generate
        from bundlespy.analysis.coverage import build_coverage_ledger
        result = self._scan_result()
        ledger = build_coverage_ledger(result.findings, result.endpoints)
        out    = generate(result, coverage_ledger=ledger)
        data   = json.loads(out)
        assert "coverage_ledger" in data
        cl = data["coverage_ledger"]
        assert "findings" in cl
        assert "endpoints" in cl
        assert cl["findings"]["total"] == 1

    def test_passive_report_in_json(self):
        import json
        from bundlespy.reporting.json_report import generate
        from bundlespy.analysis.passive_validator import PassiveValidationReport
        result = self._scan_result()
        pr     = PassiveValidationReport(probed=1, confirmed=1)
        out    = generate(result, passive_report=pr)
        data   = json.loads(out)
        assert "passive_validation" in data
        assert data["passive_validation"]["confirmed"] == 1

    def test_no_passive_report_omitted(self):
        import json
        from bundlespy.reporting.json_report import generate
        result = self._scan_result()
        out    = generate(result)
        data   = json.loads(out)
        # When not passed, the key should be absent
        assert "passive_validation" not in data
