"""
Unit tests for Stage 6: Application State Intelligence
══════════════════════════════════════════════════════

Covers:
  - infer_access_state()
  - infer_route_state()
  - build_page_states()
  - build_state_transitions()
  - apply_states_to_endpoints()
  - classify_endpoint_access()
  - build_state_intelligence_report()
  - AccessState / RouteState constants
  - PageAccessRecord and StateTransition to_dict()
"""

import pytest
from datetime import datetime

from bundlespy.storage.models import (
    AccessState,
    RouteState,
    PageAccessRecord,
    StateTransition,
    Endpoint,
    ScanResult,
    JSFile,
)
from bundlespy.analysis.state_intelligence import (
    infer_access_state,
    infer_route_state,
    build_page_states,
    build_state_transitions,
    apply_states_to_endpoints,
    classify_endpoint_access,
    build_state_intelligence_report,
    StateIntelligenceReport,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ep(url: str, path: str = "/", **kwargs) -> Endpoint:
    return Endpoint(
        url=url, path=path, method="GET", category="API",
        source_file="https://example.com/app.js", line_number=1,
        confidence=0.9, **kwargs
    )


def _scan_result(page_states=None) -> ScanResult:
    return ScanResult(
        target_url="https://example.com",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        pages_crawled=0,
        js_files=[],
        findings=[],
        endpoints=[],
        infrastructure=[],
        errors=[],
        page_states=page_states or {},
    )


# ── AccessState constants ─────────────────────────────────────────────────────

class TestAccessStateConstants:
    def test_all_values_defined(self):
        assert AccessState.PUBLIC        == "PUBLIC"
        assert AccessState.AUTHENTICATED == "AUTHENTICATED"
        assert AccessState.PRIVILEGED    == "PRIVILEGED"
        assert AccessState.UNKNOWN       == "UNKNOWN"

    def test_all_set(self):
        assert "PUBLIC"        in AccessState.ALL
        assert "AUTHENTICATED" in AccessState.ALL
        assert "PRIVILEGED"    in AccessState.ALL
        assert "UNKNOWN"       in AccessState.ALL

    def test_all_count(self):
        assert len(AccessState.ALL) == 4


# ── RouteState constants ──────────────────────────────────────────────────────

class TestRouteStateConstants:
    def test_all_values_defined(self):
        assert RouteState.DISCOVERED    == "DISCOVERED"
        assert RouteState.VISITED       == "VISITED"
        assert RouteState.OBSERVED      == "OBSERVED"
        assert RouteState.AUTH_REQUIRED == "AUTH_REQUIRED"
        assert RouteState.FORBIDDEN     == "FORBIDDEN"
        assert RouteState.REDIRECTED    == "REDIRECTED"
        assert RouteState.UNREACHABLE   == "UNREACHABLE"

    def test_all_set(self):
        for rs in ["DISCOVERED", "VISITED", "OBSERVED",
                   "AUTH_REQUIRED", "FORBIDDEN", "REDIRECTED", "UNREACHABLE"]:
            assert rs in RouteState.ALL

    def test_all_count(self):
        assert len(RouteState.ALL) == 7


# ── infer_access_state ────────────────────────────────────────────────────────

class TestInferAccessState:
    @pytest.mark.parametrize("status", [200, 201, 204, 206, 299])
    def test_2xx_is_public(self, status):
        assert infer_access_state(status) == AccessState.PUBLIC

    @pytest.mark.parametrize("status", [401, 403])
    def test_401_403_is_authenticated(self, status):
        assert infer_access_state(status) == AccessState.AUTHENTICATED

    @pytest.mark.parametrize("status", [0, 301, 302, 307, 308, 404, 429, 500, 503])
    def test_other_is_unknown(self, status):
        assert infer_access_state(status) == AccessState.UNKNOWN

    def test_zero_is_unknown(self):
        assert infer_access_state(0) == AccessState.UNKNOWN


# ── infer_route_state ─────────────────────────────────────────────────────────

class TestInferRouteState:
    def test_200_is_visited(self):
        assert infer_route_state(200) == RouteState.VISITED

    def test_201_is_visited(self):
        assert infer_route_state(201) == RouteState.VISITED

    def test_401_is_auth_required(self):
        assert infer_route_state(401) == RouteState.AUTH_REQUIRED

    def test_403_is_forbidden(self):
        assert infer_route_state(403) == RouteState.FORBIDDEN

    @pytest.mark.parametrize("status", [301, 302, 307, 308])
    def test_redirect_codes_are_redirected(self, status):
        assert infer_route_state(status) == RouteState.REDIRECTED

    def test_zero_is_discovered(self):
        assert infer_route_state(0) == RouteState.DISCOVERED

    def test_404_is_unreachable(self):
        assert infer_route_state(404) == RouteState.UNREACHABLE

    def test_500_is_unreachable(self):
        assert infer_route_state(500) == RouteState.UNREACHABLE

    def test_runtime_observed_overrides(self):
        assert infer_route_state(200, observed_at_runtime=True) == RouteState.OBSERVED

    def test_runtime_observed_overrides_403(self):
        # Observed at runtime takes priority even over 403
        assert infer_route_state(403, observed_at_runtime=True) == RouteState.OBSERVED


# ── build_page_states ─────────────────────────────────────────────────────────

class TestBuildPageStates:
    def test_empty_map(self):
        result = build_page_states({})
        assert result == {}

    def test_200_becomes_public_visited(self):
        states = build_page_states({"https://example.com/": 200})
        rec = states["https://example.com/"]
        assert rec.access_state  == AccessState.PUBLIC
        assert rec.route_state   == RouteState.VISITED
        assert rec.http_status   == 200
        assert rec.auth_required is False

    def test_401_becomes_authenticated_auth_required(self):
        states = build_page_states({"https://example.com/login": 401})
        rec = states["https://example.com/login"]
        assert rec.access_state  == AccessState.AUTHENTICATED
        assert rec.route_state   == RouteState.AUTH_REQUIRED
        assert rec.auth_required is True

    def test_403_becomes_authenticated_forbidden(self):
        states = build_page_states({"https://example.com/admin": 403})
        rec = states["https://example.com/admin"]
        assert rec.access_state  == AccessState.AUTHENTICATED
        assert rec.route_state   == RouteState.FORBIDDEN
        assert rec.auth_required is True

    def test_redirect_state(self):
        states = build_page_states({"https://example.com/old": 301})
        rec = states["https://example.com/old"]
        assert rec.route_state  == RouteState.REDIRECTED
        assert rec.access_state == AccessState.UNKNOWN

    def test_unreachable_state(self):
        states = build_page_states({"https://example.com/gone": 404})
        rec = states["https://example.com/gone"]
        assert rec.route_state == RouteState.UNREACHABLE

    def test_never_visited_auth_required_unknown(self):
        states = build_page_states({"https://example.com/secret": 0})
        rec = states["https://example.com/secret"]
        assert rec.route_state   == RouteState.DISCOVERED
        assert rec.access_state  == AccessState.UNKNOWN
        assert rec.auth_required is None

    def test_multiple_urls(self):
        url_map = {
            "https://example.com/":        200,
            "https://example.com/admin":   403,
            "https://example.com/api/v1":  200,
            "https://example.com/secret":  401,
        }
        states = build_page_states(url_map)
        assert len(states) == 4
        assert states["https://example.com/"].route_state          == RouteState.VISITED
        assert states["https://example.com/admin"].route_state     == RouteState.FORBIDDEN
        assert states["https://example.com/api/v1"].route_state    == RouteState.VISITED
        assert states["https://example.com/secret"].route_state    == RouteState.AUTH_REQUIRED

    def test_each_record_has_one_transition(self):
        states = build_page_states({"https://example.com/": 200})
        rec = states["https://example.com/"]
        assert len(rec.transitions) == 1
        t = rec.transitions[0]
        assert t.url         == "https://example.com/"
        assert t.http_status == 200
        assert t.route_state == RouteState.VISITED

    def test_runtime_observed_flag(self):
        states = build_page_states(
            {"https://example.com/api/data": 200},
            runtime_observed={"https://example.com/api/data": "https://example.com/"},
        )
        rec = states["https://example.com/api/data"]
        assert rec.route_state == RouteState.OBSERVED

    def test_redirect_map(self):
        states = build_page_states(
            {"https://example.com/old": 301},
            redirect_map={"https://example.com/old": "https://example.com/new"},
        )
        rec = states["https://example.com/old"]
        assert rec.redirected_to == "https://example.com/new"


# ── PageAccessRecord to_dict ──────────────────────────────────────────────────

class TestPageAccessRecordToDict:
    def test_to_dict_structure(self):
        rec = PageAccessRecord(
            url="https://example.com/admin",
            http_status=403,
            route_state=RouteState.FORBIDDEN,
            access_state=AccessState.AUTHENTICATED,
            auth_required=True,
        )
        d = rec.to_dict()
        assert d["url"]           == "https://example.com/admin"
        assert d["http_status"]   == 403
        assert d["route_state"]   == "FORBIDDEN"
        assert d["access_state"]  == "AUTHENTICATED"
        assert d["auth_required"] is True
        assert "transitions" in d

    def test_to_dict_with_transition(self):
        rec = PageAccessRecord(url="https://example.com/", http_status=200,
                               route_state=RouteState.VISITED,
                               access_state=AccessState.PUBLIC)
        rec.transitions.append(StateTransition(
            url="https://example.com/", http_status=200,
            route_state=RouteState.VISITED, access_state=AccessState.PUBLIC,
        ))
        d = rec.to_dict()
        assert len(d["transitions"]) == 1
        assert d["transitions"][0]["route_state"] == "VISITED"


# ── StateTransition to_dict ───────────────────────────────────────────────────

class TestStateTransitionToDict:
    def test_to_dict(self):
        t = StateTransition(
            url="https://example.com/admin",
            http_status=403,
            route_state=RouteState.FORBIDDEN,
            access_state=AccessState.AUTHENTICATED,
            redirected_to="",
        )
        d = t.to_dict()
        assert d["url"]           == "https://example.com/admin"
        assert d["http_status"]   == 403
        assert d["route_state"]   == "FORBIDDEN"
        assert d["access_state"]  == "AUTHENTICATED"
        assert d["redirected_to"] == ""


# ── build_state_transitions ───────────────────────────────────────────────────

class TestBuildStateTransitions:
    def test_empty_states(self):
        assert build_state_transitions({}) == []

    def test_transitions_collected(self):
        states = build_page_states({
            "https://example.com/":      200,
            "https://example.com/admin": 403,
        })
        transitions = build_state_transitions(states)
        assert len(transitions) == 2

    def test_auth_required_sorted_first(self):
        states = build_page_states({
            "https://example.com/":      200,
            "https://example.com/api":   200,
            "https://example.com/login": 401,
            "https://example.com/admin": 403,
        })
        transitions = build_state_transitions(states)
        # auth_required (priority 0) should come before forbidden (1) and visited (3)
        route_states = [t.route_state for t in transitions]
        assert route_states.index("AUTH_REQUIRED") < route_states.index("VISITED")
        assert route_states.index("FORBIDDEN") < route_states.index("VISITED")


# ── classify_endpoint_access ──────────────────────────────────────────────────

class TestClassifyEndpointAccess:
    def test_direct_url_match(self):
        ep = _ep("https://example.com/api/users", path="/api/users")
        states = build_page_states({"https://example.com/api/users": 200})
        assert classify_endpoint_access(ep, states) == AccessState.PUBLIC

    def test_direct_url_match_auth(self):
        ep = _ep("https://example.com/admin/users", path="/admin/users")
        states = build_page_states({"https://example.com/admin/users": 403})
        assert classify_endpoint_access(ep, states) == AccessState.AUTHENTICATED

    def test_path_substring_match(self):
        ep = _ep("https://example.com/api/v2/orders", path="/api/v2/orders")
        states = build_page_states({"https://example.com/api/v2/orders": 200})
        assert classify_endpoint_access(ep, states) == AccessState.PUBLIC

    def test_no_match_unknown(self):
        ep = _ep("https://example.com/undiscovered", path="/undiscovered")
        states = build_page_states({"https://example.com/other": 200})
        assert classify_endpoint_access(ep, states) == AccessState.UNKNOWN

    def test_auth_context_fallback(self):
        ep = _ep("https://example.com/private", path="/private",
                 auth_context="Bearer")
        assert classify_endpoint_access(ep, {}) == AccessState.AUTHENTICATED

    def test_empty_auth_context_unknown(self):
        ep = _ep("https://example.com/unknown", path="/unknown", auth_context="")
        assert classify_endpoint_access(ep, {}) == AccessState.UNKNOWN


# ── apply_states_to_endpoints ─────────────────────────────────────────────────

class TestApplyStatesToEndpoints:
    def test_direct_match_applied(self):
        ep = _ep("https://example.com/api", path="/api")
        states = build_page_states({"https://example.com/api": 200})
        apply_states_to_endpoints([ep], states)
        assert ep.http_status  == 200
        assert ep.access_state == AccessState.PUBLIC
        assert ep.route_state  == RouteState.VISITED

    def test_403_applied(self):
        ep = _ep("https://example.com/admin", path="/admin")
        states = build_page_states({"https://example.com/admin": 403})
        apply_states_to_endpoints([ep], states)
        assert ep.http_status  == 403
        assert ep.access_state == AccessState.AUTHENTICATED
        assert ep.route_state  == RouteState.FORBIDDEN

    def test_no_match_stays_discovered(self):
        ep = _ep("https://example.com/api/missing", path="/api/missing")
        states = build_page_states({"https://example.com/other": 200})
        apply_states_to_endpoints([ep], states)
        assert ep.route_state == RouteState.DISCOVERED

    def test_provenance_synced(self):
        from bundlespy.storage.models import Provenance
        ep = _ep("https://example.com/admin", path="/admin")
        ep.provenance = Provenance()
        states = build_page_states({"https://example.com/admin": 401})
        apply_states_to_endpoints([ep], states)
        assert ep.provenance.access_level == AccessState.AUTHENTICATED
        assert ep.provenance.auth_required is True

    def test_public_provenance_synced(self):
        from bundlespy.storage.models import Provenance
        ep = _ep("https://example.com/api", path="/api")
        ep.provenance = Provenance()
        states = build_page_states({"https://example.com/api": 200})
        apply_states_to_endpoints([ep], states)
        assert ep.provenance.access_level == AccessState.PUBLIC
        assert ep.provenance.auth_required is False

    def test_multiple_endpoints(self):
        ep1 = _ep("https://example.com/public",  path="/public")
        ep2 = _ep("https://example.com/admin",   path="/admin")
        ep3 = _ep("https://example.com/unknown", path="/unknown")
        states = build_page_states({
            "https://example.com/public": 200,
            "https://example.com/admin":  403,
        })
        apply_states_to_endpoints([ep1, ep2, ep3], states)
        assert ep1.access_state == AccessState.PUBLIC
        assert ep2.access_state == AccessState.AUTHENTICATED
        assert ep3.access_state == AccessState.UNKNOWN

    def test_empty_endpoints(self):
        states = build_page_states({"https://example.com/": 200})
        apply_states_to_endpoints([], states)   # should not raise


# ── build_state_intelligence_report ──────────────────────────────────────────

class TestBuildStateIntelligenceReport:
    def test_empty_result(self):
        result = _scan_result()
        report = build_state_intelligence_report(result)
        assert isinstance(report, StateIntelligenceReport)
        assert report.total_urls == 0

    def test_counts_correct(self):
        url_map = {
            "https://example.com/":        200,
            "https://example.com/api/v1":  200,
            "https://example.com/login":   401,
            "https://example.com/admin":   403,
            "https://example.com/old":     301,
            "https://example.com/broken":  404,
        }
        states = build_page_states(url_map)
        result = _scan_result(page_states=states)
        report = build_state_intelligence_report(result)

        assert report.total_urls    == 6
        assert report.public        == 2   # 200, 200
        assert report.authenticated == 2   # 401, 403
        assert report.unknown       == 2   # 301, 404
        assert report.visited       == 2
        assert report.auth_required == 1
        assert report.forbidden     == 1
        assert report.redirected    == 1
        assert report.unreachable   == 1

    def test_auth_gated_urls_populated(self):
        states = build_page_states({
            "https://example.com/login": 401,
            "https://example.com/admin": 403,
        })
        result = _scan_result(page_states=states)
        report = build_state_intelligence_report(result)
        assert "https://example.com/login" in report.auth_gated_urls
        assert "https://example.com/admin" in report.forbidden_urls

    def test_redirected_urls_populated(self):
        states = build_page_states({
            "https://example.com/old": 301,
        })
        result = _scan_result(page_states=states)
        report = build_state_intelligence_report(result)
        assert "https://example.com/old" in report.redirected_urls

    def test_transitions_present(self):
        states = build_page_states({"https://example.com/": 200})
        result = _scan_result(page_states=states)
        report = build_state_intelligence_report(result)
        assert len(report.transitions) == 1

    def test_to_dict_structure(self):
        states = build_page_states({
            "https://example.com/": 200,
            "https://example.com/admin": 403,
        })
        result = _scan_result(page_states=states)
        report = build_state_intelligence_report(result)
        d = report.to_dict()
        assert "total_urls"    in d
        assert "access_states" in d
        assert "route_states"  in d
        assert "transitions"   in d
        assert d["access_states"]["public"]        == 1
        assert d["access_states"]["authenticated"] == 1
        assert d["route_states"]["visited"]        == 1
        assert d["route_states"]["forbidden"]      == 1


# ── Endpoint model Stage 6 fields ────────────────────────────────────────────

class TestEndpointStage6Fields:
    def test_defaults(self):
        ep = _ep("https://example.com/api")
        assert ep.http_status  == 0
        assert ep.access_state == AccessState.UNKNOWN
        assert ep.route_state  == RouteState.DISCOVERED

    def test_can_set_fields(self):
        ep = _ep("https://example.com/api")
        ep.http_status  = 200
        ep.access_state = AccessState.PUBLIC
        ep.route_state  = RouteState.VISITED
        assert ep.http_status  == 200
        assert ep.access_state == AccessState.PUBLIC
        assert ep.route_state  == RouteState.VISITED


# ── ScanResult page_states field ─────────────────────────────────────────────

class TestScanResultPageStates:
    def test_default_empty_dict(self):
        result = _scan_result()
        assert result.page_states == {}

    def test_can_assign_page_states(self):
        states = build_page_states({"https://example.com/": 200})
        result = _scan_result(page_states=states)
        assert "https://example.com/" in result.page_states
