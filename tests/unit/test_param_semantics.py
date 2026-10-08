"""
Unit tests for param_semantics.py - centralized parameter classification.
"""
import pytest
from bundlespy.testing.param_semantics import (
    classify_param,
    is_file_param,
    is_url_param,
    is_id_param,
    tier_to_confidence_level,
    ParamType,
    ParamTier,
    ALL_FILE_PARAMS,
    ALL_SSRF_PARAMS,
    ALL_REDIRECT_PARAMS,
    ALL_IDOR_PARAMS,
    ALL_PRIVESC_PARAMS,
    ALL_TENANT_PARAMS,
    ALL_CMD_PARAMS,
    ALL_SSTI_PARAMS,
    ALL_LDAP_PARAMS,
    ALL_XXE_PARAMS,
    ALL_CSRF_PARAMS,
    HIGH_FILE_PARAMS,
    HIGH_SSRF_PARAMS,
    HIGH_REDIRECT_PARAMS,
    HIGH_PATH_PARAM_NAMES,
)


# -----------------------------------------------------------------
# classify_param - type detection
# -----------------------------------------------------------------

class TestParamTypeDetection:
    def test_command_high(self):
        c = classify_param("cmd")
        assert c.param_type == ParamType.COMMAND
        assert c.tier == ParamTier.HIGH

    def test_command_exec(self):
        c = classify_param("exec")
        assert c.param_type == ParamType.COMMAND

    def test_command_shell(self):
        c = classify_param("shell")
        assert c.param_type == ParamType.COMMAND

    def test_template_high(self):
        c = classify_param("template")
        assert c.param_type == ParamType.TEMPLATE
        assert c.tier == ParamTier.HIGH

    def test_template_render(self):
        c = classify_param("render")
        assert c.param_type == ParamType.TEMPLATE

    def test_template_medium(self):
        c = classify_param("view")
        assert c.param_type == ParamType.TEMPLATE
        assert c.tier == ParamTier.MEDIUM

    def test_ldap_high_cn(self):
        c = classify_param("cn")
        assert c.param_type == ParamType.LDAP_IDENTITY
        assert c.tier == ParamTier.HIGH

    def test_ldap_high_dn(self):
        c = classify_param("dn")
        assert c.param_type == ParamType.LDAP_IDENTITY

    def test_ldap_medium_username(self):
        c = classify_param("username")
        assert c.param_type == ParamType.LDAP_IDENTITY
        assert c.tier == ParamTier.MEDIUM

    def test_auth_token_csrf(self):
        c = classify_param("csrf_token")
        assert c.param_type == ParamType.AUTH_TOKEN
        assert c.tier == ParamTier.HIGH

    def test_auth_token_csrfmiddlewaretoken(self):
        c = classify_param("csrfmiddlewaretoken")
        assert c.param_type == ParamType.AUTH_TOKEN

    def test_privilege_role(self):
        c = classify_param("role")
        assert c.param_type == ParamType.PRIVILEGE
        assert c.tier == ParamTier.HIGH

    def test_privilege_is_admin(self):
        c = classify_param("is_admin")
        assert c.param_type == ParamType.PRIVILEGE

    def test_privilege_elevation(self):
        c = classify_param("elevation")
        assert c.param_type == ParamType.PRIVILEGE

    def test_tenant_org_id(self):
        c = classify_param("org_id")
        assert c.param_type == ParamType.TENANT
        assert c.tier == ParamTier.HIGH

    def test_tenant_workspace_id(self):
        c = classify_param("workspace_id")
        assert c.param_type == ParamType.TENANT

    def test_redirect_high(self):
        c = classify_param("redirect_url")
        assert c.param_type == ParamType.REDIRECT
        assert c.tier == ParamTier.HIGH

    def test_redirect_next(self):
        c = classify_param("next")
        assert c.param_type == ParamType.REDIRECT

    def test_redirect_medium(self):
        c = classify_param("goto")
        assert c.param_type == ParamType.REDIRECT
        assert c.tier == ParamTier.MEDIUM

    def test_redirect_low(self):
        c = classify_param("to")
        assert c.param_type == ParamType.REDIRECT
        assert c.tier == ParamTier.LOW

    def test_url_high_webhook(self):
        c = classify_param("webhook")
        assert c.param_type == ParamType.URL
        assert c.tier == ParamTier.HIGH

    def test_url_high_callback(self):
        c = classify_param("callback")
        assert c.param_type == ParamType.URL

    def test_url_medium_proxy(self):
        c = classify_param("proxy")
        assert c.param_type == ParamType.URL
        assert c.tier == ParamTier.MEDIUM

    def test_file_path_high_file(self):
        c = classify_param("file")
        assert c.param_type == ParamType.FILE_PATH
        assert c.tier == ParamTier.HIGH

    def test_file_path_high_filepath(self):
        c = classify_param("filepath")
        assert c.param_type == ParamType.FILE_PATH

    def test_file_path_medium_download(self):
        c = classify_param("download")
        assert c.param_type == ParamType.FILE_PATH
        assert c.tier == ParamTier.MEDIUM

    def test_file_path_low_asset(self):
        c = classify_param("asset")
        assert c.param_type == ParamType.FILE_PATH
        assert c.tier == ParamTier.LOW

    def test_xml_body_payload(self):
        c = classify_param("payload")
        assert c.param_type == ParamType.XML_BODY

    def test_xml_body_soap(self):
        c = classify_param("soap")
        assert c.param_type == ParamType.XML_BODY

    def test_object_id_user_id(self):
        c = classify_param("user_id")
        assert c.param_type == ParamType.OBJECT_ID
        assert c.tier == ParamTier.HIGH

    def test_object_id_record_id(self):
        c = classify_param("record_id")
        assert c.param_type == ParamType.OBJECT_ID

    def test_search_filter_query(self):
        c = classify_param("query")
        assert c.param_type == ParamType.SEARCH_FILTER

    def test_search_filter_filter(self):
        c = classify_param("filter")
        assert c.param_type == ParamType.SEARCH_FILTER

    def test_unknown_random_name(self):
        c = classify_param("foobar_xyz")
        assert c.param_type == ParamType.UNKNOWN

    def test_empty_name(self):
        c = classify_param("")
        assert c.param_type == ParamType.UNKNOWN
        assert c.raw_confidence == 0.0

    def test_case_insensitive(self):
        c_lower = classify_param("file")
        c_upper = classify_param("FILE")
        c_mixed = classify_param("File")
        assert c_lower.param_type == c_upper.param_type == c_mixed.param_type


# -----------------------------------------------------------------
# classify_param - value boosting
# -----------------------------------------------------------------

class TestValueBoosting:
    def test_file_medium_boosted_by_extension(self):
        # "download" is medium - value with .php should boost to HIGH
        c = classify_param("download", value="config.php")
        assert c.param_type == ParamType.FILE_PATH
        assert c.tier == ParamTier.HIGH
        assert c.value_boosted is True

    def test_file_low_boosted_by_extension(self):
        # "asset" is low - value with .env should boost to MEDIUM
        c = classify_param("asset", value="secrets.env")
        assert c.param_type == ParamType.FILE_PATH
        assert c.tier == ParamTier.MEDIUM
        assert c.value_boosted is True

    def test_file_high_not_double_boosted(self):
        # already HIGH - no further boost
        c_plain = classify_param("file")
        c_with_val = classify_param("file", value="config.php")
        assert c_plain.tier == ParamTier.HIGH
        assert c_with_val.tier == ParamTier.HIGH
        # boosted flag only set when tier actually changed
        assert c_with_val.value_boosted is False

    def test_url_medium_boosted_by_scheme(self):
        c = classify_param("proxy", value="http://internal-service/api")
        assert c.param_type == ParamType.URL
        assert c.tier == ParamTier.HIGH
        assert c.value_boosted is True

    def test_redirect_low_boosted_by_scheme(self):
        c = classify_param("to", value="https://evil.com")
        assert c.param_type == ParamType.REDIRECT
        assert c.tier == ParamTier.MEDIUM
        assert c.value_boosted is True

    def test_no_boost_without_value(self):
        c = classify_param("download")
        assert c.tier == ParamTier.MEDIUM
        assert c.value_boosted is False

    def test_no_boost_plain_value(self):
        c = classify_param("download", value="somefile")
        assert c.tier == ParamTier.MEDIUM
        assert c.value_boosted is False

    def test_boost_various_extensions(self):
        for ext in [".php", ".asp", ".aspx", ".jsp", ".env", ".conf", ".yaml"]:
            c = classify_param("download", value=f"config{ext}")
            assert c.tier == ParamTier.HIGH, f"expected HIGH boost for extension {ext}"


# -----------------------------------------------------------------
# classify_param - confidence and attack categories
# -----------------------------------------------------------------

class TestConfidenceAndCategories:
    def test_command_high_confidence(self):
        c = classify_param("cmd")
        assert c.raw_confidence >= 0.85

    def test_file_path_high_confidence(self):
        c = classify_param("filepath")
        assert c.raw_confidence >= 0.80

    def test_unknown_zero_confidence(self):
        c = classify_param("unknownxyz")
        assert c.raw_confidence == 0.0

    def test_command_has_injection_category(self):
        c = classify_param("cmd")
        assert "INJECTION" in c.attack_categories

    def test_privilege_has_access_control_category(self):
        c = classify_param("role")
        assert "ACCESS_CONTROL" in c.attack_categories

    def test_redirect_has_open_redirect_category(self):
        c = classify_param("next")
        assert "OPEN_REDIRECT" in c.attack_categories

    def test_url_has_ssrf_category(self):
        c = classify_param("webhook")
        assert "SSRF" in c.attack_categories

    def test_file_has_path_traversal_category(self):
        c = classify_param("filepath")
        assert "PATH_TRAVERSAL" in c.attack_categories

    def test_csrf_has_csrf_category(self):
        c = classify_param("csrf_token")
        assert "CSRF" in c.attack_categories

    def test_matched_name_populated(self):
        c = classify_param("FILE")
        assert c.matched_name == "file"

    def test_unknown_matched_name_populated(self):
        c = classify_param("FOOBAR")
        assert c.matched_name == "foobar"

    def test_attack_categories_is_frozenset(self):
        c = classify_param("cmd")
        assert isinstance(c.attack_categories, frozenset)


# -----------------------------------------------------------------
# Priority ordering - cmd/template should not fall through to search
# -----------------------------------------------------------------

class TestPriority:
    def test_cmd_wins_over_search(self):
        # "cmd" is in COMMAND, should NOT be classified as SEARCH
        c = classify_param("cmd")
        assert c.param_type == ParamType.COMMAND

    def test_template_wins_over_file(self):
        # "template" is TEMPLATE, not FILE_PATH
        c = classify_param("template")
        assert c.param_type == ParamType.TEMPLATE

    def test_cn_wins_over_generic(self):
        # "cn" is LDAP_IDENTITY, unambiguous
        c = classify_param("cn")
        assert c.param_type == ParamType.LDAP_IDENTITY

    def test_csrf_token_wins_over_search(self):
        c = classify_param("csrf_token")
        assert c.param_type == ParamType.AUTH_TOKEN

    def test_role_wins_over_search(self):
        c = classify_param("role")
        assert c.param_type == ParamType.PRIVILEGE


# -----------------------------------------------------------------
# Quick helper functions
# -----------------------------------------------------------------

class TestHelpers:
    def test_is_file_param_true(self):
        assert is_file_param("filepath") is True
        assert is_file_param("file") is True
        assert is_file_param("download") is True

    def test_is_file_param_false(self):
        assert is_file_param("user_id") is False
        assert is_file_param("cmd") is False

    def test_is_url_param_true(self):
        assert is_url_param("webhook") is True
        assert is_url_param("callback") is True
        assert is_url_param("redirect") is True
        assert is_url_param("next") is True

    def test_is_url_param_false(self):
        assert is_url_param("user_id") is False
        assert is_url_param("cmd") is False

    def test_is_id_param_true(self):
        assert is_id_param("user_id") is True
        assert is_id_param("org_id") is True  # tenant also
        assert is_id_param("account_id") is True

    def test_is_id_param_false(self):
        assert is_id_param("cmd") is False
        assert is_id_param("template") is False

    def test_tier_to_confidence_level_high(self):
        assert tier_to_confidence_level(ParamTier.HIGH) == "HIGH"

    def test_tier_to_confidence_level_medium(self):
        assert tier_to_confidence_level(ParamTier.MEDIUM) == "MEDIUM"

    def test_tier_to_confidence_level_low(self):
        assert tier_to_confidence_level(ParamTier.LOW) == "LOW"

    def test_tier_to_confidence_level_unknown(self):
        assert tier_to_confidence_level("BOGUS") == "LOW"


# -----------------------------------------------------------------
# Convenience export sets
# -----------------------------------------------------------------

class TestConvenienceExports:
    def test_all_file_params_contains_high(self):
        assert "file" in ALL_FILE_PARAMS
        assert "filepath" in ALL_FILE_PARAMS

    def test_all_file_params_contains_medium(self):
        assert "download" in ALL_FILE_PARAMS
        assert "attachment" in ALL_FILE_PARAMS

    def test_all_file_params_contains_low(self):
        assert "asset" in ALL_FILE_PARAMS
        assert "image" in ALL_FILE_PARAMS

    def test_all_ssrf_params_contains_high(self):
        assert "webhook" in ALL_SSRF_PARAMS
        assert "callback" in ALL_SSRF_PARAMS

    def test_all_ssrf_params_contains_medium(self):
        assert "proxy" in ALL_SSRF_PARAMS

    def test_all_redirect_params_contains_high(self):
        assert "redirect" in ALL_REDIRECT_PARAMS
        assert "next" in ALL_REDIRECT_PARAMS

    def test_all_idor_params(self):
        assert "user_id" in ALL_IDOR_PARAMS
        assert "record_id" in ALL_IDOR_PARAMS

    def test_all_privesc_params(self):
        assert "role" in ALL_PRIVESC_PARAMS
        assert "is_admin" in ALL_PRIVESC_PARAMS

    def test_all_tenant_params(self):
        assert "org_id" in ALL_TENANT_PARAMS
        assert "tenant_id" in ALL_TENANT_PARAMS

    def test_all_cmd_params(self):
        assert "cmd" in ALL_CMD_PARAMS
        assert "exec" in ALL_CMD_PARAMS

    def test_all_ssti_params(self):
        assert "template" in ALL_SSTI_PARAMS
        assert "render" in ALL_SSTI_PARAMS

    def test_all_ldap_params(self):
        assert "cn" in ALL_LDAP_PARAMS
        assert "username" in ALL_LDAP_PARAMS

    def test_all_xxe_params(self):
        assert "xml" in ALL_XXE_PARAMS
        assert "payload" in ALL_XXE_PARAMS

    def test_all_csrf_params(self):
        assert "csrf_token" in ALL_CSRF_PARAMS
        assert "csrfmiddlewaretoken" in ALL_CSRF_PARAMS

    def test_high_file_params_subset_of_all(self):
        assert HIGH_FILE_PARAMS.issubset(ALL_FILE_PARAMS)

    def test_high_ssrf_params_subset_of_all(self):
        assert HIGH_SSRF_PARAMS.issubset(ALL_SSRF_PARAMS)

    def test_high_path_param_names_is_file_path(self):
        # HIGH_PATH_PARAM_NAMES must be the same as HIGH_FILE_PARAMS for path_traversal.py
        assert HIGH_PATH_PARAM_NAMES == HIGH_FILE_PARAMS

    def test_exports_are_frozensets(self):
        for export in [
            ALL_FILE_PARAMS, ALL_SSRF_PARAMS, ALL_REDIRECT_PARAMS,
            ALL_IDOR_PARAMS, ALL_PRIVESC_PARAMS, ALL_TENANT_PARAMS,
            ALL_CMD_PARAMS, ALL_SSTI_PARAMS, ALL_LDAP_PARAMS,
            ALL_XXE_PARAMS, ALL_CSRF_PARAMS,
        ]:
            assert isinstance(export, frozenset), f"expected frozenset, got {type(export)}"


# -----------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------

class TestEdgeCases:
    def test_whitespace_stripped(self):
        c = classify_param("  file  ")
        assert c.param_type == ParamType.FILE_PATH

    def test_all_caps(self):
        c = classify_param("WEBHOOK")
        assert c.param_type == ParamType.URL

    def test_value_empty_string(self):
        c = classify_param("file", value="")
        assert c.param_type == ParamType.FILE_PATH
        assert c.value_boosted is False

    def test_confidence_capped_at_1(self):
        # Even with boost, confidence should not exceed 1.0
        c = classify_param("download", value="file.php")
        assert c.raw_confidence <= 1.0

    def test_multiple_calls_stable(self):
        # classify_param is stateless - same result on repeated calls
        c1 = classify_param("file")
        c2 = classify_param("file")
        assert c1.param_type == c2.param_type
        assert c1.tier == c2.tier
        assert c1.raw_confidence == c2.raw_confidence
