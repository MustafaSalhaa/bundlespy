"""
WebSocket payload analyzer.

Parses captured WS messages (from headless interception) and extracts:
- JSON schemas (field names, types, nesting)
- RPC method/action/event names
- Sensitive field names (tokens, passwords, PII)
- Endpoint paths embedded in payloads
- Protocol type (JSON-RPC, Socket.IO, custom JSON, binary/blob)

Input: list of {url, data, dir} dicts from headless capture.
Output: WebSocketPayloadReport dataclass.
"""

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set


# Field names that indicate sensitive data in WS payloads
_SENSITIVE_FIELD_RE = re.compile(
    r'^(?:password|passwd|secret|token|access_token|refresh_token|'
    r'api_key|apikey|auth|authorization|jwt|session|session_id|'
    r'ssn|social_security|credit_card|card_number|cvv|pin|'
    r'private_key|client_secret|otp|mfa_code)$',
    re.IGNORECASE,
)

# RPC method/action/event field names (common across Socket.IO, JSON-RPC, custom)
_METHOD_FIELDS = {"method", "action", "event", "type", "cmd", "command", "op", "operation", "msg_type", "msgType"}

# Path patterns inside WS payloads
_PATH_RE = re.compile(r'["\'](?:url|path|endpoint|resource|route|href|api)["\']:?\s*["\'](/[^\s"\'<>]+)["\']', re.I)

# JSON-RPC 2.0 indicator
_JSONRPC_RE = re.compile(r'"jsonrpc"\s*:\s*"2\.0"')

# Socket.IO frame prefix (42 = event message type)
_SOCKETIO_RE = re.compile(r'^(?:42|40|41|43|44|45)\[')


@dataclass
class WsMessage:
    """Parsed single WebSocket message."""
    url:        str          # WS endpoint URL
    direction:  str          # send | recv
    raw:        str          # original message string
    protocol:   str          # json-rpc | socket.io | json | binary | text
    method:     str          # extracted action/method/event name
    fields:     List[str]    # top-level JSON field names
    sensitive:  List[str]    # sensitive field names found
    paths:      List[str]    # API path strings embedded in payload
    schema:     dict         # field -> inferred type (str, int, bool, list, dict, null)


@dataclass
class WsEndpointSummary:
    """Summary of messages observed on a single WS endpoint."""
    url:            str
    message_count:  int
    send_count:     int
    recv_count:     int
    protocol:       str
    methods:        List[str]     # all unique method/action/event names seen
    sensitive_fields: List[str]   # sensitive field names found across all messages
    embedded_paths: List[str]     # API path hints from payloads
    schema_union:   dict          # union of all field -> type mappings
    sample_send:    Optional[str] # one example outbound message (truncated)
    sample_recv:    Optional[str] # one example inbound message (truncated)


@dataclass
class WebSocketPayloadReport:
    total_messages:   int
    endpoints:        List[WsEndpointSummary]
    all_methods:      List[str]         # deduplicated across all endpoints
    all_sensitive:    List[str]         # deduplicated sensitive fields
    all_paths:        List[str]         # deduplicated embedded paths
    has_json_rpc:     bool
    has_socket_io:    bool


def _detect_protocol(data: str) -> str:
    """Detect WS sub-protocol from message content."""
    if not data or not isinstance(data, str):
        return "binary"
    if _SOCKETIO_RE.match(data):
        return "socket.io"
    if _JSONRPC_RE.search(data):
        return "json-rpc"
    stripped = data.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    return "text"


def _extract_fields(obj, prefix: str = "", depth: int = 0) -> Dict[str, str]:
    """
    Recursively extract field -> type mappings from a parsed JSON object.
    Stops at depth 3 to avoid huge blobs.
    """
    if depth > 3:
        return {}
    result = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                result[key] = "object"
                result.update(_extract_fields(v, key, depth + 1))
            elif isinstance(v, list):
                result[key] = "array"
                if v and isinstance(v[0], dict):
                    result.update(_extract_fields(v[0], f"{key}[]", depth + 1))
            elif isinstance(v, bool):
                result[key] = "bool"
            elif isinstance(v, int):
                result[key] = "int"
            elif isinstance(v, float):
                result[key] = "float"
            elif v is None:
                result[key] = "null"
            else:
                result[key] = "str"
    return result


def _parse_socket_io(data: str):
    """
    Socket.IO messages look like: 42["event_name", {...payload...}]
    Returns (event_name, payload_dict) or (None, None).
    """
    try:
        # Strip the numeric prefix (e.g. 42)
        bracket_pos = data.index("[")
        json_part = data[bracket_pos:]
        parsed = json.loads(json_part)
        if isinstance(parsed, list) and len(parsed) >= 1:
            event = str(parsed[0]) if parsed else ""
            payload = parsed[1] if len(parsed) > 1 else {}
            return event, payload
    except Exception:
        pass
    return None, None


def _parse_message(raw: str, url: str, direction: str) -> WsMessage:
    """Parse a single WS message into structured WsMessage."""
    if not raw or not isinstance(raw, str):
        return WsMessage(
            url=url, direction=direction, raw="",
            protocol="binary", method="", fields=[],
            sensitive=[], paths=[], schema={},
        )

    protocol = _detect_protocol(raw)
    method   = ""
    fields:  List[str] = []
    schema:  dict      = {}
    sensitive: List[str] = []
    paths:   List[str] = []

    # Extract embedded API paths from the raw string regardless of protocol
    for m in _PATH_RE.finditer(raw):
        p = m.group(1)
        if p not in paths:
            paths.append(p)

    try:
        if protocol == "socket.io":
            event, payload = _parse_socket_io(raw)
            if event:
                method = event
            if isinstance(payload, dict):
                schema = _extract_fields(payload)
                fields = list(payload.keys())

        elif protocol in ("json", "json-rpc"):
            obj = json.loads(raw.strip())
            if isinstance(obj, dict):
                schema = _extract_fields(obj)
                fields = list(obj.keys())
                # Extract method/action/event name
                for mf in _METHOD_FIELDS:
                    if mf in obj and isinstance(obj[mf], str):
                        method = obj[mf]
                        break
            elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                # Array of objects - analyze first item
                schema = _extract_fields(obj[0])
                fields = list(obj[0].keys())

    except Exception:
        pass

    # Find sensitive field names (top-level keys only)
    for f in fields:
        bare = f.split(".")[-1]
        if _SENSITIVE_FIELD_RE.match(bare):
            if bare not in sensitive:
                sensitive.append(bare)

    # Also scan schema keys for sensitive names at any depth
    for k in schema:
        bare = k.split(".")[-1]
        if _SENSITIVE_FIELD_RE.match(bare) and bare not in sensitive:
            sensitive.append(bare)

    return WsMessage(
        url=url, direction=direction, raw=raw,
        protocol=protocol, method=method,
        fields=fields, sensitive=sensitive,
        paths=paths, schema=schema,
    )


def analyze(ws_messages: List[dict]) -> Optional[WebSocketPayloadReport]:
    """
    Analyze a list of captured WS messages.
    Returns None if no messages provided.
    """
    if not ws_messages:
        return None

    # Group by endpoint URL
    by_url: Dict[str, List[dict]] = {}
    for msg in ws_messages:
        url = msg.get("url", "unknown")
        by_url.setdefault(url, []).append(msg)

    endpoint_summaries: List[WsEndpointSummary] = []
    all_methods:   List[str] = []
    all_sensitive: List[str] = []
    all_paths:     List[str] = []
    has_json_rpc   = False
    has_socket_io  = False

    for url, msgs in by_url.items():
        parsed_msgs = []
        for m in msgs:
            pm = _parse_message(
                raw       = m.get("data", "") or "",
                url       = url,
                direction = m.get("dir", "send"),
            )
            parsed_msgs.append(pm)

        send_msgs = [m for m in parsed_msgs if m.direction == "send"]
        recv_msgs = [m for m in parsed_msgs if m.direction == "recv"]

        # Protocol - pick most specific
        protocols = {m.protocol for m in parsed_msgs}
        if "json-rpc" in protocols:
            protocol = "json-rpc"
            has_json_rpc = True
        elif "socket.io" in protocols:
            protocol = "socket.io"
            has_socket_io = True
        elif "json" in protocols:
            protocol = "json"
        elif "text" in protocols:
            protocol = "text"
        else:
            protocol = "binary"

        # Deduplicate across all messages for this endpoint
        methods_seen:   List[str] = []
        sensitive_seen: List[str] = []
        paths_seen:     List[str] = []
        schema_union:   dict      = {}

        for pm in parsed_msgs:
            if pm.method and pm.method not in methods_seen:
                methods_seen.append(pm.method)
            for s in pm.sensitive:
                if s not in sensitive_seen:
                    sensitive_seen.append(s)
            for p in pm.paths:
                if p not in paths_seen:
                    paths_seen.append(p)
            schema_union.update(pm.schema)

        # Sample messages (truncated to 200 chars for display)
        sample_send = (send_msgs[0].raw[:200] if send_msgs else None)
        sample_recv = (recv_msgs[0].raw[:200] if recv_msgs else None)

        endpoint_summaries.append(WsEndpointSummary(
            url            = url,
            message_count  = len(parsed_msgs),
            send_count     = len(send_msgs),
            recv_count     = len(recv_msgs),
            protocol       = protocol,
            methods        = methods_seen,
            sensitive_fields = sensitive_seen,
            embedded_paths = paths_seen,
            schema_union   = schema_union,
            sample_send    = sample_send,
            sample_recv    = sample_recv,
        ))

        for m in methods_seen:
            if m not in all_methods:
                all_methods.append(m)
        for s in sensitive_seen:
            if s not in all_sensitive:
                all_sensitive.append(s)
        for p in paths_seen:
            if p not in all_paths:
                all_paths.append(p)

    return WebSocketPayloadReport(
        total_messages = len(ws_messages),
        endpoints      = endpoint_summaries,
        all_methods    = all_methods,
        all_sensitive  = all_sensitive,
        all_paths      = all_paths,
        has_json_rpc   = has_json_rpc,
        has_socket_io  = has_socket_io,
    )
