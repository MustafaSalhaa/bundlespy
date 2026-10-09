"""
Unit tests for analysis/ws_payload.py
"""
import json
import pytest

from bundlespy.analysis.ws_payload import (
    analyze, _parse_message, _detect_protocol,
    WebSocketPayloadReport, WsMessage,
)


# ── Protocol detection ────────────────────────────────────────────────────────

def test_detect_protocol_json():
    assert _detect_protocol('{"type":"hello"}') == "json"


def test_detect_protocol_json_rpc():
    assert _detect_protocol('{"jsonrpc":"2.0","method":"ping","id":1}') == "json-rpc"


def test_detect_protocol_socket_io():
    assert _detect_protocol('42["message",{"text":"hi"}]') == "socket.io"


def test_detect_protocol_text():
    assert _detect_protocol("hello world") == "text"


def test_detect_protocol_empty():
    assert _detect_protocol("") == "binary"


def test_detect_protocol_none():
    assert _detect_protocol(None) == "binary"


# ── Message parsing ───────────────────────────────────────────────────────────

def test_parse_plain_json_message():
    raw = json.dumps({"action": "subscribe", "channel": "prices", "userId": 42})
    msg = _parse_message(raw, url="wss://example.com/ws", direction="send")
    assert msg.protocol == "json"
    assert msg.method == "subscribe"
    assert "action" in msg.fields
    assert "channel" in msg.fields


def test_parse_json_rpc_message():
    raw = json.dumps({"jsonrpc": "2.0", "method": "getUser", "params": {"id": 1}, "id": 1})
    msg = _parse_message(raw, url="wss://example.com/ws", direction="send")
    assert msg.protocol == "json-rpc"
    assert msg.method == "getUser"


def test_parse_socket_io_message():
    raw = '42["chat:message",{"text":"hello","room":"general"}]'
    msg = _parse_message(raw, url="wss://example.com/socket.io/", direction="send")
    assert msg.protocol == "socket.io"
    assert msg.method == "chat:message"
    assert "text" in msg.fields


def test_parse_sensitive_fields():
    raw = json.dumps({"action": "login", "token": "abc123", "password": "secret"})
    msg = _parse_message(raw, url="wss://example.com/ws", direction="send")
    assert "token" in msg.sensitive
    assert "password" in msg.sensitive


def test_parse_embedded_path():
    raw = json.dumps({"type": "fetch", "url": "/api/v2/users", "method": "GET"})
    msg = _parse_message(raw, url="wss://example.com/ws", direction="send")
    assert "/api/v2/users" in msg.paths


def test_parse_schema_extraction():
    raw = json.dumps({"user": {"id": 1, "name": "alice", "active": True}, "count": 5})
    msg = _parse_message(raw, url="wss://example.com/ws", direction="recv")
    assert msg.schema.get("user") == "object"
    assert msg.schema.get("user.id") == "int"
    assert msg.schema.get("user.name") == "str"
    assert msg.schema.get("user.active") == "bool"
    assert msg.schema.get("count") == "int"


def test_parse_non_json_text():
    msg = _parse_message("PING", url="wss://example.com/ws", direction="send")
    assert msg.protocol == "text"
    assert msg.method == ""
    assert msg.fields == []


def test_parse_empty_message():
    msg = _parse_message("", url="wss://example.com/ws", direction="send")
    assert msg.protocol == "binary"


def test_parse_none_data():
    msg = _parse_message(None, url="wss://example.com/ws", direction="send")
    assert msg.protocol == "binary"


# ── Full analysis ─────────────────────────────────────────────────────────────

def test_analyze_returns_none_for_empty():
    assert analyze([]) is None
    assert analyze(None) is None


def test_analyze_single_json_message():
    msgs = [
        {"url": "wss://example.com/ws", "data": json.dumps({"action": "ping"}), "dir": "send"},
    ]
    report = analyze(msgs)
    assert report is not None
    assert report.total_messages == 1
    assert len(report.endpoints) == 1
    assert report.endpoints[0].url == "wss://example.com/ws"
    assert "ping" in report.all_methods


def test_analyze_multiple_endpoints():
    msgs = [
        {"url": "wss://a.com/ws", "data": json.dumps({"action": "sub"}), "dir": "send"},
        {"url": "wss://b.com/ws", "data": json.dumps({"action": "pub"}), "dir": "send"},
    ]
    report = analyze(msgs)
    assert len(report.endpoints) == 2


def test_analyze_send_recv_counts():
    msgs = [
        {"url": "wss://example.com/ws", "data": '{"action":"send"}', "dir": "send"},
        {"url": "wss://example.com/ws", "data": '{"action":"ack"}',  "dir": "recv"},
        {"url": "wss://example.com/ws", "data": '{"action":"send"}', "dir": "send"},
    ]
    report = analyze(msgs)
    ep = report.endpoints[0]
    assert ep.send_count == 2
    assert ep.recv_count == 1
    assert ep.message_count == 3


def test_analyze_detects_json_rpc():
    msgs = [
        {"url": "wss://example.com/rpc", "data": '{"jsonrpc":"2.0","method":"add","id":1}', "dir": "send"},
    ]
    report = analyze(msgs)
    assert report.has_json_rpc is True
    assert report.has_socket_io is False


def test_analyze_detects_socket_io():
    msgs = [
        {"url": "wss://example.com/socket.io/", "data": '42["event",{"data":1}]', "dir": "send"},
    ]
    report = analyze(msgs)
    assert report.has_socket_io is True
    assert report.has_json_rpc is False


def test_analyze_sensitive_aggregation():
    msgs = [
        {"url": "wss://example.com/ws", "data": json.dumps({"token": "x", "msg": "hi"}), "dir": "send"},
        {"url": "wss://example.com/ws", "data": json.dumps({"token": "y", "msg": "bye"}), "dir": "send"},
    ]
    report = analyze(msgs)
    # token should appear once despite two messages
    assert report.all_sensitive.count("token") == 1


def test_analyze_sample_messages_stored():
    msgs = [
        {"url": "wss://example.com/ws", "data": '{"action":"hello"}', "dir": "send"},
        {"url": "wss://example.com/ws", "data": '{"action":"world"}', "dir": "recv"},
    ]
    report = analyze(msgs)
    ep = report.endpoints[0]
    assert ep.sample_send is not None
    assert ep.sample_recv is not None


def test_analyze_schema_union_across_messages():
    msgs = [
        {"url": "wss://x.com/ws", "data": json.dumps({"a": 1}),        "dir": "send"},
        {"url": "wss://x.com/ws", "data": json.dumps({"b": "hello"}),  "dir": "recv"},
    ]
    report = analyze(msgs)
    schema = report.endpoints[0].schema_union
    assert "a" in schema
    assert "b" in schema


def test_analyze_embedded_paths_deduped():
    path_msg = json.dumps({"url": "/api/v1/data", "type": "fetch"})
    msgs = [
        {"url": "wss://example.com/ws", "data": path_msg, "dir": "send"},
        {"url": "wss://example.com/ws", "data": path_msg, "dir": "send"},
    ]
    report = analyze(msgs)
    assert report.all_paths.count("/api/v1/data") == 1


def test_analyze_methods_deduped_across_messages():
    msgs = [
        {"url": "wss://x.com/ws", "data": json.dumps({"action": "ping"}), "dir": "send"},
        {"url": "wss://x.com/ws", "data": json.dumps({"action": "ping"}), "dir": "send"},
    ]
    report = analyze(msgs)
    assert report.all_methods.count("ping") == 1


def test_analyze_non_json_messages_handled():
    msgs = [
        {"url": "wss://x.com/ws", "data": "PING", "dir": "send"},
        {"url": "wss://x.com/ws", "data": "PONG", "dir": "recv"},
    ]
    report = analyze(msgs)
    assert report is not None
    assert report.total_messages == 2
    assert report.endpoints[0].protocol == "text"


def test_analyze_malformed_json_handled():
    msgs = [
        {"url": "wss://x.com/ws", "data": "{broken json here", "dir": "send"},
    ]
    report = analyze(msgs)
    assert report is not None  # should not raise


def test_analyze_missing_data_field():
    msgs = [
        {"url": "wss://x.com/ws", "dir": "send"},  # no "data" key
    ]
    report = analyze(msgs)
    assert report is not None
    assert report.total_messages == 1
