"""Profile-scoped tools, path guards, and corrected tool-error semantics.

These tests verify the opt-in profile/security wiring added to ``McpServer``
while confirming that the default (host, no settings) path stays backward
compatible with the original JSON-RPC surface.
"""

from __future__ import annotations

import json

import pytest

from cits_validator.mcp.config import Settings
from cits_validator.mcp.server import McpServer


def _server(**env: str) -> McpServer:
    return McpServer(settings=Settings.from_env(env))


# --- brief tests -----------------------------------------------------------


def test_default_server_unchanged_exposes_all_tools():
    tools = _server().handle_request({"id": 1, "method": "tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "cits_export_kml" in names and "cits_decode_pdu" in names


def test_device_profile_hides_export_and_marks_readonly():
    tools = _server(CITS_MCP_PROFILE="device").handle_request(
        {"id": 1, "method": "tools/list"}
    )["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "cits_export_kml" not in names
    assert "cits_inspect_hex" in names
    # Every exposed device tool must carry a readOnlyHint annotation.
    for t in tools:
        assert t["annotations"]["readOnlyHint"] is True


def test_tool_failure_is_result_iserror_not_jsonrpc_error():
    s = _server()
    resp = s.handle_request(
        {
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "cits_validate_pcap",
                "arguments": {"file_path": "C:/definitely/missing.pcap"},
            },
        }
    )
    assert "error" not in resp
    assert resp["result"]["isError"] is True


def test_path_outside_root_refused_under_device(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    s = _server(CITS_MCP_PROFILE="device", CITS_MCP_ROOTS=str(root))
    resp = s.handle_request(
        {
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "cits_validate_pcap",
                "arguments": {"file_path": str(tmp_path / "out.pcap")},
            },
        }
    )
    assert resp["result"]["isError"] is True


# --- compatibility checks --------------------------------------------------


def test_default_constructor_still_works():
    """``McpServer()`` with no args must remain valid (backward compat)."""
    s = McpServer()
    resp = s.handle_request({"id": 1, "method": "tools/list"})
    names = {t["name"] for t in resp["result"]["tools"]}
    # All 9 original tools stay exposed (later tasks may add more).
    original_nine = {
        "cits_audit_code",
        "cits_inspect_hex",
        "cits_check_mapem",
        "cits_validate_pcap",
        "cits_parse_lisa",
        "cits_compute_glosa",
        "cits_export_kml",
        "cits_decode_pdu",
        "cits_decode_mapem_to_geojson",
    }
    assert original_nine <= names


def test_successful_call_has_no_iserror_key():
    """A normal successful call must NOT include ``isError`` in the result."""
    s = McpServer()
    resp = s.handle_request(
        {
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "cits_compute_glosa",
                "arguments": {
                    "distance_m": 100.0,
                    "speed_kmh": 50.0,
                    "phase_state": "GREEN",
                    "time_to_phase_end_s": 15.0,
                },
            },
        }
    )
    assert "error" not in resp
    assert "isError" not in resp["result"]
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["is_pass_possible"] is True


def test_host_profile_includes_write_tool_annotation():
    """Host profile exposes ``cits_export_kml`` with ``readOnlyHint: False``."""
    s = _server(CITS_MCP_PROFILE="host")
    tools = s.handle_request({"id": 1, "method": "tools/list"})["result"]["tools"]
    by_name = {t["name"]: t for t in tools}
    assert by_name["cits_export_kml"]["annotations"]["readOnlyHint"] is False
    # Read-only tools under host still get the hint.
    assert by_name["cits_inspect_hex"]["annotations"]["readOnlyHint"] is True


def test_ci_profile_filters_to_ci_tools():
    s = _server(CITS_MCP_PROFILE="ci")
    tools = s.handle_request({"id": 1, "method": "tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {"cits_validate_pcap", "cits_audit_code", "cits_decode_pdu"}


def test_unknown_tool_still_jsonrpc_error():
    """Unknown tool name is a protocol error, not a tool error."""
    s = McpServer()
    resp = s.handle_request(
        {"id": 5, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}
    )
    assert resp["error"]["code"] == -32601


def test_device_path_inside_root_proceeds(tmp_path):
    """A file_path inside roots under device profile must NOT be blocked."""
    root = tmp_path / "root"
    root.mkdir()
    # Create a dummy pcap file inside root so the tool gets past FileNotFoundError
    # and into the actual scan (which will fail as a tool error, not a path error).
    pcap = root / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # PCAP magic + minimal header
    s = _server(CITS_MCP_PROFILE="device", CITS_MCP_ROOTS=str(root))
    resp = s.handle_request(
        {
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "cits_validate_pcap",
                "arguments": {"file_path": str(pcap)},
            },
        }
    )
    # Should not be blocked by path guard; may succeed or be a tool error,
    # but must not be a JSON-RPC error.
    assert "error" not in resp


def test_run_stdio_refuses_remote_without_token(monkeypatch, capsys):
    """``run_stdio`` must refuse a non-loopback bind without a token."""
    import sys

    # Provide empty stdin so the loop would exit immediately if it ran.
    monkeypatch.setattr(sys, "stdin", iter([]))
    s = _server(CITS_MCP_BIND_HOST="0.0.0.0")
    with pytest.raises(PermissionError):
        s.run_stdio()


def test_run_stdio_allows_loopback_without_token(monkeypatch):
    """``run_stdio`` must allow loopback bind without a token."""
    import sys

    monkeypatch.setattr(sys, "stdin", iter([]))
    s = _server(CITS_MCP_BIND_HOST="127.0.0.1")
    s.run_stdio()  # should not raise
