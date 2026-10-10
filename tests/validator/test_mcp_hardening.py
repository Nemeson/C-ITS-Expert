"""Hardening of the MCP dispatch layer: sandbox, profile gate, input validation, limits."""

from __future__ import annotations

import io
import json
import sys

import pytest

from cits_validator.mcp import server as server_module
from cits_validator.mcp.config import Settings
from cits_validator.mcp.server import McpServer
from cits_validator.mcp.tools import cits_validate_pcap


def _server(**env: str) -> McpServer:
    return McpServer(settings=Settings.from_env(env))


def _call(server: McpServer, name: str, arguments, req_id: int = 7) -> dict:
    return server.handle_request(
        {"id": req_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )


# --- H3: sandbox applies to every profile ---------------------------------------------


@pytest.mark.parametrize("profile", ["device", "host", "ci"])
def test_path_outside_roots_is_refused_in_every_profile(tmp_path, profile):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"")
    s = _server(CITS_MCP_PROFILE=profile, CITS_MCP_ROOTS=str(root))

    resp = _call(s, "cits_validate_pcap", {"file_path": str(outside)})

    assert resp["result"]["isError"] is True
    assert "allowed root" in resp["result"]["content"][0]["text"]


# --- H4: the handler gets the resolved path that was checked --------------------------


def test_handler_receives_the_resolved_path(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    target = root / "f.pcap"
    target.write_bytes(b"")
    s = _server(CITS_MCP_PROFILE="host", CITS_MCP_ROOTS=str(root))
    seen: list[str] = []
    s.tool_handlers["cits_validate_pcap"] = lambda args: seen.append(args["file_path"]) or {}

    _call(s, "cits_validate_pcap", {"file_path": str(root / "sub" / ".." / "f.pcap")})

    assert seen == [str(target.resolve())]


# --- H7: tools/call honours the profile ------------------------------------------------


def test_tool_hidden_by_profile_cannot_be_called():
    s = _server(CITS_MCP_PROFILE="device")

    resp = _call(s, "cits_export_kml", {"lanes_json": []})

    assert resp["error"]["code"] == -32601
    assert resp["id"] == 7


# --- H13: request / argument validation ------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [None, [], "x", {}, {"code": 123}],
    ids=["null", "list", "string", "missing-required", "wrong-type"],
)
def test_invalid_arguments_yield_invalid_params_with_request_id(arguments):
    resp = _call(_server(), "cits_audit_code", arguments)

    assert resp["error"]["code"] == -32602
    assert resp["id"] == 7


def test_missing_required_argument_is_named():
    resp = _call(_server(), "cits_audit_code", {})

    assert "code" in resp["error"]["message"]


@pytest.mark.parametrize("params", [None, [], "x"])
def test_non_object_params_yield_invalid_params(params):
    resp = _server().handle_request({"id": 9, "method": "tools/call", "params": params})

    assert resp["error"]["code"] == -32602
    assert resp["id"] == 9


# --- stdio loop -------------------------------------------------------------------------


def _run(monkeypatch, capsys, server: McpServer, lines: list[str]) -> list[dict]:
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(line + "\n" for line in lines)))
    server.run_stdio()
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_stdio_malformed_json_is_parse_error_with_null_id(monkeypatch, capsys):
    out = _run(monkeypatch, capsys, _server(), ["{not json"])

    assert out[0]["error"]["code"] == -32700
    assert out[0]["id"] is None


def test_stdio_handler_crash_is_internal_error_with_request_id(monkeypatch, capsys):
    s = _server()

    def boom(req):
        raise RuntimeError("kaput")

    s.handle_request = boom  # type: ignore[method-assign]
    out = _run(monkeypatch, capsys, s, [json.dumps({"jsonrpc": "2.0", "id": 5, "method": "x"})])

    assert out[0]["error"]["code"] == -32603
    assert out[0]["id"] == 5


def test_stdio_non_object_request_is_invalid_request(monkeypatch, capsys):
    out = _run(monkeypatch, capsys, _server(), ["[1, 2]"])

    assert out[0]["error"]["code"] == -32600


def test_stdio_roundtrip_tools_list(monkeypatch, capsys):
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    out = _run(monkeypatch, capsys, _server(), ["", req])

    assert out[0]["id"] == 1
    assert any(t["name"] == "cits_selftest" for t in out[0]["result"]["tools"])


# --- H5: input size limits --------------------------------------------------------------


def test_stdio_overlong_request_line_is_rejected_and_loop_continues(monkeypatch, capsys):
    monkeypatch.setattr(server_module, "MAX_REQUEST_BYTES", 200)
    huge = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "x", "pad": "a" * 1000})
    ok = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

    out = _run(monkeypatch, capsys, _server(), [huge, ok])

    assert out[0]["error"]["code"] == -32600
    assert out[1]["id"] == 2 and "result" in out[1]


def test_validate_pcap_rejects_file_over_size_limit(tmp_path):
    big = tmp_path / "big.pcap"
    big.write_bytes(b"\x00" * 2048)

    with pytest.raises(ValueError, match="too large"):
        cits_validate_pcap(str(big), max_bytes=1000)
