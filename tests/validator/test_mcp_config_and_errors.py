"""Config validation and error-text hygiene for the MCP server."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cits_validator.mcp.config import Settings
from cits_validator.mcp.server import McpServer


@pytest.mark.parametrize("name", ["CITS_MCP_MAX_OUTPUT_BYTES", "CITS_MCP_MAX_FILE_BYTES"])
@pytest.mark.parametrize("value", ["abc", "0", "-5", "10"])
def test_numeric_limits_must_be_sane_integers(name, value):
    with pytest.raises(ValueError, match=name):
        Settings.from_env({name: value})


def test_roots_use_the_platform_path_separator(monkeypatch):
    monkeypatch.setattr(os, "pathsep", ":")

    settings = Settings.from_env({"CITS_MCP_ROOTS": "data/a:data/b"})

    assert settings.roots == (Path("data/a"), Path("data/b"))


def test_filesystem_root_is_refused_as_allowed_root():
    root = Path(Path.cwd().anchor)

    with pytest.raises(ValueError, match="filesystem root"):
        Settings.from_env({"CITS_MCP_ROOTS": str(root)})


def _call(server, name="cits_audit_code", args=None):
    return server.handle_request(
        {"id": 1, "method": "tools/call", "params": {"name": name, "arguments": args or {"code": "x"}}}
    )


def test_unexpected_exception_text_is_not_leaked_to_the_client():
    server = McpServer(settings=Settings.from_env({}))
    server.tool_handlers["cits_audit_code"] = lambda a: (_ for _ in ()).throw(
        RuntimeError("secret detail at /etc/shadow")
    )

    resp = _call(server)

    text = resp["result"]["content"][0]["text"]
    assert resp["result"]["isError"] is True
    assert "secret" not in text and "RuntimeError" in text


def test_expected_input_errors_keep_their_message():
    server = McpServer(settings=Settings.from_env({}))
    server.tool_handlers["cits_audit_code"] = lambda a: (_ for _ in ()).throw(
        ValueError("hex_payload is not valid hex")
    )

    resp = _call(server)

    assert resp["result"]["content"][0]["text"] == "hex_payload is not valid hex"
