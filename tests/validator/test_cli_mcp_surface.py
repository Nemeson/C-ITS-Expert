"""CLI and MCP surface tests added for the v1.3.0 hardening pass."""

from __future__ import annotations

import json
import struct

from cits_validator.cli.main import run_cli
from cits_validator.mcp.server import McpServer
from cits_validator.mcp.tools import cits_audit_code, cits_inspect_hex, cits_validate_pcap

LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"


def _geonet_frame(btp_port: int = 2001) -> bytes:
    basic = bytes([0x11, 0x00, 0x1A, 0x03])
    common = bytes([0x10, 0x50, 0x00, 0x00]) + (40).to_bytes(2, "little") + bytes([0x07, 0x00])
    extended = b"\x00" * 28
    return basic + common + extended + btp_port.to_bytes(2, "big") + b"\x00\x00" + b"\xde\xad"


def _write_pcap(tmp_path, dlt: int, frames: list[bytes], nano: bool = False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    header = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, dlt)
    body = b""
    for ts, frame in enumerate(frames, start=1):
        body += struct.pack("<IIII", 1000 + ts, 0, len(frame), len(frame)) + frame
    path = tmp_path / ("nano.pcap" if nano else "test.pcap")
    path.write_bytes(header + body)
    return path


def test_cli_rules_filter_limits_active_rules(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("lat = 52.0 + math.sin(t) * 0.22\n", encoding="utf-8")

    assert run_cli([str(bad), "--rules", "R01", "--format", "json"]) == 0
    only_r01 = json.loads(capsys.readouterr().out)
    assert only_r01["error_count"] == 0

    assert run_cli([str(bad), "--rules", "R02", "--format", "json"]) == 1
    only_r02 = json.loads(capsys.readouterr().out)
    assert only_r02["error_count"] == 1


def test_cli_max_chord_is_configurable(tmp_path, capsys):
    topology = {
        "connections": [
            {
                "fromLane": 1,
                "toLane": 2,
                "fromNode": {"lat": 52.5200, "lon": 13.4000},
                "toNode": {"lat": 52.5210, "lon": 13.4000},  # ~111 m
            }
        ]
    }
    topo = tmp_path / "topo.json"
    topo.write_text(json.dumps(topology), encoding="utf-8")

    # Default 25 m bound flags it; a raised bound accepts it.
    assert run_cli(["--topology", str(topo), "--rules", "R03", "--format", "json"]) == 1
    caught = json.loads(capsys.readouterr().out)
    assert caught["error_count"] == 1

    assert (
        run_cli(
            ["--topology", str(topo), "--rules", "R03", "--max-chord", "500", "--format", "json"]
        )
        == 0
    )
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["error_count"] == 0


def test_cli_strict_promotes_warnings(tmp_path, capsys):
    # A capture that ends with a truncated record yields a WARNING, not an ERROR.
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    partial = struct.pack("<II", 1234, 0)
    path = tmp_path / "truncated.pcap"
    path.write_bytes(header + partial)

    assert run_cli([str(path), "--format", "json"]) == 0
    relaxed = json.loads(capsys.readouterr().out)
    assert relaxed["warning_count"] >= 1
    assert relaxed["is_valid"] is True

    assert run_cli([str(path), "--strict", "--format", "json"]) == 1


def test_cli_reports_file_path_in_json(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("lon = 13.4 + math.cos(t) * 0.22\n", encoding="utf-8")

    run_cli([str(bad), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["violations"][0]["file_path"].endswith("bad.py")


def test_cli_text_report_shows_data_status(tmp_path, capsys):
    path = _write_pcap(tmp_path, 1, [b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_frame()])
    assert run_cli([str(path)]) == 0
    out = capsys.readouterr().out
    assert "Data Status: OK" in out
    assert "btp=1" in out


def test_cli_nanosecond_capture_metadata(tmp_path, capsys):
    path = _write_pcap(
        tmp_path, 1, [b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_frame()], nano=True
    )
    run_cli([str(path), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["metadata"]["is_nanosecond"] is True


def test_cli_unknown_target_exits_two(capsys):
    assert run_cli([str("does/not/exist.pcap")]) == 2
    assert "not found" in capsys.readouterr().err


def test_mcp_tool_audit_code_accepts_rules():
    filtered = cits_audit_code("lat = 52.0 + math.sin(t) * 0.22", "python", rules=["R01"])
    assert filtered["error_count"] == 0

    unfiltered = cits_audit_code("lat = 52.0 + math.sin(t) * 0.22", "python", rules=["R02"])
    assert unfiltered["error_count"] == 1


def test_mcp_tool_inspect_hex_rejects_bad_hex():
    try:
        cits_inspect_hex("zzzz", dlt=127)
    except ValueError as exc:
        assert "hexadecimal" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for non-hex input")


def test_mcp_tool_inspect_hex_reports_btp_port():
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    dot11 = b"\x08\x00\x00\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6 + b"\x00\x00"
    frame = radiotap + dot11 + LLC_SNAP + _geonet_frame(2004)

    result = cits_inspect_hex(frame.hex(), dlt=127)
    assert result["is_valid"] is True
    assert result["metadata"]["btp_ports"] == {"2004": 1}


def test_mcp_tool_validate_pcap_uses_full_pipeline(tmp_path):
    path = _write_pcap(tmp_path, 1, [b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_frame(2003)])
    result = cits_validate_pcap(str(path))
    assert result["is_valid"] is True
    assert result["coverage"]["btp"] == 1


def test_mcp_tool_validate_pcap_missing_file():
    try:
        cits_validate_pcap("no/such/file.pcap")
    except FileNotFoundError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected FileNotFoundError")


def test_mcp_server_version_matches_package():
    from cits_validator import __version__

    assert McpServer.SERVER_VERSION == __version__


def test_mcp_server_unknown_method_and_tool():
    server = McpServer()
    assert server.handle_request({"id": 1, "method": "nope"})["error"]["code"] == -32601

    resp = server.handle_request(
        {"id": 2, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}
    )
    assert resp["error"]["code"] == -32601


def test_mcp_server_reports_tool_errors():
    server = McpServer()
    resp = server.handle_request(
        {
            "id": 3,
            "method": "tools/call",
            "params": {"name": "cits_inspect_hex", "arguments": {"hex_payload": "zz"}},
        }
    )
    assert resp["error"]["code"] == -32000


def test_mcp_server_notification_returns_empty():
    assert McpServer().handle_request({"method": "notifications/initialized"}) == {}
