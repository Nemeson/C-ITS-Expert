"""A hostile capture with millions of tiny packets must not run unbounded."""

from __future__ import annotations

import struct

import pytest

from cits_validator.cli.main import build_default_registry, scan_file
from cits_validator.core.models import ValidationReport
from cits_validator.mcp.config import Settings
from cits_validator.mcp.server import McpServer
from cits_validator.mcp.tools import cits_validate_pcap


def _pcap(path, packets: int):
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 0, 0, 14, 14) + b"\x00" * 14
    path.write_bytes(header + record * packets)
    return path


def _scan(path, max_packets):
    report = ValidationReport()
    scan_file(path, build_default_registry(), None, report, max_packets=max_packets)
    return report


def test_scan_stops_at_the_packet_limit_and_says_so(tmp_path):
    report = _scan(_pcap(tmp_path / "a.pcap", 50), max_packets=10)

    assert report.total_inspected == 10
    messages = [v.message for v in report.violations]
    assert any("stopped after 10 packets" in m for m in messages)


def test_no_limit_scans_everything(tmp_path):
    assert _scan(_pcap(tmp_path / "b.pcap", 20), max_packets=None).total_inspected == 20


def test_tool_applies_the_packet_limit(tmp_path):
    result = cits_validate_pcap(str(_pcap(tmp_path / "c.pcap", 30)), max_packets=5)

    assert result["total_inspected"] == 5


@pytest.mark.parametrize("value", ["abc", "0", "-1"])
def test_packet_limit_setting_is_validated(value):
    with pytest.raises(ValueError, match="CITS_MCP_MAX_PACKETS"):
        Settings.from_env({"CITS_MCP_MAX_PACKETS": value})


def test_server_passes_the_configured_limit(tmp_path):
    pcap = _pcap(tmp_path / "d.pcap", 30)
    server = McpServer(
        settings=Settings.from_env({"CITS_MCP_ROOTS": str(tmp_path), "CITS_MCP_MAX_PACKETS": "4"})
    )

    resp = server.handle_request(
        {"id": 1, "method": "tools/call",
         "params": {"name": "cits_validate_pcap", "arguments": {"file_path": str(pcap)}}}
    )

    assert '"total_inspected": 4' in resp["result"]["content"][0]["text"]
