import json
import struct

from cits_validator.mcp.server import McpServer
from cits_validator.mcp.tools import (
    cits_audit_code,
    cits_check_mapem,
    cits_inspect_hex,
)


def test_tool_cits_audit_code():
    bad_code = "lat = 52.0 + math.sin(t) * 0.22"
    res = cits_audit_code(bad_code, "python")
    assert res["is_valid"] is False
    assert res["error_count"] > 0
    assert any("synthetic GNSS" in v["message"] for v in res["violations"])


def test_tool_cits_inspect_hex_valid_frame():
    # Valid Radiotap (8B) + 802.11 Data (24B) + LLC/SNAP (8B)
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    dot11 = b"\x08\x00\x00\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6 + b"\x00\x00"  # 24B
    llc = b"\xAA\xAA\x03\x00\x00\x00\x89\x47"
    raw = (radiotap + dot11 + llc).hex()

    res = cits_inspect_hex(raw, dlt=127)
    assert res["is_valid"] is True
    assert res["error_count"] == 0


def test_tool_cits_check_mapem_chord_overflow():
    connection = {
        "fromLane": 1,
        "toLane": 2,
        "fromNode": {"lat": 52.5200, "lon": 13.4000},
        "toNode": {"lat": 52.5210, "lon": 13.4000},  # ~111m away
    }
    res = cits_check_mapem({"connections": [connection]})
    assert res["is_valid"] is False
    assert any("Overlong chord" in v["message"] for v in res["violations"])


def test_mcp_server_dispatch_initialize_and_tools():
    server = McpServer()

    # 1. Initialize
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"clientInfo": {"name": "test-agent"}},
    }
    resp = server.handle_request(init_req)
    assert resp["id"] == 1
    assert "serverInfo" in resp["result"]
    assert resp["result"]["serverInfo"]["name"] == "cits-mcp"

    # 2. tools/list
    tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    resp = server.handle_request(tools_req)
    assert resp["id"] == 2
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "cits_audit_code" in tool_names
    assert "cits_inspect_hex" in tool_names
    assert "cits_check_mapem" in tool_names
    assert "cits_validate_pcap" in tool_names

    # 3. tools/call
    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "cits_audit_code",
            "arguments": {"code": "lane_group = (lane % 4) + 1", "language": "python"},
        },
    }
    resp = server.handle_request(call_req)
    assert resp["id"] == 3
    content = resp["result"]["content"][0]["text"]
    result_data = json.loads(content)
    assert result_data["is_valid"] is False
