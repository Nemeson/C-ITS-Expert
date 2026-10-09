import json

from cits_validator.mcp.server import McpServer


def test_selftest_reports_profile_and_version():
    s = McpServer()
    resp = s.handle_request(
        {
            "id": 1,
            "method": "tools/call",
            "params": {"name": "cits_selftest", "arguments": {}},
        }
    )
    assert "error" not in resp
    data = json.loads(resp["result"]["content"][0]["text"])
    assert data["ok"] is True
    assert data["profile"] == "host"
    assert "version" in data


def test_selftest_reports_device_profile_when_configured():
    from cits_validator.mcp.config import Settings

    s = McpServer(settings=Settings.from_env({"CITS_MCP_PROFILE": "device"}))
    resp = s.handle_request(
        {
            "id": 1,
            "method": "tools/call",
            "params": {"name": "cits_selftest", "arguments": {}},
        }
    )
    data = json.loads(resp["result"]["content"][0]["text"])
    assert data["profile"] == "device"


def test_resources_list_and_read_rules():
    s = McpServer()
    lst = s.handle_request({"id": 2, "method": "resources/list"})["result"]["resources"]
    uris = {r["uri"] for r in lst}
    assert "cits://rules" in uris and "cits://version" in uris

    read = s.handle_request(
        {"id": 3, "method": "resources/read", "params": {"uri": "cits://rules"}}
    )["result"]
    assert "R01" in read["contents"][0]["text"]


def test_resources_read_version():
    s = McpServer()
    read = s.handle_request(
        {"id": 4, "method": "resources/read", "params": {"uri": "cits://version"}}
    )["result"]
    assert "version" in read["contents"][0]["text"]


def test_resources_read_unknown_uri_is_error():
    s = McpServer()
    resp = s.handle_request(
        {"id": 5, "method": "resources/read", "params": {"uri": "cits://nope"}}
    )
    assert resp["error"]["code"] == -32002


def test_initialize_advertises_resources_capability():
    s = McpServer()
    caps = s.handle_request({"id": 6, "method": "initialize"})["result"]["capabilities"]
    assert "tools" in caps and "resources" in caps
