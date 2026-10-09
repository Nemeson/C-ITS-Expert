from cits_validator.mcp.config import Settings


def test_defaults_are_host_profile_and_loopback():
    s = Settings.from_env({})
    assert s.profile == "host"
    assert s.bind_host == "127.0.0.1"
    assert s.token is None
    assert s.max_output_bytes == 262144
    assert s.roots  # non-empty: defaults to cwd


def test_env_overrides():
    s = Settings.from_env({
        "CITS_MCP_PROFILE": "device",
        "CITS_MCP_TOKEN": "secret",
        "CITS_MCP_MAX_OUTPUT_BYTES": "1024",
        "CITS_MCP_ROOTS": "a;b",
    })
    assert s.profile == "device"
    assert s.token == "secret"
    assert s.max_output_bytes == 1024
    assert [str(p) for p in s.roots] == ["a", "b"]


def test_invalid_profile_rejected():
    import pytest
    with pytest.raises(ValueError):
        Settings.from_env({"CITS_MCP_PROFILE": "nope"})
