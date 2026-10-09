import pytest

from cits_validator.mcp.security import (
    cap_output,
    ensure_path_allowed,
    require_token_if_remote,
)


def test_path_outside_roots_refused(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.pcap"
    outside.write_bytes(b"x")
    with pytest.raises(PermissionError):
        ensure_path_allowed(outside, roots=(root,))


def test_path_inside_roots_allowed(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "a.pcap"
    inside.write_bytes(b"x")
    assert ensure_path_allowed(inside, roots=(root,)) == inside.resolve()


def test_remote_bind_without_token_refused():
    with pytest.raises(PermissionError):
        require_token_if_remote("0.0.0.0", None)


def test_loopback_without_token_allowed():
    require_token_if_remote("127.0.0.1", None)  # no raise


def test_cap_output_truncates_and_marks():
    payload = {"violations": list(range(100))}
    capped = cap_output(payload, max_bytes=200)
    assert capped["truncated"] is True
    assert capped["total"] == 100
    assert len(capped["violations"]) < 100


# --- Ruling: added tests for the non-lossy fallback behavior ---


def test_cap_output_truncates_huge_string_preserving_key():
    """(a) A huge KML string is truncated, not dropped; key stays non-empty."""
    huge = "x" * 10_000
    payload = {"kml": huge}
    capped = cap_output(payload, max_bytes=500)
    assert capped["truncated"] is True
    assert "kml" in capped
    assert isinstance(capped["kml"], str)
    assert len(capped["kml"]) > 0
    assert len(capped["kml"]) < len(huge)


def test_cap_output_truncates_features_list_with_total():
    """(b) GeoJSON features list is truncated with total == original length."""
    payload = {"features": [{"i": i} for i in range(200)]}
    capped = cap_output(payload, max_bytes=300)
    assert capped["truncated"] is True
    assert capped["total"] == 200
    assert len(capped["features"]) < 200


def test_cap_output_small_payload_passes_through_byte_identical():
    """(c) A small payload passes through unchanged (byte-identical)."""
    import json

    payload = {"status": "ok", "count": 3}
    capped = cap_output(payload, max_bytes=4096)
    assert capped is payload
    assert json.dumps(capped, sort_keys=True) == json.dumps(payload, sort_keys=True)


# --- Review fix: path traversal defense and cap_output branch 4 ---


def test_path_traversal_with_dotdot_refused(tmp_path):
    """resolve() must collapse .. before relative_to() so traversal is blocked."""
    root = tmp_path / "root"
    root.mkdir()
    sneaky = root / ".." / "out.pcap"
    with pytest.raises(PermissionError):
        ensure_path_allowed(sneaky, roots=(root,))


def test_cap_output_over_cap_no_truncatable_returns_unchanged():
    """Branch 4: over-cap payload with no truncatable list and no over-cap
    string must be returned unchanged — never drop data."""
    payload = {"a": "x" * 50, "b": "x" * 50, "c": "x" * 50}
    # total encoded size (177) > max_bytes (100), but no single top-level
    # string exceeds 100 bytes and there is no truncatable list.
    capped = cap_output(payload, max_bytes=100)
    assert capped is payload
    assert "truncated" not in capped
