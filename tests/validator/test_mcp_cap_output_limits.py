"""cap_output must honour max_bytes for the exact serialisation the server emits."""

from __future__ import annotations

import pytest

from cits_validator.mcp.security import cap_output, dump_json


def _size(payload: dict) -> int:
    return len(dump_json(payload).encode("utf-8"))


@pytest.mark.parametrize("max_bytes", [300, 800, 2000])
def test_list_truncation_fits_with_indent_and_marker_fields(max_bytes):
    payload = {"violations": [{"id": i, "msg": "m" * 20} for i in range(500)], "meta": "ok"}

    capped = cap_output(payload, max_bytes)

    assert _size(capped) <= max_bytes
    assert capped["truncated"] is True and capped["total"] == 500


def test_other_large_field_next_to_a_list_still_fits():
    payload = {"violations": [1, 2, 3], "blob": "x" * 10_000}

    capped = cap_output(payload, 500)

    assert _size(capped) <= 500
    assert capped["truncated"] is True


def test_multibyte_string_truncation_fits_after_json_escaping():
    payload = {"kml": "ä" * 5_000}

    capped = cap_output(payload, 600)

    assert _size(capped) <= 600
    assert capped["kml"].startswith("ä")


def test_nested_untruncatable_payload_becomes_error_object_within_cap():
    payload = {"result": {"deep": {"values": ["v" * 30] * 100}}}

    capped = cap_output(payload, 400)

    assert _size(capped) <= 400
    assert capped["truncated"] is True and "error" in capped
