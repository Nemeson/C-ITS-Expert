from cits_validator.mcp.profiles import get_profile

DEVICE = ["cits_inspect_hex", "cits_validate_pcap", "cits_check_mapem",
          "cits_compute_glosa", "cits_parse_lisa", "cits_selftest"]


def test_device_hides_non_device_tools():
    p = get_profile("device")
    kept = p.filter_tools(DEVICE + ["cits_export_kml", "cits_decode_pdu"])
    assert "cits_export_kml" not in kept
    assert "cits_decode_pdu" not in kept
    assert set(kept) == set(DEVICE)


def test_device_is_read_only():
    assert get_profile("device").read_only is True
    assert get_profile("host").read_only is False


def test_host_exposes_everything():
    p = get_profile("host")
    names = DEVICE + ["cits_export_kml", "cits_decode_pdu"]
    assert set(p.filter_tools(names)) == set(names)


CI = ["cits_validate_pcap", "cits_audit_code", "cits_decode_pdu"]


def test_ci_hides_non_ci_tools():
    p = get_profile("ci")
    kept = p.filter_tools(CI + ["cits_export_kml", "cits_inspect_hex"])
    assert "cits_export_kml" not in kept
    assert "cits_inspect_hex" not in kept
    assert set(kept) == set(CI)


def test_ci_is_read_only():
    assert get_profile("ci").read_only is True


def test_unknown_profile_raises_value_error():
    import pytest

    with pytest.raises(ValueError):
        get_profile("nonexistent")


def test_filter_preserves_input_order():
    p = get_profile("device")
    names = ["cits_selftest", "cits_export_kml", "cits_inspect_hex", "cits_decode_pdu", "cits_check_mapem"]
    kept = p.filter_tools(names)
    assert kept == ["cits_selftest", "cits_inspect_hex", "cits_check_mapem"]
