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
