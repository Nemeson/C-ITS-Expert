"""v1.3.0 regression tests: GeoNetworking framing, PCAPNG, coverage contract, R02 hygiene."""

from __future__ import annotations

import struct

from cits_validator.core.geonet import (
    DLT_EN10MB,
    DLT_IEEE802_11_RADIO,
    link_layer_offset,
    locate_geonetworking_frame,
    message_type_for_port,
)
from cits_validator.core.models import Severity, ValidationReport, Violation
from cits_validator.core.stream import PcapStreamingIterator
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r02_anti_fake import AntiHallucinationRule

LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"


# --------------------------------------------------------------------------- #
# GeoNetworking / BTP framing
# --------------------------------------------------------------------------- #
def _geonet_tsb_frame(btp_port: int, secured: bool = False) -> bytes:
    """Basic Header + Common Header (TSB, 0x50) + extended header + BTP."""
    if secured:
        basic = bytes([0x12, 0x00, 0x1A, 0x03])  # version 1, nextHeader 2 (secured)
        return basic + b"\x00" * 40
    basic = bytes([0x11, 0x00, 0x1A, 0x03])  # version 1, nextHeader 1 (common)
    common = bytes([0x10, 0x50, 0x00, 0x00]) + (60).to_bytes(2, "little") + bytes([0x07, 0x00])
    extended = b"\x00" * (4 + 24)  # TSB single hop: 4 reserved + LongPositionVector
    btp = btp_port.to_bytes(2, "big") + b"\x00\x00"
    return basic + common + extended + btp + b"\xaa\xbb\xcc\xdd"


def test_link_layer_offset_ethernet():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_tsb_frame(2003)
    assert link_layer_offset(frame, DLT_EN10MB) == 14


def test_link_layer_offset_radiotap():
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    # Non-QoS Data frame: Frame Control 0x0008 (type 2, subtype 0) -> 24-byte MAC header.
    dot11 = b"\x08\x00\x00\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6 + b"\x00\x00"
    frame = radiotap + dot11 + LLC_SNAP + _geonet_tsb_frame(2004)
    assert link_layer_offset(frame, DLT_IEEE802_11_RADIO) == len(radiotap) + 24 + 8


def test_link_layer_offset_rejects_non_v2x():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x08\x00" + b"\x00" * 40  # IPv4 EtherType
    assert link_layer_offset(frame, DLT_EN10MB) is None


def test_btp_port_is_read_after_geonetworking_not_after_llc_snap():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_tsb_frame(2003)
    resolved = locate_geonetworking_frame(frame, DLT_EN10MB)
    assert resolved is not None
    assert resolved.btp_port == 2003
    assert message_type_for_port(resolved.btp_port) == "MAPEM"
    # The port must NOT be the two bytes immediately after the EtherType.
    assert resolved.btp_offset != 14


def test_secured_frame_reports_no_btp_port():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_tsb_frame(2001, secured=True)
    resolved = locate_geonetworking_frame(frame, DLT_EN10MB)
    assert resolved is not None
    assert resolved.was_secured is True
    assert resolved.btp_port is None


def test_r01_counts_geonet_and_secured_coverage():
    rule = LinkLayerRule()
    state: dict = {}
    secured = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_tsb_frame(2001, secured=True)
    plain = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_tsb_frame(2007)

    rule.audit_packet(_record(secured), dlt=DLT_EN10MB, state=state)
    rule.audit_packet(_record(plain), dlt=DLT_EN10MB, state=state)

    coverage = state["_coverage"]
    assert coverage["geonet"] == 2
    assert coverage["secured"] == 1
    assert coverage["btp"] == 1
    assert state["btp_ports"] == {2007: 1}


def _record(data: bytes, index: int = 1):
    from cits_validator.core.stream import PacketRecord

    return PacketRecord(index=index, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


# --------------------------------------------------------------------------- #
# PCAPNG block parsing
# --------------------------------------------------------------------------- #
def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _build_pcapng(
    linktype: int = 105, tsresol: int = 9, payloads: list[bytes] | None = None
) -> bytes:
    payloads = payloads or [b"\x01\x02\x03\x04", b"\xaa\xbb"]
    shb = _pcapng_block(
        0x0A0D0D0A,
        b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HH", 1, 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0),
    )
    # IDB options must be padded to a 32-bit boundary.
    opt = struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
    idb = _pcapng_block(1, struct.pack("<HHI", linktype, 0, 0) + opt)
    eps = b"".join(
        _pcapng_block(
            6,
            struct.pack("<IIIII", 0, 0, 1_000_000_000, len(p), len(p))
            + p
            + b"\x00" * ((4 - len(p) % 4) % 4),
        )
        for p in payloads
    )
    return shb + idb + eps


def test_pcapng_header_and_records_are_parsed():
    streamer = PcapStreamingIterator()
    import io

    records = list(streamer.iter_records(io.BytesIO(_build_pcapng())))
    assert streamer.header_info is not None
    assert streamer.header_info.is_pcapng is True
    assert streamer.header_info.byte_order == "little"
    assert len(records) == 2
    assert records[0].data == b"\x01\x02\x03\x04"
    assert records[0].dlt == 105
    assert records[1].data == b"\xaa\xbb"


def test_pcapng_timestamp_resolution_is_honoured():
    streamer = PcapStreamingIterator()
    import io

    records = list(streamer.iter_records(io.BytesIO(_build_pcapng(tsresol=9))))
    # 1e9 ticks at 10^-9 resolution == 1 second; a 10^-6 misread would give 1000s.
    assert records[0].timestamp == 1.0


def test_pcapng_is_not_rejected_as_unknown_magic():
    streamer = PcapStreamingIterator()
    import io

    header = streamer.read_header(io.BytesIO(_build_pcapng()))
    assert header.is_pcapng is True
    assert header.dlt == 0  # resolved from the IDB during iteration
    assert streamer.truncated_eof is False


def test_classic_pcap_still_detected():
    streamer = PcapStreamingIterator()
    import io

    classic = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    header = streamer.read_header(io.BytesIO(classic + b"\x00" * 16))
    assert header.is_pcapng is False
    assert header.magic == 0xD4C3B2A1


# --------------------------------------------------------------------------- #
# Data coverage contract
# --------------------------------------------------------------------------- #
def test_missing_categories_reported_for_radiotap_capture():
    report = ValidationReport(total_inspected=10, metadata={"dlt": 127})
    report.record_coverage("radiotap", 10)
    report.record_coverage("dot11", 10)

    missing = report.missing_categories()
    assert "llc_snap" in missing
    assert "btp" in missing
    assert report.to_dict()["data_status"] == "NO DATA IN CAPTURE"
    assert report.to_dict()["has_data"] is False


def test_complete_coverage_reports_ok():
    report = ValidationReport(total_inspected=3, metadata={"dlt": 127})
    for category in ("radiotap", "dot11", "llc_snap", "btp"):
        report.record_coverage(category, 3)

    assert report.missing_categories() == []
    assert report.to_dict()["data_status"] == "OK"
    assert report.has_data() is True


def test_suppressed_findings_still_count_as_errors():
    report = ValidationReport()
    report.add_violation(Violation(rule_id="R01", severity=Severity.ERROR, message="a"))
    report.suppress(Severity.ERROR, 999)

    assert len(report.violations) == 1
    assert report.error_count == 1000
    assert report.is_valid is False
    assert report.to_dict()["reported_violations"] == 1


# --------------------------------------------------------------------------- #
# R02 false-positive hygiene (the self-scan must be clean, real patterns caught)
# --------------------------------------------------------------------------- #
def test_r02_ignores_string_literal_anti_pattern():
    rule = AntiHallucinationRule()
    code = 'BAD = "lat = 52.0 + math.sin(t) * 0.22"\n'
    assert rule.audit_code(code, "python") == []


def test_r02_ignores_comment_anti_pattern():
    rule = AntiHallucinationRule()
    code = "# lat = 52.0 + math.sin(t) * 0.22  (documented prohibition)\n"
    assert rule.audit_code(code, "python") == []


def test_r02_pragma_suppresses_finding():
    rule = AntiHallucinationRule()
    code = "lat = 52.0 + math.sin(t) * 0.22  # cits-lint: allow\n"
    assert rule.audit_code(code, "python") == []


def test_r02_distance_function_trigonometry_allowed():
    rule = AntiHallucinationRule()
    code = (
        "import math\n"
        "def haversine(delta_phi, phi1, phi2, delta_lambda):\n"
        "    a = math.sin(delta_phi / 2.0) ** 2\n"
        "    b = math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2\n"
        "    return a + b\n"
    )
    assert rule.audit_code(code, "python") == []


def test_r02_still_catches_real_synthesis():
    rule = AntiHallucinationRule()
    assert rule.audit_code("lat = 52.52 + math.sin(t) * 0.22\n", "python")
    assert rule.audit_code("lon = 13.4 + math.cos(t) * 0.22\n", "python")


def test_r02_still_catches_modulo_in_assignment_and_return():
    rule = AntiHallucinationRule()
    assert rule.audit_code("x = (lane % 4) + 1\n", "python")
    assert rule.audit_code("def g(l):\n    return (l % 4) + 1\n", "python")


def test_r02_still_catches_90s_cycle_in_javascript():
    rule = AntiHallucinationRule()
    code = "const DEFAULT_CYCLE = 90;\nconst elapsed = timestamp % 90;\n"
    assert len(rule.audit_code(code, "javascript")) >= 1


def test_r02_self_scan_of_validator_package_is_clean():
    """The linter must pass on its own source tree."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent / "cits_validator"
    rule = AntiHallucinationRule()
    findings = []
    for path in root.rglob("*.py"):
        findings.extend(rule.audit_code(path.read_text(encoding="utf-8"), "python"))
    assert findings == [], [f"{v.file_path}:{v.line_number} {v.message}" for v in findings]
