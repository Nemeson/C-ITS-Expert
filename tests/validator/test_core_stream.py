import io
import struct

from cits_validator.core.models import Severity, ValidationReport, Violation
from cits_validator.core.stream import PcapStreamingIterator


def test_models_report_aggregation():
    report = ValidationReport()
    assert report.is_valid is True
    assert report.error_count == 0

    report.add_violation(
        Violation(
            rule_id="R01",
            severity=Severity.ERROR,
            message="Invalid Radiotap length",
            packet_index=1,
            remediation_hint="Read uint16 at offset 2",
        )
    )
    report.add_violation(
        Violation(
            rule_id="R04",
            severity=Severity.WARNING,
            message="Unclosed SREM session",
            packet_index=2,
            remediation_hint="Track 4-tuple key",
        )
    )

    assert report.is_valid is False
    assert report.error_count == 1
    assert report.warning_count == 1
    assert len(report.violations) == 2


def test_pcap_header_nanosecond_little_endian():
    # 0xA1B23C4D packed as little-endian produces byte sequence: 4D 3C B2 A1
    header = struct.pack(
        "<IHHiIII",
        0xA1B23C4D,
        2,
        4,
        0,
        0,
        65535,
        127,  # DLT 127
    )
    streamer = PcapStreamingIterator()
    header_info = streamer.read_header(io.BytesIO(header))

    assert header_info.magic == 0x4D3CB2A1
    assert header_info.is_nanosecond is True
    assert header_info.byte_order == "little"
    assert header_info.dlt == 127
    assert header_info.timestamp_scale == 1_000_000_000


def test_pcap_header_microsecond_big_endian():
    # 0xa1b2c3d4 -> Big endian microsecond PCAP
    header = struct.pack(
        ">IHHiIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,  # DLT 1 (Ethernet)
    )
    streamer = PcapStreamingIterator()
    header_info = streamer.read_header(io.BytesIO(header))

    assert header_info.magic == 0xA1B2C3D4
    assert header_info.is_nanosecond is False
    assert header_info.byte_order == "big"
    assert header_info.dlt == 1
    assert header_info.timestamp_scale == 1_000_000


def test_pcap_streaming_records():
    # Little-endian microsecond PCAP (0xA1B2C3D4 packed little-endian is D4 C3 B2 A1)
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)

    payload1 = b"ABCDEFGH1234"  # 12 bytes
    rec1 = struct.pack("<IIII", 1000, 500000, len(payload1), len(payload1)) + payload1

    payload2 = b"WXYZ9876"  # 8 bytes
    rec2 = struct.pack("<IIII", 1001, 100000, len(payload2), len(payload2)) + payload2

    raw_pcap = header + rec1 + rec2
    streamer = PcapStreamingIterator()
    records = list(streamer.iter_records(io.BytesIO(raw_pcap)))

    assert len(records) == 2
    assert records[0].index == 1
    assert records[0].timestamp == 1000.5
    assert records[0].data == payload1

    assert records[1].index == 2
    assert records[1].timestamp == 1001.1
    assert records[1].data == payload2


def test_truncated_packet_at_eof():
    # Truncate record header
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    payload = b"TESTING123"
    rec = struct.pack("<IIII", 1000, 0, len(payload), len(payload)) + payload
    truncated_rec = struct.pack("<II", 1001, 0)  # Only 8 bytes of record header

    raw = header + rec + truncated_rec
    streamer = PcapStreamingIterator()
    records = list(streamer.iter_records(io.BytesIO(raw)))

    assert len(records) == 1
    assert streamer.truncated_eof is True
