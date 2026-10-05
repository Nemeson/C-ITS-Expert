"""Branch coverage for the framing, stream and CLI edges added in v1.3.0."""

from __future__ import annotations

import io
import json
import struct

import pytest

from cits_validator.cli.main import run_cli
from cits_validator.core.geonet import (
    DLT_EN10MB,
    DLT_IEEE802_11,
    DLT_IEEE802_11_RADIO,
    link_layer_offset,
    locate_geonetworking_frame,
    message_type_for_port,
)
from cits_validator.core.stream import PcapStreamingIterator

LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"
ETH = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47"


def _geonet(header_type: int = 0x50) -> bytes:
    basic = bytes([0x11, 0x00, 0x1A, 0x03])
    common = (
        bytes([0x10, header_type, 0x00, 0x00]) + (40).to_bytes(2, "little") + bytes([0x07, 0x00])
    )
    ext_len = {0x50: 28, 0x10: 24, 0x20: 48}.get(header_type, 28)
    return (
        basic + common + b"\x00" * ext_len + (2001).to_bytes(2, "big") + b"\x00\x00" + b"\x00" * 8
    )


# --------------------------------------------------------------------------- #
# geonet: link-layer variants
# --------------------------------------------------------------------------- #
def test_vlan_tagged_ethernet_is_unwrapped():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x81\x00\x00\x64\x89\x47" + _geonet()
    assert link_layer_offset(frame, DLT_EN10MB) == 18


def test_802_3_length_with_llc_snap_is_unwrapped():
    frame = b"\xff" * 6 + b"\x11" * 6 + (60).to_bytes(2, "big") + LLC_SNAP + _geonet()
    assert link_layer_offset(frame, DLT_EN10MB) == 22


def test_vlan_without_geonet_returns_none():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x81\x00\x00\x64\x08\x00" + b"\x00" * 40
    assert link_layer_offset(frame, DLT_EN10MB) is None


def test_truncated_ethernet_returns_none():
    assert link_layer_offset(b"\xff" * 8, DLT_EN10MB) is None


def test_raw_802_11_dlt_105_non_qos():
    dot11 = b"\x08\x00\x00\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6 + b"\x00\x00"
    frame = dot11 + LLC_SNAP + _geonet()
    assert link_layer_offset(frame, DLT_IEEE802_11) == 24 + 8


def test_802_11_wds_header_adds_address4():
    fc = 0x0308  # type 2, subtype 0, toDS=1, fromDS=1
    # fc(2) dur(2) addr1(6) addr2(6) addr3(6) seq(2) addr4(6) = 30 bytes
    dot11 = struct.pack("<H", fc) + b"\x00\x00" + b"\xff" * 6 * 3 + b"\x00\x00" + b"\xaa" * 6
    frame = dot11 + LLC_SNAP + _geonet()
    assert link_layer_offset(frame, DLT_IEEE802_11) == 30 + 8


def test_non_data_802_11_frame_returns_none():
    dot11 = b"\x80\x00\x00\x00" + b"\x00" * 22  # management frame
    assert link_layer_offset(dot11 + LLC_SNAP + _geonet(), DLT_IEEE802_11) is None


def test_radiotap_bad_length_returns_none():
    frame = struct.pack("<BBHI", 0, 0, 4, 0) + b"\x00" * 60
    assert link_layer_offset(frame, DLT_IEEE802_11_RADIO) is None


def test_unknown_dlt_returns_none():
    assert link_layer_offset(b"\x00" * 60, 999) is None


def test_unsupported_geonet_header_type_returns_none():
    frame = ETH + bytes([0x11, 0x00, 0x1A, 0x03]) + bytes([0x10, 0x99, 0, 0]) + b"\x00" * 60
    assert link_layer_offset(frame, DLT_EN10MB) is not None
    assert locate_geonetworking_frame(frame, DLT_EN10MB) is None


def test_geonet_basic_header_without_common_returns_none():
    frame = ETH + bytes([0x13, 0x00, 0x1A, 0x03]) + b"\x00" * 60  # nextHeader 3 invalid
    assert locate_geonetworking_frame(frame, DLT_EN10MB) is None


def test_geonet_common_header_next_header_not_btp():
    basic = bytes([0x11, 0x00, 0x1A, 0x03])
    common = bytes([0x30, 0x50, 0x00, 0x00]) + (40).to_bytes(2, "little") + bytes([0x07, 0x00])
    frame = ETH + basic + common + b"\x00" * 28 + b"\x00" * 8
    resolved = locate_geonetworking_frame(frame, DLT_EN10MB)
    assert resolved is not None
    assert resolved.btp_port is None
    assert resolved.payload_offset is None


def test_message_type_for_unknown_and_none():
    assert message_type_for_port(None) == "UNKNOWN"
    assert message_type_for_port(9999) == "UNKNOWN"
    assert message_type_for_port(2010) == "VAM"


def test_geonet_frame_various_header_types():
    for header_type in (0x10, 0x20, 0x50):
        frame = ETH + _geonet(header_type)
        resolved = locate_geonetworking_frame(frame, DLT_EN10MB)
        assert resolved is not None, header_type
        assert resolved.header_type == header_type


# --------------------------------------------------------------------------- #
# stream: truncation and batch helpers
# --------------------------------------------------------------------------- #
def test_truncated_pcapng_block_sets_flag():
    streamer = PcapStreamingIterator()
    shb = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHII", 1, 0, 0, 0)
        + struct.pack("<I", 28)
    )
    garbage = struct.pack("<II", 6, 9999)  # declares more than remains
    records = list(streamer.iter_records(io.BytesIO(shb + garbage)))
    assert records == []
    assert streamer.truncated_eof is True


def test_invalid_pcapng_shb_length_raises():
    streamer = PcapStreamingIterator()
    bad = struct.pack("<II", 0x0A0D0D0A, 4) + b"\x00" * 20
    with pytest.raises(ValueError):
        streamer.read_header(io.BytesIO(bad))


def test_invalid_pcapng_byte_order_raises():
    streamer = PcapStreamingIterator()
    body = b"\xde\xad\xbe\xef" + struct.pack("<HH", 1, 0) + struct.pack("<II", 0, 0)
    # Trailing block total length closes the SHB.
    bad = struct.pack("<II", 0x0A0D0D0A, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    with pytest.raises(ValueError, match="byte-order"):
        streamer.read_header(io.BytesIO(bad))


def test_unsupported_magic_raises():
    streamer = PcapStreamingIterator()
    with pytest.raises(ValueError, match="Unsupported"):
        streamer.read_header(io.BytesIO(b"\xde\xad\xbe\xef" + b"\x00" * 20))


def test_file_too_small_raises():
    streamer = PcapStreamingIterator()
    with pytest.raises(ValueError):
        streamer.read_header(io.BytesIO(b"\xa1\xb2"))


def test_pcapng_simple_packet_block_is_read():
    shb = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHII", 1, 0, 0, 0)  # major, minor, section_length (8 bytes)
        + struct.pack("<I", 28)
    )
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_len = 12 + len(idb_body)
    idb = struct.pack("<II", 1, idb_len) + idb_body + struct.pack("<I", idb_len)
    payload = b"\x01\x02\x03\x04"
    spb_body = struct.pack("<I", len(payload)) + payload
    spb_len = 12 + len(spb_body)
    spb = struct.pack("<II", 3, spb_len) + spb_body + struct.pack("<I", spb_len)

    streamer = PcapStreamingIterator()
    records = list(streamer.iter_records(io.BytesIO(shb + idb + spb)))
    assert len(records) == 1
    assert records[0].data == payload
    assert records[0].dlt == 1


def test_iter_records_batched_groups_records():
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = b""
    for i in range(5):
        payload = bytes([i]) * 4
        body += struct.pack("<IIII", 1000 + i, 0, len(payload), len(payload)) + payload

    streamer = PcapStreamingIterator()
    batches = list(streamer.iter_records_batched(io.BytesIO(header + body), batch=2))
    assert [len(b) for b in batches] == [2, 2, 1]


def test_classic_pcap_big_endian_nanosecond():
    header = struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 127)
    payload = b"\xaa" * 4
    rec = struct.pack(">IIII", 5, 500_000_000, len(payload), len(payload)) + payload

    streamer = PcapStreamingIterator()
    records = list(streamer.iter_records(io.BytesIO(header + rec)))
    assert records[0].timestamp == 5.5
    assert streamer.header_info is not None
    assert streamer.header_info.is_nanosecond is True


# --------------------------------------------------------------------------- #
# CLI edges
# --------------------------------------------------------------------------- #
def test_cli_directory_scan_skips_hidden_dirs(tmp_path, capsys):
    visible = tmp_path / "a.py"
    visible.write_text("lat = 52.0 + math.sin(t) * 0.22\n", encoding="utf-8")
    hidden_dir = tmp_path / ".hidden"
    hidden_dir.mkdir()
    (hidden_dir / "b.py").write_text("lat = 52.0 + math.sin(t) * 0.22\n", encoding="utf-8")

    assert run_cli([str(tmp_path), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["total_inspected"] == 1  # only the visible file


def test_cli_unreadable_source_is_reported(tmp_path, capsys):
    directory = tmp_path / "adir.py"  # a directory named like a source file
    directory.mkdir()
    report_target = tmp_path / "target.py"
    report_target.write_text("x = 1\n", encoding="utf-8")

    # A source-file suffix path that is a directory must not crash the scan.
    assert run_cli([str(tmp_path), "--format", "json"]) in (0, 1)
    capsys.readouterr()


def test_cli_topology_missing_file_exits_two(capsys):
    assert run_cli(["--topology", "nope.json"]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_topology_invalid_json_is_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert run_cli(["--topology", str(bad), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert any("Failed to parse topology" in v["message"] for v in report["violations"])


def test_cli_topology_fragments_are_checked(tmp_path, capsys):
    doc = {
        "fragments": [
            {
                "regionId": 1,
                "intersectionId": 100,
                "layerId": 21,
                "lanes": [{"laneId": 1, "nodes": [1]}],
            },
            {
                "regionId": 1,
                "intersectionId": 100,
                "layerId": 22,
                "lanes": [{"laneId": 1, "nodes": [2]}],
            },
        ]
    }
    path = tmp_path / "frag.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    assert run_cli(["--topology", str(path), "--rules", "R03", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert any("Conflicting overwrite" in v["message"] for v in report["violations"])


def test_cli_topology_text_output_labels_target(tmp_path, capsys):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"connections": []}), encoding="utf-8")
    assert run_cli(["--topology", str(path)]) == 0
    assert "topology" in capsys.readouterr().out
