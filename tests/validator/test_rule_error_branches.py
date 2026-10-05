"""Error-branch coverage for the link-layer (R01) and hardware (R05) rules.

These are the paths a real capture hits when it is truncated, mis-framed or
carries a foreign EtherType. They matter more than the happy path: a decoder
that silently accepts a malformed frame is exactly what an audit must not do.
"""

from __future__ import annotations

import struct

from cits_validator.core.geonet import DLT_EN10MB
from cits_validator.core.stream import PacketRecord
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r05_hardware import HardwareStreamRule

LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"


def _record(data: bytes, index: int = 1) -> PacketRecord:
    return PacketRecord(index=index, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


def _radiotap(it_len: int = 8) -> bytes:
    return struct.pack("<BBHI", 0, 0, it_len, 0) + b"\x00" * (it_len - 8)


# --------------------------------------------------------------------------- #
# R01: Radiotap
# --------------------------------------------------------------------------- #
def test_r01_radiotap_too_short():
    violations = LinkLayerRule().audit_packet(_record(b"\x00\x00\x08"), dlt=127, state={})
    assert violations
    assert "too short for Radiotap" in violations[0].message


def test_r01_radiotap_length_beyond_packet():
    # it_len claims 5000 bytes inside a 40-byte frame.
    frame = struct.pack("<BBHI", 0, 0, 5000, 0) + b"\x00" * 32
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=127, state={})
    assert any("Invalid Radiotap length" in v.message for v in violations)


# --------------------------------------------------------------------------- #
# R01: 802.11
# --------------------------------------------------------------------------- #
def test_r01_payload_too_short_for_dot11_header():
    frame = _radiotap() + b"\x08\x00\x00\x00" + b"\x00" * 10  # 14 of 24 bytes
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=127, state={})
    assert any("too short for 802.11 MAC header" in v.message for v in violations)


def test_r01_qos_frame_truncated_during_mac_header():
    # QoS Data claims 26 bytes but only 24 are present after Radiotap.
    frame = _radiotap() + b"\x88\x00\x00\x00" + b"\x00" * 20
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=127, state={})
    assert any("truncated during 802.11 header" in v.message for v in violations)


def test_r01_truncated_before_llc_snap():
    frame = _radiotap() + b"\x08\x00\x00\x00" + b"\x00" * 20 + b"\xaa\xaa\x03"
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=127, state={})
    assert any("before 8-byte LLC/SNAP" in v.message for v in violations)


def test_r01_non_v2x_llc_snap():
    frame = _radiotap() + b"\x08\x00\x00\x00" + b"\x00" * 20 + b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=127, state={})
    assert any("non-V2X LLC/SNAP" in v.message for v in violations)
    assert violations[0].offending_sample


def test_r01_dlt105_raw_dot11_is_accepted():
    frame = b"\x08\x00\x00\x00" + b"\x00" * 20 + LLC_SNAP + b"\x11\x00\x1a\x03" + b"\x00" * 40
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=105, state={})
    assert violations == []


# --------------------------------------------------------------------------- #
# R01: Ethernet
# --------------------------------------------------------------------------- #
def test_r01_ethernet_too_short():
    violations = LinkLayerRule().audit_packet(_record(b"\x00" * 10), dlt=DLT_EN10MB, state={})
    assert any("too short for Ethernet" in v.message for v in violations)


def test_r01_non_v2x_ethertype():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x08\x00" + b"\x00" * 40
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=DLT_EN10MB, state={})
    assert any("Non-V2X Ethernet EtherType" in v.message for v in violations)


def test_r01_8023_length_without_llc_snap():
    frame = b"\xff" * 6 + b"\x11" * 6 + (60).to_bytes(2, "big") + b"\x00" * 40
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=DLT_EN10MB, state={})
    assert any("Invalid 802.3 LLC/SNAP" in v.message for v in violations)


def test_r01_8023_length_with_llc_snap_passes():
    frame = (
        b"\xff" * 6
        + b"\x11" * 6
        + (60).to_bytes(2, "big")
        + LLC_SNAP
        + b"\x11\x00\x1a\x03"
        + b"\x00" * 40
    )
    state: dict = {}
    violations = LinkLayerRule().audit_packet(_record(frame), dlt=DLT_EN10MB, state=state)
    assert violations == []
    assert "ethernet" in state["_coverage"]
    assert "llc_snap" in state["_coverage"]


def test_r01_truncated_after_llc_snap_has_no_btp_coverage():
    # Reaches LLC/SNAP but nothing follows, so the BTP layer must not be claimed.
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + b"\x00" * 2
    state: dict = {}
    LinkLayerRule().audit_packet(_record(frame), dlt=DLT_EN10MB, state=state)
    assert state.get("_coverage", {}).get("btp") is None


# --------------------------------------------------------------------------- #
# R05: hardware framing
# --------------------------------------------------------------------------- #
def _its5_frame(sec: int, usec: int, payload: bytes) -> bytes:
    return b"ITS5" + struct.pack("<IIH", sec, usec, len(payload)) + payload


def _its6_frame(sec: int, usec: int, payload: bytes, rssi: int) -> bytes:
    return b"ITS6" + struct.pack("<IIHb", sec, usec, len(payload), rssi) + payload


def test_r05_parses_its5_and_its6_frames():
    chunk = _its5_frame(10, 500_000, b"\xaa\xbb") + _its6_frame(11, 0, b"\xcc", -70)
    violations, frames = HardwareStreamRule().audit_stream_chunk(chunk, state={})
    assert len(frames) == 2
    assert frames[0]["magic"] == "ITS5"
    assert frames[0]["rssi"] is None
    assert frames[1]["rssi"] == -70
    assert violations == []


def test_r05_rssi_sentinel_becomes_none():
    violations, frames = HardwareStreamRule().audit_stream_chunk(
        _its6_frame(1, 0, b"\x01", -128), state={}
    )
    assert frames[0]["rssi"] is None


def test_r05_skips_garbage_before_magic():
    chunk = b"\x00\x01\x02" + _its5_frame(1, 0, b"\x01")
    violations, frames = HardwareStreamRule().audit_stream_chunk(chunk, state={})
    assert len(frames) == 1


def test_r05_truncated_header_stops_parsing():
    chunk = b"ITS5" + struct.pack("<II", 1, 0)  # header incomplete
    violations, frames = HardwareStreamRule().audit_stream_chunk(chunk, state={})
    assert frames == []


def test_r05_truncated_payload_stops_parsing():
    chunk = b"ITS5" + struct.pack("<IIH", 1, 0, 100) + b"\x00" * 4
    violations, frames = HardwareStreamRule().audit_stream_chunk(chunk, state={})
    assert frames == []


def test_r05_backward_uptime_jump_is_flagged():
    state: dict = {}
    HardwareStreamRule().audit_stream_chunk(_its5_frame(100, 0, b"\x01"), state=state)
    violations, _ = HardwareStreamRule().audit_stream_chunk(
        _its5_frame(90, 0, b"\x01"), state=state
    )
    assert any("backward uptime jump" in v.message for v in violations)


def test_r05_forward_uptime_gap_is_flagged():
    state: dict = {}
    HardwareStreamRule().audit_stream_chunk(_its5_frame(100, 0, b"\x01"), state=state)
    violations, _ = HardwareStreamRule().audit_stream_chunk(
        _its5_frame(400, 0, b"\x01"), state=state
    )
    assert any("forward uptime gap" in v.message for v in violations)
