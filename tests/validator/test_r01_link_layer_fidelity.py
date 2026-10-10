"""R01 must agree with core.geonet on what a valid link layer looks like.

Management/control frames, WDS (Addr4), HT-Control and VLAN tags are all valid
captures; reporting them as corrupt LLC/SNAP or non-V2X traffic is a false alarm.
"""

from __future__ import annotations

import pytest

from cits_validator.core.geonet import DLT_EN10MB, DLT_IEEE802_11
from cits_validator.core.stream import PacketRecord
from cits_validator.rules.r01_link_layer import LinkLayerRule

LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"
GEONET = bytes([0x11, 0x00, 0x1A, 0x03]) + bytes([0x10, 0x50, 0x00, 0x00, 0x04, 0x00, 7, 0])
GEONET += b"\x00" * 28 + (2001).to_bytes(2, "big") + b"\x00\x00"


def _audit(data: bytes, dlt: int) -> tuple[list, dict]:
    state: dict = {}
    record = PacketRecord(index=1, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)
    return LinkLayerRule().audit_packet(record, dlt=dlt, state=state), state


def _dot11(fc: int, mac_len: int, body: bytes) -> bytes:
    return fc.to_bytes(2, "little") + b"\x00" * (mac_len - 2) + body


@pytest.mark.parametrize(
    ("label", "frame"),
    [
        ("beacon", _dot11(0x0080, 24, b"\x00" * 40)),
        ("ack-control", bytes([0xD4, 0x00]) + b"\x00" * 8),
        ("rts-control", bytes([0xB4, 0x00]) + b"\x00" * 14),
    ],
)
def test_non_data_80211_frames_are_not_link_layer_errors(label, frame):
    violations, _ = _audit(frame, DLT_IEEE802_11)

    assert violations == [], label


@pytest.mark.parametrize(
    ("label", "fc", "mac_len"),
    [
        ("wds-addr4", 0x0308, 30),
        ("qos", 0x0088, 26),
        ("qos-ht-control", 0x8088, 30),
    ],
)
def test_valid_data_frame_header_variants_reach_geonetworking(label, fc, mac_len):
    frame = _dot11(fc, mac_len, LLC_SNAP + GEONET)

    violations, state = _audit(frame, DLT_IEEE802_11)

    assert violations == [], label
    assert state["btp_ports"] == {2001: 1}, label


def test_vlan_tagged_ethernet_geonetworking_is_accepted():
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x81\x00" + b"\x00\x01" + b"\x89\x47" + GEONET

    violations, state = _audit(frame, DLT_EN10MB)

    assert violations == []
    assert state["btp_ports"] == {2001: 1}


def test_data_frame_with_wrong_llc_is_still_an_error():
    frame = _dot11(0x0008, 24, b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + b"\x00" * 40)

    violations, _ = _audit(frame, DLT_IEEE802_11)

    assert [v.severity.value for v in violations] == ["ERROR"]
