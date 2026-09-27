import struct

from cits_validator.core.models import Severity
from cits_validator.core.stream import PacketRecord
from cits_validator.rules.r01_link_layer import LinkLayerRule


def make_packet(data: bytes, index: int = 1) -> PacketRecord:
    return PacketRecord(
        index=index,
        timestamp=1000.0,
        caplen=len(data),
        wirelen=len(data),
        data=data,
    )


def test_dlt127_valid_qos_cam_frame():
    # 1. Radiotap header: 36 bytes (ver=0, pad=0, len=36, present=0x0000482e)
    radiotap_hdr = struct.pack("<BBHI", 0, 0, 36, 0x0000482E) + b"\x00" * 28

    # 2. 802.11 QoS Data header: 26 bytes (fc=0x0888, dur=0, addrs..., qos_ctrl=0)
    # Type 2 (Data), Subtype 8 (QoS Data) -> fc = 0x8808 in LE -> frame_ctrl byte 0 = 0x88, byte 1 = 0x01
    dot11_qos = b"\x88\x01\x00\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6 + b"\x00\x00\x00\x00"

    # 3. LLC/SNAP header: 8 bytes (AA AA 03 00 00 00 89 47)
    llc_snap = b"\xAA\xAA\x03\x00\x00\x00\x89\x47"

    # 4. BTP header (BTP-B): dst port 2001 (CAM), dst port info 0
    btp = struct.pack(">HH", 2001, 0)

    # 5. Payload
    payload = b"\x01\x02\x03\x04"

    raw = radiotap_hdr + dot11_qos + llc_snap + btp + payload
    rule = LinkLayerRule()
    violations = rule.audit_packet(make_packet(raw), dlt=127, state={})

    assert len(violations) == 0


def test_dlt127_invalid_radiotap_length():
    # Radiotap length field at offset 2 says 4 bytes (illegal, min is 8)
    bad_radiotap = struct.pack("<BBHI", 0, 0, 4, 0) + b"\x00" * 20
    rule = LinkLayerRule()
    violations = rule.audit_packet(make_packet(bad_radiotap), dlt=127, state={})

    assert any(v.rule_id == "R01" and v.severity == Severity.ERROR for v in violations)
    assert any("Radiotap length" in v.message for v in violations)


def test_dlt127_invalid_llc_snap_header():
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    dot11_data = b"\x08\x00\x00\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6  # 24B normal data
    bad_llc = b"\xAA\xAA\x03\x00\x00\x00\x08\x00"  # IPv4 instead of 0x8947

    raw = radiotap + dot11_data + bad_llc + b"\x00" * 10
    rule = LinkLayerRule()
    violations = rule.audit_packet(make_packet(raw), dlt=127, state={})

    assert any(v.rule_id == "R01" and "0x8947" in v.message for v in violations)


def test_dlt1_ethernet_v2x_frame():
    # DLT 1: 14 bytes Ethernet header (dst 6B, src 6B, ethertype 2B = 0x8947)
    eth_hdr = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47"
    btp = struct.pack(">HH", 2004, 0)  # SPATEM
    raw = eth_hdr + btp + b"\xaa\xbb\xcc"

    rule = LinkLayerRule()
    violations = rule.audit_packet(make_packet(raw), dlt=1, state={})
    assert len(violations) == 0
