import struct

from dlt_unwrapper import DltUnwrapper, PcapHeaderInfo


def test_pcap_magic_nanosecond_detection():
    # Microsecond magic
    info_us = PcapHeaderInfo.from_magic(b"\xa1\xb2\xc3\xd4")
    assert info_us.is_nanosecond is False
    assert info_us.timestamp_scale == 1_000_000

    # Nanosecond magic
    info_ns = PcapHeaderInfo.from_magic(b"\xa1\xb2\x3c\x4d")
    assert info_ns.is_nanosecond is True
    assert info_ns.timestamp_scale == 1_000_000_000


def test_dlt1_ethernet_unwrapping():
    unwrapper = DltUnwrapper()
    # Ethernet II frame: Dest MAC (6), Src MAC (6), EtherType 0x8947 (2), followed by dummy GeoNet
    dummy_geonet = b"\x10\x01\x00\x00\x00\x05\x00\x00"  # Basic + Common header, BTP-B next header
    eth_frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x89\x47" + dummy_geonet

    result = unwrapper.unwrap(eth_frame, link_type=1)
    assert result is not None
    assert result.geonet_payload == dummy_geonet
    assert result.link_type == 1


def test_dlt127_radiotap_real_byte_sequence():
    unwrapper = DltUnwrapper()

    # Reconstruct real DLT 127 capture structure:
    # 1. Radiotap header: Version 0, Pad 0, Length = 0x0020 (32 bytes), Present flag ...
    rt_len = 32
    radiotap = b"\x00\x00" + struct.pack("<H", rt_len) + b"\x00" * (rt_len - 4)

    # 2. 802.11 QoS Data header: Frame Control (0x88 0x02 = Data, QoS Data), Duration, Addr1..3, Seq, QoS
    # Frame Control: Type 2 (Data), Subtype 8 (QoS Data) -> 0x88 0x02
    dot11_mac = b"\x88\x02\x30\x00" + b"\xff" * 6 + b"\x11" * 6 + b"\x22" * 6 + b"\x00\x00" + b"\x00\x00"
    assert len(dot11_mac) == 26  # 24B MAC + 2B QoS Control

    # 3. LLC / SNAP Header: aa aa 03 00 00 00 89 47
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"

    # 4. GeoNet Header + BTP (Port 2004 for SPATEM = 0x07D4)
    # GeoNet Common Header: NextHeader = BTP-B (2), HeaderType = TSB (4), HopLimit ...
    # Let's mock a standard GeoNet packet (Basic 4B + Common 8B = 12B) followed by BTP-B (DestPort 2B, Info 2B)
    geonet_basic = b"\x10\x00\x00\x00"  # Vers 1, NextHeader 0 (Common)
    geonet_common = b"\x02\x40\x00\x00\x00\x00\x00\x00"  # NextHeader=2 (BTP-B), HeaderType=0x40 (TSB)
    btp_b = struct.pack(">HH", 2004, 0)  # Port 2004 (SPATEM), Info 0
    its_spat_pdu = b"\x02\x01\x04\x00\x12\x34\x56\x78"

    payload = geonet_basic + geonet_common + btp_b + its_spat_pdu
    raw_packet = radiotap + dot11_mac + llc_snap + payload

    result = unwrapper.unwrap(raw_packet, link_type=127)
    assert result is not None
    assert result.link_type == 127
    assert result.geonet_payload == payload
    assert result.btp_port == 2004
    assert result.is_qos_data is True


def test_corrupted_or_non_v2x_frame():
    unwrapper = DltUnwrapper()
    # Packet too short
    assert unwrapper.unwrap(b"\x00\x01", link_type=1) is None
    # Ethernet frame with IPv4 (0x0800) instead of GeoNetworking (0x8947)
    eth_ip = b"\x00" * 12 + b"\x08\x00" + b"\x45\x00\x00\x20"
    assert unwrapper.unwrap(eth_ip, link_type=1) is None
