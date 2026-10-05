"""GeoNetworking (ETSI EN 302 636-4-1) plaintext framing and BTP (EN 302 636-5-1).

Single source of truth for "where does the ASN.1 UPER payload of this captured
frame begin?". Every consumer — the R01 link-layer audit, the PCAP payload
extractor used by ``cits-export`` and the ASN.1 conformance rule — resolves its
offsets here instead of re-deriving them, so a header change cannot make two
readers of the same field disagree.

A frame that cannot be resolved with certainty yields ``None`` rather than a
plausible-looking offset. Secured frames (IEEE 1609.2 / ETSI TS 103 097) are
reported as such: their Common Header and BTP live inside the security envelope,
so the BTP port is genuinely unavailable without unwrapping it.
"""

from __future__ import annotations

from dataclasses import dataclass

ETHERTYPE_GEONETWORKING = 0x8947
ETHERTYPE_VLAN_8021Q = 0x8100
ETHERTYPE_VLAN_8021AD = 0x88A8
ETHERNET_HEADER_LEN = 14
VLAN_TAG_LEN = 4
LLC_SNAP_GEONET = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"

DLT_EN10MB = 1
DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127

BASIC_HEADER_LEN = 4
COMMON_HEADER_LEN = 8
BTP_HEADER_LEN = 4

NEXT_HEADER_BASIC_COMMON = 1
NEXT_HEADER_BASIC_SECURED = 2
NEXT_HEADER_COMMON_BTP_A = 1
NEXT_HEADER_COMMON_BTP_B = 2

# IEEE 1609.2 / TS 103 097 envelope protocol versions (COER = 3, v1.2.1 = 2).
IEEE1609_PROTOCOL_VERSION = 3
TS103097_V1_PROTOCOL_VERSION = 2

# Extended header length per Common Header HeaderType (EN 302 636-4-1, 8.7.3 + cl. 9).
_EXTENDED_HEADER_LEN: dict[int, int] = {
    0x10: 24,  # Beacon: LongPositionVector only
    0x20: 4 + 24 + 20,  # GeoUnicast
    0x30: 20 + 24,  # GeoAnycast circle
    0x31: 20 + 24,  # GeoAnycast rectangle
    0x32: 20 + 24,  # GeoAnycast ellipse
    0x40: 20 + 24,  # GeoBroadcast circle
    0x41: 20 + 24,  # GeoBroadcast rectangle
    0x42: 20 + 24,  # GeoBroadcast ellipse
    0x50: 4 + 24,  # TSB single hop
    0x51: 4 + 24,  # TSB multi hop
    0x60: 4 + 24 + 8,  # LS request
    0x61: 4 + 24 + 20,  # LS reply
}

BTP_PORTS = {
    2001: "CAM",
    2002: "DENM",
    2003: "MAPEM",
    2004: "SPATEM",
    2005: "SAEM",
    2006: "IVIM",
    2007: "SREM",
    2008: "SSEM",
    2009: "CPM",
    2010: "EVCSN",  # EVCSN POI message (ETSI TS 101 556-1)
    2011: "TPG",  # TRM/TCM/VDRM/VDPM/EOFM (ETSI TS 101 556-2)
    2013: "RTCMEM",
    2018: "VAM",  # VA (VAM), ETSI TS 103 300-3
    2019: "IMZM",
}
# Source: ETSI TS 103 248 Table 1 "List of well-known BTP port number values"
# (v2.4.1), which lists 2 009 = CP (CPM) and 2 018 = VA (VAM). An earlier draft
# of this table carried VAM at 2 010, which the standard assigns to the EVCSN POI
# message; the value was corrected against the specification rather than kept
# because it appeared in a neighbouring implementation.


@dataclass
class GeoNetworkingFrame:
    """Byte-level layout of one captured ITS frame."""

    geonet_offset: int
    basic_header_offset: int
    header_type: int
    geonet_version: int
    was_secured: bool
    btp_offset: int | None = None
    btp_port: int | None = None
    payload_offset: int | None = None


def link_layer_offset(data: bytes, dlt: int) -> int | None:
    """Returns the offset at which the GeoNetworking Basic Header starts, or None.

    ``None`` means the frame is not recognisably GeoNetworking at this link type
    (a non-0x8947 EtherType, a wrong LLC/SNAP value, a non-Data 802.11 frame, or
    a frame too short to carry the header). No offset is guessed: an unresolvable
    frame is reported as such by the caller.
    """
    if dlt == DLT_EN10MB:
        return _ethernet_geonet_offset(data)

    if dlt in (DLT_IEEE802_11_RADIO, DLT_IEEE802_11):
        return _dot11_geonet_offset(data, dlt)

    return None


def _ethernet_geonet_offset(data: bytes) -> int | None:
    if len(data) < ETHERNET_HEADER_LEN:
        return None
    offset = ETHERNET_HEADER_LEN
    ethertype = int.from_bytes(data[12:14], "big")

    if ethertype in (ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD):
        # 802.1Q: dst(6) src(6) TPID(2) TCI(2) inner-EtherType(2) payload.
        # The inner EtherType sits two bytes before the payload, not four.
        if len(data) < offset + VLAN_TAG_LEN:
            return None
        ethertype = int.from_bytes(data[offset + VLAN_TAG_LEN - 2 : offset + VLAN_TAG_LEN], "big")
        offset += VLAN_TAG_LEN

    if ethertype == ETHERTYPE_GEONETWORKING:
        return offset
    # 802.3 length field: an LLC/SNAP header may follow directly.
    if ethertype <= 1500 and len(data) >= offset + 8:
        if data[offset : offset + 8] == LLC_SNAP_GEONET:
            return offset + 8
    return None


def _dot11_geonet_offset(data: bytes, dlt: int) -> int | None:
    offset = 0
    if dlt == DLT_IEEE802_11_RADIO:
        if len(data) < 8:
            return None
        it_len = int.from_bytes(data[2:4], "little")
        if it_len < 8 or it_len > len(data):
            return None
        offset = it_len

    if len(data) < offset + 24:
        return None
    fc = int.from_bytes(data[offset : offset + 2], "little")
    if ((fc >> 2) & 0x03) != 2:  # Not a Data frame
        return None

    to_ds = (fc >> 8) & 0x01
    from_ds = (fc >> 9) & 0x01
    # 802.11 MAC header: 24 bytes, +6 for Address 4 (WDS), +2 for QoS Control,
    # +4 for HT Control when the Order bit is set on a QoS frame. Captures vary;
    # each component is derived from the Frame Control word, never assumed.
    mac_len = 24
    if to_ds and from_ds:
        mac_len += 6
    subtype = (fc >> 4) & 0x0F
    if subtype == 8:  # QoS Data
        mac_len += 2
    if subtype == 8 and ((fc >> 15) & 0x01):  # Order bit on a QoS frame
        mac_len += 4
    offset += mac_len

    if len(data) < offset + 8:
        return None
    if data[offset : offset + 8] == LLC_SNAP_GEONET:
        return offset + 8

    # Some capture pipelines (notably the ESP32-C5 host stream written to PCAP)
    # wrap the original Ethernet frame inside the 802.11 payload, so the
    # GeoNetworking EtherType 0x8947 appears where LLC/SNAP would be, without the
    # 8-byte SNAP prefix. The candidate is accepted only when the octet following
    # the EtherType decodes as a well-formed GeoNetworking Basic Header (version
    # 1, next header either Common or Secured) — otherwise the marker is treated
    # as payload and the frame stays unresolved.
    return _embedded_ethertype_offset(data, offset)


def _embedded_ethertype_offset(data: bytes, offset: int) -> int | None:
    for pos in range(offset, min(offset + 12, len(data) - 3)):
        if data[pos : pos + 2] != b"\x89\x47":
            continue
        basic = data[pos + 2]
        if (basic >> 4) != 1:
            continue
        if (basic & 0x0F) not in (NEXT_HEADER_BASIC_COMMON, NEXT_HEADER_BASIC_SECURED):
            continue
        return pos + 2
    return None


def locate_geonetworking_frame(data: bytes, dlt: int) -> GeoNetworkingFrame | None:
    """Resolves the GeoNetworking headers and the BTP payload of one frame.

    Returns ``None`` when the frame is not GeoNetworking or a header cannot be
    resolved. A secured frame is returned with ``was_secured=True`` and no
    ``btp_offset``: its Common Header sits inside the IEEE 1609.2 envelope, so
    reporting a port from the ciphertext would be a fabrication.
    """
    basic_offset = link_layer_offset(data, dlt)
    if basic_offset is None or basic_offset + BASIC_HEADER_LEN > len(data):
        return None

    basic = data[basic_offset]
    geonet_version = (basic >> 4) & 0x0F
    next_header = basic & 0x0F

    if next_header == NEXT_HEADER_BASIC_SECURED:
        return GeoNetworkingFrame(
            geonet_offset=basic_offset,
            basic_header_offset=basic_offset,
            header_type=-1,
            geonet_version=geonet_version,
            was_secured=True,
        )
    if next_header != NEXT_HEADER_BASIC_COMMON:
        return None

    common_offset = basic_offset + BASIC_HEADER_LEN
    if common_offset + COMMON_HEADER_LEN > len(data):
        return None

    next_header_common = (data[common_offset] >> 4) & 0x0F
    header_type = data[common_offset + 1]

    extended_len = _EXTENDED_HEADER_LEN.get(header_type)
    if extended_len is None:
        return None

    extended_offset = common_offset + COMMON_HEADER_LEN
    btp_offset = extended_offset + extended_len
    if btp_offset > len(data):
        return None

    if next_header_common not in (NEXT_HEADER_COMMON_BTP_A, NEXT_HEADER_COMMON_BTP_B):
        return GeoNetworkingFrame(
            geonet_offset=basic_offset,
            basic_header_offset=basic_offset,
            header_type=header_type,
            geonet_version=geonet_version,
            was_secured=False,
        )

    if btp_offset + BTP_HEADER_LEN > len(data):
        return None

    btp_port = int.from_bytes(data[btp_offset : btp_offset + 2], "big")
    return GeoNetworkingFrame(
        geonet_offset=basic_offset,
        basic_header_offset=basic_offset,
        header_type=header_type,
        geonet_version=geonet_version,
        was_secured=False,
        btp_offset=btp_offset,
        btp_port=btp_port,
        payload_offset=btp_offset + BTP_HEADER_LEN,
    )


def message_type_for_port(port: int | None) -> str:
    """Human-readable ITS message type for a BTP destination port."""
    if port is None:
        return "UNKNOWN"
    return BTP_PORTS.get(port, "UNKNOWN")
