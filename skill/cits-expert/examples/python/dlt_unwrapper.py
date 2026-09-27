"""DLT Unwrapper and Link-Layer Stripper for C-ITS / V2X PCAP Dissection.

Handles DLT 1 (Ethernet II), DLT 105 (IEEE 802.11), and DLT 127 (IEEE 802.11 Radiotap).
Extracts GeoNetworking payloads and inspects Basic Transport Protocol (BTP) destination ports.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

LLC_SNAP_GEONET = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"
ETHERTYPE_GEONET = 0x8947


@dataclass(frozen=True)
class PcapHeaderInfo:
    is_nanosecond: bool
    timestamp_scale: int

    @classmethod
    def from_magic(cls, magic: bytes) -> PcapHeaderInfo:
        if magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
            return cls(is_nanosecond=True, timestamp_scale=1_000_000_000)
        return cls(is_nanosecond=False, timestamp_scale=1_000_000)


@dataclass
class UnwrappedPacket:
    link_type: int
    geonet_payload: bytes
    btp_port: int | None = None
    is_qos_data: bool = False


class DltUnwrapper:
    """Dissects link-layer encapsulation to access raw GeoNetworking frames."""

    def unwrap(self, packet_bytes: bytes, link_type: int) -> UnwrappedPacket | None:
        if link_type == 1:
            return self._unwrap_dlt1(packet_bytes)
        elif link_type == 105:
            return self._unwrap_dlt105(packet_bytes)
        elif link_type == 127:
            return self._unwrap_dlt127(packet_bytes)
        return None

    def _unwrap_dlt1(self, packet_bytes: bytes) -> UnwrappedPacket | None:
        if len(packet_bytes) < 14:
            return None
        ethertype = struct.unpack(">H", packet_bytes[12:14])[0]
        if ethertype != ETHERTYPE_GEONET:
            return None
        payload = packet_bytes[14:]
        btp_port = self._extract_btp_port(payload)
        return UnwrappedPacket(link_type=1, geonet_payload=payload, btp_port=btp_port)

    def _unwrap_dlt105(self, packet_bytes: bytes) -> UnwrappedPacket | None:
        return self._strip_dot11_and_llc(packet_bytes, link_type=105)

    def _unwrap_dlt127(self, packet_bytes: bytes) -> UnwrappedPacket | None:
        if len(packet_bytes) < 4:
            return None
        # Radiotap header: bytes 2..4 = total header length (little-endian uint16)
        rt_len = struct.unpack("<H", packet_bytes[2:4])[0]
        if len(packet_bytes) < rt_len:
            return None
        dot11_frame = packet_bytes[rt_len:]
        return self._strip_dot11_and_llc(dot11_frame, link_type=127)

    def _strip_dot11_and_llc(self, dot11_bytes: bytes, link_type: int) -> UnwrappedPacket | None:
        if len(dot11_bytes) < 24:
            return None

        # Frame control word (first 2 bytes, little-endian)
        fc = struct.unpack("<H", dot11_bytes[:2])[0]
        frame_type = (fc >> 2) & 0x03
        frame_subtype = (fc >> 4) & 0x0F

        # Type 2 = Data Frame
        if frame_type != 2:
            return None

        is_qos = frame_subtype == 8
        mac_header_len = 26 if is_qos else 24

        if len(dot11_bytes) < mac_header_len + 8:
            return None

        # Verify LLC/SNAP: 8 bytes
        llc_snap = dot11_bytes[mac_header_len : mac_header_len + 8]
        if llc_snap != LLC_SNAP_GEONET:
            return None

        payload = dot11_bytes[mac_header_len + 8 :]
        btp_port = self._extract_btp_port(payload)
        return UnwrappedPacket(
            link_type=link_type,
            geonet_payload=payload,
            btp_port=btp_port,
            is_qos_data=is_qos,
        )

    def _extract_btp_port(self, geonet_bytes: bytes) -> int | None:
        """Parses GeoNetworking Common Header and BTP header to find destination port."""
        # Minimum GeoNetworking: Basic Header (4B) + Common Header (8B) = 12B
        if len(geonet_bytes) < 12:
            return None

        # Common Header byte 0: NextHeader (1 = BTP-A, 2 = BTP-B)
        next_header = geonet_bytes[4] >> 4
        if next_header not in (1, 2):
            # Sometimes next_header is raw 1 or 2
            next_header = geonet_bytes[4]

        # Let's inspect the payload following the GeoNetworking extended headers.
        # Common header starts at offset 4.
        # Byte 5: HeaderType & HeaderSubType
        # Standard GeoNet TSB/SHB headers have length 12B + 28B/40B etc.
        # Alternatively, search for standard BTP ports if within standard header window:
        # Ports: 2001 (CAM), 2002 (DENM), 2003 (MAPEM), 2004 (SPATEM), 2006 (IVIM), 2007 (SREM), 2008 (SSEM)
        known_ports = {2001, 2002, 2003, 2004, 2006, 2007, 2008}

        # In typical captures, BTP follows GeoNet header. If offset is known or small (12 to 52 bytes):
        for offset in range(12, min(len(geonet_bytes) - 2, 64)):
            port = struct.unpack(">H", geonet_bytes[offset : offset + 2])[0]
            if port in known_ports:
                return port
        return None
