from __future__ import annotations

import struct
from typing import Any

from cits_validator.core.geonet import (
    BTP_PORTS,
    DLT_EN10MB,
    DLT_IEEE802_11,
    DLT_IEEE802_11_RADIO,
    LLC_SNAP_GEONET,
    dot11_mac_header_len,
    ethernet_payload,
    locate_geonetworking_frame,
)
from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule
from cits_validator.core.stream import PacketRecord

ETHERTYPE_GEONETWORKING = 0x8947
MAX_802_3_LENGTH = 1500
MIN_RADIOTAP_LEN = 8
MIN_DOT11_DATA_HEADER = 24
FC_TYPE_DATA = 2

# Result of one unwrapping step: (next offset, finding). An offset with no finding
# continues; a finding stops the audit of the packet; (None, None) stops silently.
_Step = tuple[int | None, Violation | None]


class LinkLayerRule(BaseRule):
    """Audits link-layer unwrapping, 802.11 QoS headers, LLC/SNAP and BTP ports."""

    rule_id = "R01"
    name = "Link Layer & Wire Framing Integrity"
    description = (
        "Enforces dynamic Radiotap length parsing, 802.11 QoS Data traversal, "
        "LLC/SNAP 0x8947 validation, and BTP port sanity."
    )

    @staticmethod
    def _cover(state: dict[str, Any], category: str, count: int = 1) -> None:
        """Records that a framing layer was actually reached in this capture."""
        coverage = state.setdefault("_coverage", {})
        coverage[category] = coverage.get(category, 0) + count

    def _error(
        self,
        record: PacketRecord,
        message: str,
        offset: int,
        *,
        sample: str | None = None,
        hint: str | None = None,
    ) -> Violation:
        return Violation(
            rule_id=self.rule_id,
            severity=Severity.ERROR,
            message=message,
            packet_index=record.index,
            byte_offset=offset,
            offending_sample=sample,
            remediation_hint=hint,
        )

    def audit_packet(
        self, record: PacketRecord, dlt: int, state: dict[str, Any]
    ) -> list[Violation]:
        data = record.data
        offset = 0

        if dlt == DLT_IEEE802_11_RADIO:
            offset, finding = self._radiotap(record, state)
            if finding is not None:
                return [finding]

        if dlt in (DLT_IEEE802_11_RADIO, DLT_IEEE802_11):
            step, finding = self._dot11(record, offset, state)
        elif dlt == DLT_EN10MB:
            step, finding = self._ethernet(record, state)
        else:
            step, finding = 0, None

        if finding is not None:
            return [finding]
        if step is None:
            return []  # valid frame that carries no V2X data (management/control)

        return self._geonetworking(record, dlt, state, data)

    # -- link layer steps ------------------------------------------------------
    def _radiotap(self, record: PacketRecord, state: dict[str, Any]) -> tuple[int, Violation | None]:
        data = record.data
        if len(data) < MIN_RADIOTAP_LEN:
            return 0, self._error(
                record,
                f"Packet too short for Radiotap header ({len(data)} < {MIN_RADIOTAP_LEN} bytes)",
                0,
                hint="Verify packet capture integrity or minimum payload length.",
            )

        it_len = struct.unpack("<H", data[2:4])[0]
        if it_len < MIN_RADIOTAP_LEN or it_len > len(data):
            return 0, self._error(
                record,
                f"Invalid Radiotap length at byte offset 2: it_len={it_len}",
                2,
                sample=data[:4].hex(),
                hint=(
                    "Always read uint16_le at offset 2 to dynamically skip Radiotap. "
                    "Never assume a static 36-byte offset."
                ),
            )

        self._cover(state, "radiotap")
        return it_len, None

    def _dot11(self, record: PacketRecord, offset: int, state: dict[str, Any]) -> _Step:
        data = record.data
        truncated_hint = "Check if frame was truncated before the 802.11 MAC header."
        if len(data) < offset + 2:
            return None, self._error(
                record, "Payload too short for 802.11 Frame Control", offset, hint=truncated_hint
            )

        fc = struct.unpack("<H", data[offset : offset + 2])[0]
        if (fc & 0x000C) >> 2 != FC_TYPE_DATA:
            # Management and control frames (beacons, ACK, RTS ...) carry no
            # LLC/SNAP and may be shorter than 24 bytes: valid, just not V2X data.
            self._cover(state, "dot11_non_data")
            return None, None

        if len(data) < offset + MIN_DOT11_DATA_HEADER:
            return None, self._error(
                record,
                f"Payload too short for 802.11 MAC header "
                f"({len(data) - offset} < {MIN_DOT11_DATA_HEADER} bytes)",
                offset,
                hint=truncated_hint,
            )

        mac_len = dot11_mac_header_len(fc)
        if len(data) < offset + mac_len:
            return None, self._error(
                record, f"Payload truncated during 802.11 header (expected {mac_len} bytes)", offset
            )

        self._cover(state, "dot11")
        offset += mac_len
        return self._llc_snap(record, offset, state)

    def _llc_snap(self, record: PacketRecord, offset: int, state: dict[str, Any]) -> _Step:
        data = record.data
        if len(data) < offset + len(LLC_SNAP_GEONET):
            return None, self._error(
                record, "Payload truncated before 8-byte LLC/SNAP header", offset
            )

        llc_snap = data[offset : offset + len(LLC_SNAP_GEONET)]
        if llc_snap != LLC_SNAP_GEONET:
            return None, self._error(
                record,
                f"Corrupt or non-V2X LLC/SNAP header: got {llc_snap.hex()}, expected 0x8947",
                offset,
                sample=llc_snap.hex(),
                hint=(
                    "Expected ETSI ITS EtherType 0x8947 with SNAP header "
                    "'AA AA 03 00 00 00 89 47'."
                ),
            )

        self._cover(state, "llc_snap")
        return offset + len(LLC_SNAP_GEONET), None

    def _ethernet(self, record: PacketRecord, state: dict[str, Any]) -> _Step:
        data = record.data
        parsed = ethernet_payload(data)
        if parsed is None:
            return None, self._error(record, "Packet too short for Ethernet header (< 14 bytes)", 0)

        ethertype, payload_offset = parsed
        if ethertype == ETHERTYPE_GEONETWORKING:
            self._cover(state, "ethernet")
            return payload_offset, None

        if ethertype <= MAX_802_3_LENGTH:  # 802.3 length field, LLC/SNAP follows
            llc_end = payload_offset + len(LLC_SNAP_GEONET)
            if data[payload_offset:llc_end] == LLC_SNAP_GEONET:
                self._cover(state, "ethernet")
                self._cover(state, "llc_snap")
                return llc_end, None
            return None, self._error(
                record, "Invalid 802.3 LLC/SNAP EtherType: expected 0x8947", payload_offset
            )

        return None, self._error(
            record,
            f"Non-V2X Ethernet EtherType: 0x{ethertype:04x}",
            12,
            hint="EtherType must be 0x8947 for C-ITS / GeoNetworking frames.",
        )

    # -- GeoNetworking + BTP -----------------------------------------------------
    def _geonetworking(
        self, record: PacketRecord, dlt: int, state: dict[str, Any], data: bytes
    ) -> list[Violation]:
        """The BTP destination port sits after the GeoNetworking Basic, Common and
        extended headers (EN 302 636-4-1 / -5-1), not immediately after LLC/SNAP. A
        secured frame hides it inside the 1609.2 envelope, so no port is reported
        rather than a fabricated one."""
        frame = locate_geonetworking_frame(data, dlt)
        if frame is None:
            return []

        self._cover(state, "geonet")
        if frame.was_secured:
            self._cover(state, "secured")
            state["secured_frames"] = state.get("secured_frames", 0) + 1
        if frame.btp_port is None:  # encrypted or unparsable envelope: no port to report
            return []

        self._cover(state, "btp")
        ports = state.setdefault("btp_ports", {})
        ports[frame.btp_port] = ports.get(frame.btp_port, 0) + 1
        if frame.btp_port in BTP_PORTS or ports[frame.btp_port] != 1:
            return []
        return [
            Violation(
                rule_id=self.rule_id,
                severity=Severity.INFO,
                message=(
                    f"BTP destination port {frame.btp_port} is not a well-known "
                    "ITS service port (ETSI TS 103 248)"
                ),
                packet_index=record.index,
                byte_offset=frame.btp_offset,
            )
        ]
