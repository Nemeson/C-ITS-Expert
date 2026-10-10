from __future__ import annotations

import struct
from typing import Any

from cits_validator.core.geonet import (
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


class LinkLayerRule(BaseRule):
    """Audits link-layer unwrapping, 802.11 QoS headers, LLC/SNAP and BTP ports."""

    rule_id = "R01"
    name = "Link Layer & Wire Framing Integrity"
    description = (
        "Enforces dynamic Radiotap length parsing, 802.11 QoS Data traversal, "
        "LLC/SNAP 0x8947 validation, and BTP port sanity."
    )

    KNOWN_BTP_PORTS = {
        2001: "CAM",
        2002: "DENM",
        2003: "MAPEM",
        2004: "SPATEM",
        2006: "IVIM",
        2007: "SREM",
        2008: "SSEM",
    }

    @staticmethod
    def _cover(state: dict[str, Any], category: str, count: int = 1) -> None:
        """Records that a framing layer was actually reached in this capture."""
        coverage = state.setdefault("_coverage", {})
        coverage[category] = coverage.get(category, 0) + count

    def audit_packet(
        self, record: PacketRecord, dlt: int, state: dict[str, Any]
    ) -> list[Violation]:
        violations: list[Violation] = []
        data = record.data
        offset = 0

        # 1. Radiotap Unwrapping
        if dlt == DLT_IEEE802_11_RADIO:
            if len(data) < 8:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=f"Packet too short for Radiotap header ({len(data)} < 8 bytes)",
                        packet_index=record.index,
                        byte_offset=0,
                        remediation_hint="Verify packet capture integrity or minimum payload length.",
                    )
                )
                return violations

            it_len = struct.unpack("<H", data[2:4])[0]
            if it_len < 8 or it_len > len(data):
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=f"Invalid Radiotap length at byte offset 2: it_len={it_len}",
                        packet_index=record.index,
                        byte_offset=2,
                        offending_sample=data[:4].hex(),
                        remediation_hint=(
                            "Always read uint16_le at offset 2 to dynamically skip Radiotap. "
                            "Never assume a static 36-byte offset."
                        ),
                    )
                )
                return violations

            self._cover(state, "radiotap")
            offset = it_len

        # 2. 802.11 MAC Frame Unwrapping
        if dlt in (DLT_IEEE802_11_RADIO, DLT_IEEE802_11):
            if len(data) < offset + 2:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message="Payload too short for 802.11 Frame Control",
                        packet_index=record.index,
                        byte_offset=offset,
                        remediation_hint="Check if frame was truncated before the 802.11 MAC header.",
                    )
                )
                return violations

            fc = struct.unpack("<H", data[offset : offset + 2])[0]
            if (fc & 0x000C) >> 2 != 2:
                # Management and control frames (beacons, ACK, RTS ...) carry no
                # LLC/SNAP and may be shorter than 24 bytes: valid, just not V2X data.
                self._cover(state, "dot11_non_data")
                return violations

            if len(data) < offset + 24:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=f"Payload too short for 802.11 MAC header ({len(data) - offset} < 24 bytes)",
                        packet_index=record.index,
                        byte_offset=offset,
                        remediation_hint="Check if frame was truncated before the 802.11 MAC header.",
                    )
                )
                return violations

            mac_len = dot11_mac_header_len(fc)
            if len(data) < offset + mac_len:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=f"Payload truncated during 802.11 header (expected {mac_len} bytes)",
                        packet_index=record.index,
                        byte_offset=offset,
                    )
                )
                return violations

            self._cover(state, "dot11")
            offset += mac_len

            # 3. LLC/SNAP Validation for 802.11
            if len(data) < offset + 8:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message="Payload truncated before 8-byte LLC/SNAP header",
                        packet_index=record.index,
                        byte_offset=offset,
                    )
                )
                return violations

            llc_snap = data[offset : offset + 8]
            if llc_snap != LLC_SNAP_GEONET:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=f"Corrupt or non-V2X LLC/SNAP header: got {llc_snap.hex()}, expected 0x8947",
                        packet_index=record.index,
                        byte_offset=offset,
                        offending_sample=llc_snap.hex(),
                        remediation_hint=(
                            "Expected ETSI ITS EtherType 0x8947 with SNAP header "
                            "'AA AA 03 00 00 00 89 47'."
                        ),
                    )
                )
                return violations

            self._cover(state, "llc_snap")
            offset += 8

        elif dlt == DLT_EN10MB:
            parsed = ethernet_payload(data)
            if parsed is None:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message="Packet too short for Ethernet header (< 14 bytes)",
                        packet_index=record.index,
                        byte_offset=0,
                    )
                )
                return violations

            ethertype, payload_offset = parsed
            if ethertype == 0x8947:
                self._cover(state, "ethernet")
                offset = payload_offset
            elif ethertype <= 1500:
                # 802.3 length + LLC/SNAP
                llc_end = payload_offset + len(LLC_SNAP_GEONET)
                if data[payload_offset:llc_end] == LLC_SNAP_GEONET:
                    self._cover(state, "ethernet")
                    self._cover(state, "llc_snap")
                    offset = llc_end
                else:
                    violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message="Invalid 802.3 LLC/SNAP EtherType: expected 0x8947",
                            packet_index=record.index,
                            byte_offset=payload_offset,
                        )
                    )
                    return violations
            else:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=f"Non-V2X Ethernet EtherType: 0x{ethertype:04x}",
                        packet_index=record.index,
                        byte_offset=12,
                        remediation_hint="EtherType must be 0x8947 for C-ITS / GeoNetworking frames.",
                    )
                )
                return violations

        # 4. GeoNetworking + BTP. The link layer has been unwrapped at this point;
        #    the BTP destination port sits after the GeoNetworking Basic, Common
        #    and extended headers (EN 302 636-4-1 / -5-1), not immediately after
        #    LLC/SNAP. A secured frame hides it inside the 1609.2 envelope, so no
        #    port is reported rather than a fabricated one.
        frame = locate_geonetworking_frame(data, dlt)
        if frame is not None:
            self._cover(state, "geonet")
            if frame.was_secured:
                self._cover(state, "secured")
                state["secured_frames"] = state.get("secured_frames", 0) + 1
            elif frame.btp_port is not None:
                self._cover(state, "btp")
                ports = state.setdefault("btp_ports", {})
                ports[frame.btp_port] = ports.get(frame.btp_port, 0) + 1

        return violations
