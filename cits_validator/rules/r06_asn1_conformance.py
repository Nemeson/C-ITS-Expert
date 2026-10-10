from __future__ import annotations

from typing import Any

from cits_validator.asn1.decoder import (
    MESSAGE_TYPES,
    DecoderUnavailableError,
    PduDecodeError,
    decode_pdu,
    is_available,
    peek_message_id,
    release_for_message_id,
)
from cits_validator.asn1.provenance import STANDARDS_DIR
from cits_validator.core.geonet import BTP_PORTS, locate_geonetworking_frame
from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule
from cits_validator.core.stream import PacketRecord

# BTP destination port -> ITS PDU type, for the packet path.
_PORT_TO_TYPE = {port: name for port, name in BTP_PORTS.items() if name in MESSAGE_TYPES}
# The two header key spellings seen across the release baselines: Release 1 uses
# `messageID`/`stationID`, Release 2 renamed them to `messageId`/`stationId`.
_HEADER_ID_KEYS = ("messageID", "messageId")
_HEADER_STATION_KEYS = ("stationID", "stationId")


class Asn1ConformanceRule(BaseRule):
    """Decodes the ASN.1 UPER payload of a C-ITS frame and reports real encoding faults.

    This rule replaces textual heuristics with an actual decoder: a PDU that does
    not decode is a finding, and one that decodes is not guessed at. Two limits
    are stated rather than worked around:

    * IEEE 1609.2 secured frames carry their payload inside the security
      envelope. They are counted as `secured_undecodable` and not decoded — a
      plaintext decode of ciphertext would be a fabrication.
    * Release 1 and Release 2 have different decoders (different CDD module), so
      the release must be chosen explicitly for direct PDU decoding.
    """

    rule_id = "R06"
    name = "ASN.1 / UPER Conformance"
    description = (
        "Decodes CAM, DENM, MAPEM, SPATEM, SREM and SSEM payloads with the vendored "
        "ETSI/ISO ASN.1 modules and reports encoding faults (truncation, range "
        "violation, unknown type) instead of pattern-matching source code."
    )

    def __init__(self, release: str = "r1", max_decodes_per_type: int = 200) -> None:
        if release not in ("r1", "r2"):
            raise ValueError(f"release must be 'r1' or 'r2', got {release!r}")
        self.release = release
        # Decoding every frame of a 100k-packet capture is not the point of a
        # conformance pass; a representative sample per message type is, with the
        # frame count kept so the sampling is visible rather than silent.
        self.max_decodes_per_type = max_decodes_per_type

    # -- direct PDU decoding ---------------------------------------------------
    def audit_pdu(
        self, payload: bytes, message_type: str, release: str | None = None
    ) -> list[Violation]:
        """Decodes one PDU and returns findings (empty on a clean decode)."""
        if not is_available():
            return [
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=(
                        "ASN.1 decoding unavailable: asn1tools is not installed "
                        "(install the extra: pip install -e '.[asn1]')"
                    ),
                    remediation_hint=(
                        "The PDU was not decoded. Without the dependency the conformance "
                        "check cannot run; it is reported rather than silently skipped."
                    ),
                )
            ]

        decoded_release = release or self.release
        try:
            result = decode_pdu(payload, message_type, decoded_release)
        except PduDecodeError as exc:
            return [
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.ERROR,
                    message=f"{message_type} PDU does not decode: {exc}",
                    offending_sample=payload[:16].hex(),
                    remediation_hint=(
                        "The bytes could not be decoded against the vendored standard "
                        "modules. Check the release baseline, the framing offsets, and "
                        "whether the frame is IEEE 1609.2 secured."
                    ),
                )
            ]

        header = result.value.get("header", {}) if isinstance(result.value, dict) else {}
        station = next((header[k] for k in _HEADER_STATION_KEYS if k in header), None)
        message_id = next((header[k] for k in _HEADER_ID_KEYS if k in header), None)
        return [
            Violation(
                rule_id=self.rule_id,
                severity=Severity.INFO,
                message=(
                    f"{message_type} decoded ({decoded_release}, {result.byte_length} bytes): "
                    f"messageID={message_id}, stationID={station}"
                ),
                offending_sample=", ".join(result.standards) or None,
            )
        ]

    # -- packet path -----------------------------------------------------------
    def audit_packet(
        self, record: PacketRecord, dlt: int, state: dict[str, Any]
    ) -> list[Violation]:
        """Decodes the payload of a plaintext GeoNetworking frame.

        Secured frames are counted and skipped; a frame whose type has no
        decoder is skipped. Neither is reported as an error, because neither is
        a conformance fault — inventing one would be exactly the failure this
        repository forbids.
        """
        frame = locate_geonetworking_frame(record.data, dlt)
        if frame is None:
            return []

        if frame.was_secured:
            state["secured_undecodable"] = state.get("secured_undecodable", 0) + 1
            return []

        # Report a missing decoder once per scan, not once per packet.
        if not is_available():
            if not state.get("asn1_unavailable_reported"):
                state["asn1_unavailable_reported"] = True
                return self.audit_pdu(b"", "CAM")
            return []

        message_type = frame.btp_port if frame.btp_port is not None else None
        type_name = _PORT_TO_TYPE.get(message_type) if message_type is not None else None
        if type_name is None or frame.payload_offset is None:
            return []

        payload = record.data[frame.payload_offset :]
        if not payload:
            return []

        seen_key = f"seen_{type_name}"
        state[seen_key] = state.get(seen_key, 0) + 1
        if state[seen_key] > self.max_decodes_per_type:
            return []

        # A successful decode is progress, not a finding: emitting an INFO per
        # frame would bury the report. Only a real fault becomes a violation, and
        # only its first occurrence is listed.
        try:
            decode_pdu(payload, type_name, self.release)
        except DecoderUnavailableError as exc:
            # A broken decoder setup says nothing about the capture: report it
            # once per scan as a WARNING and do not count it as a decode failure.
            if state.get("decoder_unavailable_reported"):
                return []
            state["decoder_unavailable_reported"] = True
            return [
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=f"ASN.1 decoder unavailable, payloads were not checked: {exc}",
                    remediation_hint="Run scripts/vendor_asn1.py or reinstall the package.",
                )
            ]
        except PduDecodeError as exc:
            key = f"decode_failures_{type_name}"
            state[key] = state.get(key, 0) + 1
            if state[key] > 1:
                return []
            return [
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.ERROR,
                    message=f"{type_name} payload does not decode: {exc}",
                    packet_index=record.index,
                    offending_sample=payload[:16].hex(),
                    remediation_hint=(
                        "The ASN.1 payload could not be decoded against the vendored "
                        "standard modules for the configured release baseline."
                    ),
                )
            ]

        state[f"decoded_{type_name}"] = state.get(f"decoded_{type_name}", 0) + 1
        return []

    # -- helpers for tooling ---------------------------------------------------
    @staticmethod
    def peek_type(payload: bytes) -> str | None:
        """The message family implied by the ItsPduHeader messageID, if known."""
        message_id = peek_message_id(payload)
        return release_for_message_id(message_id) if message_id is not None else None

    @staticmethod
    def standards_dir() -> str:
        return str(STANDARDS_DIR)
