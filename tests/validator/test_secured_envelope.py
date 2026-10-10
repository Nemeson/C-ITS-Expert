"""IEEE 1609.2 / ETSI TS 103 097 secured frames: unwrap the envelope, never fake a payload.

A *signed* message carries its payload in plaintext inside the envelope; only the
signature is cryptographic. So the GeoNetworking headers and the ITS PDU can be
read without any key. *Encrypted* messages cannot, and must stay opaque.

Envelope layout (COER), per the vendored-by-reference IEEE 1609.2 module:

    Ieee1609Dot2Data  ::= SEQUENCE { protocolVersion Uint8(3), content CHOICE }
    content tags      :  0x80 unsecuredData | 0x81 signedData | 0x82 encryptedData
    SignedData        ::= SEQUENCE { hashId (1 byte), tbsData, signer, signature }
    ToBeSignedData    ::= SEQUENCE { payload SignedDataPayload, headerInfo }  (not extensible)
    SignedDataPayload ::= extensible SEQUENCE { data OPTIONAL, extDataHash OPTIONAL }
                          preamble 0x40 = data present, 0x20 = extDataHash present
    Opaque            :  COER length determinant + bytes
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cits_validator.asn1 import is_available
from cits_validator.core.geonet import DLT_EN10MB, locate_geonetworking_frame
from cits_validator.core.secured import unwrap_secured
from cits_validator.core.stream import PacketRecord
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

PAYLOAD = bytes(range(20))
SIGNATURE_TAIL = b"\xaa" * 60  # headerInfo + signer + signature: opaque to us


def coer_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def inner_gn(port: int, payload: bytes) -> bytes:
    """Common Header + TSB extended header + BTP-B + payload (what the envelope carries)."""
    btp = port.to_bytes(2, "big") + b"\x00\x00"
    common = bytes([0x20, 0x50, 0x00, 0x00]) + (len(btp) + len(payload)).to_bytes(2, "big") + bytes([7, 0])
    return common + b"\x00" * 28 + btp + payload


def signed_envelope(inner: bytes) -> bytes:
    data = bytes([3, 0x80]) + coer_length(len(inner)) + inner
    return bytes([3, 0x81, 0x00, 0x40]) + data + SIGNATURE_TAIL


def frame(envelope: bytes) -> bytes:
    basic = bytes([0x12, 0x00, 0x1A, 0x03])  # version 1, next header 2 = secured
    return b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + basic + envelope


def test_signed_message_exposes_btp_port_and_payload():
    data = frame(signed_envelope(inner_gn(2001, PAYLOAD)))

    located = locate_geonetworking_frame(data, DLT_EN10MB)

    assert located is not None and located.was_secured
    assert located.secured_kind == "signed"
    assert located.btp_port == 2001
    assert data[located.payload_offset : located.payload_end] == PAYLOAD


def test_payload_longer_than_127_bytes_uses_the_multibyte_length_determinant():
    big = bytes(range(256)) * 2
    data = frame(signed_envelope(inner_gn(2002, big)))

    located = locate_geonetworking_frame(data, DLT_EN10MB)

    assert located is not None
    assert data[located.payload_offset : located.payload_end] == big


def test_unsecured_data_content_is_unwrapped():
    inner = inner_gn(2003, PAYLOAD)
    data = frame(bytes([3, 0x80]) + coer_length(len(inner)) + inner)

    located = locate_geonetworking_frame(data, DLT_EN10MB)

    assert located is not None and located.secured_kind == "unsecured"
    assert located.btp_port == 2003


def test_encrypted_message_stays_opaque():
    data = frame(bytes([3, 0x82]) + b"\x01\x02\x03" * 30)

    located = locate_geonetworking_frame(data, DLT_EN10MB)

    assert located is not None and located.was_secured
    assert located.secured_kind == "encrypted"
    assert located.btp_port is None and located.payload_offset is None


def test_hash_only_payload_has_nothing_to_unwrap():
    envelope = bytes([3, 0x81, 0x00, 0x20]) + b"\x00" * 40  # extDataHash, no data

    assert unwrap_secured(envelope) is None


@pytest.mark.parametrize(
    "envelope",
    [
        b"",
        bytes([3]),
        bytes([4, 0x81, 0x00, 0x40, 3, 0x80, 5]),  # wrong protocolVersion
        bytes([3, 0x81, 0x00, 0x40, 3, 0x80, 0x82, 0xFF, 0xFF]),  # length beyond data
        bytes([3, 0x81, 0x00, 0xC0, 3, 0x80, 1, 0]),  # extension bit set: unsupported
        bytes([3, 0x81, 0x00, 0x40, 3, 0x81, 0]),  # nested signed data: unsupported
    ],
    ids=["empty", "short", "version", "length", "extension", "nested"],
)
def test_malformed_envelope_never_raises_and_yields_nothing(envelope):
    assert unwrap_secured(envelope) is None
    located = locate_geonetworking_frame(frame(envelope), DLT_EN10MB)
    assert located is None or located.btp_port is None


def _record(data: bytes) -> PacketRecord:
    return PacketRecord(index=1, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


def test_r01_still_counts_secured_frames_and_now_sees_their_port():
    state: dict = {}

    LinkLayerRule().audit_packet(_record(frame(signed_envelope(inner_gn(2001, PAYLOAD)))), DLT_EN10MB, state)

    assert state["secured_frames"] == 1
    assert state["btp_ports"] == {2001: 1}


@pytest.mark.skipif(not is_available(), reason="asn1tools not installed")
def test_r06_decodes_the_payload_of_a_signed_message():
    spatem = bytes.fromhex(
        json.loads(
            (Path(__file__).parents[1] / "asn1" / "fixtures" / "spatem.json").read_text(encoding="utf-8")
        )["minimal"]["hex"]
    )
    state: dict = {}

    violations = Asn1ConformanceRule(release="r1").audit_packet(
        _record(frame(signed_envelope(inner_gn(2004, spatem)))), DLT_EN10MB, state
    )

    assert violations == []
    assert state["decoded_SPATEM"] == 1
    assert state["secured_decoded"] == 1


@pytest.mark.skipif(not is_available(), reason="asn1tools not installed")
def test_r06_counts_encrypted_messages_as_undecodable():
    state: dict = {}

    Asn1ConformanceRule(release="r1").audit_packet(
        _record(frame(bytes([3, 0x82]) + b"\x01" * 50)), DLT_EN10MB, state
    )

    assert state["secured_undecodable"] == 1
