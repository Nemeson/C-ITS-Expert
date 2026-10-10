"""Minimal reader for the IEEE 1609.2 / ETSI TS 103 097 secured-message envelope.

A signed C-ITS message carries its payload in plaintext inside a COER-encoded
``Ieee1609Dot2Data``; the cryptography only protects integrity and origin. This
module locates that payload without any key and without third-party packages,
so the zero-dependency device profile can use it too. It does **not** verify
signatures or certificates, and it cannot read ``encryptedData`` (that needs a
key), which stays opaque.

COER layout handled (IEEE 1609.2 ``Ieee1609Dot2Data``)::

    Ieee1609Dot2Data  ::= SEQUENCE { protocolVersion Uint8(3), content CHOICE }
    content (tag)     :  0x80 unsecuredData | 0x81 signedData | 0x82 encryptedData
    SignedData        ::= SEQUENCE { hashId, tbsData, signer, signature }
    ToBeSignedData    ::= SEQUENCE { payload, headerInfo }   -- not extensible
    SignedDataPayload ::= extensible SEQUENCE { data OPTIONAL, extDataHash OPTIONAL }
                          preamble bit 0x80 extension, 0x40 data, 0x20 extDataHash
    Opaque            :  COER length determinant followed by the octets

Anything outside this shape (other protocol version, extension additions, a hash
only payload, nested signed data) yields ``None``: the frame stays "secured, not
readable" instead of being guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass

PROTOCOL_VERSION = 3
TAG_UNSECURED = 0x80
TAG_SIGNED = 0x81
TAG_ENCRYPTED = 0x82

_PREAMBLE_EXTENSION = 0x80
_PREAMBLE_DATA = 0x40
_MAX_LENGTH_OCTETS = 4


@dataclass(frozen=True)
class SecuredPayload:
    """Where the plaintext payload sits inside the envelope (offsets into it)."""

    kind: str  # "signed" | "unsecured" | "encrypted"
    payload_start: int | None = None
    payload_end: int | None = None


def _coer_length(data: bytes, pos: int) -> tuple[int, int] | None:
    """Reads a COER length determinant; returns (value, next position) or None."""
    if pos >= len(data):
        return None
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    octets = first & 0x7F
    if octets == 0 or octets > _MAX_LENGTH_OCTETS or pos + 1 + octets > len(data):
        return None
    return int.from_bytes(data[pos + 1 : pos + 1 + octets], "big"), pos + 1 + octets


def unwrap_secured(envelope: bytes) -> SecuredPayload | None:
    """Locates the payload inside an ``Ieee1609Dot2Data``; None if not readable."""
    if len(envelope) < 2 or envelope[0] != PROTOCOL_VERSION:
        return None

    tag = envelope[1]
    pos = 2
    if tag == TAG_ENCRYPTED:
        return SecuredPayload(kind="encrypted")

    if tag == TAG_SIGNED:
        kind = "signed"
        pos += 1  # hashId (enumerated, one octet)
        if pos >= len(envelope):
            return None
        preamble = envelope[pos]
        pos += 1
        if preamble & _PREAMBLE_EXTENSION or not preamble & _PREAMBLE_DATA:
            return None
        # The embedded data is itself an Ieee1609Dot2Data holding unsecuredData.
        if envelope[pos : pos + 2] != bytes([PROTOCOL_VERSION, TAG_UNSECURED]):
            return None
        pos += 2
    elif tag == TAG_UNSECURED:
        kind = "unsecured"
    else:
        return None

    parsed = _coer_length(envelope, pos)
    if parsed is None:
        return None
    length, start = parsed
    end = start + length
    if end > len(envelope):
        return None
    return SecuredPayload(kind=kind, payload_start=start, payload_end=end)
