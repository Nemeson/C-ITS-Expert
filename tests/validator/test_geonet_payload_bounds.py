"""The GN Common Header payload length (PL, big-endian) bounds the BTP payload."""

from __future__ import annotations

from cits_validator.core.geonet import DLT_EN10MB, locate_geonetworking_frame

PAYLOAD = bytes(range(10))


def _frame(pl: int | None, trailer: bytes = b"", version: int = 1, payload: bytes = PAYLOAD) -> bytes:
    btp = (2001).to_bytes(2, "big") + b"\x00\x00"
    if pl is None:
        pl = len(btp) + len(payload)
    basic = bytes([(version << 4) | 1, 0x00, 0x1A, 0x03])
    common = bytes([0x10, 0x50, 0x00, 0x00]) + pl.to_bytes(2, "big") + bytes([0x07, 0x00])
    return b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + basic + common + b"\x00" * 28 + btp + payload + trailer


def _payload(frame_bytes: bytes) -> bytes:
    frame = locate_geonetworking_frame(frame_bytes, DLT_EN10MB)
    assert frame is not None and frame.payload_offset is not None
    return frame_bytes[frame.payload_offset : frame.payload_end]


def test_trailing_bytes_after_the_declared_payload_are_excluded():
    assert _payload(_frame(pl=None, trailer=b"\xde\xad\xbe\xef")) == PAYLOAD


def test_implausible_payload_length_falls_back_to_frame_end():
    assert _payload(_frame(pl=60000)) == PAYLOAD
    assert _payload(_frame(pl=1)) == PAYLOAD


def test_unsupported_geonetworking_version_is_not_parsed():
    assert locate_geonetworking_frame(_frame(pl=None, version=2), DLT_EN10MB) is None
