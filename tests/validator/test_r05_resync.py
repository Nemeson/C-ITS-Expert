"""R05 must survive chunk boundaries and must not drop stream bytes silently."""

from __future__ import annotations

import struct

from cits_validator.rules.r05_hardware import HardwareStreamRule


def _its5(sec: int, usec: int, payload: bytes) -> bytes:
    return b"ITS5" + struct.pack("<IIH", sec, usec, len(payload)) + payload


def test_frame_split_across_chunks_is_reassembled():
    frame = _its5(5, 0, b"\x01\x02\x03\x04")
    rule = HardwareStreamRule()
    state: dict = {}

    _, first = rule.audit_stream_chunk(frame[:9], state)
    violations, second = rule.audit_stream_chunk(frame[9:], state)

    assert first == []
    assert [f["payload"] for f in second] == [b"\x01\x02\x03\x04"]
    assert violations == []


def test_many_frames_split_at_every_byte_boundary_are_all_recovered():
    stream = b"".join(_its5(i, 0, bytes([i]) * 3) for i in range(1, 5))
    rule = HardwareStreamRule()
    state: dict = {}
    payloads: list[bytes] = []

    for i in range(len(stream)):
        _, frames = rule.audit_stream_chunk(stream[i : i + 1], state)
        payloads += [f["payload"] for f in frames]

    assert payloads == [bytes([i]) * 3 for i in range(1, 5)]


def test_discarded_garbage_bytes_are_reported():
    chunk = b"\x00\x01\x02\x03\x04" + _its5(1, 0, b"\x01")

    violations, frames = HardwareStreamRule().audit_stream_chunk(chunk, {})

    assert len(frames) == 1
    warnings = [v for v in violations if "discarded 5 byte" in v.message]
    assert len(warnings) == 1
    assert warnings[0].severity.value == "WARNING"


def test_false_magic_with_invalid_usec_is_not_accepted_as_a_frame():
    fake = b"ITS5" + struct.pack("<IIH", 1, 2_000_000, 1) + b"\x00"
    chunk = fake + _its5(2, 0, b"\x07")

    violations, frames = HardwareStreamRule().audit_stream_chunk(chunk, {})

    assert [f["payload"] for f in frames] == [b"\x07"]
    assert any("discarded" in v.message for v in violations)
