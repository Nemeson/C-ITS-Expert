import struct

from cits_validator.core.models import Severity
from cits_validator.rules.r05_hardware import HardwareStreamRule


def test_esp32_valid_its6_framing():
    # ITS6 framing: magic(4B="ITS6"), sec(4B), usec(4B), len(2B), rssi(1B) -> 15B
    payload = b"\x01\x02\x03\x04\x05"
    frame = b"ITS6" + struct.pack("<IIHb", 120, 500000, len(payload), -65) + payload

    rule = HardwareStreamRule()
    violations, parsed_frames = rule.audit_stream_chunk(frame, state={})

    assert len(violations) == 0
    assert len(parsed_frames) == 1
    assert parsed_frames[0]["rssi"] == -65


def test_esp32_rssi_sentinel_resolution():
    # RSSI = -128 must be resolved to None
    payload = b"\xaa\xbb"
    frame = b"ITS6" + struct.pack("<IIHb", 120, 0, len(payload), -128) + payload

    rule = HardwareStreamRule()
    violations, parsed_frames = rule.audit_stream_chunk(frame, state={})

    assert len(violations) == 0
    assert parsed_frames[0]["rssi"] is None


def test_esp32_discontinuity_backward_jump():
    rule = HardwareStreamRule()
    state = {}

    # Frame 1: sec=100
    f1 = b"ITS5" + struct.pack("<IIH", 100, 0, 4) + b"\x01\x02\x03\x04"
    rule.audit_stream_chunk(f1, state)

    # Frame 2: sec=50 (reboot / backward jump of -50s)
    f2 = b"ITS5" + struct.pack("<IIH", 50, 0, 4) + b"\x01\x02\x03\x04"
    violations, _ = rule.audit_stream_chunk(f2, state)

    assert any(v.rule_id == "R05" and "backward" in v.message.lower() for v in violations)
    assert any(v.severity == Severity.WARNING for v in violations)
