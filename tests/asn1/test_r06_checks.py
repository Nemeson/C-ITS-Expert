"""R06 checks beyond 'does it decode': trailing bytes, port/messageID agreement, sampling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cits_validator.asn1 import decode_pdu, is_available
from cits_validator.core.geonet import DLT_EN10MB
from cits_validator.core.stream import PacketRecord
from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

pytestmark = pytest.mark.skipif(not is_available(), reason="asn1tools not installed")

SPATEM = bytes.fromhex(
    json.loads((Path(__file__).parent / "fixtures" / "spatem.json").read_text(encoding="utf-8"))[
        "minimal"
    ]["hex"]
)


def _frame(payload: bytes, port: int) -> bytes:
    btp = port.to_bytes(2, "big") + b"\x00\x00"
    basic = bytes([0x11, 0x00, 0x1A, 0x03])
    common = bytes([0x10, 0x50, 0x00, 0x00]) + (len(btp) + len(payload)).to_bytes(2, "big") + bytes([7, 0])
    return b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + basic + common + b"\x00" * 28 + btp + payload


def _record(payload: bytes, port: int, index: int = 1) -> PacketRecord:
    data = _frame(payload, port)
    return PacketRecord(index=index, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


def test_decode_reports_trailing_bytes():
    assert decode_pdu(SPATEM, "SPATEM", "r1").trailing_bytes == 0
    assert decode_pdu(SPATEM + bytes(2), "SPATEM", "r1").trailing_bytes == 2


def test_trailing_bytes_become_a_warning_once():
    rule = Asn1ConformanceRule(release="r1")
    state: dict = {}

    first = rule.audit_packet(_record(SPATEM + bytes(2), 2004), DLT_EN10MB, state)
    second = rule.audit_packet(_record(SPATEM + bytes(2), 2004, 2), DLT_EN10MB, state)

    assert [v.severity.value for v in first] == ["WARNING"]
    assert "trailing" in first[0].message.lower()
    assert second == []


def test_message_id_that_contradicts_the_btp_port_is_reported_as_such():
    rule = Asn1ConformanceRule(release="r1")

    violations = rule.audit_packet(_record(SPATEM, 2001), DLT_EN10MB, {})  # SPATEM on the CAM port

    assert len(violations) == 1
    assert violations[0].severity.value == "ERROR"
    assert "messageID" in violations[0].message and "2001" in violations[0].message


def test_sampling_cutoff_is_visible_once_per_type():
    rule = Asn1ConformanceRule(release="r1", max_decodes_per_type=1)
    state: dict = {}

    results = [rule.audit_packet(_record(SPATEM, 2004, i), DLT_EN10MB, state) for i in (1, 2, 3)]

    assert results[0] == []
    assert [v.severity.value for v in results[1]] == ["INFO"]
    assert "sampl" in results[1][0].message.lower()
    assert results[2] == []
