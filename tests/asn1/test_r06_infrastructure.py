"""A broken decoder setup is not a capture fault: R06 must say so once, as a WARNING."""

from __future__ import annotations

import pytest

from cits_validator.asn1 import decoder, is_available
from cits_validator.asn1.decoder import DecoderUnavailableError, PduDecodeError
from cits_validator.core.geonet import DLT_EN10MB
from cits_validator.core.stream import PacketRecord
from cits_validator.rules import r06_asn1_conformance
from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

pytestmark = pytest.mark.skipif(not is_available(), reason="asn1tools not installed")


def _frame(payload: bytes, btp_port: int = 2004) -> bytes:
    basic = bytes([0x11, 0x00, 0x1A, 0x03])
    common = (
        bytes([0x10, 0x50, 0x00, 0x00])
        + (len(payload) + 4).to_bytes(2, "little")
        + bytes([0x07, 0x00])
    )
    btp = btp_port.to_bytes(2, "big") + b"\x00\x00"
    return b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + basic + common + b"\x00" * 28 + btp + payload


def _record(index: int) -> PacketRecord:
    data = _frame(b"\x01\x04" + b"\x00" * 18)  # messageID 4 = SPATEM, matching port 2004
    return PacketRecord(index=index, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


def test_missing_vendored_modules_raise_decoder_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(decoder, "STANDARDS_DIR", tmp_path)
    decoder._compile.cache_clear()
    try:
        with pytest.raises(DecoderUnavailableError):
            decoder.decode_pdu(b"\x01\x02", "SPATEM", "r1")
    finally:
        decoder._compile.cache_clear()


def test_decoder_unavailable_is_still_a_pdu_decode_error():
    assert issubclass(DecoderUnavailableError, PduDecodeError)


def test_r06_reports_unavailable_decoder_once_as_warning_not_as_capture_error(monkeypatch):
    def broken(*_args, **_kwargs):
        raise DecoderUnavailableError("Vendored ASN.1 modules missing: DSRC.asn")

    monkeypatch.setattr(r06_asn1_conformance, "decode_pdu", broken)
    rule = Asn1ConformanceRule(release="r1")
    state: dict = {}

    first = rule.audit_packet(_record(1), dlt=DLT_EN10MB, state=state)
    second = rule.audit_packet(_record(2), dlt=DLT_EN10MB, state=state)

    assert [v.severity.value for v in first] == ["WARNING"]
    assert "unavailable" in first[0].message.lower()
    assert first[0].packet_index is None
    assert second == []
    assert not any(key.startswith("decode_failures_") for key in state)
