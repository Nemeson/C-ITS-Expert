"""Seeded malformed-input sweep: parsers may reject input, but only in defined ways.

Deterministic (fixed seed, no extra dependency). Each parser gets random bytes,
truncations and single-bit flips of a valid sample; anything other than its
documented exceptions is a bug.
"""

from __future__ import annotations

import io
import random
import struct

import pytest

from cits_validator.asn1 import decode_pdu, is_available
from cits_validator.asn1.decoder import PduDecodeError
from cits_validator.core.geonet import (
    DLT_EN10MB,
    DLT_IEEE802_11,
    DLT_IEEE802_11_RADIO,
    locate_geonetworking_frame,
)
from cits_validator.core.stream import PacketRecord, PcapStreamingIterator
from cits_validator.lisa.parser import parse_lisa_xml
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r05_hardware import HardwareStreamRule

ROUNDS = 400
SEED = 20261010


def _mutations(sample: bytes, rng: random.Random) -> list[bytes]:
    out = [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 96))) for _ in range(ROUNDS // 2)]
    out += [sample[: rng.randrange(0, len(sample) + 1)] for _ in range(ROUNDS // 4)]
    for _ in range(ROUNDS // 4):
        mutated = bytearray(sample)
        mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
        out.append(bytes(mutated))
    return out


CLASSIC = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127) + struct.pack(
    "<IIII", 1, 0, 8, 8
) + b"\xaa" * 8
SHB = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
IDB = struct.pack("<IIHHII", 1, 20, 127, 0, 0, 20)
EPB_BODY = struct.pack("<IIIII", 0, 0, 0, 8, 8) + b"\xaa" * 8
EPB = struct.pack("<II", 6, len(EPB_BODY) + 12) + EPB_BODY + struct.pack("<I", len(EPB_BODY) + 12)
PCAPNG = SHB + IDB + EPB


@pytest.mark.parametrize("sample", [CLASSIC, PCAPNG], ids=["classic", "pcapng"])
def test_capture_reader_rejects_or_reads_but_never_crashes(sample):
    rng = random.Random(SEED)
    for data in _mutations(sample, rng):
        reader = PcapStreamingIterator()
        stream = io.BytesIO(data)
        try:
            reader.read_header(stream)
            list(reader.iter_records(stream))
        except ValueError:
            pass


@pytest.mark.parametrize("dlt", [DLT_EN10MB, DLT_IEEE802_11, DLT_IEEE802_11_RADIO])
def test_link_layer_locator_and_rule_never_raise(dlt):
    rng = random.Random(SEED + dlt)
    rule = LinkLayerRule()
    sample = b"\x08\x00" + b"\x00" * 22 + b"\xaa\xaa\x03\x00\x00\x00\x89\x47" + b"\x11\x00\x1a\x03" + b"\x00" * 60
    for data in _mutations(sample, rng):
        locate_geonetworking_frame(data, dlt)
        record = PacketRecord(index=1, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)
        rule.audit_packet(record, dlt=dlt, state={})


def test_hardware_stream_rule_never_raises_and_keeps_tail_bounded():
    rng = random.Random(SEED)
    rule = HardwareStreamRule()
    state: dict = {}
    sample = b"ITS5" + struct.pack("<IIH", 1, 0, 4) + b"abcd"
    for data in _mutations(sample, rng):
        rule.audit_stream_chunk(data, state)
        assert len(state["_r05_tail"]) <= 15 + 65535


@pytest.mark.skipif(not is_available(), reason="asn1tools not installed")
@pytest.mark.parametrize("message_type", ["CAM", "DENM", "MAPEM", "SPATEM"])
def test_asn1_decoder_raises_only_pdu_decode_error(message_type):
    rng = random.Random(SEED)
    for data in _mutations(b"\x02\x02\x00\x00\x01\x02\x03\x04" * 3, rng):
        try:
            decode_pdu(data, message_type, "r1")
        except PduDecodeError:
            pass


LISA_SAMPLE = b'<Root><Knotenpunkt name="K"><Signalgruppe ObjNr="1" Bezeichnung="K1"/></Knotenpunkt></Root>'


def test_lisa_text_parser_raises_only_value_error():
    rng = random.Random(SEED)
    for data in _mutations(LISA_SAMPLE, rng):
        try:
            parse_lisa_xml(data.decode("utf-8", errors="replace"))
        except ValueError:
            pass
