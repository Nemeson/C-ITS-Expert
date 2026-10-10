"""PCAPNG files may be big-endian; the SHB length must follow the BOM, not assume LE."""

from __future__ import annotations

import io
import struct

import pytest

from cits_validator.core.stream import PcapStreamingIterator

PAYLOAD = bytes(range(16))


def _block(fmt: str, block_type: int, body: bytes) -> bytes:
    padded = body + b"\x00" * (-len(body) % 4)
    total = len(padded) + 12
    return struct.pack(f"{fmt}II", block_type, total) + padded + struct.pack(f"{fmt}I", total)


def _pcapng(byte_order: str) -> bytes:
    fmt = "<" if byte_order == "little" else ">"
    shb = _block(fmt, 0x0A0D0D0A, struct.pack(f"{fmt}IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _block(fmt, 0x00000001, struct.pack(f"{fmt}HHI", 127, 0, 0))
    epb_body = struct.pack(f"{fmt}IIIII", 0, 0, 1_000_000, len(PAYLOAD), len(PAYLOAD)) + PAYLOAD
    return shb + idb + _block(fmt, 0x00000006, epb_body)


@pytest.mark.parametrize("byte_order", ["little", "big"])
def test_pcapng_packet_is_read_in_either_byte_order(byte_order):
    reader = PcapStreamingIterator()
    stream = io.BytesIO(_pcapng(byte_order))

    info = reader.read_header(stream)
    records = list(reader.iter_records(stream))

    assert info.byte_order == byte_order
    assert [r.data for r in records] == [PAYLOAD]
    assert records[0].dlt == 127
    assert reader.truncated_eof is False
