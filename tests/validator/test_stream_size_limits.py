"""Untrusted length fields must never drive an unbounded read (OOM on edge devices)."""

from __future__ import annotations

import io
import struct

import pytest

from cits_validator.core.stream import PcapStreamingIterator

READ_CEILING = 1 << 20  # No single read may ask for more than 1 MiB.


class _BoundedReads(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        assert size is not None and (size < 0 or size <= READ_CEILING), f"unbounded read({size})"
        return super().read(size)


def _classic_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)


def test_classic_record_with_huge_caplen_is_rejected_without_big_read():
    record = struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00" * 32
    stream = _BoundedReads(_classic_header() + record)

    reader = PcapStreamingIterator()
    reader.read_header(stream)
    records = list(reader.iter_records(stream))

    assert records == []
    assert reader.truncated_eof is True


def test_pcapng_block_with_huge_length_is_rejected_without_big_read():
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    bogus = struct.pack("<II", 0x00000006, 0xFFFFFFFC) + b"\x00" * 32
    stream = _BoundedReads(shb + bogus)

    reader = PcapStreamingIterator()
    reader.read_header(stream)
    records = list(reader.iter_records(stream))

    assert records == []
    assert reader.truncated_eof is True


def test_pcapng_shb_with_huge_length_raises_without_big_read():
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 0xFFFFFFFC, 0x1A2B3C4D, 1, 0, -1)
    reader = PcapStreamingIterator()

    with pytest.raises(ValueError):
        reader.read_header(_BoundedReads(shb))


def test_pcapng_trailing_length_mismatch_is_flagged():
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack("<IIHHII", 1, 20, 127, 0, 0, 999)  # trailer 999 != 20
    stream = io.BytesIO(shb + idb)

    reader = PcapStreamingIterator()
    reader.read_header(stream)
    list(reader.iter_records(stream))

    assert reader.truncated_eof is True
