"""PCAPNG semantics beyond the happy path: resolution, lengths, sections, interfaces."""

from __future__ import annotations

import io
import struct

import pytest

from cits_validator.core.stream import PcapStreamingIterator

DATA = bytes(range(8))


def _block(fmt: str, block_type: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack(f"{fmt}II", block_type, total) + body + struct.pack(f"{fmt}I", total)


def _shb(fmt: str) -> bytes:
    return _block(fmt, 0x0A0D0D0A, struct.pack(f"{fmt}IHHq", 0x1A2B3C4D, 1, 0, -1))


def _idb(fmt: str, linktype: int = 127, tsresol: int | None = None) -> bytes:
    options = b""
    if tsresol is not None:
        options = struct.pack(f"{fmt}HH", 9, 1) + bytes([tsresol, 0, 0, 0]) + b"\x00" * 4
    return _block(fmt, 1, struct.pack(f"{fmt}HHI", linktype, 0, 0) + options)


def _epb(fmt: str, iface: int = 0, ticks: int = 0, caplen: int | None = None, origlen: int | None = None) -> bytes:
    caplen = len(DATA) if caplen is None else caplen
    origlen = len(DATA) if origlen is None else origlen
    body = struct.pack(f"{fmt}IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF, caplen, origlen) + DATA
    return _block(fmt, 6, body)


def _read(blob: bytes):
    reader = PcapStreamingIterator()
    stream = io.BytesIO(blob)
    reader.read_header(stream)
    return reader, list(reader.iter_records(stream))


def test_base2_timestamp_resolution_is_exact():
    # 0x8A = base 2, exponent 10 -> 1024 ticks per second.
    blob = _shb("<") + _idb("<", tsresol=0x8A) + _epb("<", ticks=1024)

    _, records = _read(blob)

    assert records[0].timestamp == pytest.approx(1.0, abs=1e-12)


def test_original_wire_length_is_preserved():
    _, records = _read(_shb("<") + _idb("<") + _epb("<", origlen=1500))

    assert records[0].caplen == len(DATA)
    assert records[0].wirelen == 1500


def test_epb_claiming_more_bytes_than_present_is_truncation_not_a_short_record():
    reader, records = _read(_shb("<") + _idb("<") + _epb("<", caplen=4096))

    assert records == []
    assert reader.truncated_eof is True


def test_second_section_may_use_the_other_byte_order():
    blob = _shb("<") + _idb("<") + _epb("<") + _shb(">") + _idb(">") + _epb(">")

    reader, records = _read(blob)

    assert [r.data for r in records] == [DATA, DATA]
    assert reader.truncated_eof is False


def test_file_dlt_is_the_first_interface_and_all_dlts_are_listed():
    blob = _shb("<") + _idb("<", linktype=127) + _idb("<", linktype=1) + _epb("<", iface=1) + _epb("<", iface=0)

    reader, records = _read(blob)

    assert reader.header_info.dlt == 127
    assert reader.dlts == [1, 127]
    assert [r.dlt for r in records] == [1, 127]


def test_record_for_an_undeclared_interface_is_counted():
    reader, records = _read(_shb("<") + _idb("<") + _epb("<", iface=7))

    assert len(records) == 1
    assert reader.unknown_interface_records == 1
