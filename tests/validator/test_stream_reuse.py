"""iter_records(path) must yield the same records every time it is called."""

from __future__ import annotations

import struct

import pytest

from cits_validator.core.stream import PcapStreamingIterator

PAYLOAD = b"\xaa" * 12


def _classic(path):
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    record = struct.pack("<IIII", 1, 0, len(PAYLOAD), len(PAYLOAD)) + PAYLOAD
    path.write_bytes(header + record)
    return path


def _pcapng(path):
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack("<IIHHII", 1, 20, 127, 0, 0, 20)
    body = struct.pack("<IIIII", 0, 0, 0, len(PAYLOAD), len(PAYLOAD)) + PAYLOAD
    epb = struct.pack("<II", 6, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    path.write_bytes(shb + idb + epb)
    return path


@pytest.mark.parametrize("build", [_classic, _pcapng])
def test_iterating_a_path_twice_yields_the_same_records(tmp_path, build):
    path = build(tmp_path / "capture.bin")
    reader = PcapStreamingIterator()

    first = [r.data for r in reader.iter_records(path)]
    second = [r.data for r in reader.iter_records(path)]

    assert first == [PAYLOAD]
    assert second == first
