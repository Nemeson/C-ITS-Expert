#!/usr/bin/env python3
"""Generates a small, self-contained DLT 127 sample capture for the test suite.

Why this exists: the end-to-end test previously pointed at a fixture living in a
sibling project, so the suite was not portable. Rather than depend on a path
outside this repository, the capture is generated here from documented, valid
framing — and the generator is committed next to the file it produces, so the
bytes can be explained instead of merely trusted.

The frames are synthetic *framing* (Radiotap + 802.11 QoS + LLC/SNAP +
GeoNetworking + BTP), which is exactly what a link-layer audit checks. They are
**not** presented as field data: the ASN.1 payloads are not real PDUs and are
never decoded. Real-capture decoding is covered by the vectors under
``tests/asn1/fixtures/``, which come from actual captures.

Usage:
    python scripts/make_sample_capture.py [output.pcap]
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sample_dlt127.pcap"
)

RADIOTAP_LEN = 8
LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x47"
# A minimal, well-formed GeoNetworking TSB header (EN 302 636-4-1) followed by BTP.
BASIC_HEADER = bytes([0x11, 0x00, 0x1A, 0x03])  # version 1, nextHeader 1 (common)
COMMON_HEADER = bytes([0x10, 0x50, 0x00, 0x00]) + (40).to_bytes(2, "little") + bytes([0x07, 0x00])
EXTENDED_HEADER = b"\x00" * 28  # TSB single hop: reserved quad + LongPositionVector

# (BTP destination port, payload) — one frame per standard C-ITS message port.
FRAMES = [
    (2001, b"\x02\x02\x00\x00\x00\x00\x01"),
    (2002, b"\x02\x01\x00\x00\x00\x00\x02"),
    (2003, b"\x02\x05\x00\x00\x00\x00\x03"),
    (2004, b"\x02\x04\x00\x00\x00\x00\x04"),
    (2006, b"\x02\x06\x00\x00\x00\x00\x06"),
    (2007, b"\x02\x09\x00\x00\x00\x00\x07"),
    (2008, b"\x02\x0a\x00\x00\x00\x00\x08"),
]


def build_frame(btp_port: int, payload: bytes) -> bytes:
    radiotap = struct.pack("<BBHI", 0, 0, RADIOTAP_LEN, 0)
    # 802.11 QoS Data header, 26 bytes: fc(2) dur(2) addr1(6) addr2(6) addr3(6)
    # seq(2) qos(2). Leaving out the Sequence Control field yields a 24-byte
    # header, which shifts every following layer by two bytes.
    dot11 = (
        b"\x88\x00"  # Frame Control: type 2 (Data), subtype 8 (QoS Data)
        b"\x00\x00"  # Duration
        + b"\xff" * 6  # Address 1
        + b"\x11" * 6  # Address 2
        + b"\x22" * 6  # Address 3
        + b"\x00\x00"  # Sequence Control
        + b"\x00\x00"  # QoS Control
    )
    assert len(dot11) == 26
    btp = btp_port.to_bytes(2, "big") + b"\x00\x00"
    return (
        radiotap + dot11 + LLC_SNAP + BASIC_HEADER + COMMON_HEADER + EXTENDED_HEADER + btp + payload
    )


def build_capture() -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)  # DLT 127
    body = b""
    for index, (port, payload) in enumerate(FRAMES, start=1):
        frame = build_frame(port, payload)
        body += struct.pack("<IIII", 1000 + index, index * 1000, len(frame), len(frame)) + frame
    return header + body


def main(argv: list[str]) -> int:
    output = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(build_capture())
    print(f"[OK] {output} ({len(FRAMES)} frames, {output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
