from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator


@dataclass
class PcapHeaderInfo:
    magic: int
    is_nanosecond: bool
    byte_order: str  # "little" or "big"
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    dlt: int
    timestamp_scale: int


@dataclass
class PacketRecord:
    index: int
    timestamp: float
    caplen: int
    wirelen: int
    data: bytes


class PcapStreamingIterator:
    """Zero-allocation streaming iterator for PCAP capture files."""

    MAGIC_BYTES = {
        b"\xa1\xb2\xc3\xd4": (0xA1B2C3D4, False, "big", ">"),
        b"\xd4\xc3\xb2\xa1": (0xD4C3B2A1, False, "little", "<"),
        b"\xa1\xb2\x3c\x4d": (0xA1B23C4D, True, "big", ">"),
        b"\x4d\x3c\xb2\xa1": (0x4D3CB2A1, True, "little", "<"),
    }

    def __init__(self) -> None:
        self.header_info: PcapHeaderInfo | None = None
        self.truncated_eof: bool = False

    def read_header(self, stream: BinaryIO) -> PcapHeaderInfo:
        header_bytes = stream.read(24)
        if len(header_bytes) < 24:
            raise ValueError(f"File too small for PCAP header (read {len(header_bytes)} bytes)")

        magic_raw = header_bytes[:4]
        if magic_raw not in self.MAGIC_BYTES:
            magic_hex = magic_raw.hex()
            raise ValueError(f"Unsupported PCAP magic number: 0x{magic_hex}")

        magic, is_nano, byte_order, fmt_char = self.MAGIC_BYTES[magic_raw]
        scale = 1_000_000_000 if is_nano else 1_000_000

        _, v_maj, v_min, thiszone, sigfigs, snaplen, dlt = struct.unpack(
            f"{fmt_char}IHHiIII", header_bytes
        )

        self.header_info = PcapHeaderInfo(
            magic=magic,
            is_nanosecond=is_nano,
            byte_order=byte_order,
            version_major=v_maj,
            version_minor=v_min,
            thiszone=thiszone,
            sigfigs=sigfigs,
            snaplen=snaplen,
            dlt=dlt,
            timestamp_scale=scale,
        )
        return self.header_info

    def iter_records(self, stream_or_path: BinaryIO | str | Path) -> Iterator[PacketRecord]:
        self.truncated_eof = False

        if isinstance(stream_or_path, (str, Path)):
            with open(stream_or_path, "rb") as f:
                yield from self._iter_stream(f)
        else:
            yield from self._iter_stream(stream_or_path)

    def _iter_stream(self, stream: BinaryIO) -> Iterator[PacketRecord]:
        if self.header_info is None:
            self.read_header(stream)

        assert self.header_info is not None
        fmt_char = ">" if self.header_info.byte_order == "big" else "<"
        scale = float(self.header_info.timestamp_scale)

        packet_index = 0
        while True:
            rec_hdr = stream.read(16)
            if not rec_hdr:
                break  # Clean EOF

            if len(rec_hdr) < 16:
                self.truncated_eof = True
                break

            ts_sec, ts_sub, caplen, origlen = struct.unpack(f"{fmt_char}IIII", rec_hdr)
            data = stream.read(caplen)

            if len(data) < caplen:
                self.truncated_eof = True
                break

            packet_index += 1
            timestamp = float(ts_sec) + (float(ts_sub) / scale)

            yield PacketRecord(
                index=packet_index,
                timestamp=timestamp,
                caplen=caplen,
                wirelen=origlen,
                data=data,
            )
