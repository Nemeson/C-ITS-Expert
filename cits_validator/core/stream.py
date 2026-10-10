from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator

# Magic byte prefixes of a PCAPNG Section Header Block (SHB block type 0x0A0D0D0A).
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BT_SHB = 0x0A0D0D0A
PCAPNG_BT_IDB = 0x00000001
PCAPNG_BT_EPB = 0x00000006
PCAPNG_BT_SPB = 0x00000003
PCAPNG_BT_PB = 0x00000002
# Blocks whose body is a captured record; anything else is skipped generically.
PCAPNG_RECORD_BLOCKS = {PCAPNG_BT_EPB, PCAPNG_BT_SPB, PCAPNG_BT_PB}

# Length fields come from the (untrusted) file; cap them so a forged header cannot
# make a single read() allocate gigabytes.
MAX_RECORD_BYTES = 262_144  # classic-pcap caplen; also the usual maximum snaplen
MAX_BLOCK_BYTES = 1 << 20  # any PCAPNG block, including the Section Header Block


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
    is_pcapng: bool = False


@dataclass
class PacketRecord:
    index: int
    timestamp: float
    caplen: int
    wirelen: int
    data: bytes
    interface_id: int = 0
    # Link type of the record's own interface. None for classic PCAP, where the
    # single file header carries the DLT for every record.
    dlt: int | None = None


@dataclass
class _PcapngInterface:
    linktype: int
    snaplen: int = 0
    tsresol: int = 6  # 10^-6 seconds unless an if_tsresol option says otherwise


class PcapStreamingIterator:
    """Zero-allocation streaming iterator for classic PCAP and PCAPNG files.

    Classic PCAP is the four-magic little/big-endian micro/nanosecond format.
    PCAPNG is parsed block-by-block (SHB / IDB / EPB / SPB / PB); the timestamp
    resolution is read from each interface's ``if_tsresol`` option so records are
    never silently scaled wrong. A classic PCAP whose file begins with the SHB
    block type is recognised as PCAPNG instead of being rejected.
    """

    MAGIC_BYTES = {
        b"\xa1\xb2\xc3\xd4": (0xA1B2C3D4, False, "big", ">"),
        b"\xd4\xc3\xb2\xa1": (0xD4C3B2A1, False, "little", "<"),
        b"\xa1\xb2\x3c\x4d": (0xA1B23C4D, True, "big", ">"),
        b"\x4d\x3c\xb2\xa1": (0x4D3CB2A1, True, "little", "<"),
    }

    def __init__(self) -> None:
        self.header_info: PcapHeaderInfo | None = None
        self.truncated_eof: bool = False
        self.is_pcapng: bool = False
        self.interfaces: list[_PcapngInterface] = []
        self.unsupported_blocks: dict[int, int] = {}
        self._interface_count: int = 0

    # -- header ----------------------------------------------------------------
    def read_header(self, stream: BinaryIO) -> PcapHeaderInfo:
        prefix = stream.read(4)
        if len(prefix) < 4:
            raise ValueError(f"File too small for PCAP/PCAPNG header (read {len(prefix)} bytes)")

        if prefix == PCAPNG_MAGIC:
            self.is_pcapng = True
            return self._read_pcapng_header(stream, prefix)

        header_bytes = prefix + stream.read(20)
        if len(header_bytes) < 24:
            raise ValueError(f"File too small for PCAP header (read {len(header_bytes)} bytes)")

        if prefix not in self.MAGIC_BYTES:
            raise ValueError(f"Unsupported PCAP magic number: 0x{prefix.hex()}")

        magic, is_nano, byte_order, fmt_char = self.MAGIC_BYTES[prefix]
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
            is_pcapng=False,
        )
        return self.header_info

    def _read_pcapng_header(self, stream: BinaryIO, shb_prefix: bytes) -> PcapHeaderInfo:
        """Parses the Section Header Block, reading the whole block by its declared length.

        The SHB declares its total length at offset 4, so the block is consumed
        exactly — options and padding included — instead of assuming a fixed
        28-byte header. ``dlt`` starts at 0 and is filled in by the first
        Interface Description Block encountered while iterating records, because
        a PCAPNG carries no link type in the section header itself.
        """
        length_bytes = stream.read(4)
        if len(length_bytes) < 4:
            raise ValueError("Truncated PCAPNG Section Header Block (no block length)")
        bom = stream.read(4)
        if len(bom) < 4:
            raise ValueError("Truncated PCAPNG Section Header Block (no byte-order magic)")
        # The PCAPNG byte-order magic is 0x1A2B3C4D, emitted in the file's own
        # byte order: 1A 2B 3C 4D means big-endian, 4D 3C 2B 1A little-endian.
        # It must be read before the block length, which uses that same order.
        if bom == b"\x4d\x3c\x2b\x1a":
            byte_order = "little"
        elif bom == b"\x1a\x2b\x3c\x4d":
            byte_order = "big"
        else:
            raise ValueError(f"Invalid PCAPNG byte-order magic: {bom.hex()}")

        fmt = "<" if byte_order == "little" else ">"
        block_len = struct.unpack(f"{fmt}I", length_bytes)[0]
        if block_len < 28 or block_len % 4 != 0 or block_len > MAX_BLOCK_BYTES:
            raise ValueError(f"Invalid PCAPNG Section Header block length: {block_len}")

        rest = bom + stream.read(block_len - 12)
        if len(rest) < block_len - 8:
            raise ValueError("Truncated PCAPNG Section Header Block body")

        major, minor = struct.unpack(f"{fmt}HH", rest[4:8])

        self.interfaces = []
        self.header_info = PcapHeaderInfo(
            magic=PCAPNG_BT_SHB,
            is_nanosecond=False,
            byte_order=byte_order,
            version_major=major,
            version_minor=minor,
            thiszone=0,
            sigfigs=0,
            snaplen=0,
            dlt=0,  # Resolved from the first IDB during record iteration.
            timestamp_scale=1_000_000,
            is_pcapng=True,
        )
        return self.header_info

    # -- records ---------------------------------------------------------------
    def iter_records(self, stream_or_path: BinaryIO | str | Path) -> Iterator[PacketRecord]:
        self.truncated_eof = False

        if isinstance(stream_or_path, (str, Path)):
            # A fresh file starts at its global header; drop state from any earlier pass.
            self.header_info = None
            self.interfaces = []
            with open(stream_or_path, "rb") as f:
                yield from self._iter_stream(f)
        else:
            yield from self._iter_stream(stream_or_path)

    def _iter_stream(self, stream: BinaryIO) -> Iterator[PacketRecord]:
        if self.header_info is None:
            self.read_header(stream)

        assert self.header_info is not None
        if self.header_info.is_pcapng:
            yield from self._iter_pcapng(stream)
        else:
            yield from self._iter_classic(stream)

    def _iter_classic(self, stream: BinaryIO) -> Iterator[PacketRecord]:
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
            if caplen > MAX_RECORD_BYTES:
                self.truncated_eof = True  # corrupt or hostile length; stream is unusable
                break
            data = stream.read(caplen)

            if len(data) < caplen:
                self.truncated_eof = True
                break

            packet_index += 1
            yield PacketRecord(
                index=packet_index,
                timestamp=float(ts_sec) + (float(ts_sub) / scale),
                caplen=caplen,
                wirelen=origlen,
                data=data,
            )

    def _iter_pcapng(self, stream: BinaryIO) -> Iterator[PacketRecord]:
        assert self.header_info is not None
        fmt = "<" if self.header_info.byte_order == "little" else ">"
        packet_index = 0
        section_dlts: set[int] = set()

        while True:
            head = stream.read(8)
            if not head:
                break
            if len(head) < 8:
                self.truncated_eof = True
                break

            block_type, block_len = struct.unpack(f"{fmt}II", head)
            if block_len < 12 or block_len % 4 != 0 or block_len > MAX_BLOCK_BYTES:
                self.truncated_eof = True
                break

            body_len = block_len - 12
            body = stream.read(body_len)
            trailer = stream.read(4)
            if (
                len(body) < body_len
                or len(trailer) < 4
                or struct.unpack(f"{fmt}I", trailer)[0] != block_len
            ):
                self.truncated_eof = True
                break

            if block_type == PCAPNG_BT_SHB:
                # A new section may re-declare its byte order; interfaces reset.
                self.interfaces = []
                continue

            if block_type == PCAPNG_BT_IDB:
                iface = _PcapngInterface(linktype=127)
                if len(body) >= 8:
                    iface.linktype, _r, iface.snaplen = struct.unpack(f"{fmt}HHI", body[:8])
                    iface.tsresol = _parse_tsresol_option(body[8:], fmt)
                self.interfaces.append(iface)
                self._interface_count += 1
                if not section_dlts:
                    # The section header carries no link type; the first interface
                    # definition supplies the effective DLT for the whole section.
                    self.header_info.dlt = iface.linktype
                    self.header_info.is_nanosecond = iface.tsresol == 9
                    self.header_info.timestamp_scale = 10**iface.tsresol
                continue

            if block_type in PCAPNG_RECORD_BLOCKS:
                data, ts_ticks, iface_id = _parse_record_block(block_type, body, fmt)
                if data is None:
                    continue
                iface = (
                    self.interfaces[iface_id]
                    if 0 <= iface_id < len(self.interfaces)
                    else (_PcapngInterface(linktype=self.header_info.dlt))
                )
                section_dlts.add(iface.linktype)
                packet_index += 1
                yield PacketRecord(
                    index=packet_index,
                    timestamp=ts_ticks / (10.0**iface.tsresol) if ts_ticks is not None else 0.0,
                    caplen=len(data),
                    wirelen=len(data),
                    data=data,
                    interface_id=iface_id,
                    dlt=iface.linktype,
                )
                continue

            self.unsupported_blocks[block_type] = self.unsupported_blocks.get(block_type, 0) + 1

        if section_dlts:
            self.header_info.dlt = next(iter(section_dlts))

    def iter_records_batched(self, stream_or_path: BinaryIO | str | Path, batch: int = 256):
        """Yields lists of records, bounding per-record iterator overhead."""
        chunk: list[PacketRecord] = []
        for record in self.iter_records(stream_or_path):
            chunk.append(record)
            if len(chunk) >= batch:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


def _parse_tsresol_option(options: bytes, fmt: str) -> int:
    """Extracts the timestamp resolution exponent from IDB option bytes."""
    tsresol = 6
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(f"{fmt}HH", options[offset : offset + 4])
        offset += 4
        if offset + length > len(options):
            break
        value = options[offset : offset + length]
        if code == 9 and length >= 1:  # if_tsresol
            raw = value[0]
            if raw & 0x80:
                # Base-2 exponent form
                tsresol = max(1, min(12, (raw & 0x7F) * 3 // 10))
            else:
                tsresol = max(0, min(12, raw))
        offset += length + ((-length) % 4)
    return tsresol


def _parse_record_block(
    block_type: int, body: bytes, fmt: str
) -> tuple[bytes | None, int | None, int]:
    """Returns (data, timestamp_ticks, interface_id) for a record-bearing block."""
    if block_type == PCAPNG_BT_EPB:
        if len(body) < 20:
            return None, None, 0
        iface_id, ts_high, ts_low, caplen, _origlen = struct.unpack(f"{fmt}IIIII", body[:20])
        data = body[20 : 20 + caplen]
        ticks = (ts_high << 32) | ts_low
        return data, ticks, iface_id

    if block_type == PCAPNG_BT_SPB:
        if len(body) < 4:
            return None, None, 0
        origlen = struct.unpack(f"{fmt}I", body[:4])[0]
        data = body[4 : 4 + min(origlen, len(body) - 4)]
        return data, None, 0

    if block_type == PCAPNG_BT_PB:
        if len(body) < 4:
            return None, None, 0
        iface_id = struct.unpack(f"{fmt}H", body[:2])[0]
        data = body[4:]
        return data, None, iface_id

    return None, None, 0


@dataclass
class StreamSummary:
    """Aggregate facts about a capture file, gathered in a single streaming pass."""

    total_records: int = 0
    dlt_types: set[int] = field(default_factory=set)
    btp_ports: dict[int, int] = field(default_factory=dict)
    is_nanosecond: bool = False
    is_pcapng: bool = False
    truncated_eof: bool = False
    unsupported_blocks: dict[int, int] = field(default_factory=dict)
