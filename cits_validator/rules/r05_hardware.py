from __future__ import annotations

import struct
from typing import Any

from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule


class HardwareStreamRule(BaseRule):
    """Audits ESP32-C5 ITS5/ITS6 binary framing, RSSI sentinel mapping, and host time anchoring."""

    rule_id = "R05"
    name = "Hardware Framing & Sensor Stream Invariant"
    description = (
        "Validates ESP32-C5 ITS5 (14B) and ITS6 (15B) framing, ensures INT8_MIN (-128 dBm) "
        "sentinel resolution, and audits host time anchoring against uptime discontinuities."
    )

    def audit_stream_chunk(
        self, chunk: bytes, state: dict[str, Any]
    ) -> tuple[list[Violation], list[dict[str, Any]]]:
        violations: list[Violation] = []
        parsed_frames: list[dict[str, Any]] = []

        offset = 0
        chunk_len = len(chunk)

        while offset < chunk_len:
            if offset + 4 > chunk_len:
                break

            magic = chunk[offset : offset + 4]
            if magic not in (b"ITS5", b"ITS6"):
                offset += 1
                continue

            is_its6 = magic == b"ITS6"
            hdr_len = 15 if is_its6 else 14

            if offset + hdr_len > chunk_len:
                break

            # ITS5: magic(4B), sec(4B), usec(4B), len(2B)
            # ITS6: magic(4B), sec(4B), usec(4B), len(2B), rssi(1B)
            if is_its6:
                sec, usec, payload_len, raw_rssi = struct.unpack(
                    "<IIHb", chunk[offset + 4 : offset + 15]
                )
                rssi = None if raw_rssi == -128 else raw_rssi
            else:
                sec, usec, payload_len = struct.unpack(
                    "<IIH", chunk[offset + 4 : offset + 14]
                )
                rssi = None

            frame_total = hdr_len + payload_len
            if offset + frame_total > chunk_len:
                break

            payload = chunk[offset + hdr_len : offset + frame_total]

            # Lookahead check: if there is more data, next 4 bytes should be a magic
            if offset + frame_total + 4 <= chunk_len:
                next_magic = chunk[offset + frame_total : offset + frame_total + 4]
                if next_magic not in (b"ITS5", b"ITS6"):
                    # Possible false positive collision in stream
                    pass

            uptime = float(sec) + (float(usec) / 1_000_000.0)

            # Check time continuity
            last_uptime = state.get("last_uptime")
            if last_uptime is not None:
                delta = uptime - last_uptime
                if delta < -2.0:
                    violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            severity=Severity.WARNING,
                            message=f"ESP32 backward uptime jump ({delta:.2f}s): reboot detected",
                            remediation_hint="Host must reset its SystemTime wall-clock anchor upon backward uptime jumps.",
                        )
                    )
                elif delta > 60.0:
                    violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            severity=Severity.WARNING,
                            message=f"ESP32 forward uptime gap ({delta:.2f}s): sleep or stall detected",
                            remediation_hint="Re-synchronize host wall-clock time anchor after large idle gaps.",
                        )
                    )

            state["last_uptime"] = uptime

            parsed_frames.append(
                {
                    "magic": magic.decode("ascii", errors="replace"),
                    "uptime": uptime,
                    "rssi": rssi,
                    "payload": payload,
                }
            )

            offset += frame_total

        return violations, parsed_frames
