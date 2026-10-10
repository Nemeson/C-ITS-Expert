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

    _TAIL_KEY = "_r05_tail"
    _MAGICS = (b"ITS5", b"ITS6")
    _MAX_USEC = 1_000_000

    def audit_stream_chunk(
        self, chunk: bytes, state: dict[str, Any]
    ) -> tuple[list[Violation], list[dict[str, Any]]]:
        """Parses ITS5/ITS6 frames from one chunk of the serial stream.

        An incomplete frame at the end of the chunk is kept in ``state`` and
        completed by the next call, so frames may span chunk boundaries. Bytes
        that cannot belong to any frame are dropped, but never silently: they
        are reported as one WARNING per resynchronisation.
        """
        violations: list[Violation] = []
        parsed_frames: list[dict[str, Any]] = []

        buf = state.get(self._TAIL_KEY, b"") + chunk
        offset = 0
        discarded = 0

        def flush_discarded() -> None:
            nonlocal discarded
            if discarded:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message=(
                            f"discarded {discarded} byte(s) while resynchronising "
                            "on ITS5/ITS6 frame magic"
                        ),
                        remediation_hint="Check the serial link for corruption or framing loss.",
                    )
                )
                discarded = 0

        while offset + 4 <= len(buf):
            magic = buf[offset : offset + 4]
            if magic not in self._MAGICS:
                offset += 1
                discarded += 1
                continue

            is_its6 = magic == b"ITS6"
            hdr_len = 15 if is_its6 else 14
            if offset + hdr_len > len(buf):
                break

            # ITS5: magic(4B), sec(4B), usec(4B), len(2B)
            # ITS6: magic(4B), sec(4B), usec(4B), len(2B), rssi(1B)
            if is_its6:
                sec, usec, payload_len, raw_rssi = struct.unpack(
                    "<IIHb", buf[offset + 4 : offset + 15]
                )
                rssi = None if raw_rssi == -128 else raw_rssi
            else:
                sec, usec, payload_len = struct.unpack("<IIH", buf[offset + 4 : offset + 14])
                rssi = None

            if usec >= self._MAX_USEC:
                # Not a real header: the magic bytes occurred inside other data.
                offset += 1
                discarded += 1
                continue

            frame_total = hdr_len + payload_len
            if offset + frame_total > len(buf):
                break

            flush_discarded()
            payload = buf[offset + hdr_len : offset + frame_total]
            uptime = float(sec) + (float(usec) / 1_000_000.0)
            violations.extend(self._check_time_continuity(uptime, state))
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

        flush_discarded()
        state[self._TAIL_KEY] = buf[offset:]
        return violations, parsed_frames

    def _check_time_continuity(self, uptime: float, state: dict[str, Any]) -> list[Violation]:
        last_uptime = state.get("last_uptime")
        if last_uptime is None:
            return []
        delta = uptime - last_uptime
        if delta < -2.0:
            return [
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=f"ESP32 backward uptime jump ({delta:.2f}s): reboot detected",
                    remediation_hint="Host must reset its SystemTime wall-clock anchor upon backward uptime jumps.",
                )
            ]
        if delta > 60.0:
            return [
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=f"ESP32 forward uptime gap ({delta:.2f}s): sleep or stall detected",
                    remediation_hint="Re-synchronize host wall-clock time anchor after large idle gaps.",
                )
            ]
        return []
