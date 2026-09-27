"""ESP32-C5 V2X Receiver Host Time Anchor and Discontinuity Handler.

Translates firmware boot-relative uptime timestamps into wall-clock Unix time,
handles ESP32-C5 reboots / timer resets, and parses ITS6 RSSI sentinels.
"""

from __future__ import annotations

import time

RSSI_SENTINEL_NONE = -128  # INT8_MIN denotes no signal level measured


class Esp32HostTimeAnchor:
    """Anchors boot-relative firmware timestamps against host wall clock."""

    def __init__(self) -> None:
        self._anchor_wall_time: float | None = None
        self._anchor_fw_time: float | None = None
        self._last_fw_time: float | None = None
        self.discontinuity_count: int = 0

    def compute_host_time(
        self, fw_sec: int, fw_usec: int, wall_now: float | None = None
    ) -> float:
        fw_time = float(fw_sec) + (float(fw_usec) / 1_000_000.0)
        current_wall = time.time() if wall_now is None else wall_now

        # Initial anchor
        if self._anchor_wall_time is None or self._anchor_fw_time is None:
            self._anchor_wall_time = current_wall
            self._anchor_fw_time = fw_time
            self._last_fw_time = fw_time
            return current_wall

        # Discontinuity checks:
        # Backward jump > 2s (e.g. board reset / reboot)
        # Forward jump > 60s (e.g. sleep or timer wraparound)
        delta_since_last = fw_time - (self._last_fw_time or fw_time)
        if delta_since_last < -2.0 or delta_since_last > 60.0:
            self.discontinuity_count += 1
            self._anchor_wall_time = current_wall
            self._anchor_fw_time = fw_time
            self._last_fw_time = fw_time
            return current_wall

        self._last_fw_time = fw_time
        return self._anchor_wall_time + (fw_time - self._anchor_fw_time)

    @staticmethod
    def parse_rssi(raw_rssi: int) -> int | None:
        """Parses 1-byte signed RSSI from ITS6 frame into dBm or None if unavailable."""
        if raw_rssi == RSSI_SENTINEL_NONE:
            return None
        return raw_rssi
