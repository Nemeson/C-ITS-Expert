from esp32_host_anchor import Esp32HostTimeAnchor


def test_host_time_anchoring_linear_progression():
    anchor = Esp32HostTimeAnchor()
    wall_start = 1727438400.0

    # First frame anchors the session
    t0 = anchor.compute_host_time(fw_sec=50, fw_usec=0, wall_now=wall_start)
    assert t0 == wall_start

    # Second frame 5.25 seconds later in firmware time
    t1 = anchor.compute_host_time(fw_sec=55, fw_usec=250_000, wall_now=wall_start + 5.25)
    assert t1 == wall_start + 5.25


def test_discontinuity_backward_jump_resets_anchor():
    anchor = Esp32HostTimeAnchor()
    wall_start = 1727438400.0

    anchor.compute_host_time(fw_sec=100, fw_usec=0, wall_now=wall_start)

    # Board reset / reboot: fw_sec suddenly drops to 2 (backward jump > 2s)
    wall_reboot = wall_start + 10.0
    t_after_reboot = anchor.compute_host_time(fw_sec=2, fw_usec=0, wall_now=wall_reboot)

    # Must re-anchor to the reboot wall-clock time rather than subtracting 98 seconds from 1970
    assert t_after_reboot == wall_reboot
    assert anchor.discontinuity_count == 1


def test_discontinuity_forward_jump_resets_anchor():
    anchor = Esp32HostTimeAnchor()
    wall_start = 1727438400.0

    anchor.compute_host_time(fw_sec=100, fw_usec=0, wall_now=wall_start)

    # Firmware clock jumps forward by 120s (> 60s threshold)
    wall_later = wall_start + 5.0
    t_after_jump = anchor.compute_host_time(fw_sec=220, fw_usec=0, wall_now=wall_later)

    assert t_after_jump == wall_later
    assert anchor.discontinuity_count == 1


def test_rssi_sentinel_resolution():
    assert Esp32HostTimeAnchor.parse_rssi(-128) is None
    assert Esp32HostTimeAnchor.parse_rssi(-65) == -65
    assert Esp32HostTimeAnchor.parse_rssi(-127) == -127
