"""GLOSA (Green Light Optimal Speed Advisory) trajectory calculation engine.

Pure-Python implementation adhering to ISO TS 19091 and ETSI TS 103 301.
Computes recommended speed advisory windows to allow vehicles to pass traffic
signals on green without stopping, minimizing stop-and-go energy losses.
"""

from __future__ import annotations

from dataclasses import dataclass

RECOMMENDATION_CRUISE = "CRUISE"
RECOMMENDATION_DECELERATE = "DECELERATE"
RECOMMENDATION_ACCELERATE = "ACCELERATE"
RECOMMENDATION_STOP = "PREPARE_TO_STOP"


@dataclass
class GlosaAdvisory:
    """GLOSA Speed Advisory output.

    Attributes:
        speed_min_kmh: Minimum recommended advisory speed in km/h.
        speed_max_kmh: Maximum recommended advisory speed in km/h.
        recommendation: One of CRUISE, DECELERATE, ACCELERATE, PREPARE_TO_STOP.
        time_to_stopline_s: Estimated arrival time at stop line in seconds.
        is_pass_possible: Whether passing on green is achievable.
        details: Human-readable diagnostic description of the trajectory advisory.
    """

    speed_min_kmh: float
    speed_max_kmh: float
    recommendation: str
    time_to_stopline_s: float
    is_pass_possible: bool
    details: str = ""


def compute_glosa_advisory(
    distance_m: float,
    current_speed_kmh: float,
    speed_limit_kmh: float = 50.0,
    phase_state: str = "GREEN",
    time_to_phase_end_s: float = 0.0,
    next_green_duration_s: float = 0.0,
    min_comfort_speed_kmh: float = 20.0,
    safety_buffer_s: float = 0.5,
) -> GlosaAdvisory:
    """Computes a GLOSA speed advisory window for an approaching vehicle.

    Args:
        distance_m: Remaining distance to the stop line (Node 0) in meters.
        current_speed_kmh: Current vehicle approach speed in km/h.
        speed_limit_kmh: Legal street speed limit in km/h (default: 50.0).
        phase_state: Current signal phase ("GREEN", "RED", "YELLOW", case-insensitive).
        time_to_phase_end_s: Remaining time in seconds of the current phase.
        next_green_duration_s: Duration in seconds of the subsequent green phase (for RED).
        min_comfort_speed_kmh: Minimum comfortable driving speed in km/h (default: 20.0).
        safety_buffer_s: Safety buffer before phase change in seconds (default: 0.5s).

    Returns:
        GlosaAdvisory with speed window and driving recommendation.
    """
    if distance_m <= 0.0:
        return GlosaAdvisory(
            speed_min_kmh=round(current_speed_kmh, 1),
            speed_max_kmh=round(current_speed_kmh, 1),
            recommendation=RECOMMENDATION_CRUISE,
            time_to_stopline_s=0.0,
            is_pass_possible=True,
            details="Stopline already reached or crossed.",
        )

    speed_limit_kmh = max(speed_limit_kmh, 10.0)
    current_speed_ms = max(current_speed_kmh, 0.0) / 3.6
    speed_limit_ms = speed_limit_kmh / 3.6

    eta_current_s = (distance_m / current_speed_ms) if current_speed_ms > 0.1 else float("inf")
    eta_fastest_s = distance_m / speed_limit_ms

    state = phase_state.strip().upper()

    if state == "GREEN":
        effective_green_end = max(0.0, time_to_phase_end_s - safety_buffer_s)

        # 1. Check if vehicle passes during current green at current speed
        if eta_current_s <= effective_green_end:
            # Cruising is optimal
            # Advisory window allows small comfortable margin around current speed
            v_pass_min = (distance_m / effective_green_end) * 3.6 if effective_green_end > 0 else min_comfort_speed_kmh
            v_min = min(speed_limit_kmh, max(min_comfort_speed_kmh, max(v_pass_min, current_speed_kmh - 5.0)))
            v_max = min(speed_limit_kmh, max(v_min, current_speed_kmh))
            return GlosaAdvisory(
                speed_min_kmh=round(v_min, 1),
                speed_max_kmh=round(v_max, 1),
                recommendation=RECOMMENDATION_CRUISE,
                time_to_stopline_s=round(eta_current_s, 1),
                is_pass_possible=True,
                details=f"Current speed {current_speed_kmh:.1f} km/h passes green ending in {time_to_phase_end_s:.1f}s.",
            )

        # 2. Can vehicle pass during current green by accelerating?
        if eta_fastest_s <= effective_green_end:
            v_req_min = (distance_m / effective_green_end) * 3.6
            v_min = min(speed_limit_kmh, max(current_speed_kmh, v_req_min))
            v_max = speed_limit_kmh
            return GlosaAdvisory(
                speed_min_kmh=round(v_min, 1),
                speed_max_kmh=round(v_max, 1),
                recommendation=RECOMMENDATION_ACCELERATE,
                time_to_stopline_s=round(distance_m / (v_min / 3.6), 1),
                is_pass_possible=True,
                details=f"Accelerate to {v_min:.1f} - {v_max:.1f} km/h to pass green before {time_to_phase_end_s:.1f}s.",
            )

        # 3. Cannot pass current green
        return GlosaAdvisory(
            speed_min_kmh=0.0,
            speed_max_kmh=0.0,
            recommendation=RECOMMENDATION_STOP,
            time_to_stopline_s=round(eta_current_s if eta_current_s != float("inf") else 0.0, 1),
            is_pass_possible=False,
            details=f"Cannot reach stopline before green ends in {time_to_phase_end_s:.1f}s. Prepare to stop.",
        )

    elif state == "YELLOW":
        # YELLOW ends in RED, not green: time_to_phase_end_s is when red starts, and
        # the red duration is unknown, so no safe pass window can be derived.
        return GlosaAdvisory(
            speed_min_kmh=0.0,
            speed_max_kmh=0.0,
            recommendation=RECOMMENDATION_STOP,
            time_to_stopline_s=round(eta_current_s if eta_current_s != float("inf") else 0.0, 1),
            is_pass_possible=False,
            details="Signal is YELLOW and turns red next. Prepare to stop.",
        )

    elif state == "RED":
        # Vehicle must wait for the red phase to end
        red_end = time_to_phase_end_s
        if red_end > 0.0:
            if next_green_duration_s > 0.0:
                green_start = red_end
                green_end = red_end + next_green_duration_s - safety_buffer_s

                # Green shorter than the safety buffer leaves no usable window.
                if green_end <= green_start:
                    return GlosaAdvisory(
                        speed_min_kmh=0.0,
                        speed_max_kmh=0.0,
                        recommendation=RECOMMENDATION_STOP,
                        time_to_stopline_s=round(
                            eta_current_s if eta_current_s != float("inf") else 0.0, 1
                        ),
                        is_pass_possible=False,
                        details="Upcoming green is too short to pass safely. Prepare to stop.",
                    )

                # Earliest arrival allowed is green_start
                v_max_allowable = distance_m / green_start * 3.6
                v_max = min(speed_limit_kmh, v_max_allowable)

                # Latest arrival allowed is green_end
                v_min_allowable = distance_m / green_end * 3.6
                v_min = max(min_comfort_speed_kmh, v_min_allowable)
            else:
                # Standard SPATEM without upcoming phase duration:
                # Decelerate so arrival is at or after green onset (t >= red_end)
                v_max_allowable = (distance_m / red_end) * 3.6
                v_max = min(speed_limit_kmh, v_max_allowable)
                v_min = min_comfort_speed_kmh

            if v_min <= v_max and v_max >= min_comfort_speed_kmh:
                rec = RECOMMENDATION_DECELERATE if v_max < current_speed_kmh else RECOMMENDATION_CRUISE
                return GlosaAdvisory(
                    speed_min_kmh=round(v_min, 1),
                    speed_max_kmh=round(v_max, 1),
                    recommendation=rec,
                    time_to_stopline_s=round(distance_m / ((v_min + v_max) / 2 / 3.6), 1),
                    is_pass_possible=True,
                    details=f"Adjust speed to {v_min:.1f} - {v_max:.1f} km/h to meet green onset at {red_end:.1f}s.",
                )

        # Cannot pass upcoming phase comfortably
        return GlosaAdvisory(
            speed_min_kmh=0.0,
            speed_max_kmh=0.0,
            recommendation=RECOMMENDATION_STOP,
            time_to_stopline_s=round(eta_current_s if eta_current_s != float("inf") else 0.0, 1),
            is_pass_possible=False,
            details=f"Approaching {state}. Decelerate to safe stop.",
        )

    # Unknown phase state fallback
    return GlosaAdvisory(
        speed_min_kmh=0.0,
        speed_max_kmh=0.0,
        recommendation=RECOMMENDATION_STOP,
        time_to_stopline_s=round(eta_current_s if eta_current_s != float("inf") else 0.0, 1),
        is_pass_possible=False,
        details=f"Unknown signal phase '{phase_state}'. Defaulting to stop.",
    )
