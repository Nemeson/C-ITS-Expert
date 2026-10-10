"""GLOSA (Green Light Optimal Speed Advisory) trajectory calculation engine.

Pure-Python implementation adhering to ISO TS 19091 and ETSI TS 103 301.
Computes recommended speed advisory windows to allow vehicles to pass traffic
signals on green without stopping, minimizing stop-and-go energy losses.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

RECOMMENDATION_CRUISE = "CRUISE"
RECOMMENDATION_DECELERATE = "DECELERATE"
RECOMMENDATION_ACCELERATE = "ACCELERATE"
RECOMMENDATION_STOP = "PREPARE_TO_STOP"

KMH_PER_MS = 3.6
MIN_SPEED_LIMIT_KMH = 10.0  # a lower configured limit is treated as this
MIN_MOVING_SPEED_MS = 0.1  # below this the vehicle is considered standing
CRUISE_MARGIN_KMH = 5.0  # advisory window below the current speed when cruising


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


@dataclass(frozen=True)
class _Approach:
    """Kinematic facts about the approach, derived once from the validated inputs."""

    distance_m: float
    speed_kmh: float
    limit_kmh: float
    min_comfort_kmh: float
    safety_buffer_s: float
    eta_current_s: float
    eta_fastest_s: float

    @property
    def reported_eta_s(self) -> float:
        return round(self.eta_current_s if math.isfinite(self.eta_current_s) else 0.0, 1)


def _check_finite(**values: float) -> None:
    for name, value in values.items():
        if not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number, got {value!r}")


def _stop(approach: _Approach, details: str) -> GlosaAdvisory:
    return GlosaAdvisory(
        speed_min_kmh=0.0,
        speed_max_kmh=0.0,
        recommendation=RECOMMENDATION_STOP,
        time_to_stopline_s=approach.reported_eta_s,
        is_pass_possible=False,
        details=details,
    )


def _advise_green(approach: _Approach, time_to_phase_end_s: float) -> GlosaAdvisory:
    a = approach
    effective_green_end = max(0.0, time_to_phase_end_s - a.safety_buffer_s)

    # 1. Passes during the current green at the current speed: cruising is optimal.
    if a.eta_current_s <= effective_green_end:
        v_pass_min = (
            (a.distance_m / effective_green_end) * KMH_PER_MS
            if effective_green_end > 0
            else a.min_comfort_kmh
        )
        v_min = min(
            a.limit_kmh,
            max(a.min_comfort_kmh, max(v_pass_min, a.speed_kmh - CRUISE_MARGIN_KMH)),
        )
        v_max = min(a.limit_kmh, max(v_min, a.speed_kmh))
        return GlosaAdvisory(
            speed_min_kmh=round(v_min, 1),
            speed_max_kmh=round(v_max, 1),
            recommendation=RECOMMENDATION_CRUISE,
            time_to_stopline_s=round(a.eta_current_s, 1),
            is_pass_possible=True,
            details=(
                f"Current speed {a.speed_kmh:.1f} km/h passes green ending "
                f"in {time_to_phase_end_s:.1f}s."
            ),
        )

    # 2. Can pass the current green by accelerating.
    if a.eta_fastest_s <= effective_green_end:
        v_req_min = (a.distance_m / effective_green_end) * KMH_PER_MS
        v_min = min(a.limit_kmh, max(a.speed_kmh, v_req_min))
        return GlosaAdvisory(
            speed_min_kmh=round(v_min, 1),
            speed_max_kmh=round(a.limit_kmh, 1),
            recommendation=RECOMMENDATION_ACCELERATE,
            time_to_stopline_s=round(a.distance_m / (v_min / KMH_PER_MS), 1),
            is_pass_possible=True,
            details=(
                f"Accelerate to {v_min:.1f} - {a.limit_kmh:.1f} km/h to pass green "
                f"before {time_to_phase_end_s:.1f}s."
            ),
        )

    # 3. Cannot pass the current green.
    return _stop(
        a,
        f"Cannot reach stopline before green ends in {time_to_phase_end_s:.1f}s. Prepare to stop.",
    )


def _advise_red(
    approach: _Approach, red_end: float, next_green_duration_s: float
) -> GlosaAdvisory:
    a = approach
    if red_end <= 0.0:
        return _stop(a, "Approaching RED. Decelerate to safe stop.")

    if next_green_duration_s > 0.0:
        green_start = red_end
        green_end = red_end + next_green_duration_s - a.safety_buffer_s
        # A green shorter than the safety buffer leaves no usable window.
        if green_end <= green_start:
            return _stop(a, "Upcoming green is too short to pass safely. Prepare to stop.")
        # Earliest arrival allowed is green_start, latest is green_end.
        v_max = min(a.limit_kmh, a.distance_m / green_start * KMH_PER_MS)
        v_min = max(a.min_comfort_kmh, a.distance_m / green_end * KMH_PER_MS)
    else:
        # Standard SPATEM without upcoming phase duration: decelerate so arrival is
        # at or after green onset (t >= red_end).
        v_max = min(a.limit_kmh, (a.distance_m / red_end) * KMH_PER_MS)
        v_min = a.min_comfort_kmh

    if v_min > v_max or v_max < a.min_comfort_kmh:
        return _stop(a, "Approaching RED. Decelerate to safe stop.")

    recommendation = RECOMMENDATION_DECELERATE if v_max < a.speed_kmh else RECOMMENDATION_CRUISE
    return GlosaAdvisory(
        speed_min_kmh=round(v_min, 1),
        speed_max_kmh=round(v_max, 1),
        recommendation=recommendation,
        time_to_stopline_s=round(a.distance_m / ((v_min + v_max) / 2 / KMH_PER_MS), 1),
        is_pass_possible=True,
        details=f"Adjust speed to {v_min:.1f} - {v_max:.1f} km/h to meet green onset at {red_end:.1f}s.",
    )


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

    Raises:
        ValueError: when a numeric input is NaN or infinite.
    """
    _check_finite(
        distance_m=distance_m,
        current_speed_kmh=current_speed_kmh,
        speed_limit_kmh=speed_limit_kmh,
        time_to_phase_end_s=time_to_phase_end_s,
        next_green_duration_s=next_green_duration_s,
        min_comfort_speed_kmh=min_comfort_speed_kmh,
        safety_buffer_s=safety_buffer_s,
    )

    if distance_m <= 0.0:
        return GlosaAdvisory(
            speed_min_kmh=round(current_speed_kmh, 1),
            speed_max_kmh=round(current_speed_kmh, 1),
            recommendation=RECOMMENDATION_CRUISE,
            time_to_stopline_s=0.0,
            is_pass_possible=True,
            details="Stopline already reached or crossed.",
        )

    limit_kmh = max(speed_limit_kmh, MIN_SPEED_LIMIT_KMH)
    current_speed_ms = max(current_speed_kmh, 0.0) / KMH_PER_MS
    approach = _Approach(
        distance_m=distance_m,
        speed_kmh=current_speed_kmh,
        limit_kmh=limit_kmh,
        min_comfort_kmh=min_comfort_speed_kmh,
        safety_buffer_s=safety_buffer_s,
        eta_current_s=(
            distance_m / current_speed_ms if current_speed_ms > MIN_MOVING_SPEED_MS else math.inf
        ),
        eta_fastest_s=distance_m / (limit_kmh / KMH_PER_MS),
    )

    state = phase_state.strip().upper()
    if state == "GREEN":
        return _advise_green(approach, time_to_phase_end_s)
    if state == "YELLOW":
        # YELLOW ends in RED, not green: time_to_phase_end_s is when red starts, and
        # the red duration is unknown, so no safe pass window can be derived.
        return _stop(approach, "Signal is YELLOW and turns red next. Prepare to stop.")
    if state == "RED":
        return _advise_red(approach, time_to_phase_end_s, next_green_duration_s)
    return _stop(approach, f"Unknown signal phase '{phase_state}'. Defaulting to stop.")
