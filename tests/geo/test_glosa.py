import pytest

from cits_validator.geo.glosa import (
    RECOMMENDATION_ACCELERATE,
    RECOMMENDATION_CRUISE,
    RECOMMENDATION_DECELERATE,
    RECOMMENDATION_STOP,
    compute_glosa_advisory,
)


def test_glosa_cruise_on_green():
    # Distance: 100m, Current: 50 km/h (~13.89 m/s, ETA ~7.2s). Green ends in 15s.
    advisory = compute_glosa_advisory(
        distance_m=100.0,
        current_speed_kmh=50.0,
        speed_limit_kmh=50.0,
        phase_state="GREEN",
        time_to_phase_end_s=15.0,
    )

    assert advisory.is_pass_possible is True
    assert advisory.recommendation == RECOMMENDATION_CRUISE
    assert 40.0 <= advisory.speed_min_kmh <= advisory.speed_max_kmh <= 50.0


def test_glosa_decelerate_for_upcoming_green():
    # Distance: 100m, Current: 50 km/h (takes 7.2s at 50 km/h).
    # Currently RED, red ends in 8.0s, then green follows for 20.0s.
    # At 50 km/h, vehicle arrives at t=7.2s (during RED!).
    # Slowing to ~35 km/h (~9.7 m/s) takes ~10.3s (during GREEN!).
    advisory = compute_glosa_advisory(
        distance_m=100.0,
        current_speed_kmh=50.0,
        speed_limit_kmh=50.0,
        phase_state="RED",
        time_to_phase_end_s=8.0,
        next_green_duration_s=20.0,
    )

    assert advisory.is_pass_possible is True
    assert advisory.recommendation == RECOMMENDATION_DECELERATE
    assert advisory.speed_max_kmh <= 45.0
    assert advisory.speed_min_kmh >= 20.0


def test_glosa_accelerate_within_speed_limit():
    # Distance: 120m, Current: 38 km/h (~10.55 m/s, takes 11.4s).
    # Green ends in 10.0s. Speed limit is 50 km/h.
    # Cruising at 38 km/h misses green by 1.4s.
    # Speeding up to 48 km/h (~13.33 m/s) takes 9.0s <= 10.0s!
    advisory = compute_glosa_advisory(
        distance_m=120.0,
        current_speed_kmh=38.0,
        speed_limit_kmh=50.0,
        phase_state="GREEN",
        time_to_phase_end_s=10.0,
    )

    assert advisory.is_pass_possible is True
    assert advisory.recommendation == RECOMMENDATION_ACCELERATE
    assert advisory.speed_min_kmh >= 44.0
    assert advisory.speed_max_kmh <= 50.0


def test_glosa_impossible_pass_prepare_to_stop():
    # Distance: 200m, Green ends in 4s. Speed limit 50 km/h.
    # Even at 50 km/h, takes 14.4s. Impossible to beat 4s!
    advisory = compute_glosa_advisory(
        distance_m=200.0,
        current_speed_kmh=50.0,
        speed_limit_kmh=50.0,
        phase_state="GREEN",
        time_to_phase_end_s=4.0,
        next_green_duration_s=0.0,
    )

    assert advisory.is_pass_possible is False
    assert advisory.recommendation == RECOMMENDATION_STOP


def test_glosa_decelerate_for_standard_spat_without_green_duration():
    # Distance: 100m, Current: 50 km/h (ETA 7.2s).
    # RED ends in 8.0s. Standard SPATEM doesn't transmit next green duration (defaults to 0.0s).
    # Slowing to <= 45 km/h arrives at t >= 8.0s (when light turns green).
    advisory = compute_glosa_advisory(
        distance_m=100.0,
        current_speed_kmh=50.0,
        speed_limit_kmh=50.0,
        phase_state="RED",
        time_to_phase_end_s=8.0,
        next_green_duration_s=0.0,  # Omitted / unknown upcoming duration
    )

    assert advisory.is_pass_possible is True
    assert advisory.recommendation == RECOMMENDATION_DECELERATE
    assert advisory.speed_max_kmh <= 45.0
    assert advisory.speed_min_kmh == 20.0



# --- YELLOW is the end of green, not the start of it --------------------------------


def test_yellow_never_advises_arriving_at_phase_end_as_if_it_were_green_onset():
    # time_to_phase_end for YELLOW is when RED begins; arriving then is the unsafe moment.
    advisory = compute_glosa_advisory(
        distance_m=200.0,
        current_speed_kmh=50.0,
        phase_state="YELLOW",
        time_to_phase_end_s=3.0,
        next_green_duration_s=20.0,
    )

    assert advisory.recommendation == RECOMMENDATION_STOP
    assert advisory.is_pass_possible is False
    assert advisory.speed_max_kmh == 0.0


def test_red_with_green_shorter_than_safety_buffer_has_no_solution():
    advisory = compute_glosa_advisory(
        distance_m=200.0,
        current_speed_kmh=50.0,
        phase_state="RED",
        time_to_phase_end_s=0.1,
        next_green_duration_s=0.3,
        safety_buffer_s=0.5,
    )

    assert advisory.is_pass_possible is False
    assert advisory.recommendation == RECOMMENDATION_STOP


# --- input validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["distance_m", "current_speed_kmh", "time_to_phase_end_s", "next_green_duration_s"],
)
@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_non_finite_inputs_are_rejected(field, bad):
    kwargs = {
        "distance_m": 100.0,
        "current_speed_kmh": 50.0,
        "phase_state": "GREEN",
        "time_to_phase_end_s": 10.0,
        "next_green_duration_s": 5.0,
    }
    kwargs[field] = bad

    with pytest.raises(ValueError, match=field):
        compute_glosa_advisory(**kwargs)
