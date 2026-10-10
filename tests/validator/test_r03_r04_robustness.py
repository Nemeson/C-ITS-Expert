"""R03/R04 must tolerate malformed events and agree with the adapter's key names."""

from __future__ import annotations

from cits_validator.rules.r03_topology import MapemTopologyRule as TopologyRule
from cits_validator.rules.r04_priority import PrioritySessionRule


def _event(kind, **overrides):
    event = {
        "type": kind,
        "timestamp": 1.0,
        "intersectionId": 1,
        "requestId": 2,
        "sequenceNumber": 3,
        "requestorStationId": 4,
    }
    event.update(overrides)
    return event


def test_r04_event_without_type_or_with_bad_timestamp_does_not_crash():
    rule = PrioritySessionRule()
    state: dict = {}

    none_type = rule.audit_event(_event(None), state)
    bad_time = rule.audit_event(_event("SREM", timestamp="n/a"), state)

    assert none_type == []
    assert [v.severity.value for v in bad_time] == ["WARNING"]
    assert "timestamp" in bad_time[0].message


def test_r04_ssem_without_request_is_reported():
    violations = PrioritySessionRule().audit_event(_event("SSEM"), {})

    assert [v.severity.value for v in violations] == ["INFO"]
    assert "no preceding SREM" in violations[0].message


def test_r04_duplicate_active_request_is_reported():
    rule = PrioritySessionRule()
    state: dict = {}
    rule.audit_event(_event("SREM"), state)

    violations = rule.audit_event(_event("SREM", timestamp=2.0), state)

    assert [v.severity.value for v in violations] == ["WARNING"]
    assert "duplicate" in violations[0].message


def _fragment(lane_key, nodes):
    return {"regionId": 0, "intersectionId": 7, "lanes": [{lane_key: 1, "nodes": nodes}]}


def test_r03_understands_the_adapter_key_names():
    rule = TopologyRule()
    state: dict = {}
    rule.audit_fragment(_fragment("lane_id", [{"lat": 52.0, "lon": 13.0}]), state)

    violations = rule.audit_fragment(_fragment("lane_id", [{"lat": 53.0, "lon": 13.0}]), state)

    assert [v.severity.value for v in violations] == ["ERROR"]


def test_r03_float_noise_is_not_a_conflict_but_real_movement_is():
    rule = TopologyRule()
    state: dict = {}
    rule.audit_fragment(_fragment("laneId", [{"lat": 52.0, "lon": 13.0}]), state)

    noise = rule.audit_fragment(_fragment("laneId", [{"lat": 52.0 + 1e-12, "lon": 13.0}]), state)
    moved = rule.audit_fragment(_fragment("laneId", [{"lat": 52.001, "lon": 13.0}]), state)

    assert noise == []
    assert len(moved) == 1


def test_r03_fragment_with_null_lanes_does_not_crash():
    fragment = {"regionId": 0, "intersectionId": 7, "lanes": None}

    assert TopologyRule().audit_fragment(fragment, {}) == []
