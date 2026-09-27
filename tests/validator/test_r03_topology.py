from cits_validator.core.models import Severity
from cits_validator.rules.r03_topology import MapemTopologyRule


def test_multi_fragment_merging_no_overwrites():
    # Fragment 1 (layerID 21): Ingress lanes 1 and 2
    frag1 = {
        "regionId": 10,
        "intersectionId": 1001,
        "layerId": 21,
        "lanes": [
            {"laneId": 1, "type": "ingress", "nodes": [{"lat": 52.5200, "lon": 13.4000}]},
            {"laneId": 2, "type": "ingress", "nodes": [{"lat": 52.5201, "lon": 13.4001}]},
        ],
    }

    # Fragment 2 (layerID 22): Egress lanes 3 and 4
    frag2 = {
        "regionId": 10,
        "intersectionId": 1001,
        "layerId": 22,
        "lanes": [
            {"laneId": 3, "type": "egress", "nodes": [{"lat": 52.5202, "lon": 13.4002}]},
            {"laneId": 4, "type": "egress", "nodes": [{"lat": 52.5203, "lon": 13.4003}]},
        ],
    }

    rule = MapemTopologyRule()
    state = {}
    v1 = rule.audit_fragment(frag1, state=state)
    v2 = rule.audit_fragment(frag2, state=state)

    assert len(v1) == 0
    assert len(v2) == 0

    # Ensure intersection in state accumulated all 4 lanes
    key = (10, 1001)
    assert key in state.get("intersections", {})
    assert len(state["intersections"][key]["lanes"]) == 4


def test_detect_overlong_stopline_chords():
    # Connecting Node N of ingress to Node N of egress (120 meters away)
    # Stopline at intersection center: (52.52000, 13.40000)
    # Tail 100 meters north: (52.52090, 13.40000) -> ~100m away
    # Tail 100 meters south: (52.51910, 13.40000) -> ~100m away
    # Connecting tails creates an overlong diagonal chord of ~200m
    bad_connection = {
        "fromLane": 1,
        "toLane": 3,
        "fromNode": {"lat": 52.52090, "lon": 13.40000},
        "toNode": {"lat": 52.51910, "lon": 13.40000},
    }

    rule = MapemTopologyRule()
    violations = rule.audit_lane_connection(bad_connection)

    assert len(violations) > 0
    assert any(v.rule_id == "R03" and v.severity == Severity.ERROR for v in violations)
    assert any("overlong chord" in v.message.lower() or "25m" in v.message for v in violations)


def test_valid_node_zero_stopline_connection():
    # Valid Stopline connection across intersection center (~12 meters)
    good_connection = {
        "fromLane": 1,
        "toLane": 2,
        "fromNode": {"lat": 52.52000, "lon": 13.40000},
        "toNode": {"lat": 52.52010, "lon": 13.40010},
    }

    rule = MapemTopologyRule()
    violations = rule.audit_lane_connection(good_connection)
    assert len(violations) == 0
