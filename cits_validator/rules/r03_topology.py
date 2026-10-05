from __future__ import annotations

import math
from typing import Any

from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule


class MapemTopologyRule(BaseRule):
    """Enforces multi-fragment MAPEM additive accumulation and Node-0 stopline orientation."""

    rule_id = "R03"
    name = "MAPEM Topography & Stopline Geometry Invariant"
    description = (
        "Validates multi-fragment MAPEM lane accumulation without overwrite loss, "
        "and checks that stopline connections do not exceed the configurable "
        "intersection chord bound."
    )

    # ISO TS 19091 stopline chords at a signalised intersection are short. The
    # bound is a heuristic guard against connecting lane tails (Node N) instead
    # of stoplines (Node 0); 25 m matches the C-Roads / ETSI guidance and can be
    # raised for large junctions (see README: intersection geometry).
    DEFAULT_MAX_STOPLINE_CHORD_METERS: float = 25.0
    EARTH_RADIUS_METERS: float = 6371000.0

    def __init__(self, max_stopline_chord_meters: float | None = None) -> None:
        self.max_stopline_chord_meters = (
            max_stopline_chord_meters
            if max_stopline_chord_meters is not None
            else self.DEFAULT_MAX_STOPLINE_CHORD_METERS
        )

    @classmethod
    def haversine_distance(cls, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        # cits-lint: allow — great-circle distance, not synthetic coordinate generation
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * (
            math.sin(delta_lambda / 2.0) ** 2
        )
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))
        return cls.EARTH_RADIUS_METERS * c

    def audit_lane_connection(self, connection: dict[str, Any]) -> list[Violation]:
        violations: list[Violation] = []
        from_node = connection.get("fromNode", {})
        to_node = connection.get("toNode", {})

        lat1, lon1 = from_node.get("lat"), from_node.get("lon")
        lat2, lon2 = to_node.get("lat"), to_node.get("lon")

        if None in (lat1, lon1, lat2, lon2):
            return violations

        dist = self.haversine_distance(lat1, lon1, lat2, lon2)
        if dist > self.max_stopline_chord_meters:
            from_lane = connection.get("fromLane", "?")
            to_lane = connection.get("toLane", "?")
            violations.append(
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.ERROR,
                    message=(
                        f"Overlong chord detected ({dist:.1f}m > "
                        f"{self.max_stopline_chord_meters}m) connecting lane "
                        f"{from_lane} to lane {to_lane}"
                    ),
                    offending_sample=f"dist={dist:.1f}m, from=({lat1},{lon1}), to=({lat2},{lon2})",
                    remediation_hint=(
                        "In ISO TS 19091, Node 0 is the stopline reference node near the "
                        "intersection center. Connecting lane tails (Node N) produces 5-fold "
                        "overlong diagonal chords that cut across oncoming traffic. Always "
                        "connect from Node 0."
                    ),
                )
            )

        return violations

    def audit_fragment(self, fragment: dict[str, Any], state: dict[str, Any]) -> list[Violation]:
        violations: list[Violation] = []
        region_id = fragment.get("regionId", 0)
        intersection_id = fragment.get("intersectionId")
        if intersection_id is None:
            return violations

        key = (region_id, intersection_id)
        intersections = state.setdefault("intersections", {})

        if key not in intersections:
            intersections[key] = {
                "regionId": region_id,
                "intersectionId": intersection_id,
                "layers": set(),
                "lanes": {},
            }

        target = intersections[key]
        layer_id = fragment.get("layerId")
        if layer_id is not None:
            target["layers"].add(layer_id)

        incoming_lanes = fragment.get("lanes", [])
        for lane in incoming_lanes:
            lane_id = lane.get("laneId")
            if lane_id is None:
                continue

            if lane_id in target["lanes"]:
                # Check for conflicting geometry overwrite
                existing = target["lanes"][lane_id]
                if existing.get("nodes") != lane.get("nodes"):
                    violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message=(
                                f"Conflicting overwrite for laneId {lane_id} in intersection "
                                f"{key} across layerId {layer_id}"
                            ),
                            remediation_hint=(
                                "Multi-fragment MAPEMs must be merged additively. "
                                "Never overwrite existing lane geometries for the same lane ID."
                            ),
                        )
                    )
            else:
                target["lanes"][lane_id] = lane

        return violations
