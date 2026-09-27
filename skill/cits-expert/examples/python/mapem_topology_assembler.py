"""MAPEM Topology Assembler and Multi-Fragment Stitcher.

Implements multi-fragment MAPEM aggregation across layerIDs without lane overwriting,
and generates topological connections originating at Node 0 stoplines to prevent overlong chords.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


def haversine_distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Computes great-circle distance between two WGS84 points in meters."""
    r = 6371000.0  # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


@dataclass
class IntersectionFragmentState:
    region_id: int
    intersection_id: int
    revision: int
    ref_point: dict[str, float]
    lanes: dict[int, dict[str, Any]] = field(default_factory=dict)
    layers_seen: set[int] = field(default_factory=set)


class MapemTopologyAssembler:
    """Aggregates segmented MAPEM fragments into a coherent intersection graph."""

    def __init__(self) -> None:
        self._intersections: dict[tuple[int, int], IntersectionFragmentState] = {}

    def ingest_fragment(self, fragment: dict[str, Any]) -> None:
        region_id = fragment.get("region_id", 0)
        intersection_id = fragment["intersection_id"]
        key = (region_id, intersection_id)

        if key not in self._intersections:
            self._intersections[key] = IntersectionFragmentState(
                region_id=region_id,
                intersection_id=intersection_id,
                revision=fragment.get("revision", 0),
                ref_point=fragment.get("ref_point", {"lat": 0.0, "lon": 0.0}),
            )

        state = self._intersections[key]
        layer_id = fragment.get("layer_id", 0)
        state.layers_seen.add(layer_id)

        # Merge lanes additively across fragments
        for lane in fragment.get("lanes", []):
            lane_id = lane["lane_id"]
            state.lanes[lane_id] = lane

    def build_topology(self, region_id: int, intersection_id: int) -> dict[str, Any] | None:
        key = (region_id, intersection_id)
        if key not in self._intersections:
            return None

        state = self._intersections[key]
        lanes_list = list(state.lanes.values())
        connections = []

        # Build topological connections between Ingress Node 0 and Target Egress Node 0
        for lane in lanes_list:
            if lane.get("lane_type") != "ingress":
                continue

            ingress_nodes = lane.get("nodes", [])
            if not ingress_nodes:
                continue
            # Node 0 is the stopline (intersection-facing node)
            stopline_node = ingress_nodes[0]
            from_pt = (stopline_node["lat"], stopline_node["lon"])

            for conn in lane.get("connects_to", []):
                target_lane_id = conn["connecting_lane_id"]
                target_lane = state.lanes.get(target_lane_id)
                if not target_lane:
                    continue

                target_nodes = target_lane.get("nodes", [])
                if not target_nodes:
                    continue
                # Target Node 0 is the start of the egress lane
                egress_node = target_nodes[0]
                to_pt = (egress_node["lat"], egress_node["lon"])

                dist_m = haversine_distance_meters(from_pt[0], from_pt[1], to_pt[0], to_pt[1])

                connections.append(
                    {
                        "from_lane_id": lane["lane_id"],
                        "to_lane_id": target_lane_id,
                        "signal_group": conn.get("signal_group"),
                        "connection_id": conn.get("connection_id"),
                        "from_point": from_pt,
                        "to_point": to_pt,
                        "distance_meters": dist_m,
                    }
                )

        return {
            "region_id": region_id,
            "intersection_id": intersection_id,
            "revision": state.revision,
            "ref_point": state.ref_point,
            "layers": list(state.layers_seen),
            "lanes": lanes_list,
            "connections": connections,
        }
