from mapem_topology_assembler import MapemTopologyAssembler


def test_multi_fragment_merging():
    assembler = MapemTopologyAssembler()

    # Fragment 1: Layer 21 contains Inbound approach lanes (IDs 1, 2)
    frag1 = {
        "region_id": 3,
        "intersection_id": 1732,
        "layer_id": 21,
        "revision": 1,
        "ref_point": {"lat": 53.5500000, "lon": 10.0000000},
        "lanes": [
            {
                "lane_id": 1,
                "lane_type": "ingress",
                "nodes": [
                    {"lat": 53.5501000, "lon": 10.0000500},  # Node 0 (Stopline)
                    {"lat": 53.5508000, "lon": 10.0000500},  # Node 1 (Upstream tail)
                ],
                "connects_to": [{"connecting_lane_id": 12, "signal_group": 7, "connection_id": 9}],
            }
        ],
    }

    # Fragment 2: Layer 22 contains Outbound egress lanes (IDs 11, 12)
    frag2 = {
        "region_id": 3,
        "intersection_id": 1732,
        "layer_id": 22,
        "revision": 1,
        "ref_point": {"lat": 53.5500000, "lon": 10.0000000},
        "lanes": [
            {
                "lane_id": 12,
                "lane_type": "egress",
                "nodes": [
                    {"lat": 53.5502000, "lon": 10.0002000},  # Node 0 (Egress start)
                    {"lat": 53.5509000, "lon": 10.0005000},  # Node 1 (Egress tail)
                ],
                "connects_to": [],
            }
        ],
    }

    assembler.ingest_fragment(frag1)
    assembler.ingest_fragment(frag2)

    topology = assembler.build_topology(region_id=3, intersection_id=1732)
    assert topology is not None
    # Both lanes must exist in the merged topology
    assert len(topology["lanes"]) == 2
    lane_ids = {lane["lane_id"] for lane in topology["lanes"]}
    assert lane_ids == {1, 12}


def test_node_zero_stopline_orientation_and_connection_distance():
    assembler = MapemTopologyAssembler()

    frag1 = {
        "region_id": 3,
        "intersection_id": 1732,
        "layer_id": 21,
        "revision": 1,
        "ref_point": {"lat": 53.5500000, "lon": 10.0000000},
        "lanes": [
            {
                "lane_id": 2,
                "lane_type": "ingress",
                "nodes": [
                    {"lat": 53.5501000, "lon": 10.0000500},  # Node 0 (Stopline, ~11m from center)
                    {"lat": 53.5510000, "lon": 10.0000500},  # Node 1 (Upstream tail, ~111m away!)
                ],
                "connects_to": [{"connecting_lane_id": 12, "signal_group": 7, "connection_id": 1}],
            },
            {
                "lane_id": 12,
                "lane_type": "egress",
                "nodes": [
                    {"lat": 53.5502000, "lon": 10.0002000},  # Node 0 (Egress start)
                    {"lat": 53.5511000, "lon": 10.0002000},  # Node 1 (Egress tail)
                ],
                "connects_to": [],
            },
        ],
    }
    assembler.ingest_fragment(frag1)
    topology = assembler.build_topology(region_id=3, intersection_id=1732)
    connections = topology["connections"]

    assert len(connections) == 1
    conn = connections[0]
    # Ingress stopline is Node 0
    assert conn["from_point"] == (53.5501000, 10.0000500)
    # Egress junction start is Node 0
    assert conn["to_point"] == (53.5502000, 10.0002000)
    # Distance between Node 0 and Node 0 must be short (< 30 meters), NOT > 100 meters
    assert conn["distance_meters"] < 30.0
