/**
 * Vanilla JavaScript MAPEM Lane Geometry & Ingress-to-Egress Connection Curve Generator.
 * Connects Node 0 of Ingress lane to Node 0 of Egress lane to prevent overlong chord errors.
 */

class LaneGeometryBuilder {
  /**
   * Builds topological connection lines between Ingress Stoplines (Node 0) and Egress starts (Node 0).
   * @param {Array<{laneId: number, laneType: string, nodes: Array<{lat: number, lon: number}>, connectsTo: Array<{connectingLaneId: number, signalGroup?: number, connectionId?: number}>}>} lanes
   * @returns {Array<{fromLaneId: number, toLaneId: number, signalGroup?: number, coordinates: Array<[number, number]>, lengthMeters: number}>}
   */
  static buildConnections(lanes) {
    const laneMap = new Map();
    for (const lane of lanes) {
      laneMap.set(lane.laneId, lane);
    }

    const connections = [];

    for (const lane of lanes) {
      if (lane.laneType !== 'ingress' || !lane.nodes || lane.nodes.length === 0) continue;

      // Node 0 is the stopline
      const stopline = lane.nodes[0];

      for (const conn of lane.connectsTo || []) {
        const target = laneMap.get(conn.connectingLaneId);
        if (!target || !target.nodes || target.nodes.length === 0) continue;

        // Target Node 0 is the start of the egress lane
        const egressStart = target.nodes[0];

        const p1 = [stopline.lon, stopline.lat];
        const p2 = [egressStart.lon, egressStart.lat];

        const dist = this.haversineDistance(stopline.lat, stopline.lon, egressStart.lat, egressStart.lon);

        connections.push({
          fromLaneId: lane.laneId,
          toLaneId: conn.connectingLaneId,
          signalGroup: conn.signalGroup,
          coordinates: [p1, p2],
          lengthMeters: dist,
        });
      }
    }

    return connections;
  }

  static haversineDistance(lat1, lon1, lat2, lon2) {
    const R = 6371000; // meters
    const dLat = ((lat2 - lat1) * Math.PI) / 180;
    const dLon = ((lon2 - lon1) * Math.PI) / 180;
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LaneGeometryBuilder };
}
