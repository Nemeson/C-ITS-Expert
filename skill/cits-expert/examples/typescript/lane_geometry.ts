/**
 * MAPEM Lane Geometry & Ingress-to-Egress Connection Curve Generator.
 * Connects Node 0 of Ingress lane to Node 0 of Egress lane to prevent overlong chord errors.
 */

export interface LaneNode {
  lat: number;
  lon: number;
  elevationM?: number;
}

export interface LaneDefinition {
  laneId: number;
  laneType: 'ingress' | 'egress' | 'crosswalk' | 'bike';
  nodes: LaneNode[]; // Node 0 is the stopline / intersection-facing node
  connectsTo: Array<{
    connectingLaneId: number;
    signalGroup?: number;
    connectionId?: number;
  }>;
}

export interface ConnectionLine {
  fromLaneId: number;
  toLaneId: number;
  signalGroup?: number;
  coordinates: [number, number][]; // [lon, lat] GeoJSON format
  lengthMeters: number;
}

export class LaneGeometryBuilder {
  /**
   * Builds topological connection lines between Ingress Stoplines (Node 0) and Egress starts (Node 0).
   */
  public static buildConnections(lanes: LaneDefinition[]): ConnectionLine[] {
    const laneMap = new Map<number, LaneDefinition>();
    for (const lane of lanes) {
      laneMap.set(lane.laneId, lane);
    }

    const connections: ConnectionLine[] = [];

    for (const lane of lanes) {
      if (lane.laneType !== 'ingress' || lane.nodes.length === 0) continue;

      // Node 0 is the stopline
      const stopline = lane.nodes[0];

      for (const conn of lane.connectsTo) {
        const target = laneMap.get(conn.connectingLaneId);
        if (!target || target.nodes.length === 0) continue;

        // Target Node 0 is the start of the egress lane
        const egressStart = target.nodes[0];

        const p1: [number, number] = [stopline.lon, stopline.lat];
        const p2: [number, number] = [egressStart.lon, egressStart.lat];

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

  public static haversineDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
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
