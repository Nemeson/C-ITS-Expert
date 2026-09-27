# MAPEM & SPATEM Topography, Geometry, and Signal Dynamics Reference

## 1. Multi-Fragment MAPEM Reconstruction

In field deployments, road operators frequently split complex intersections into multiple MAPEM messages:
- Example: `layerID = 21` carries Inbound Approach lanes (1..10), while `layerID = 22` carries Outbound Egress lanes (11..20).
- **The Segmentation Bug:** A naive decoder that stores the latest message or the fragment with the most lanes replaces previous fragments. Consequently, connecting lanes in the other layer disappear, producing one-point lines that map renderers discard.
- **Correct Assembling Rule:**
  - Key: `(regionId, intersectionId)`.
  - Maintain an additive map of `lanes[laneId]`.
  - Do NOT overwrite an existing intersection unless `revision` changes.
  - Track `layers_seen` to verify full intersection reconstruction.

---

## 2. Lane Geometry & Node 0 Stopline Orientation

ISO TS 19091 encodes lane geometries as cumulative delta vectors (`Node-XY`):
- `refPoint` is the intersection reference position (WGS84 lat/lon in $10^{-7}$ deg).
- **Node 0 is the Reference Node nearest the intersection center (the Stopline for Ingress lanes, or the crosswalk/egress beginning for Egress lanes).**
- Subsequent Nodes ($1 \dots N$) progress **upstream** (further away from the intersection).

```
[Node 2: Far Upstream] <--- [Node 1: Mid-Lane] <--- [Node 0: Stopline]
                                                          |
                                                  (connectsTo Arc)
                                                          v
[Node 2: Far Downstream] <--- [Node 1: Egress] <--- [Node 0: Egress Start]
```

### The "5-Fold Overlong Chord" Error
If an application generates connections by linking `points[points.length - 1]` (the lane tail) instead of `points[0]` (the stopline), the connection line becomes a 60–140 meter chord slicing across oncoming traffic lanes.
- **Rule:** Always connect `ingress.nodes[0]` to `egress.nodes[0]` using a smooth curve (tangent/Bézier).

---

## 3. SPATEM Real-Time Quality & Signal Dynamics

SPATEM conveys real-time phase states via `MovementState` and `MovementEvent`:

### 3.1 Signal Group Binding
- Signal groups are bound to connections via MAPEM's `connectsTo[].signalGroup`.
- **STRICT PROHIBITION:** Never calculate signal groups using modulo arithmetic (e.g. `(laneId % 4) + 1`). If a lane has no matching signal group in MAPEM, display it as unassigned.

### 3.2 Dynamic Horizon & Quality Metrics
- `eventState`: Phase state (stop-and-remain / red, permissive-movement-allowed / green, protected-movement-allowed / protected green).
- `minEndTime` / `maxEndTime`: The predicted end of the current phase in tenths of seconds within the current hour (modulo 36000).
- **Quality Checks:**
  - **MAE (Mean Absolute Error):** Difference between predicted `minEndTime` and actual phase transition time.
  - **Freeze Detection:** Flag if countdown freezes while traffic continues.
  - **Staleness:** Flag if SPATEM is not updated within standard interval ($100$ ms to $500$ ms).

---

## 4. LISA Supply File Integration (LV.XML)

RSU controllers configured with LISA systems (e.g. Schlothauer & Wauer) export supply XML files (`LV.XML`).
- Map numeric `signalGroup` IDs (e.g., `1`, `7`) to human-readable designations:
  - `K1`, `K2`: Kraftfahrzeug (Vehicle signal groups)
  - `F5`, `F6`: Fußgänger (Pedestrian signal groups)
  - `R3`: Radfahrer (Cyclist signal groups)
  - `Ö1`: ÖPNV (Public transport / tram signal groups)
