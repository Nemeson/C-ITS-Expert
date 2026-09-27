---
name: cits-expert
description: Use when developing, analyzing, decoding, or validating C-ITS and V2X applications, protocol messages (CAM, DENM, MAPEM, SPATEM, SREM, SSEM, IVIM, CPM), PCAP/PCAPNG packet dissections (DLT 127 Radiotap, LLC/SNAP, GeoNetworking, BTP), ASN.1 UPER/COER bitstreams, intersection topology geometry, signal phase forecasting, prioritization state machines, or interfacing ESP32-C5 / RSU hardware.
---

# C-ITS & V2X Protocol Engineering

## Overview

Cooperative Intelligent Transport Systems (C-ITS) and Vehicle-to-Everything (V2X) connect vehicles, infrastructure (RSUs), and road users over 5.9 GHz ITS-G5 (802.11p) and C-V2X. This skill provides standards, dissection pipelines, topology algorithms, and automated validation tools (`cits-lint`, `cits-mcp`).

---

## The C-ITS Iron Law: Zero Data Hallucination

```
NEVER SYNTHESIZE OR INVENT PROTOCOL DATA
```

1. **No Fake Signals or Phases:** If SPATEM is absent, signal groups and phase states MUST remain empty (`null`/`[]`). Never invent 90s fixed cycles or modulo phases (`(laneId % 4) + 1`).
2. **No Fake Trajectories:** Never generate synthetic GNSS drift or speed profiles using mathematical functions (e.g. sine curves). If sensor feeds are missing, report `None`.
3. **No Synthetic-Only Fixtures:** Tests MUST exercise real field PCAPs (DLT 127 Radiotap, multi-fragment MAPEMs, nanosecond timestamps). Never declare decoders production-ready based solely on synthetic fixtures.

---

## Domain Routing Matrix

Load the corresponding reference module for detailed specifications, byte layouts, and implementation patterns:

| Task / Phenomenon | Reference Guide | Key Invariants |
| :--- | :--- | :--- |
| **PCAP & Wire Dissection** | [`references/packet-dissection.md`](references/packet-dissection.md) | DLT 127 Radiotap skip (`it_len`), LLC/SNAP `0x8947`, Nanosecond magic (`0xa1b23c4d`), BTP ports (2001–2008). |
| **ASN.1 & Standards Matrix** | [`references/standards-and-asn1.md`](references/standards-and-asn1.md) | Release 1 (EN 302 637-2/3) vs. Release 2 (TS 103 900/831), UPER unaligned packing, extension markers (`...`), $10^{-7}$ coordinate scaling. |
| **Intersection Topology** | [`references/topology-mapem-spatem.md`](references/topology-mapem-spatem.md) | Multi-fragment MAPEM merge by `(regionId, intersectionId)` across `layerID`, Node 0 stopline orientation, ingress-egress tangents, LISA LV.XML mapping. |
| **Priority & GLOSA** | [`references/priority-and-glosa.md`](references/priority-and-glosa.md) | SREM 4-tuple correlation `(intersectionId, requestId, sequenceNumber, requestorStationId)`, countdown horizon metrics (MAE/staleness), ETA trajectories. |
| **ESP32 & RSU Hardware** | [`references/hardware-and-capture.md`](references/hardware-and-capture.md) | ESP32-C5 native (`0x303A:0x1001`) vs. CH343 (`0x1A86:0x55D3`), `ITS5`/`ITS6` RSSI framing, host-anchored uptime clocks, Linux RSU SSH `tcpdump -U`. |
| **Quality & Anti-Patterns** | [`references/anti-patterns-and-verification.md`](references/anti-patterns-and-verification.md) | Prohibited rationalizations, verification checklist, mandatory real-capture fixtures. |

---

## Pre-Commit Verification Gate

Before committing code in any C-ITS repository:
1. **Real PCAP Gate:** Verified against real captures containing DLT 127 Radiotap.
2. **Topology Gate:** Verified that MAPEM connections bind to Node 0 stoplines.
3. **Time Base Gate:** Verified that firmware timestamps anchor against host wall time.
4. **Automated Audit:** Run `cits-lint` or use `cits-mcp` (`cits_audit_code`) to ensure zero hallucinations.
