# C-ITS Expert: The Definitive V2X Engineering & Agent Skill Suite

[![CI Pipeline](https://github.com/Nemeson/C-ITS-Expert/actions/workflows/validate-skill.yml/badge.svg)](https://github.com/Nemeson/C-ITS-Expert/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![AgentSkills Standard](https://img.shields.io/badge/AgentSkills.io-Compliant-green.svg)](https://agentskills.io)
[![Standards](https://img.shields.io/badge/Standards-ETSI%20%7C%20ISO%20%7C%20IEEE%20%7C%20C--Roads-orange.svg)](#standards-and-specifications)
[![Hardware](https://img.shields.io/badge/Hardware-ESP32--C5%20%7C%20Linux--RSU-red.svg)](#hardware-sniffing-and-field-capture)

**C-ITS Expert** is the authoritative, cross-platform engineering, packet dissection, and validation skill suite for **Cooperative Intelligent Transport Systems (C-ITS)** and **Vehicle-to-Everything (V2X)** communications.

Engineered specifically for **AI Coding Agents** (Claude Code, OpenAI Codex, OpenCode, Antigravity agy CLI, Hermes) and human automotive/systems engineers, this repository bridges the chasm between theoretical ASN.1 standards and harsh physical field realities: IEEE 802.11p 5.9 GHz RF captures, DLT 127 Radiotap encapsulations, multi-fragment MAPEM intersection geometries, and live Linux-based Roadside Unit (RSU) deployments.

---

## 📖 Table of Contents

- [🎯 Motivation & The "Zero Data Hallucination" Iron Law](#-motivation--the-zero-data-hallucination-iron-law)
- [🏛️ Architecture: Modular Hub-and-Spoke (< 450 Words)](#️-architecture-modular-hub-and-spoke--450-words)
- [📡 Core Capabilities & Deep Technical References](#-core-capabilities--deep-technical-references)
  - [1. Link-Layer & Packet Dissection (DLT 127 Radiotap)](#1-link-layer--packet-dissection-dlt-127-radiotap)
  - [2. Standards Matrix & ASN.1 / UPER Bitstreams](#2-standards-matrix--asn1--uper-bitstreams)
  - [3. MAPEM Topography & Stopline Node Geometry](#3-mapem-topography--stopline-node-geometry)
  - [4. SPATEM Signal Phase Quality & Prognosis](#4-spatem-signal-phase-quality--prognosis)
  - [5. SREM / SSEM Request Prioritization & GLOSA](#5-srem--ssem-request-prioritization--glosa)
  - [6. ESP32-C5 & Linux-based RSU Field Sniffing](#6-esp32-c5--linux-based-rsu-field-sniffing)
- [💻 Multi-Language Reference Implementations](#-multi-language-reference-implementations)
- [📦 Universal Installation across AI Agent Runtimes](#-universal-installation-across-ai-agent-runtimes)
- [🧪 Automated Test Suite & CI/CD Pipeline](#-automated-test-suite--cicd-pipeline)
- [📚 Standards & Specifications](#-standards--specifications)
- [📄 License & Copyright](#-license--copyright)

---

## 🎯 Motivation & The "Zero Data Hallucination" Iron Law

In practical AI-assisted automotive software development, Large Language Models repeatedly fall into insidious failure modes when confronted with complex V2X protocols. Because AI agents dislike incomplete data, they frequently **synthesize** plausible-looking fake values rather than handling decoding gaps:
1. **Synthetic GNSS Drift:** When reference trajectories were missing, AI agents generated synthetic sine-wave coordinates (`lat + sin(t) * 0.22`), while outputting official audit reports that certified sensor compliance for emergency braking systems.
2. **Modulo Signal Groups:** When MAPEM lane-to-phase bindings were complex, AI agents invented signal groups using modulo arithmetic (`(laneId % 4) + 1`), placing green lights on conflicting physical movements.
3. **Invented 90-Second Signal Cycles:** When real SPATEM messages were not yet unpacked, AI agents constructed static 90-second phase loops, completely blinding conformance checkers to yellow-time and cycle-time violations.
4. **Radiotap Blindness:** 98% of field captures use DLT 127 (`IEEE 802.11 + Radiotap`), not DLT 1 (`Ethernet`). Parsers that failed to unwrap Radiotap found 0 GeoNetworking frames, masking the failure behind synthetic fixtures.

### The Binding Iron Law

```
NEVER SYNTHESIZE OR INVENT PROTOCOL DATA
```

This skill strictly enforces:
- **Zero Hallucination:** If a decoder or message is absent, data fields MUST remain `null` / `None` / `[]`, and user interfaces MUST display *"No Data in Capture"*.
- **Mandatory Real-PCAP Verification:** Decoders cannot be certified production-ready using synthetic fixtures alone. Every implementation must pass verification against real field captures.

---

## 🏛️ Architecture: Modular Hub-and-Spoke (< 450 Words)

To comply with the [AgentSkills.io](https://agentskills.io) standard and prevent Large Language Model context exhaustion, the skill uses a **Hub-and-Spoke** architecture:

```
skill/cits-expert/
├── SKILL.md                          # Ultra-lean trigger file (< 450 words) with fast routing
├── references/                       # Detailed domain references loaded on-demand
│   ├── packet-dissection.md          # DLT 127/105/1, Radiotap, LLC/SNAP 0x8947, GeoNet, BTP, PKI
│   ├── standards-and-asn1.md         # Release 1 vs 2 Matrix, UPER bit packing, 10^-7 scaling
│   ├── topology-mapem-spatem.md      # Multi-fragment MAPEM assembling, Node 0 stopline math, LISA
│   ├── priority-and-glosa.md         # SREM/SSEM 4-tuple matching, countdown metrics, GLOSA windows
│   ├── hardware-and-capture.md       # ESP32-C5 (dual-USB, ITS5/6, time anchor), Linux RSU SSH
│   └── anti-patterns-and-verification.md # Binding prohibition table & test pyramid
└── examples/                         # Bit-exact, runnable implementations
    ├── python/                       # DltUnwrapper, MapemTopologyAssembler, Esp32HostTimeAnchor
    ├── rust/                         # Zero-copy nom dissector, lookahead ITS5/6 framing
    ├── typescript/                   # DataView packet reader, GeoJSON lane connection curve builder
    ├── javascript/                   # Vanilla JS DltReader, GeoJSON lane geometry builder
    ├── cpp/                          # Modern C++17 DltDissector, Esp32FramingEngine (header-only)
    └── java/                         # Android & Java SE DltReader, Esp32HostTimeAnchor
```

---

## 📡 Core Capabilities & Deep Technical References

### 1. Link-Layer & Packet Dissection (DLT 127 Radiotap)
*Reference:* [`skill/cits-expert/references/packet-dissection.md`](skill/cits-expert/references/packet-dissection.md)

Real-world test captures (from Linux-based RSUs or 5.9 GHz test vehicles) predominantly use **DLT 127** (`DLT_IEEE802_11_RADIO`).
- **Radiotap Stripping:** Read the 16-bit little-endian length at offset 2 (`it_len`), and skip exactly `it_len` bytes.
- **802.11 MAC Header:** Detect Frame Control Type 2 (Data) and Subtype 8 (QoS Data). Skip 26 bytes for QoS Data (24-byte MAC + 2-byte QoS Control) or 24 bytes for non-QoS.
- **LLC / SNAP Demultiplexing:** Verify the 8-byte magic `aa aa 03 00 00 00 89 47` (OUI `0x000000`, EtherType `0x8947` for GeoNetworking).
- **PCAP Timestamp Formats:** Detects microsecond (`0xa1b2c3d4`) vs. nanosecond (`0xa1b23c4d`) magic to prevent 1000-fold timestamp distortion.
- **BTP Ports:** Demultiplexes Basic Transport Protocol destination ports:
  - `2001`: CAM (Cooperative Awareness)
  - `2002`: DENM (Decentralized Environmental Notification)
  - `2003`: MAPEM (Map Extended / Topology)
  - `2004`: SPATEM (Signal Phase and Timing Extended)
  - `2006`: IVIM (Infrastructure to Vehicle Information)
  - `2007`: SREM (Signal Request Extended / Priority Request)
  - `2008`: SSEM (Signal Status Extended / Priority Status)

### 2. Standards Matrix & ASN.1 / UPER Bitstreams
*Reference:* [`skill/cits-expert/references/standards-and-asn1.md`](skill/cits-expert/references/standards-and-asn1.md)

Resolves discrepancies across European deployment generations:
- **CAM:** Release 1 (`ETSI EN 302 637-2 v1.4.1`) vs. Release 2 (`ETSI TS 103 900 v2.3.1`). *Crucial note:* There is no EN 302 637-2 V2.x; R2 transitioned to TS 103 900 and imports from `ETSI-ITS-CDD`.
- **DENM:** Release 1 (`ETSI EN 302 637-3 v1.3.1`) vs. Release 2 (`ETSI TS 103 831 v2.3.1`).
- **Common Data Dictionary (CDD):** `ITS-Container.asn` (R1) vs. `ETSI-ITS-CDD.asn` (R2).
- **UPER Bit Packing Rules:** Unaligned bitstreams without byte-padding. Mandatory handling of extension markers (`...`), where missing an extension bit cascades into a 1-bit drift destroying the remaining PDU.
- **Scale Factors:** Fixed-point coordinate scaling ($10^{-7}$ degrees for WGS84 decimal degrees), speeds in $0.01$ m/s, headings in $0.1$ degrees ($0 \dots 3600$).

### 3. MAPEM Topography & Stopline Node Geometry
*Reference:* [`skill/cits-expert/references/topology-mapem-spatem.md`](skill/cits-expert/references/topology-mapem-spatem.md)

- **Multi-Fragment Merging:** Intersections are frequently segmented across multiple MAPEM messages (`layerID` 21 for inbound lanes, 22 for outbound lanes). Intersections must be merged additively across `layerID` by `(regionId, intersectionId)` without overwriting previously received lanes.
- **Node 0 Stopline Orientation:** In ISO TS 19091, Node 0 is the reference node near the intersection center (the Stopline for Ingress lanes, or the start of the crosswalk for Egress lanes). Subsequent nodes progress upstream away from the intersection. Connecting lane tails (Node N) produces 5-fold overlong diagonal chords that cut across oncoming traffic.

### 4. SPATEM Signal Phase Quality & Prognosis
*Reference:* [`skill/cits-expert/references/topology-mapem-spatem.md`](skill/cits-expert/references/topology-mapem-spatem.md)

- **Signal Group Binding:** Strictly resolved through MAPEM `connectsTo[].signalGroup`, never through modulo math.
- **Dynamic Prognosis Horizon:** Evaluates `minEndTime` and `maxEndTime`, Mean Absolute Error (MAE), freeze detection, and phase staleness.
- **LISA Integration:** Resolves numerical signal groups into human-readable designations (`K1`, `K2` for vehicles, `F5`, `F6` for pedestrians, `Ö1` for public transit) via LISA supply files (`LV.XML`).

### 5. SREM / SSEM Request Prioritization & GLOSA
*Reference:* [`skill/cits-expert/references/priority-and-glosa.md`](skill/cits-expert/references/priority-and-glosa.md)

- **The Canonical 4-Tuple Invariant:** Matches vehicle priority requests (SREM) to infrastructure status responses (SSEM) across capture jitter:
  $$\text{Key} = (\text{intersectionId},\ \text{requestId},\ \text{sequenceNumber},\ \text{requestorStationId})$$
- **Prioritization State Machine:** Tracks requests across `Requested` $\to$ `Granted` / `Rejected` $\to$ `Active` $\to$ `Terminated` / `Timeout`.
- **GLOSA (Green Light Optimal Speed Advisory):** Computes optimal speed windows $[v_{min}, v_{max}]$ for vehicles to cross stoplines during green phases without stopping.

### 6. ESP32-C5 & Linux-based RSU Field Sniffing
*Reference:* [`skill/cits-expert/references/hardware-and-capture.md`](skill/cits-expert/references/hardware-and-capture.md)

- **Dual-USB Port Management (Waveshare ESP32-C5):**
  - **Native USB-JTAG (`VID 0x303A : PID 0x1001`):** High-speed binary 5.9 GHz V2X sniffing data stream (`ITS5`/`ITS6`).
  - **CH343 UART (`VID 0x1A86 : PID 0x55D3`):** Serial console and firmware flashing.
- **Framing Protocols (`ITS5` vs. `ITS6`):**
  - `ITS5` (14 bytes): Magic, uptime seconds, microseconds, length.
  - `ITS6` (15 bytes): Adds 1-byte RSSI in dBm. Sentinel `INT8_MIN = -128` denotes no signal level measured (`None`).
  - Lookahead magic validation prevents false positive payload collisions.
- **Host Wall-Clock Anchoring:** ESP32 firmware timestamps are boot-relative uptime counters. The host must anchor `SystemTime::now()` against the initial frame and detect discontinuities ($>2$ s backwards, $>60$ s forwards).
- **Linux RSU SSH Streaming:** Uses `sudo tcpdump -i <iface> -nn -s 4096 -U ether proto 0x8947 -w -` with mandatory `-U` (packet-buffered) flag, graceful SIGINT shutdown, and atomic renaming (`.tmp` $\to$ `.pcap`).

---

## 💻 Multi-Language Reference Implementations

The repository provides production-tested, self-contained reference code snippets in [`skill/cits-expert/examples/`](skill/cits-expert/examples/):

| Language | Module | Description |
| :--- | :--- | :--- |
| **Python** | [`dlt_unwrapper.py`](skill/cits-expert/examples/python/dlt_unwrapper.py) | Strips DLT 127/105/1, detects nanosecond PCAP magics, extracts BTP ports. |
| **Python** | [`mapem_topology_assembler.py`](skill/cits-expert/examples/python/mapem_topology_assembler.py) | Merges multi-fragment MAPEMs and links Node 0 stoplines with Haversine distance checks. |
| **Python** | [`esp32_host_anchor.py`](skill/cits-expert/examples/python/esp32_host_anchor.py) | Anchors ESP32 uptime to host wall-clock time and detects reboot discontinuities. |
| **Rust** | [`dissector.rs`](skill/cits-expert/examples/rust/dissector.rs) | Zero-copy `nom`-style dissector for Radiotap, 802.11 QoS Data, and LLC/SNAP. |
| **Rust** | [`esp32_framing.rs`](skill/cits-expert/examples/rust/esp32_framing.rs) | Lookahead `ITS5`/`ITS6` streaming parser with RSSI extraction and time anchoring. |
| **TypeScript** | [`dlt_reader.ts`](skill/cits-expert/examples/typescript/dlt_reader.ts) | `DataView`-based packet dissector for web and desktop UIs (Tauri/Svelte). |
| **TypeScript** | [`lane_geometry.ts`](skill/cits-expert/examples/typescript/lane_geometry.ts) | GeoJSON LineString generator for Ingress-to-Egress stopline curves. |
| **JavaScript** | [`dlt_reader.js`](skill/cits-expert/examples/javascript/dlt_reader.js) | Vanilla JS packet reader for Node.js / browser frontends (Leaflet/MapLibre). |
| **JavaScript** | [`lane_geometry.js`](skill/cits-expert/examples/javascript/lane_geometry.js) | Vanilla JS stopline curve generator and Haversine distance calculator. |
| **C++** | [`dlt_dissector.hpp`](skill/cits-expert/examples/cpp/dlt_dissector.hpp) | Header-only C++17 zero-copy link-layer unwrapper for embedded / RSU daemons. |
| **C++** | [`esp32_framing.hpp`](skill/cits-expert/examples/cpp/esp32_framing.hpp) | Header-only C++17 `ITS5`/`ITS6` streaming framing parser and time anchor. |
| **Java** | [`DltReader.java`](skill/cits-expert/examples/java/DltReader.java) | `ByteBuffer`-based DLT unwrapper for Android (MobileInspector) & Java SE. |
| **Java** | [`Esp32HostTimeAnchor.java`](skill/cits-expert/examples/java/Esp32HostTimeAnchor.java) | Android / Java SE host wall-clock time anchor and RSSI sentinel handler. |

---

## 📦 Universal Installation across AI Agent Runtimes

The bundled `sync_skill.py` utility synchronizes the skill suite across all major AI agent runtimes with a single command:

```bash
# 1. Clone the repository
git clone https://github.com/Nemeson/C-ITS-Expert.git
cd C-ITS-Expert

# 2. Install globally for all local AI agents
python sync_skill.py --install-global
```

This immediately registers the skill in:
- **Antigravity CLI & IDE:** `~/.gemini/config/plugins/cits-expert/skills/cits-expert`
- **Universal Agent Standard (OpenCode / Codex):** `~/.agents/skills/cits-expert`
- **Claude Code:** `~/.claude/skills/cits-expert`

### Project-Specific Deployment
To vendor the skill directly into a specific project repository:

```bash
python sync_skill.py --install-project C:/path/to/my-cits-project
```

---

## 🧪 Automated Test Suite & CI/CD Pipeline

The skill suite is fully covered by an automated test suite verifying both specification compliance and protocol algorithms:

```bash
# Install dependencies
pip install -e .[dev]

# Run full test suite
pytest -v

# Run linter
ruff check .
```

### Verified Test Matrix (16 Tests, 100% Green)
- `test_skill_spec.py`: Validates YAML frontmatter, token budget (< 450 words in `SKILL.md`), and markdown link integrity.
- `test_dissection_reference.py`: Verifies DLT 127 Radiotap stripping, LLC/SNAP `0x8947` matching, and nanosecond PCAP detection on real byte sequences.
- `test_mapem_topology.py`: Verifies additive multi-fragment MAPEM aggregation across `layerID` and Node 0 stopline connection distance.
- `test_esp32_host_anchor.py`: Verifies boot-relative uptime translation, discontinuity detection (>2s backwards, >60s forwards), and RSSI sentinel mapping.
- `test_sync_skill.py`: Verifies global and project-level synchronization paths.

---

## 📚 Standards & Specifications

This skill adheres to and cross-validates against official standards:
- **ETSI EN 302 637-2 / ETSI TS 103 900:** Cooperative Awareness Basic Service (CAM).
- **ETSI EN 302 637-3 / ETSI TS 103 831:** Decentralized Environmental Notification Basic Service (DENM).
- **ETSI TS 102 894-2:** Common Data Dictionary (CDD / `ETSI-ITS-CDD`).
- **ETSI TS 103 301 / ISO TS 19091:** Infrastructure Services (MAPEM, SPATEM, SREM, SSEM, IVIM, AddGrp-C).
- **ETSI EN 302 636-4-1 / EN 302 636-5-1:** GeoNetworking & Basic Transport Protocol (BTP).
- **IEEE 1609.2 / ETSI TS 103 097:** Security Header and Certificate Management.
- **C-Roads Harmonized Specifications:** Platform Releases 1.6 to 3.2.1.
- **Car2Car Communication Consortium (C2C-CC):** Basic System Profile Releases 1.6.10 & 2.0.2.

---

## 📄 License & Copyright

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

Copyright (c) 2026 Kevin Seipel. All rights reserved.  
Contact & Enterprise Licensing: `vertrieb@seipel.uk`
