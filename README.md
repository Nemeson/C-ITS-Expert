# C-ITS Expert: The Definitive V2X Engineering & Agent Skill Suite

[![CI Pipeline](https://github.com/Nemeson/C-ITS-Expert/actions/workflows/validate-skill.yml/badge.svg)](https://github.com/Nemeson/C-ITS-Expert/actions)
[![Release](https://img.shields.io/github/v/release/Nemeson/C-ITS-Expert)](https://github.com/Nemeson/C-ITS-Expert/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Changelog](https://img.shields.io/badge/Changelog-Keep%20a%20Changelog-blue.svg)](CHANGELOG.md)
[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![AgentSkills Standard](https://img.shields.io/badge/AgentSkills.io-Compliant-green.svg)](https://agentskills.io)
[![Standards](https://img.shields.io/badge/Standards-ETSI%20%7C%20ISO%20%7C%20IEEE%20%7C%20C--Roads-orange.svg)](#standards-and-specifications)
[![Hardware](https://img.shields.io/badge/Hardware-ESP32--C5%20%7C%20Linux--RSU-red.svg)](#hardware-sniffing-and-field-capture)

<p align="center">
  <img src="docs/assets/banner.jpg" alt="C-ITS Expert Header Banner" width="100%" />
</p>

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
- [🛠️ Tool Suite: CLI Linter, 3D Geo-Visualizer & MCP Server](#️-tool-suite-cli-linter-3d-geo-visualizer--mcp-server)
  - [1. Terminal Validator (`cits-lint`)](#1-terminal-validator-cits-lint)
  - [2. 3D Geo-Visualizer & Exporter (`cits-export`)](#2-3d-geo-visualizer--exporter-cits-export)
  - [3. Interactive MCP Server (`cits-mcp`)](#3-interactive-mcp-server-cits-mcp)
- [📦 Universal Installation across AI Agent Runtimes](#-universal-installation-across-ai-agent-runtimes)
- [🧪 Automated Test Suite & CI/CD Pipeline](#-automated-test-suite--cicd-pipeline)
- [📚 Standards & Specifications](#-standards--specifications)
- [📄 License & Copyright](#-license--copyright)
- [📝 Changelog](CHANGELOG.md)

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

## 🛠️ Tool Suite: CLI Linter, 3D Geo-Visualizer & MCP Server

To programmatically halt LLM hallucinations and enforce empirical protocol rules at build time, the repository ships with `cits_validator`, providing validation, export, and interactive agent tools:

### 1. Terminal Validator (`cits-lint`)
Streams classic PCAP **and PCAPNG** captures and statically audits source code and topology files:
```bash
# Scan a capture for DLT 127 Radiotap, nanosecond magic, GeoNetworking/BTP and (optionally) ASN.1
cits-lint capture.pcap
cits-lint capture.pcapng --asn1 --release r2

# Audit source code for prohibited synthetic GNSS math and modulo signal groups
cits-lint src/v2x/ --strict --format json

# Audit a MAPEM topology document (connections / multi-fragment accumulation)
cits-lint --topology intersection.json --max-chord 25

# Decode one PDU straight from hex
cits-lint --pdu 0204000013900000181c81000000001043000320 --msg-type SPATEM
```

**Rules:**

| ID | Checks |
| :--- | :--- |
| `R01` | Radiotap length, 802.11 QoS/WDS MAC header, LLC/SNAP `0x8947`, GeoNetworking framing, BTP port. IEEE 1609.2 secured frames are counted as `secured`; for signed messages the BTP port is read from the envelope (encrypted ones stay opaque). Unknown BTP ports are reported once. |
| `R02` | Anti-hallucination source audit: synthetic GNSS drift, modulo signal groups, 90 s static cycles. Strings/comments are not treated as code; `# cits-lint: allow` silences a line. |
| `R03` | Multi-fragment MAPEM accumulation and stopline chord bounds (configurable via `--max-chord`). |
| `R04` | SREM/SSEM 4-tuple session tracking and unclosed priority requests. |
| `R05` | ESP32-C5 `ITS5`/`ITS6` framing, RSSI sentinel, host time anchoring. |
| `R06` | ASN.1/UPER conformance against the vendored ETSI/ISO modules (needs the `[asn1]` extra). Decodes CAM, DENM, MAPEM, SPATEM, SREM, SSEM, CPM and VAM, including the payload of IEEE 1609.2 *signed* messages (signatures are not verified). Also flags trailing bytes, `messageID`/port mismatches and the sampling cutoff. |

### BTP destination ports (ETSI TS 103 248, Table 1)

| Port | Service | Port | Service |
| :--- | :--- | :--- | :--- |
| 2001 | CAM | 2009 | **CPM** (TS 103 324) |
| 2002 | DENM | 2010 | EVCSN POI |
| 2003 | MAPEM | 2011 | TPG (TRM/TCM/…) |
| 2004 | SPATEM | 2013 | RTCMEM |
| 2005 | SAEM | **2018** | **VAM** (TS 103 300-3) |
| 2006 | IVIM | 2019 | IMZM |
| 2007 | SREM | | |
| 2008 | SSEM | | |

CPM and VAM are Release 2 services with no Release 1 baseline; `--release r1` refuses them rather than decoding against the wrong data dictionary.

Every report carries a **data coverage** section: a capture in which no GeoNetworking/BTP record was reachable states `NO DATA IN CAPTURE` instead of passing silently, and `error_count` stays authoritative even when repeated findings are listed only as a sample.

### 2. 3D Geo-Visualizer & Exporter (`cits-export`)
Converts MAPEM topologies — from a JSON document **or from a raw MAPEM PDU** — into 3D KML (Google Earth Pro / ArcGIS) and RFC 7946 GeoJSON, enriched with LISA `LV.XML` signal group designations:
```bash
# Export MAPEM topology to 3D KML document with stopline Node-0 orientation markers
cits-export --mapem intersection.json --lisa supply.xml --format kml --output intersection.kml

# Export MAPEM topology to RFC 7946 GeoJSON with semantic traffic participant coloring
cits-export --mapem intersection.json --lisa supply.xml --format geojson --output intersection.geojson

# Decode a real MAPEM PDU and map the geometry directly (no intermediate JSON)
cits-export --pdu a2b4c6... --release r1 --format geojson --output intersection.geojson
```

### 3. Interactive MCP Server (`cits-mcp`)
Connect `cits-mcp` directly to **Antigravity**, **Claude Code**, or **Cursor** to let coding agents self-audit code snippets, packet byte-streams, and compute GLOSA trajectories during pair-programming:

```json
{
  "mcpServers": {
    "cits-validator": {
      "command": "python",
      "args": ["-m", "cits_validator.mcp.server"]
    }
  }
}
```

Exposed Agent Tools:
* `cits_audit_code(code, language, rules)`: Registry-backed scanner detecting `sin(t)` coordinate drift, modulo phase arithmetic, and 90-second static cycle loops (same rule set as `cits-lint --rules`).
* `cits_inspect_hex(hex_payload, dlt)`: Wire dissector verifying Radiotap offsets, 802.11 QoS headers, LLC/SNAP `0x8947`, GeoNetworking framing and the BTP port.
* `cits_check_mapem(lanes_geojson, max_chord_meters)`: Checks stopline Node-0 orientations and flags diagonal overlong chords.
* `cits_validate_pcap(file_path)`: Streams and audits full PCAP/PCAPNG capture files (bounded by `CITS_MCP_MAX_FILE_BYTES` and `CITS_MCP_MAX_PACKETS`).
* `cits_parse_lisa(xml_content)`: Ingests LISA `LV.XML` controller files and classifies signal groups (e.g. `K1` vehicle, `F5` pedestrian, `R17` bicycle).
* `cits_compute_glosa(distance_m, speed_kmh, phase_state, time_to_phase_end_s, ...)`: Real-time Green Light Optimal Speed Advisory trajectory calculation engine.
* `cits_export_kml(lanes_json, lisa_xml, intersection_name)`: Generates pure-Python 3D OGC KML 2.2 documents with extruded lane ribbons and stopline markers.
* `cits_decode_pdu(hex_payload, msg_type, release)`: Decodes a CAM/DENM/MAPEM/SPATEM/SREM/SSEM PDU against the vendored ETSI/ISO modules and returns the fields plus the standards used.
* `cits_decode_mapem_to_geojson(hex_payload, release, lisa_xml)`: Decodes a MAPEM PDU straight to GeoJSON, reporting `lane_count` and `data_status` so an empty result is visible.
* `cits_selftest()`: Liveness/health probe returning the active profile and version.

Read-only resources: `cits://rules` (machine-readable rule catalog) and `cits://version`.

#### Capability profiles

The server exposes a filtered tool surface per role, selected with `CITS_MCP_PROFILE`:

| Profile | Tools | Purpose |
| :--- | :--- | :--- |
| `host` (default) | all tools | Development host / coding agents. |
| `device` | read-only tools only (`inspect_hex`, `validate_pcap`, `check_mapem`, `compute_glosa`, `parse_lisa`, `selftest`) | On-RSU / edge deployment. |
| `ci` | `validate_pcap`, `audit_code`, `decode_pdu` | Pipeline gate. |

#### Security & limits (environment)

- `CITS_MCP_BIND_HOST` — bind address (default `127.0.0.1`). A non-loopback bind **requires** `CITS_MCP_TOKEN` or the server refuses to start.
- `CITS_MCP_TOKEN` — shared token for remote binds.
- `CITS_MCP_ROOTS` — path allowlist separated by the platform path separator (`;` on Windows, `:` on POSIX); **every** profile refuses file paths outside it (default: the working directory). A filesystem root such as `/` is refused.
- `CITS_MCP_MAX_OUTPUT_BYTES` — output cap (default `262144`, minimum `1024`). The cap applies to the exact JSON that is sent: lists are truncated at a record boundary and marked `truncated` with a `total`; data that cannot be truncated becomes `{"error": "output too large", ...}`.
- `CITS_MCP_MAX_FILE_BYTES` — largest capture file `cits_validate_pcap` opens (default 256 MiB).
- `CITS_MCP_MAX_PACKETS` — packets inspected per scan (default 2,000,000); the scan stops with a warning.
- Tool arguments are validated against each tool's `inputSchema` (`-32602` on violation), request lines are limited to 8 MiB, and unexpected internal errors are reported as `Internal error: <Type>` without details.
- XML inputs (`xml_content`, `lisa_xml`) are parsed as text only; DTD/entity declarations are rejected.

#### Embedded deployment (`cits-edge`)

For constrained Linux (musl/static, low RAM/Flash), build a device-profile zipapp with
zero third-party dependencies and run it under systemd:

```bash
python scripts/build_edge_zipapp.py --output cits-edge.pyz   # also writes cits-edge.pyz.sha256
sha256sum -c cits-edge.pyz.sha256
python cits-edge.pyz selftest
```
The build is reproducible (identical sources give an identical archive) and the zipapp honours the `CITS_MCP_*` environment. A hardened unit template (`DynamicUser`, empty capability set, syscall/namespace restrictions, memory caps) is at [`packaging/cits-edge.service`](packaging/cits-edge.service); set `CITS_MCP_ROOTS` to the directory holding your captures.

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

# Optional: ASN.1 / UPER conformance core (rule R06, PDU decoding)
pip install -e .[asn1]

# Run full test suite (the CI coverage gate is 85 %)
pytest -q --cov=cits_validator --cov-fail-under=85

# Run linter and type checker
ruff check .
mypy cits_validator
```

### Verified Test Matrix (266 Tests, 100% Green)
- `tests/test_skill_spec.py`: Validates YAML frontmatter, token budget (< 450 words in `SKILL.md`), and markdown link integrity.
- `tests/test_dissection_reference.py`: Verifies DLT 127 Radiotap stripping, LLC/SNAP `0x8947` matching, and nanosecond PCAP detection on real byte sequences.
- `tests/test_mapem_topology.py`: Verifies additive multi-fragment MAPEM aggregation across `layerID` and Node 0 stopline connection distance.
- `tests/test_esp32_host_anchor.py`: Verifies boot-relative uptime translation, discontinuity detection (>2s backwards, >60s forwards), and RSSI sentinel mapping.
- `tests/geo/`: Tests pure-Python RFC 7946 GeoJSON export, 3D OGC KML 2.2 generation, and GLOSA speed advisory trajectories (cruise, decelerate, accelerate, stop).
- `tests/lisa/`: Tests LISA `LV.XML` supply compiler, signal group object mapping, and vehicle/pedestrian/cyclist classification heuristics.
- `tests/cli/`: End-to-end CLI tests for `cits-lint` and `cits-export` (stdout, file output, LISA enrichment, `--pdu`).
- `tests/asn1/`: ASN.1 conformance against byte-exact reference vectors from an independent encoder **and real field MAPEM captures** across both release baselines; the vendored-module provenance, the failure modes (truncated/garbage PDU never yields a partial decode) and the PDU → lane-geometry adapter.
- `tests/validator/`: Conformance rules R01–R06 including their error branches, live STDIO MCP server JSON-RPC dispatch, PCAPNG block parsing, profile filtering, security guards (`tests/validator/test_mcp_security.py`), resource reads, the `cits-edge` zipapp build/smoke test (`tests/validator/test_edge_zipapp.py`), and subprocess E2E validations.

### Standards corpus
The ASN.1 modules the conformance core compiles are vendored under
`cits_validator/asn1/standards/` (Release 1 and Release 2) and recorded in
`manifest.json` with their standard, version and origin. Refresh them with:

```bash
python scripts/vendor_asn1.py --source <path-to-standards-corpus>
```

### Known limitation: non-conformant captures
A capture whose 802.11 payload does not carry the LLC/SNAP header
`aa aa 03 00 00 00 89 47` is reported by `R01` as a framing error on every
record. This is intentional — the bytes do not contain a GeoNetworking frame at
the position the link layer says they should.

Concretely, `PCAPSender/tests/fixtures/All_UE_01.pcapng` (DLT 105, 4333 records)
yields 4333 `R01` findings. That is not a false positive: PCAPSender's own
dissector classifies **0 of those 4333** records as ITS-G5 for the same reason.
The origin is in the producing pipeline (firmware or capture writer), not in this
audit. Findings are listed as a sample (5 per rule per file) while `error_count`
keeps the authoritative total.

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
