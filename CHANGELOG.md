# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned (Milestone 2 - v1.3.0: European Day-2 Suite)
- **CPM (Collective Perception Message, ETSI TS 103 324):** Perceived object container dissection, sensor field-of-view cones, dynamic tracking coordinate scaling.
- **VAM (Vulnerable Road User Awareness Message, ETSI TS 103 300-3):** VRU cluster profiles, trajectory forecasting, path history analysis.
- **ETSI TS 103 097 PKI SecuredData:** Header-Audit & certificate chain verification frames.

---

## [1.2.0] - 2026-09-27

### Added
- **3D Geo-Visualizer & Exporter (`cits_validator/geo/`):**
  - Pure-Python **OGC KML 2.2** 3D visualizer (`export_mapem_kml`) with 3D coordinate tuples `(lon, lat, alt)`, extruded ribbons, and dedicated Node-0 Ingress Stopline Placemarks.
  - Pure-Python **RFC 7946 GeoJSON** exporter (`export_mapem_geojson`) with semantic color styling (Cyan for Ingress, Emerald for Egress, Orange for Crosswalks, Yellow for Connections) and stopline markers.
  - Zero third-party GIS or C-extension dependencies (no `shapely`, `geopandas`, or `simplekml` required).
- **LISA `LV.XML` Signal Compiler (`cits_validator/lisa/`):**
  - Full parser and object model for European traffic controller configuration XML files (`LisaSupplyCatalog`, `LisaSignalGroup`).
  - Heuristic classifier identifying traffic participant movements: vehicle (`K`), pedestrian (`F`), bicycle (`R`), transit (`B`).
  - Robust handling of separated turn arrows (Yellow + Green without Red) and case-insensitive XML attribute extraction.
- **GLOSA Trajectory Engine (`cits_validator/geo/glosa.py`):**
  - Implementation adhering to **ISO TS 19091** and **ETSI TS 103 301**.
  - Dynamic speed window calculation (`[speed_min_kmh, speed_max_kmh]`) and driving maneuver recommendations: `CRUISE`, `DECELERATE`, `ACCELERATE`, and `PREPARE_TO_STOP`.
- **New CLI Command (`cits-export`):**
  - Console command to transform MAPEM topologies into 3D KML and RFC 7946 GeoJSON documents.
  - Supports `--mapem`, `--lisa`, `--format`, `--output`, and `--name` options.
- **Expanded MCP Server Tools (`cits-mcp`):**
  - `cits_parse_lisa`: Ingests and classifies LISA `LV.XML` supply files into structured JSON catalogs.
  - `cits_compute_glosa`: Real-time calculation of Green Light Optimal Speed Advisory speed windows.
  - `cits_export_kml`: Generates 3D KML documents directly from AI coding agent pair-programming contexts.
- **Testing & Quality:**
  - Expanded test suite to **62 automated tests** (100% passing).
  - Added test modules: `tests/geo/test_geojson_builder.py`, `tests/geo/test_kml_builder.py`, `tests/geo/test_glosa.py`, `tests/lisa/test_lisa_parser.py`, `tests/cli/test_export_cli.py`.

### Changed
- Updated `pyproject.toml` version to `1.2.0` and refined setuptools package discovery with `include = ["cits_validator*"]`.
- Modernized SPDX license declaration (`license = "MIT"`).
- Updated `README.md` to reflect all new CLI commands, 3D visualizers, and test matrix expansion.

---

## [1.1.0] - 2026-09-27

### Added
- **Automated Validation Core (`cits_validator`):**
  - Rule registry and validator data models (`ValidationReport`, `Violation`, `Severity`).
  - Zero-copy streaming PCAP/PCAPNG reader (`PcapStreamingIterator`) operating with $< 2$ MB RAM footprint.
- **Conformance Rules Engine (R01–R05):**
  - `R01_LINK_LAYER`: DLT 127 Radiotap length offset validation, nanosecond magic header verification, and LLC/SNAP `0x8947` frame demultiplexing.
  - `R02_ANTI_HALLUCINATION`: AST and regex static analysis detecting synthetic GNSS drift (`sin(t)`), modulo phase arithmetic, and 90-second static cycle loops.
  - `R03_MAPEM_TOPOLOGY`: Multi-fragment additive accumulation without state overwrite and detection of overlong diagonal chords ($> 25$ m).
  - `R04_PRIORITY_SESSION`: SREM/SSEM 4-tuple session tracking `(intersectionId, requestId, sequenceNumber, requestorStationId)` and unclosed session timeouts.
  - `R05_HARDWARE_STREAM`: ESP32-C5 native USB CDC vs CH343 UART routing, `ITS5`/`ITS6` framing, host wall-clock time anchoring, and RSSI sentinel mapping.
- **CLI Linter (`cits-lint`):**
  - Terminal tool supporting file and recursive directory scanning, strict warning promotion, and text/JSON report formatting.
- **Interactive MCP Server (`cits-mcp`):**
  - Pure-Python STDIO JSON-RPC 2.0 MCP server exposing validation tools to AI coding agents.
- **End-to-End Test Suite:**
  - Added `tests/validator/test_e2e.py` covering live CLI subprocesses and live STDIO MCP client pipes.

---

## [1.0.0] - 2026-09-27

### Added
- **Initial Release:** Universal C-ITS & V2X Knowledge, Dissection, and Engineering Skill Suite.
- **Agent Skill Core (`skill/cits-expert/SKILL.md`):**
  - Token-efficient root skill trigger ($< 450$ words) complying with AgentSkills.io standards.
  - Comprehensive reference modules for packet dissection, ASN.1 UPER bitstreams, MAPEM/SPATEM topology, SREM/SSEM priority, and ESP32-C5 / Linux RSU hardware.
- **Polyglot Reference Implementations:**
  - Bit-exact reference implementations in Python, Rust, TypeScript, JavaScript, C++17, and Java.
- **Synchronization Utility (`sync_skill.py`):**
  - One-command synchronizer for Antigravity, OpenCode, Codex, and Claude Code environments.

[Unreleased]: https://github.com/Nemeson/C-ITS-Expert/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Nemeson/C-ITS-Expert/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Nemeson/C-ITS-Expert/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Nemeson/C-ITS-Expert/releases/tag/v1.0.0
