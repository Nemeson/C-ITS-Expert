# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

### Changed

### Fixed

### Documented

### Planned (Milestone 3 - v1.5.0: European Day-2 Suite)
- **ETSI TS 103 097 PKI SecuredData:** certificate-chain verification for the frames rule
  R01 currently reports as `secured` but does not unwrap.

---

## [1.4.0] - 2026-10-05

### Added
- **ASN.1 / UPER Conformance Core (`cits_validator/asn1/`):** real PDU decoding, replacing
  the previously advertised-but-absent UPER checks.
  - `decoder.py`: compiles the vendored ETSI/ISO ASN.1 modules with `asn1tools` and decodes
    CAM, DENM, MAPEM, SPATEM, SREM, SSEM, CPM and VAM from raw UPER bytes.
  - `provenance.py`: every module is recorded with its standard, version and source URL, so a
    decoded field can be traced back to the specification that defines it.
  - Standards vendored under `cits_validator/asn1/standards/` (24 modules): ETSI TS 102 894-2
    v1.3.1/v2.4.1, ETSI TS 103 301 v1.3.1/v2.2.1 + ISO TS 19091 DSRC, ETSI EN 302 637-2
    v1.4.1 / TS 103 900 v2.3.1, ETSI EN 302 637-3 v1.3.1 / TS 103 831 v2.3.1.
  - New extra `pip install -e ".[asn1]"`; the link-layer and anti-hallucination rules stay
    dependency-free.
- **Rule `R06_ASN1_CONFORMANCE`:** decodes the ASN.1 payload of a capture and reports real
  encoding faults (truncated PDU, unresolvable message, missing decoder) instead of matching
  source code with regular expressions.
- **CPM and VAM decoding (ETSI TS 103 324 / TS 103 300-3).** The two Release 2 day-2 services
  are decodable from raw UPER bytes, taking the corpus from 17 to 24 modules. Both are Release
  2 only and have no Release 1 baseline, so `decode_pdu(..., release="r1")` refuses them rather
  than compiling against the wrong CDD module. CPM's ASN.1 top-level type is
  `CollectivePerceptionMessage`, not `CPM`; the mapping is explicit. Verified against byte-exact
  vectors produced by an independent encoder for both types.
- **PDU pipeline in `cits-export`:** `--pdu <hex> --msg-type <type>` decodes a raw PDU and
  feeds the MAPEM topology straight into the KML / GeoJSON exporters.
- **MCP tool `cits_decode_pdu`:** decodes a raw PDU hex string into structured fields.

### Changed
- **GeoNetworking framing (`cits_validator/core/geonet.py`):** single source of truth for the
  link-layer → GeoNetworking → BTP offset arithmetic, shared by R01, R06 and the exporters.
  Fixes the BTP port being read at the wrong offset: the destination port follows the
  GeoNetworking Basic, Common and extended headers, not LLC/SNAP. The MAC header length is
  derived from the Frame Control word (QoS Control, Address 4, HT Control). IEEE 1609.2
  secured frames are reported as such with no BTP port, rather than a port derived from
  ciphertext.
- **Version is single-sourced** from the installed distribution metadata, ending the
  `pyproject.toml` / `__init__.py` drift.
- **Findings carry their file path** in text and JSON; directory scans were previously anonymous.
- **Repeating findings are sampled:** at most 5 instances per rule per file are listed, with the
  full count preserved and still counted as errors.

### Fixed
- **R02 no longer fails on its own repository.** Anti-patterns in string literals or comments
  are not reported (the regex pass runs over masked lines; Python uses the tokenizer).
  Trigonometry inside a named distance function is accepted and `dLat`-style identifiers are no
  longer mistaken for coordinates. `# cits-lint: allow` suppresses a finding. Real synthesis
  patterns are still detected in assignments and returns.
- **PCAPNG is actually parsed.** The docs and CLI advertised `.pcapng` while the reader rejected
  it. Section Header, Interface Description and Enhanced/Simple/Packet blocks are parsed,
  `if_tsresol` is honoured, and per-record link types are respected.
- **Configurable stopline chord bound:** `cits-lint --max-chord` (default 25 m).
- `cits-lint` exits 2 with a message on an unreadable target instead of crashing.
- **VAM was mapped to the wrong BTP port.** The port table carried `2010: VAM`, inherited from
  a neighbouring implementation. ETSI TS 103 248 (Table 1 of v2.4.1) assigns **2 009 to CP
  (CPM)** and **2 018 to VA (VAM)**; 2 010 is the EVCSN POI message. The table now follows the
  specification, with 2005 (SAEM), 2011 (TPG), 2013 (RTCMEM) and 2019 (IMZM) added. Because the
  port selects the decoder, the wrong entry silently mis-decoded VAM traffic.
- **The end-to-end test was not portable.** `tests/validator/test_e2e.py` pointed at a fixture
  inside a sibling project and returned early when it was missing, so on any other machine the
  test passed as a no-op. It now uses a committed capture
  (`tests/fixtures/sample_dlt127.pcap`), generated and explained by
  `scripts/make_sample_capture.py`, and asserts the full framing chain
  (radiotap → dot11 → llc_snap → geonet → btp) was reached.

### Documented
- **Non-conformant captures are reported, not tolerated.** `R01` flags all 4333 records of
  `PCAPSender/tests/fixtures/All_UE_01.pcapng` because the 802.11 payload carries no LLC/SNAP
  header. Verified as not a false positive: PCAPSender's own dissector classifies 0 of those
  records as ITS-G5 for the same reason. Recorded as a known limitation in the README.

### Added (tooling)
- `cits-lint --topology <file.json>` audits MAPEM topology documents with R03; topology JSON was
  previously reachable by no code path.
- `sync_skill.py --check` reports drift in every vendored skill copy; CI fails on drift.
- CI tests Python 3.11–3.14, installs the package so the console entry points are exercised,
  type-checks with mypy, enforces an 85 % coverage gate, runs an R02 self-audit guard and
  verifies vendored-skill drift.

---

## [1.3.0] - 2026-10-04

### Fixed
- **Version drift:** `pyproject.toml` (1.2.0) and `cits_validator/__init__.py` (1.1.0) disagreed.
- **MCP bypassed the rule registry:** `cits_audit_code` called the rule directly, so the CLI's
  `--rules` selection had no MCP equivalent. Both now run through `RuleRegistry`.

### Added
- `cits-lint --version`.
- **Data coverage contract:** reports carry `coverage`, `has_data`, `data_status` and
  `missing_categories`, and the text report prints a `Data Status` line. A capture in which no
  GeoNetworking/BTP record was reachable is reported as "No Data in Capture" instead of
  silently passing — the failure mode the Iron Law section describes.

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
  - Expanded test suite to **67 automated tests** (100% passing).
  - Added test modules: `tests/geo/test_geojson_builder.py`, `tests/geo/test_kml_builder.py`, `tests/geo/test_glosa.py`, `tests/lisa/test_lisa_parser.py`, `tests/cli/test_export_cli.py`.
  - Added robust aspect extraction for `<Signalbild Name="..." />` and transit movement heuristics for German `Ö` / `ÖV` / `ÖPNV` prefixes.
  - Added raw multi-fragment (`{"fragments": [...]}`) input support and signal group ID 0 compatibility in KML/GeoJSON exporters.
  - Added SPATEM RED phase deceleration optimization when subsequent green duration is omitted.

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
