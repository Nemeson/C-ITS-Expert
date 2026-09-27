# C-ITS Validator & MCP Toolset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure-Python validation engine, CLI linter (`cits-lint`), and STDIO MCP server (`cits-mcp`) that automates C-ITS protocol verification and halts AI agent data hallucinations.

**Architecture:** A modular core library (`cits_validator/`) containing a zero-allocation streaming PCAP iterator, unified `RuleRegistry`, and 5 discrete inspection rule modules. Two lightweight interface adapters expose this engine: a terminal CLI with colorized output/JSON reporting, and a JSON-RPC 2.0 STDIO MCP server for AI coding agents.

**Tech Stack:** Python 3.11–3.14 (Pure Python standard library: `struct`, `dataclasses`, `ast`, `re`, `json`, `argparse`, `sys`).

**Spec:** [`docs/superpowers/specs/2026-09-27-cits-validator-design.md`](docs/superpowers/specs/2026-09-27-cits-validator-design.md)

## Global Constraints

- **Python Floor:** Pure Python 3.11+ compatible; zero C-extensions and zero required third-party runtime dependencies.
- **Memory Footprint:** Streaming PCAP iterator MUST maintain $< 2$ MB RAM usage regardless of trace file size.
- **Zero Data Hallucination:** Strict enforcement of empirical protocol offsets; violations produce `Severity.ERROR` with concrete `remediation_hint`s.
- **MCP Standard:** JSON-RPC 2.0 over STDIO, fully compliant with Claude Code, Antigravity, and Cursor MCP clients.
- **Vendor Neutrality:** Use generic terminology ("Linux-based RSU" / "Roadside Unit (RSU)").

## Review Focus

1. **Truncated Capture EOF:** Sudden socket disconnects or SIGINT must produce graceful EOF warnings rather than unhandled `struct.error` or `IndexError` exceptions.
2. **Nanosecond PCAP Scaling:** Traces with magic `0xa1b23c4d` must scale subsecond timestamps by $10^{-9}$, not $10^{-6}$.
3. **AST Parsing Safety:** Syntax errors or non-Python code passed to AST analyzer must fall back to regex scanning without crashing.
4. **Multi-Fragment Accumulation:** Successive MAPEM fragments with differing `layerID`s must not overwrite existing lane maps.
5. **Lookahead Magic Framing:** ESP32 binary stream parser must validate frame headers against false-positive payload byte sequences.

---

### Task 1: Core Models & Streaming PCAP Iterator

**Files:**
- Create: `cits_validator/core/__init__.py`
- Create: `cits_validator/core/models.py`
- Create: `cits_validator/core/stream.py`
- Create: `cits_validator/core/registry.py`
- Create: `cits_validator/__init__.py`
- Test: `tests/validator/test_core_stream.py`

**Interfaces:**
- `Severity`: Enum (`ERROR`, `WARNING`, `INFO`)
- `Violation`: Dataclass (`rule_id`, `severity`, `message`, `packet_index`, `byte_offset`, `offending_sample`, `remediation_hint`)
- `ValidationReport`: Dataclass (`total_inspected`, `error_count`, `warning_count`, `violations`, `is_valid`)
- `PcapStreamingIterator`: Class with generator `iter_packets(file_obj_or_path) -> Iterator[PacketRecord]`

- [ ] **Step 1: Write failing tests `tests/validator/test_core_stream.py`**
  - Test big-endian microsecond PCAP magic `0xa1b2c3d4`.
  - Test little-endian nanosecond PCAP magic `0x4d3cb2a1` and verify $10^{-9}$ timestamp scaling.
  - Test streaming iteration on valid multi-packet mock bytes.
  - Test graceful handling of truncated EOF records.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_core_stream.py`
- [ ] **Step 3: Implement `models.py`, `stream.py`, and `registry.py`**
  - Implement dataclasses in `cits_validator/core/models.py`.
  - Implement header unwrapping and streaming record generator in `cits_validator/core/stream.py`.
  - Implement base rule and registry in `cits_validator/core/registry.py`.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_core_stream.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement cits_validator core models and streaming PCAP iterator`

---

### Task 2: Rule R01 - Link Layer & Wire Framing

**Files:**
- Create: `cits_validator/rules/__init__.py`
- Create: `cits_validator/rules/r01_link_layer.py`
- Test: `tests/validator/test_r01_link_layer.py`

**Interfaces:**
- `LinkLayerRule(BaseRule)`:
  - Audits raw packet bytes: DLT 127 Radiotap length at byte 2 (`it_len`), 802.11 QoS Data headers (26 bytes) vs Data (24 bytes), LLC/SNAP `0x8947`, and BTP destination ports (2001–2008).

- [ ] **Step 1: Write failing tests `tests/validator/test_r01_link_layer.py`**
  - Test valid DLT 127 frame with dynamic 36-byte Radiotap header.
  - Test corrupted / missing Radiotap length field.
  - Test 802.11 QoS Data frame offset handling.
  - Test LLC/SNAP header mismatch (e.g. non-V2X EtherType).
  - Test valid BTP port demuxing (e.g. 2001 CAM, 2004 SPATEM).
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_r01_link_layer.py`
- [ ] **Step 3: Implement `r01_link_layer.py`**
  - Write parsing logic according to `references/packet-dissection.md`.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_r01_link_layer.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement R01 link-layer and wire-framing validation rule`

---

### Task 3: Rule R02 - Anti-Hallucination & Code Linter

**Files:**
- Create: `cits_validator/rules/r02_anti_fake.py`
- Test: `tests/validator/test_r02_anti_fake.py`

**Interfaces:**
- `AntiHallucinationRule(BaseRule)`:
  - Scans source code and logs for:
    1. Trigonometric / synthetic coordinate generation (`sin(...)`, `cos(...)`).
    2. Modulo signal group calculations (`lane % 4 + 1`).
    3. Static 90-second cycle loops.
    4. Unchecked UPER extension markers.

- [ ] **Step 1: Write failing tests `tests/validator/test_r02_anti_fake.py`**
  - Test detection of synthetic sine-wave coordinates in Python AST and regex.
  - Test detection of `(lane_id % 4) + 1` modulo phase synthesis.
  - Test detection of hardcoded 90-second cycle constants.
  - Test polyglot regex scanning for JavaScript, C++, Rust, and Java code snippets.
  - Test clean code without false positives.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_r02_anti_fake.py`
- [ ] **Step 3: Implement `r02_anti_fake.py`**
  - Implement Python AST NodeVisitor and polyglot regex scanners.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_r02_anti_fake.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement R02 anti-hallucination code audit rule`

---

### Task 4: Rule R03 - MAPEM Topography & Stopline Geometry

**Files:**
- Create: `cits_validator/rules/r03_topology.py`
- Test: `tests/validator/test_r03_topology.py`

**Interfaces:**
- `MapemTopologyRule(BaseRule)`:
  - Validates multi-fragment MAPEM assembly (additive lane merging by `(regionId, intersectionId)`).
  - Verifies Node 0 stopline orientation and calculates Haversine chord lengths ($> 25$ m threshold).

- [ ] **Step 1: Write failing tests `tests/validator/test_r03_topology.py`**
  - Test multi-fragment accumulation with layers 21 and 22 without lane overwrites.
  - Test detection of diagonal overlong chords ($> 25$ m) caused by connecting lane tails.
  - Test valid stopline connection between ingress and egress lanes.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_r03_topology.py`
- [ ] **Step 3: Implement `r03_topology.py`**
  - Implement Haversine distance calculator and fragment integrity checker.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_r03_topology.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement R03 MAPEM topology and stopline geometry rule`

---

### Task 5: Rule R04 & R05 - Priority Tracking & Hardware Streams

**Files:**
- Create: `cits_validator/rules/r04_priority.py`
- Create: `cits_validator/rules/r05_hardware.py`
- Test: `tests/validator/test_r04_priority.py`
- Test: `tests/validator/test_r05_hardware.py`

**Interfaces:**
- `PrioritySessionRule(BaseRule)`: 4-tuple key tracking and timeout auditing.
- `HardwareStreamRule(BaseRule)`: ESP32-C5 `ITS5`/`ITS6` framing, RSSI `-128 dBm` sentinel verification, host time anchor jumps.

- [ ] **Step 1: Write failing tests `test_r04_priority.py` & `test_r05_hardware.py`**
  - Test 4-tuple correlation and unclosed session leak detection.
  - Test `ITS5` vs `ITS6` header length and magic lookahead validation.
  - Test `-128 dBm` RSSI sentinel handling.
  - Test backward uptime jump ($> 2.0$ s) detection.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_r04_priority.py tests/validator/test_r05_hardware.py`
- [ ] **Step 3: Implement `r04_priority.py` and `r05_hardware.py`**
  - Implement session state tracking and binary framing auditor.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_r04_priority.py tests/validator/test_r05_hardware.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement R04 priority session and R05 hardware stream rules`

---

### Task 6: CLI Interface (`cits-lint`)

**Files:**
- Create: `cits_validator/cli/__init__.py`
- Create: `cits_validator/cli/main.py`
- Modify: `pyproject.toml` (add `cits-lint = "cits_validator.cli.main:main"`)
- Test: `tests/validator/test_cli.py`

**Interfaces:**
- `cits-lint` command line entry point supporting `--format text|json`, `--strict`, and directory crawling.

- [ ] **Step 1: Write failing tests `tests/validator/test_cli.py`**
  - Test CLI argument parsing and help output.
  - Test scanning sample PCAP fixture yielding exit code 0 or 1.
  - Test JSON output formatting.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_cli.py`
- [ ] **Step 3: Implement `cits_validator/cli/main.py` and update `pyproject.toml`**
  - Build ANSI formatted terminal reports and JSON export.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_cli.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement cits-lint CLI tool with text and JSON reporting`

---

### Task 7: MCP Server (`cits-mcp`)

**Files:**
- Create: `cits_validator/mcp/__init__.py`
- Create: `cits_validator/mcp/tools.py`
- Create: `cits_validator/mcp/server.py`
- Modify: `pyproject.toml` (add `cits-mcp = "cits_validator.mcp.server:main"`)
- Test: `tests/validator/test_mcp_server.py`

**Interfaces:**
- JSON-RPC 2.0 STDIO Server exposing:
  - `cits_validate_pcap(file_path: str)`
  - `cits_audit_code(code: str, language: str)`
  - `cits_inspect_hex(hex_payload: str, dlt: int)`
  - `cits_check_mapem(lanes_geojson: dict)`

- [ ] **Step 1: Write failing tests `tests/validator/test_mcp_server.py`**
  - Test JSON-RPC handshake (`initialize`, `tools/list`).
  - Test tool execution `cits_audit_code` with synthetic formula.
  - Test tool execution `cits_inspect_hex` with invalid Radiotap offset.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/validator/test_mcp_server.py`
- [ ] **Step 3: Implement `tools.py` and `server.py`**
  - Implement lightweight STDIO JSON-RPC 2.0 server without third-party frameworks.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_mcp_server.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement cits-mcp STDIO server for interactive agent auditing`

---

### Task 8: Integration, Documentation & Global Deployment

**Files:**
- Modify: `README.md` (add CLI & MCP quickstart guide and usage examples)
- Modify: `skill/cits-expert/SKILL.md` (update tool invocation routing table)
- Sync: `sync_skill.py` (deploy updated skill across all agent dirs)
- Test: Full test suite (`pytest -v` across both spec tests and validator tests)

- [ ] **Step 1: Update `README.md` and `skill/cits-expert/SKILL.md`**
  - Document `cits-lint` and `cits-mcp` commands.
  - Verify `SKILL.md` word count remains $< 450$ words.
- [ ] **Step 2: Run all tests & linters**
  - Run: `py -3.14 -m pytest -v`
  - Run: `py -3.14 -m ruff check .`
- [ ] **Step 3: Execute `sync_skill.py`**
  - Run: `py -3.14 sync_skill.py --install-global`
- [ ] **Step 4: Git commit & push**
  - Commit: `feat: integrate cits_validator into skill documentation and deployment suite`
  - Push to GitHub remote `origin master` and tag `v1.1.0`.
