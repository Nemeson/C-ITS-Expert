# Design Specification: C-ITS Validator & MCP Toolset

**Date:** 2026-09-27  
**Status:** Approved  
**Author:** Pair-Programming AI Agent & User  
**Target Architecture:** Python 3.11–3.14 (Pure-Python Core), STDIO MCP Server, Terminal CLI  

---

## 1. Overview & Understanding Summary

The **C-ITS Validator** (`cits_validator`) is a lightweight, pure-Python validation engine, CLI linter (`cits-lint`), and Model Context Protocol (MCP) server (`cits-mcp`) designed to enforce empirical protocol invariants and prevent AI agent hallucinations across Cooperative Intelligent Transport Systems (C-ITS) and V2X developments.

### Key Objectives
* **Automated Rule Enforcement:** Programmatically verify link-layer framing (DLT 127/1/105, 802.11 QoS Data, LLC/SNAP `0x8947`), stopline geometry (ISO TS 19091 Node 0), priority sessions (4-tuple key), and hardware streaming (ESP32-C5 `ITS5`/`ITS6`).
* **Anti-Hallucination Scanning:** Static AST and regex code auditing to prevent LLMs from introducing synthetic GNSS curves (`sin(t)`), modulo signal phase assignments (`lane % 4 + 1`), and static 90-second cycle loops.
* **Dual Interface Integration:** Seamless execution both as a fast CLI tool for CI/CD pipelines and as an interactive STDIO MCP server for coding agents (Antigravity, Claude Code, Cursor, Codex).

---

## 2. Assumptions & Constraints

1. **Pure-Python Core:** Zero external binary dependencies; does not require Wireshark or `tshark` installations. Runs anywhere Python 3.11+ is available.
2. **Streaming Execution:** PCAP inspection uses a generator-based record stream, guaranteeing constant memory consumption ($< 2$ MB RAM) even on traces exceeding 100 MB.
3. **STDIO MCP Transport:** Standard JSON-RPC 2.0 communication over standard input/output ensures broad interoperability across all modern agent environments.
4. **Iron Law Compliance:** Violations of the "Zero Data Hallucination" doctrine trigger immediate `ERROR` level reports with actionable remediation hints.

---

## 3. Package & Directory Structure

```
C-ITS-Expert/
├── cits_validator/
│   ├── __init__.py
│   ├── core/
│   │   ├── models.py         # Severity (ERROR, WARNING, INFO), Violation, ValidationReport
│   │   ├── stream.py         # Streaming PCAP iterator (< 2 MB RAM footprint)
│   │   └── registry.py       # RuleRegistry and BaseRule base class
│   ├── rules/
│   │   ├── r01_link_layer.py # DLT 127 offsets, nanosecond magic, LLC/SNAP 0x8947
│   │   ├── r02_anti_fake.py  # AST/Regex detection for synthetic drifts & modulo phases
│   │   ├── r03_topology.py   # Multi-fragment MAPEM assembly & Node-0 stopline chords
│   │   ├── r04_priority.py   # SREM/SSEM 4-tuple tracking & session timeouts
│   │   └── r05_hardware.py   # ESP32-C5 ITS5/6 framing, time jumps & RSSI -128
│   ├── cli/
│   │   └── main.py           # CLI entrypoint: 'cits-lint <path> [--format json|text] [--strict]'
│   └── mcp/
│       ├── server.py         # Pure-Python JSON-RPC 2.0 STDIO Server
│       └── tools.py          # Tools: cits_validate_pcap, cits_audit_code, cits_inspect_hex
├── tests/
│   └── validator/
│       ├── test_r01_link_layer.py
│       ├── test_r02_anti_fake.py
│       ├── test_r03_topology.py
│       ├── test_r04_priority.py
│       ├── test_r05_hardware.py
│       ├── test_cli.py
│       └── test_mcp_server.py
```

---

## 4. Core Components & Data Flow

### 4.1 Data Models (`core/models.py`)
* `Severity`: Enum with values `ERROR`, `WARNING`, `INFO`.
* `Violation`: Dataclass containing `rule_id`, `severity`, `message`, `packet_index` / `line_number`, `byte_offset`, `offending_sample`, and `remediation_hint`.
* `ValidationReport`: Summary containing `total_inspected`, `error_count`, `warning_count`, `violations: list[Violation]`, and `is_valid: bool`.

### 4.2 Streaming Reader (`core/stream.py`)
Reads 24-byte PCAP header, resolves byte-order and timestamp resolution (`0xa1b2c3d4` vs `0xa1b23c4d`), and yields `PacketRecord(timestamp, caplen, wirelen, data)` iteratively without loading the full file into memory.

---

## 5. Inspection Rules (MVP Specification)

| Rule ID | Module | Focus Area | Error Condition |
| :--- | :--- | :--- | :--- |
| **R01** | `r01_link_layer` | DLT & Wire Framing | Fixed Radiotap offsets (failing to read `it_len` at byte 2), corrupted LLC/SNAP header, unhandled nanosecond PCAP magic. |
| **R02** | `r02_anti_fake` | Anti-Hallucination & Code | Synthetic GNSS drift (`sin(t)`), modulo signal assignments (`lane % 4`), static 90s cycle loops, unhandled UPER extension bits. |
| **R03** | `r03_topology` | MAPEM Topography | Overwriting intersection lanes across multi-fragment `layerID`s, connection chords $> 25$ m caused by linking Node $N$ instead of Node 0 stoplines. |
| **R04** | `r04_priority` | SREM/SSEM Prioritization | Priority request matching without complete 4-tuple key, unclosed sessions $> 5$ s without SSEM response. |
| **R05** | `r05_hardware` | ESP32-C5 Hardware Stream | Unhandled `-128 dBm` RSSI sentinel (failing to convert to `None`), backward jumps $> 2$ s or forward drift $> 60$ s without anchor reset. |

---

## 6. Interfaces

### 6.1 CLI Interface (`cits-lint`)
* **Commands:** `cits-lint <file_or_dir> [--format text|json] [--strict] [--rules R01,R02]`
* **Outputs:**
  * `text`: Colorized terminal summary with line numbers, hex offsets, and remediation instructions.
  * `json`: Machine-readable report for CI/CD test gates.
* **Exit Codes:** `0` = Clean / warnings only, `1` = One or more `ERROR`s detected, `2` = Command error.

### 6.2 MCP Interface (`cits-mcp`)
Exposes JSON-RPC 2.0 tools over STDIO:
* `cits_validate_pcap(file_path: str)`: Inspects capture trace and reports link-layer violations.
* `cits_audit_code(code: str, language: str)`: Scans code snippet for prohibited synthetic fallback patterns.
* `cits_inspect_hex(hex_payload: str, dlt: int)`: Decodes and audits raw packet byte-streams.
* `cits_check_mapem(lanes_geojson: dict)`: Verifies stopline Node-0 orientation and lane chord distances.

---

## 7. Decision Log

| Date | Topic | Chosen Decision | Alternatives Rejected | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| 2026-09-27 | Integration Form | Hybrid Tool (CLI + STDIO MCP) | CLI-only, MCP-only | Enables shared validation logic for CI/CD pipelines and interactive AI coding sessions. |
| 2026-09-27 | Architecture | Modular Rule Registry with streaming I/O | Monolith script, Subprocess CLI wrapper | Clean separation of rules, direct in-memory evaluation for agents, low memory footprint. |
| 2026-09-27 | Dependencies | Pure Python standard library | Native `mcp` SDK, `tshark` / Wireshark binaries | Zero external setup hurdles, maximum portability across developer machines and agents. |
| 2026-09-27 | Code Auditing | AST (`ast`) + regex heuristics | Runtime execution only | Catches hallucinated math formulas in agent-generated code before tests are run. |
| 2026-09-27 | Geometry Threshold | 25-meter maximum stopline chord | Arbitrary threshold | Physically motivated bound that detects 5-fold overlong diagonal connection errors. |
| 2026-09-27 | Truncation Handling | Graceful EOF warning on truncated records | Unhandled `IndexError` crash | Real-world SSH field captures frequently terminate abruptly. |
