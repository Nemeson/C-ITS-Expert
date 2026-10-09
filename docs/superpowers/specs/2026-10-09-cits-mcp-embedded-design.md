# Design Specification: C-ITS MCP Server for RSU/OBU and Embedded Deployment

**Date:** 2026-10-09
**Status:** Approved
**Author:** Pair-Programming AI Agent & User
**Target Runtime:** CPython 3.11–3.14, musl/static-capable, low RAM/Flash (embedded Linux)
**Supersedes scope of:** `2026-09-27-cits-validator-design.md` (MCP surface only; the rule core is unchanged)

---

## 1. Overview & Understanding Summary

`cits_validator` today ships a pure-Python rule engine, a CLI (`cits-lint`, `cits-export`) and a
**STDIO-only** hand-rolled MCP server (`cits-mcp`) exposing nine tools. It is a developer-host
tool: no network transport, no capability scoping, no output caps, no path guard, and no
embedded distribution form.

This work turns `cits-mcp` into a **portable control-and-validation layer** that:

1. runs on **Linux-based RSU/Edge** hardware (constrained but Python-capable),
2. can be driven against devices that **cannot run Python on-device** (MCU / FreeRTOS /
   AUTOSAR-class) through a host/edge bridge,
3. ships an **embedded distribution form** suitable for musl/static and small RAM/Flash,
4. keeps a **single source of truth** for all validation and decoding logic.

### Intended outcome

An operator or agent can use the same MCP server, with the same tool contracts, on a laptop, in
CI, on an RSU, or as the controller of a device that only speaks raw bytes — and every result is
produced by the same rule core, upholding the repository's Iron Law.

### Success criteria

- The existing nine tools keep their names and parameter shapes; existing agents keep working.
- The server starts and serves `tools/list` + core tools with **zero third-party dependencies**
  (no `asn1tools`) in the `device` profile.
- A remote HTTP bind without a configured token refuses to start; a `file_path` outside the
  configured roots is refused.
- An oversized result is truncated at a record boundary and marked `truncated: true` with a
  `total` count, never silently.
- The embedded distribution (`.pyz`) passes a smoke test in CI **without** the ASN.1 extra.

### Non-goals (YAGNI)

- No authentication database, no multi-tenancy, no web UI, no OAuth server.
- No second ASN.1 compiler and no independent Rust/C++ decoder in Milestone 1–2.
- No rule-logic changes; the rules R01–R06 stay as they are.

---

## 2. Assumptions & Constraints

1. **Runtime target is constrained Linux (Class B):** Yocto/Buildroot/musl or cross-compiled
   static. CPython 3.11+ is available or can be cross-built, but RAM/Flash are small and the
   full scientific/ASN.1 stack is not assumed.
2. **Host/edge first, codegen prepared:** On-device capability is delivered first as a trimmed
   Python edge daemon (Branch 3, stage 1). A native (C/Rust) artifact generated from the same
   rule metadata is prepared, not built, in Milestone 1–2.
3. **Single source of truth:** The `cits_validator` core remains the only implementation of
   validation and decoding. Any device-side artifact must consume the same rules, not re-derive
   them.
4. **Transport neutrality:** Tool behaviour is identical across STDIO and HTTP; only exposure,
   auth and limits differ by profile.
5. **Backward compatibility:** Existing tool names, parameters and the STDIO entrypoint
   (`cits-mcp`, `python -m cits_validator.mcp.server`) are preserved.
6. **Iron Law compliance:** `NO DATA IN CAPTURE` stays visible; missing data is never replaced
   by synthetic or inferred values.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│  MCP surface (tools / resources / prompts)                 │  contractual, stable
├────────────────────────────────────────────────────────────┤
│  Transport abstraction (STDIO | Streamable-HTTP/SSE)       │  pluggable, per-profile
├────────────────────────────────────────────────────────────┤
│  Capability profiles (device | host | ci)                  │  tool set + rights + limits
├────────────────────────────────────────────────────────────┤
│  Core engine  cits_validator (rules R01–R06, ASN.1, geo)   │  UNCHANGED, single truth
└────────────────────────────────────────────────────────────┘
        │                                   │
   (a) Python edge daemon              (b) native artifact
       `cits-edge`, device profile         generated from rule metadata (Milestone 3)
```

### 3.1 Invariant

The core engine is the only source of validation/decoding truth. No second decoder may exist as
an independent implementation. The Milestone 3 codegen consumes rule **metadata** emitted from
that same core; it does not fork the rules.

### 3.2 Units of work (isolation and clarity)

| Unit | Responsibility | Interface | Depends on |
| :--- | :--- | :--- | :--- |
| `mcp/server.py` (existing) | JSON-RPC dispatch, STDIO loop | `McpServer.handle_request` | profiles, tools |
| `mcp/transport.py` (new) | STDIO + HTTP/SSE run loops | `Transport.serve(server)` | server |
| `mcp/profiles.py` (new) | Profile definition, tool filtering, rights, limits | `Profile.apply(tools, args)` | config |
| `mcp/config.py` (new) | Env/CLI configuration surface | `Settings.from_env()` | — |
| `mcp/security.py` (new) | Token gate, path allowlist, output caps | guards invoked by server | config |
| `mcp/tools.py` (existing) | Tool implementations | unchanged signatures | core engine |
| `mcp/resources.py` (new) | `cits://` resources (rules, standards, version) | MCP `resources/read` | core engine |
| `cits_validator/rules/export.py` (new) | Machine-readable rule metadata JSON | `export_rule_catalog()` | rules |
| packaging (`cits-edge` zipapp) | Embedded distribution | `python cits-edge.pyz` | device profile |

Each unit has one purpose and can be read and tested without the others.

---

## 4. Capability Profiles

A profile **filters** `tools/list` and **enforces** rights and limits. It never duplicates
logic.

| Profile | Target | Tools exposed | Rights | Limits |
| :--- | :--- | :--- | :--- | :--- |
| `device` | RSU/OBU on-device | `cits_inspect_hex`, `cits_validate_pcap` (streaming), `cits_check_mapem`, `cits_compute_glosa`, `cits_parse_lisa`, `cits_selftest` | read-only; `file_path` restricted to configured roots; no disk writes | small output cap; `cits_export_kml` hidden |
| `host` | Dev host / agent | all current tools + additions | writes allowed within roots | moderate cap |
| `ci` | Pipeline gate | `cits_validate_pcap`, `cits_audit_code`, `cits_decode_pdu` | no network binds | JSON-only, exit-capable |

Selection: `--profile {device,host,ci}` or `CITS_MCP_PROFILE` (default `host`). An unknown
profile fails closed at startup.

---

## 5. On-Device Runtime Strategy (Branch 3, staged)

- **Stage 1 — Python edge daemon (`cits-edge`):** a trimmed distribution serving only the
  `device` profile. Ships as a `.pyz` zipapp (pure stdlib), optionally cross-built for
  musl/static. Speaks local STDIO or loopback HTTP; a host agent bridges to it. Deployed via a
  `cits-edge.service` systemd unit template plus a health endpoint (`cits_selftest`).
- **Stage 2 — native artifact (prepared, not built):** Milestone 3 consumes the machine-readable
  rule catalog (`cits-export --rules-json`) to generate a C/Rust validation library linked into
  Python-free firmware. The MCP server remains the host/edge control layer. This stage exists so
  the rule metadata contract is finalized now, without building a second decoder prematurely.

---

## 6. Security & Resource Limits

- **Transport auth:** STDIO trusts its parent process (standard). HTTP/SSE binds to `127.0.0.1`
  by default. Binding to a non-loopback address **requires** `CITS_MCP_TOKEN`; without it the
  server refuses to start.
- **Path allowlist:** `cits_validate_pcap(file_path)` and any file-reading tool accept paths only
  under configured roots (`CITS_MCP_ROOTS`, default = current working directory). Attempts
  outside are refused with a clear error. This closes the path-local-file-disclosure gap in the
  current `cits_validate_pcap`.
- **Read-only device profile:** no writes, no on-disk KML/GeoJSON export (results returned in
  the response only), no free-form `file_path`.
- **Output caps:** `CITS_MCP_MAX_OUTPUT_BYTES` (default 262144). Results larger than the cap are
  truncated at a record boundary and carry `truncated: true` and `total`; truncation is explicit,
  never silent.
- **Memory discipline:** `cits_validate_pcap` uses the existing streaming reader (constant,
  sub-2 MB footprint). A scan never loads the whole capture into memory, so a large capture on
  embedded hardware cannot trigger an OOM kill.
- **Cancellation / progress:** tool calls carry request ids; long scans emit progress and honor
  MCP `notifications/cancelled`.
- **Tool error semantics:** tool failures are returned as `result.isError: true` (MCP tool
  error), not as a JSON-RPC `error`. Protocol-level faults (unknown method, parse error) remain
  JSON-RPC errors. This lets an agent separate "the tool says no" from "the protocol broke".

---

## 7. Tool Surface

### 7.1 Compatibility

The existing nine tools (`cits_audit_code`, `cits_inspect_hex`, `cits_check_mapem`,
`cits_validate_pcap`, `cits_parse_lisa`, `cits_compute_glosa`, `cits_export_kml`,
`cits_decode_pdu`, `cits_decode_mapem_to_geojson`) keep their names and parameter shapes.
Additions are **annotations** (`readOnlyHint`, `idempotentHint`, `destructiveHint`) and new
optional fields only.

### 7.2 Additions

- `cits_stream_frames(frames, dlt)` — validates a batch of raw frames incrementally (RSU/OBU
  live capture) without file round-trips.
- `cits_diff_captures(baseline_path, candidate_path)` — regression comparison between two field
  captures (field-test QA).
- `cits_explain_rule(rule_id)` — returns rule metadata (id, name, description, threshold,
  detection descriptor). This is the machine-readable basis for Milestone 3 codegen.
- `cits_selftest()` — liveness/health check for the edge daemon.

### 7.3 Resources

- `cits://rules` — rule catalog metadata.
- `cits://standards` — vendored ASN.1 modules with provenance.
- `cits://version` — server and core version.

Resources let an agent **read** catalogs instead of abusing tools.

### 7.4 Prompts

Optional predefined templates (e.g. "audit this capture"). Included only if they add value;
otherwise omitted (YAGNI).

---

## 8. Packaging & Embedded Build

Two distribution forms from one source:

1. **Standard package** (`pip install cits-expert`) for host/CI — unchanged entrypoints.
2. **`cits-edge` zipapp** (`.pyz`): `device`-profile only, **zero third-party dependencies**
   (ASN.1 not bundled), runs on a minimal `python3`, cross-compilable for musl/static.

Dependency discipline: the `device` profile requires no third-party packages. This is already
achievable because `asn1tools` is an optional extra.

Rule-metadata export: `cits-export --rules-json` emits the rule catalog as JSON. That exact flag
is the M1 contract; its output schema is stable for Milestone 3. It is the first step toward
C/Rust codegen and is finalized in Milestone 1 so the contract is stable.

Service integration: a `cits-edge.service` systemd template plus a healthcheck endpoint.

---

## 9. Additional Deployment Areas (documented for the spec, delivered across milestones)

**Mature / immediate:** (1) RSU/OBU live diagnosis and stream validation; (2) field-test QA
pipeline / CI gate; (3) C-ITS conformance pre-check (C-Roads/ETSI; R06 + the Day-2 suite).

**Medium:** (4) digital-twin / simulator validation (SUMO/CARLA/Veins); (5) PKI / security audit
per ETSI TS 103 097 (already planned for v1.5.0); (6) OEM/Tier-1 OBU reference SDK;
(7) traffic-management monitoring; (8) testbench automation.

**Low:** (9) research-data quality gate; (10) education / training tooling.

Only areas (1)–(3) are in scope for Milestone 1; the rest are recorded so the architecture does
not foreclose them.

---

## 10. Roadmap

- **M1 — Branch 3, stage 1.** Transport abstraction (STDIO first), `device`/`host`/`ci`
  profiles, security (token gate, path allowlist, output caps), corrected tool error semantics,
  `cits-edge` zipapp, `cits_selftest`. Delivers immediate RSU/Edge usability with zero new
  runtime dependencies.
- **M2 — Network & live.** Streamable-HTTP/SSE transport, resources and prompts,
  `cits_stream_frames`, `cits_diff_captures`, progress and cancellation.
- **M3 — Native path.** Rule catalog JSON finalized, C/Rust codegen prototype for Python-free
  devices, and ETSI TS 103 097 PKI secured-frame handling.

---

## 11. Testing & CI

Existing 225 tests stay green. New tests:

- **Transport matrix:** identical tool responses over STDIO and HTTP.
- **Profile filter:** `device` hides non-device tools and enforces roots and caps.
- **Security:** non-loopback bind without token refuses to start; path outside root is refused.
- **Embedded budget:** the `.pyz` starts without `asn1tools`; the output cap triggers and marks
  `truncated: true`.
- **New tools:** round-trip tests for `cits_stream_frames`, `cits_diff_captures`,
  `cits_explain_rule`, `cits_selftest`.
- **CI embedded gate:** a job builds the zipapp, imports it without the ASN.1 extra, and runs a
  smoke test. The coverage gate stays at 85 %.

---

## 12. Decision Log

| Date | Topic | Chosen Decision | Alternatives Rejected | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| 2026-10-09 | Path | Architectural (full spec) | Spike, bounded | Touches transport, runtime footprint, security and tool surface — restructures how components fit together. |
| 2026-10-09 | Overall approach | Branch 3 (transport/edge layer, staged from in-place extension) | Pure in-place extension; second runtime | Reaches RSU/OBU without forking logic; keeps Iron Law single-source. |
| 2026-10-09 | Embedded runtime | Class B constrained Linux, Python-capable | MCU-only; full Python stack | RSU/OBU in scope run constrained Linux; a trimmed Python edge is viable now. |
| 2026-10-09 | On-device strategy | Stage 1 Python edge first; stage 2 native codegen prepared | Immediate Rust/C decoder | Avoids two decoders before the rule metadata contract exists. |
| 2026-10-09 | Logic duplication | Forbidden — core engine is single truth | Parallel C/Rust decoder | Two implementations are two truths; breaks the anti-hallucination principle. |
| 2026-10-09 | Transport | Pluggable STDIO + HTTP/SSE, identical tool behaviour | STDIO-only; HTTP-only | Host, CI and remote device control share one contract. |
| 2026-10-09 | Security default | Loopback HTTP; non-loopback requires token; path allowlist | Open bind; unrestricted paths | Current `validate_pcap` reads arbitrary paths; embedded exposure needs a guard. |
| 2026-10-09 | Output handling | Truncate at record boundary with `truncated`/`total` | Unbounded output; silent cut | Unbounded results exhaust agent and device memory. |
| 2026-10-09 | Tool errors | `result.isError` for tool faults; JSON-RPC error for protocol faults | Single error channel | Agents must distinguish tool failure from protocol failure. |
| 2026-10-09 | Compatibility | Names/params/entrypoints preserved; additions only | Rename or regroup tools | Existing agents must keep working. |
