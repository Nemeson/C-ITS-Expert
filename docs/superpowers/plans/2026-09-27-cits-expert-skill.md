# C-ITS Expert Skill Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aufbau der vollständigen, universell kompatiblen und modularisierten "C-ITS Expert" Skill Suite unter `C:\PythonTools\C-ITS-Expert` inklusive CI/CD-Pipeline, Test-Suite, bitgenauen Referenz-Modulen und Synchronisations-CLI zur weltweiten Bereitstellung für Antigravity agy CLI, Claude Code, Codex, OpenCode und GitHub.

**Architecture:** Modulare Hub-and-Spoke Architektur mit kompaktem `< 450` Wörter Master-Skill (`SKILL.md`), 6 thematischen Deep-Dive-Referenzdateien in `references/`, sprachspezifischen Referenz-Snippets in `examples/`, einer automatisierten TDD-Testsuite in `tests/` und dem Multi-Target Synchronisations-Tool `sync_skill.py`.

**Tech Stack:** Markdown (AgentSkills.io Standard), Python 3.11–3.14 (pytest, ruff, mypy), Rust (nom, memmap2), TypeScript, GitHub Actions.

**Spec:** [`docs/superpowers/specs/2026-09-27-cits-expert-skill-design.md`](../specs/2026-09-27-cits-expert-skill-design.md)

## Global Constraints

- `SKILL.md` darf strikt maximal 450 Wörter umfassen (Token-Budget).
- Frontmatter muss valides YAML mit Feldern `name: cits-expert` und `description` (nur Auslösebedingungen, keine Workflow-Zusammenfassung) sein.
- Alle relativen Links in Markdown-Dateien müssen existieren und aufgelöst werden können.
- Keine synthetische Datenerfindung: Code-Beispiele und Tests müssen reale DLT 127 Radiotap- und MAPEM-Bytefolgen verwenden.
- Python-Code muss mit Python 3.11 bis 3.14 kompatibel sein und `ruff check` bestehen.

## Review Focus

1. **DLT 127 Radiotap Stripping:** Verarbeitet der Unwrapper reale DLT-127-Frames korrekt, liest er die 16-Bit-Headerlänge bei Offset 2 aus und findet er den LLC/SNAP-Header `0x8947`?
2. **Nanosekunden vs. Mikrosekunden PCAP:** Erkennt der Dissector das Nanosekunden-Magic (`0xa1b23c4d`) und skaliert Zeitstempel nicht fälschlich um den Faktor 1.000?
3. **MAPEM Fragment-Merging:** Werden bei segmentierten Kreuzungen (`layerID` 21, 22) Fahrspuren additiv über `(regionId, intersectionId)` aggregiert, ohne vorherige Lanes zu überschreiben?
4. **Node 0 Haltelinien-Orientierung:** Werden `connectsTo`-Linien zwischen Node 0 der Ingress-Spur und Node 0 der Egress-Spur gezogen, anstatt 5-fach zu lange Sehnen zum Spur-Ende zu erzeugen?
5. **ESP32 Host-Zeitankerung:** Rechnet die Host-Ankerung relative Boot-Zeiten der Firmware stabil in Host-Wall-Clock (`SystemTime`) um und detektiert sie Zeitsprünge (>2 s rückwärts, >60 s vorwärts)?

---

### Task 1: Repository Scaffolding, Tooling & CI Configuration

**Files:**
- Create: `pyproject.toml`
- Create: `LICENSE`
- Create: `.gitignore`
- Create: `.github/workflows/validate-skill.yml`

**Interfaces:**
- Consumes: None
- Produces: GitHub CI workflow, Python packaging config, Git ignore rules

- [ ] **Step 1: Write `pyproject.toml` mit pytest, ruff und mypy Konfiguration**
- [ ] **Step 2: Write `LICENSE` (MIT) und `.gitignore` (Python, Caches, OS files)**
- [ ] **Step 3: Write GitHub Actions Workflow `.github/workflows/validate-skill.yml`**
- [ ] **Step 4: Verify syntax & lint config mit `ruff check .`**
- [ ] **Step 5: Commit**

```bash
git add pyproject.toml LICENSE .gitignore .github/
git commit -m "chore: scaffold C-ITS-Expert repo with CI pipeline and ruff config"
```

---

### Task 2: Core Skill Document (`SKILL.md`) & Specification Test

**Files:**
- Create: `tests/test_skill_spec.py`
- Create: `skill/cits-expert/SKILL.md`

**Interfaces:**
- Consumes: AgentSkills.io Spec
- Produces: `cits-expert/SKILL.md` (< 450 Wörter, SDO, Iron Law, Routing Matrix, Pre-Commit Checklist)

- [ ] **Step 1: Write the failing test `tests/test_skill_spec.py`**
  - Testet, dass `skill/cits-expert/SKILL.md` existiert, valides YAML-Frontmatter enthält, Name `cits-expert` ist, Wortanzahl < 450 ist, und alle verlinkten Dateien in `references/` auflösbar sind.
- [ ] **Step 2: Run test to verify it fails**
  - Befehl: `pytest tests/test_skill_spec.py -v`
  - Erwartung: FAIL (Datei existiert noch nicht)
- [ ] **Step 3: Implement `skill/cits-expert/SKILL.md`**
  - Kompakte Struktur: Frontmatter, Übersicht, Iron Law, SDO-Routing-Matrix, Pre-Commit Checklist.
- [ ] **Step 4: Run test to verify it passes**
  - Befehl: `pytest tests/test_skill_spec.py -v`
  - Erwartung: PASS (Wortanzahl < 450, YAML valid)
- [ ] **Step 5: Commit**

```bash
git add skill/cits-expert/SKILL.md tests/test_skill_spec.py
git commit -m "feat: add cits-expert core SKILL.md with SDO routing and iron law"
```

---

### Task 3: Protocol Dissection Reference & Test

**Files:**
- Create: `skill/cits-expert/references/packet-dissection.md`
- Create: `skill/cits-expert/examples/python/dlt_unwrapper.py`
- Create: `tests/test_dissection_reference.py`

**Interfaces:**
- Consumes: DLT 127 / DLT 105 / DLT 1 Spezifikationen, GeoNetworking ETSI EN 302 636-4-1
- Produces: `DltUnwrapper` Klasse und `packet-dissection.md` Referenz

- [ ] **Step 1: Write failing test `tests/test_dissection_reference.py`**
  - Testet Radiotap-Header-Stripping mit realen Bytes (`00 00 48 00 ...`), LLC/SNAP Erkennung (`0x8947`), BTP-Port-Extraktion (2001–2008), und PCAP-Nanosekunden-Erkennung.
- [ ] **Step 2: Run test to verify it fails**
  - Befehl: `pytest tests/test_dissection_reference.py -v`
  - Erwartung: FAIL
- [ ] **Step 3: Implement `skill/cits-expert/examples/python/dlt_unwrapper.py` & `skill/cits-expert/references/packet-dissection.md`**
  - `DltUnwrapper.unwrap(raw_packet: bytes, link_type: int) -> tuple[bytes, int | None]` (Payload, BTP-Port)
  - Vollständiges `packet-dissection.md` Dokument mit Byte-Layouts und Header-Diagrammen.
- [ ] **Step 4: Run test to verify it passes**
  - Befehl: `pytest tests/test_dissection_reference.py -v`
  - Erwartung: PASS
- [ ] **Step 5: Commit**

```bash
git add skill/cits-expert/references/packet-dissection.md skill/cits-expert/examples/python/dlt_unwrapper.py tests/test_dissection_reference.py
git commit -m "feat: add packet dissection reference and DLT 127 unwrapper implementation"
```

---

### Task 4: Standards, ASN.1 & Topology References

**Files:**
- Create: `skill/cits-expert/references/standards-and-asn1.md`
- Create: `skill/cits-expert/references/topology-mapem-spatem.md`
- Create: `skill/cits-expert/examples/python/mapem_topology_assembler.py`
- Create: `tests/test_mapem_topology.py`

**Interfaces:**
- Consumes: ISO TS 19091, ETSI TS 103 301, C-Roads Topology Profile
- Produces: `MapemTopologyAssembler` und Referenzdokumente für Standards & Topologie

- [ ] **Step 1: Write failing test `tests/test_mapem_topology.py`**
  - Testet Fragment-Zusammenführung zweier MAPEM-Fragmente (`layerID` 21 + 22) für denselben Knoten `(regionId, intersectionId)` ohne Datenverlust.
  - Testet Verbindungs-Generierung ausgehend von Node 0 (Haltelinie) statt Lane-Tail.
- [ ] **Step 2: Run test to verify it fails**
  - Befehl: `pytest tests/test_mapem_topology.py -v`
  - Erwartung: FAIL
- [ ] **Step 3: Implement `mapem_topology_assembler.py`, `standards-and-asn1.md` & `topology-mapem-spatem.md`**
  - `MapemTopologyAssembler.ingest_fragment(fragment: dict) -> None`
  - `MapemTopologyAssembler.build_topology(region_id: int, intersection_id: int) -> dict`
- [ ] **Step 4: Run test to verify it passes**
  - Befehl: `pytest tests/test_mapem_topology.py -v`
  - Erwartung: PASS
- [ ] **Step 5: Commit**

```bash
git add skill/cits-expert/references/standards-and-asn1.md skill/cits-expert/references/topology-mapem-spatem.md skill/cits-expert/examples/python/mapem_topology_assembler.py tests/test_mapem_topology.py
git commit -m "feat: add standards, topology references and multi-fragment MAPEM assembler"
```

---

### Task 5: Priority, GLOSA, Hardware & Anti-Patterns References

**Files:**
- Create: `skill/cits-expert/references/priority-and-glosa.md`
- Create: `skill/cits-expert/references/hardware-and-capture.md`
- Create: `skill/cits-expert/references/anti-patterns-and-verification.md`
- Create: `skill/cits-expert/examples/python/esp32_host_anchor.py`
- Create: `tests/test_esp32_host_anchor.py`

**Interfaces:**
- Consumes: ESP32-C5 Framing, SREM/SSEM ISO TS 19091
- Produces: `Esp32HostTimeAnchor` Klasse und Referenzen für Hardware, Priorität & Anti-Patterns

- [ ] **Step 1: Write failing test `tests/test_esp32_host_anchor.py`**
  - Testet Wandlung von Uptime-Sekunden in Host-Unixzeit.
  - Testet Erkennung von Vorwärts- (>60 s) und Rückwärts- (>2 s) Diskontinuitäten.
- [ ] **Step 2: Run test to verify it fails**
  - Befehl: `pytest tests/test_esp32_host_anchor.py -v`
  - Erwartung: FAIL
- [ ] **Step 3: Implement `esp32_host_anchor.py` und die drei Referenzdokumente**
  - `Esp32HostTimeAnchor.compute_host_time(fw_sec: int, fw_usec: int, wall_now: float | None = None) -> float`
  - Schreibe `priority-and-glosa.md` (4-Tupel SREM/SSEM, Zustände, GLOSA-Formeln).
  - Schreibe `hardware-and-capture.md` (ESP32-C5 V2X Sniffer, ITS5/6, Linux RSU SSH).
  - Schreibe `anti-patterns-and-verification.md` (Verbotstabellen, Test-Pyramide, Pflicht-Fixtures).
- [ ] **Step 4: Run test to verify it passes**
  - Befehl: `pytest tests/test_esp32_host_anchor.py -v`
  - Erwartung: PASS
- [ ] **Step 5: Commit**

```bash
git add skill/cits-expert/references/priority-and-glosa.md skill/cits-expert/references/hardware-and-capture.md skill/cits-expert/references/anti-patterns-and-verification.md skill/cits-expert/examples/python/esp32_host_anchor.py tests/test_esp32_host_anchor.py
git commit -m "feat: add priority, hardware, anti-patterns references and ESP32 host time anchor"
```

---

### Task 6: Cross-Platform Implementation Snippets (Rust & TypeScript)

**Files:**
- Create: `skill/cits-expert/examples/rust/dissector.rs`
- Create: `skill/cits-expert/examples/rust/esp32_framing.rs`
- Create: `skill/cits-expert/examples/typescript/dlt_reader.ts`
- Create: `skill/cits-expert/examples/typescript/lane_geometry.ts`

**Interfaces:**
- Consumes: Referenz-Architekturen aus `cits-inspector-v2`
- Produces: Saubere, syntaktisch korrekte Rust- und TypeScript-Vorlagen für KI-Agenten

- [ ] **Step 1: Write `skill/cits-expert/examples/rust/dissector.rs` (nom-basierter Zero-Copy DLT-Dissector)**
- [ ] **Step 2: Write `skill/cits-expert/examples/rust/esp32_framing.rs` (Lookahead ITS5/ITS6 Parser)**
- [ ] **Step 3: Write `skill/cits-expert/examples/typescript/dlt_reader.ts` (DataView DLT-Reader)**
- [ ] **Step 4: Write `skill/cits-expert/examples/typescript/lane_geometry.ts` (GeoJSON Ingress/Egress Connections)**
- [ ] **Step 5: Commit**

```bash
git add skill/cits-expert/examples/rust/ skill/cits-expert/examples/typescript/
git commit -m "feat: add cross-platform Rust and TypeScript reference snippets"
```

---

### Task 7: Multi-Agent Deployment & Synchronization CLI (`sync_skill.py`)

**Files:**
- Create: `sync_skill.py`
- Create: `tests/test_sync_skill.py`

**Interfaces:**
- Consumes: `skill/cits-expert/`
- Produces: CLI Tool zur Spiegelung des Skills in Antigravity-, Claude Code- und Agent-Pfade

- [ ] **Step 1: Write failing test `tests/test_sync_skill.py`**
  - Testet Pfad-Erkennung für Antigravity Plugin, Claude Code, OpenAI Codex/OpenCode und Ziel-Validierung.
- [ ] **Step 2: Run test to verify it fails**
  - Befehl: `pytest tests/test_sync_skill.py -v`
  - Erwartung: FAIL
- [ ] **Step 3: Implement `sync_skill.py`**
  - CLI Optionen: `--install-global`, `--install-project <PATH>`, `--dry-run`, `--check`.
  - Atomare Kopie aller Markdown-, Referenz- und Example-Dateien.
- [ ] **Step 4: Run test to verify it passes**
  - Befehl: `pytest tests/test_sync_skill.py -v`
  - Erwartung: PASS
- [ ] **Step 5: Commit**

```bash
git add sync_skill.py tests/test_sync_skill.py
git commit -m "feat: add multi-agent sync_skill.py CLI tool and tests"
```

---

### Task 8: Global Installation, Open-Source README & End-to-End Verification

**Files:**
- Create: `README.md`
- Target: `C:\Users\Kevin Seipel\.gemini\config\plugins\cits-expert\skills\cits-expert\`
- Target: `C:\Users\Kevin Seipel\.gemini\config\plugins\cits-asn1\skills\cits-asn1\`
- Target: `C:\Users\Kevin Seipel\.agents\skills\cits-expert\`
- Target: `C:\Users\Kevin Seipel\.claude\skills\cits-expert\`

**Interfaces:**
- Consumes: Alle Tasks 1–7
- Produces: Global installierter Skill auf dem lokalen Rechner, zweisprachiges GitHub-README, 100% grüne Test-Suite

- [ ] **Step 1: Write comprehensive `README.md` (DE/EN) für GitHub-Veröffentlichung**
- [ ] **Step 2: Run `python sync_skill.py --install-global`**
- [ ] **Step 3: Run full test suite: `pytest -v`**
- [ ] **Step 4: Run linter: `ruff check .`**
- [ ] **Step 5: Final commit & tag v1.0.0**

```bash
git add README.md
git commit -m "feat: complete C-ITS Expert skill suite with open-source documentation and global deployment"
git tag -a v1.0.0 -m "Release v1.0.0: C-ITS Expert Skill Suite"
```
