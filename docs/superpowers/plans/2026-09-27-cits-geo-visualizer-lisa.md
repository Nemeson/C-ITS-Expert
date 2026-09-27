# 3D Geo-Visualizer, LISA LV.XML Compiler & GLOSA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a pure-Python 3D KML/GeoJSON export engine, LISA `LV.XML` signal-group compiler, and GLOSA speed-advisory calculator with CLI and MCP agent integration.

**Architecture:** A lightweight geo & infrastructure subsystem (`cits_validator/geo/` and `cits_validator/lisa/`) utilizing Python standard library (`xml.etree.ElementTree`, `json`, `math`). Exposes automated visualization pipelines via `cits-export` CLI and interactive MCP tools (`cits_export_kml`, `cits_parse_lisa`, `cits_compute_glosa`).

**Tech Stack:** Python 3.11–3.14 (Pure Python standard library: `xml.etree.ElementTree`, `dataclasses`, `math`, `json`, `argparse`).

**Spec:** [`docs/superpowers/specs/2026-09-27-cits-geo-visualizer-lisa-design.md`](docs/superpowers/specs/2026-09-27-cits-geo-visualizer-lisa-design.md)

## Global Constraints

- **Pure Python:** Zero external third-party dependencies (no `simplekml`, no `shapely`, no `geopandas`).
- **Zero Data Hallucination:** Geometry and signal groups must strictly originate from MAPEM/SPATEM and real LISA files; no fake synthetic chords or invented signal groups.
- **Node 0 Stopline Invariant:** Stopline markers and GLOSA speed calculations must anchor at Node 0 near intersection centers.
- **Token Efficiency:** Keep `SKILL.md` strictly under 450 words.

## Review Focus

1. **LISA Turn Signal Classification:** Specialized turn signals with only Gelb+Grün (e.g. `K11`) must be classified as `vehicle`, not `pedestrian`.
2. **KML 3D Coordinate Tuple Order:** KML 2.2 standard strictly specifies `longitude,latitude,altitude`. Inverting lat/lon will break 3D rendering.
3. **GLOSA Horizon Wrap-Around:** Ensure countdowns handle horizon boundary conditions without negative travel times or division by zero.
4. **Multi-Fragment Geometry Integration:** Merged MAPEM lanes across `layerID` 21 and 22 must appear seamlessly in the exported KML/GeoJSON layers.

---

### Task 1: LISA `LV.XML` Parser & Signal-Group Classifier

**Files:**
- Create: `cits_validator/lisa/__init__.py`
- Create: `cits_validator/lisa/models.py`
- Create: `cits_validator/lisa/parser.py`
- Test: `tests/lisa/test_lisa_parser.py`

**Interfaces:**
- `LisaSignalGroup`: Dataclass (`obj_nr`, `bezeichnung`, `name`, `classification`, `aspects`, `is_pedestrian`)
- `LisaSupplyCatalog`: Class with lookup `by_obj_nr(obj_nr: int) -> LisaSignalGroup`
- `parse_lisa_supply(xml_text_or_path: str | Path) -> LisaSupplyCatalog`

- [ ] **Step 1: Write failing tests `tests/lisa/test_lisa_parser.py`**
  - Test parsing XML with vehicle (`K1`), pedestrian (`F5`), bicycle (`R17`), and transit (`B1`) signal groups.
  - Test separated turn signal `K11` (Gelb+Grün) classified as `vehicle`.
  - Test catalog lookup by `obj_nr`.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/lisa/test_lisa_parser.py`
- [ ] **Step 3: Implement `models.py` and `parser.py`**
  - Implement ElementTree-based parsing in `cits_validator/lisa/parser.py`.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/lisa/test_lisa_parser.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement LISA LV.XML supply parser and signal-group classifier`

---

### Task 2: GLOSA Advisory Calculation Engine

**Files:**
- Create: `cits_validator/geo/__init__.py`
- Create: `cits_validator/geo/glosa.py`
- Test: `tests/geo/test_glosa.py`

**Interfaces:**
- `GlosaAdvisory`: Dataclass (`speed_min_kmh`, `speed_max_kmh`, `recommendation`, `time_to_stopline_s`, `is_pass_possible`)
- `compute_glosa_advisory(...) -> GlosaAdvisory`

- [ ] **Step 1: Write failing tests `tests/geo/test_glosa.py`**
  - Test cruising within green phase.
  - Test deceleration to arrive at onset of green.
  - Test acceleration within legal speed limit to pass before red.
  - Test impossible pass triggering `PREPARE_TO_STOP`.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/geo/test_glosa.py`
- [ ] **Step 3: Implement `cits_validator/geo/glosa.py`**
  - Implement GLOSA calculation logic with physical and legal bounds.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/geo/test_glosa.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement GLOSA speed advisory trajectory engine`

---

### Task 3: 3D GeoJSON & KML Exporter

**Files:**
- Create: `cits_validator/geo/geojson_builder.py`
- Create: `cits_validator/geo/kml_builder.py`
- Test: `tests/geo/test_geojson_builder.py`
- Test: `tests/geo/test_kml_builder.py`

**Interfaces:**
- `export_mapem_geojson(lanes: list[dict], lisa_catalog: LisaSupplyCatalog | None) -> dict`
- `export_mapem_kml(lanes: list[dict], lisa_catalog: LisaSupplyCatalog | None) -> str`

- [ ] **Step 1: Write failing tests `test_geojson_builder.py` and `test_kml_builder.py`**
  - Test GeoJSON LineString formatting and property decoration (`signalGroup`, `lisa_name`).
  - Test KML 2.2 XML schema generation with 3D coordinates `(lon,lat,alt)`.
  - Test stopline Node-0 point rendering.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/geo/test_geojson_builder.py tests/geo/test_kml_builder.py`
- [ ] **Step 3: Implement `geojson_builder.py` and `kml_builder.py`**
  - Pure-Python ElementTree XML builder and RFC 7946 GeoJSON builder.
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/geo/test_geojson_builder.py tests/geo/test_kml_builder.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement pure-Python 3D KML and GeoJSON MAPEM exporters`

---

### Task 4: CLI Interface (`cits-export`) & Console Script

**Files:**
- Create: `cits_validator/cli/export.py`
- Modify: `pyproject.toml` (add `cits-export = "cits_validator.cli.export:main"`)
- Test: `tests/cli/test_export_cli.py`

- [ ] **Step 1: Write failing tests `tests/cli/test_export_cli.py`**
  - Test CLI argument handling (`--mapem`, `--lisa`, `--format kml|geojson`, `--output`).
  - Test stdout and file export.
- [ ] **Step 2: Run tests to verify failure**
  - Run: `py -3.14 -m pytest tests/cli/test_export_cli.py`
- [ ] **Step 3: Implement `cits_validator/cli/export.py` and update `pyproject.toml`**
- [ ] **Step 4: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/cli/test_export_cli.py -v`
- [ ] **Step 5: Git commit**
  - Commit: `feat: implement cits-export CLI command`

---

### Task 5: MCP Agent Tools Integration (`cits-mcp`)

**Files:**
- Modify: `cits_validator/mcp/tools.py`
- Modify: `cits_validator/mcp/server.py`
- Test: `tests/validator/test_mcp_server.py`

- [ ] **Step 1: Add new test cases in `tests/validator/test_mcp_server.py`**
  - Test tool `cits_parse_lisa`.
  - Test tool `cits_compute_glosa`.
  - Test tool `cits_export_kml`.
- [ ] **Step 2: Implement tool handlers in `tools.py` and `server.py`**
- [ ] **Step 3: Run tests to verify pass**
  - Run: `py -3.14 -m pytest tests/validator/test_mcp_server.py -v`
- [ ] **Step 4: Git commit**
  - Commit: `feat: add LISA, GLOSA and KML tools to cits-mcp server`

---

### Task 6: Full Verification, Documentation & Global Sync

**Files:**
- Modify: `README.md`
- Modify: `skill/cits-expert/SKILL.md`
- Sync: `sync_skill.py`
- Test: Full test suite (`pytest -v`)

- [ ] **Step 1: Update documentation and ensure SKILL.md remains < 450 words**
- [ ] **Step 2: Run full test suite & linter**
  - `py -3.14 -m pytest -v`
  - `py -3.14 -m ruff check .`
- [ ] **Step 3: Run `sync_skill.py --install-global`**
- [ ] **Step 4: Commit & Push to GitHub with tag `v1.2.0`**
