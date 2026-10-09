# C-ITS MCP Embedded (Milestone 1) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn `cits-mcp` from a STDIO-only host tool into a profile-scoped, security-guarded MCP server that runs on constrained Linux (RSU/edge) with a zero-dependency `device` profile and a `cits-edge` zipapp, without touching the rule core.

**Architecture:** Add a thin layer above the existing `McpServer`: a `config` surface (env/CLI), `profiles` that filter tools + enforce rights/limits, `security` guards (token gate, path allowlist, output cap), and a `transport` abstraction (STDIO now, HTTP later). The `cits_validator` rule engine stays the single source of truth; nothing in `rules/` changes except an additive metadata hook.

**Tech Stack:** Python 3.11+ (stdlib only for the device profile), pytest, ruff, mypy, coverage gate 85%.

---

## Conventions for every task

- Run from repo root `C:\PythonTools\C-ITS-Expert`.
- Test command: `python -m pytest <path> -v`
- Lint: `ruff check .` — Types: `mypy cits_validator`
- Commit after each task with the message shown.

---

### Task 1: Configuration surface (`mcp/config.py`)

**Files:**
- Create: `cits_validator/mcp/config.py`
- Test: `tests/validator/test_mcp_config.py`

**Step 1: Write the failing test**

```python
from cits_validator.mcp.config import Settings


def test_defaults_are_host_profile_and_loopback():
    s = Settings.from_env({})
    assert s.profile == "host"
    assert s.bind_host == "127.0.0.1"
    assert s.token is None
    assert s.max_output_bytes == 262144
    assert s.roots  # non-empty: defaults to cwd


def test_env_overrides():
    s = Settings.from_env({
        "CITS_MCP_PROFILE": "device",
        "CITS_MCP_TOKEN": "secret",
        "CITS_MCP_MAX_OUTPUT_BYTES": "1024",
        "CITS_MCP_ROOTS": "a;b",
    })
    assert s.profile == "device"
    assert s.token == "secret"
    assert s.max_output_bytes == 1024
    assert [str(p) for p in s.roots] == ["a", "b"]


def test_invalid_profile_rejected():
    import pytest
    with pytest.raises(ValueError):
        Settings.from_env({"CITS_MCP_PROFILE": "nope"})
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/validator/test_mcp_config.py -v`
Expected: FAIL (ModuleNotFoundError: cits_validator.mcp.config)

**Step 3: Write minimal implementation**

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

VALID_PROFILES = ("device", "host", "ci")
DEFAULT_MAX_OUTPUT_BYTES = 262144


@dataclass(frozen=True)
class Settings:
    profile: str
    bind_host: str
    token: str | None
    max_output_bytes: int
    roots: tuple[Path, ...]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        e = os.environ if env is None else env
        profile = e.get("CITS_MCP_PROFILE", "host").strip().lower()
        if profile not in VALID_PROFILES:
            raise ValueError(
                f"CITS_MCP_PROFILE must be one of {VALID_PROFILES}, got {profile!r}"
            )
        roots_raw = e.get("CITS_MCP_ROOTS")
        roots = (
            tuple(Path(p) for p in roots_raw.split(";") if p.strip())
            if roots_raw
            else (Path.cwd(),)
        )
        return cls(
            profile=profile,
            bind_host=e.get("CITS_MCP_BIND_HOST", "127.0.0.1"),
            token=e.get("CITS_MCP_TOKEN") or None,
            max_output_bytes=int(e.get("CITS_MCP_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES)),
            roots=roots,
        )
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/validator/test_mcp_config.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cits_validator/mcp/config.py tests/validator/test_mcp_config.py
git commit -m "feat(mcp): add env/CLI configuration surface"
```

---

### Task 2: Capability profiles (`mcp/profiles.py`)

**Files:**
- Create: `cits_validator/mcp/profiles.py`
- Test: `tests/validator/test_mcp_profiles.py`

**Step 1: Write the failing test**

```python
from cits_validator.mcp.profiles import get_profile

DEVICE = ["cits_inspect_hex", "cits_validate_pcap", "cits_check_mapem",
          "cits_compute_glosa", "cits_parse_lisa", "cits_selftest"]


def test_device_hides_non_device_tools():
    p = get_profile("device")
    kept = p.filter_tools(DEVICE + ["cits_export_kml", "cits_decode_pdu"])
    assert "cits_export_kml" not in kept
    assert "cits_decode_pdu" not in kept
    assert set(kept) == set(DEVICE)


def test_device_is_read_only():
    assert get_profile("device").read_only is True
    assert get_profile("host").read_only is False


def test_host_exposes_everything():
    p = get_profile("host")
    names = DEVICE + ["cits_export_kml", "cits_decode_pdu"]
    assert set(p.filter_tools(names)) == set(names)
```

**Step 2: Run** — FAIL (no module).

**Step 3: Write minimal implementation**

```python
from __future__ import annotations

from dataclasses import dataclass

DEVICE_TOOLS = frozenset({
    "cits_inspect_hex", "cits_validate_pcap", "cits_check_mapem",
    "cits_compute_glosa", "cits_parse_lisa", "cits_selftest",
})
CI_TOOLS = frozenset({"cits_validate_pcap", "cits_audit_code", "cits_decode_pdu"})


@dataclass(frozen=True)
class Profile:
    name: str
    allowed: frozenset[str] | None  # None = all
    read_only: bool

    def filter_tools(self, names: list[str]) -> list[str]:
        if self.allowed is None:
            return list(names)
        return [n for n in names if n in self.allowed]


_PROFILES = {
    "device": Profile("device", DEVICE_TOOLS, True),
    "host": Profile("host", None, False),
    "ci": Profile("ci", CI_TOOLS, True),
}


def get_profile(name: str) -> Profile:
    try:
        return _PROFILES[name]
    except KeyError:
        raise ValueError(f"unknown profile: {name!r}") from None
```

**Step 4: Run** — PASS.

**Step 5: Commit**

```bash
git add cits_validator/mcp/profiles.py tests/validator/test_mcp_profiles.py
git commit -m "feat(mcp): add capability profiles (device/host/ci)"
```

---

### Task 3: Security guards (`mcp/security.py`)

**Files:**
- Create: `cits_validator/mcp/security.py`
- Test: `tests/validator/test_mcp_security.py`

**Step 1: Write the failing test**

```python
from pathlib import Path
import pytest
from cits_validator.mcp.security import ensure_path_allowed, cap_output, require_token_if_remote


def test_path_outside_roots_refused(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.pcap"
    outside.write_bytes(b"x")
    with pytest.raises(PermissionError):
        ensure_path_allowed(outside, roots=(root,))


def test_path_inside_roots_allowed(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "a.pcap"
    inside.write_bytes(b"x")
    assert ensure_path_allowed(inside, roots=(root,)) == inside.resolve()


def test_remote_bind_without_token_refused():
    with pytest.raises(PermissionError):
        require_token_if_remote("0.0.0.0", None)


def test_loopback_without_token_allowed():
    require_token_if_remote("127.0.0.1", None)  # no raise


def test_cap_output_truncates_and_marks():
    payload = {"violations": list(range(100))}
    capped = cap_output(payload, max_bytes=200)
    assert capped["truncated"] is True
    assert capped["total"] == 100
    assert len(capped["violations"]) < 100
```

**Step 2: Run** — FAIL.

**Step 3: Write minimal implementation**

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def ensure_path_allowed(path: Path, roots: tuple[Path, ...]) -> Path:
    resolved = Path(path).resolve()
    for root in roots:
        try:
            resolved.relative_to(Path(root).resolve())
            return resolved
        except ValueError:
            continue
    raise PermissionError(f"path not under any allowed root: {resolved}")


def require_token_if_remote(bind_host: str, token: str | None) -> None:
    if bind_host not in _LOOPBACK and not token:
        raise PermissionError(
            "binding to a non-loopback address requires CITS_MCP_TOKEN"
        )


def cap_output(payload: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    encoded = json.dumps(payload)
    if len(encoded.encode("utf-8")) <= max_bytes:
        return payload
    items = payload.get("violations")
    if not isinstance(items, list):
        return {"truncated": True, "total": None, "data": payload.get("data")}
    total = len(items)
    kept = items
    while kept and len(json.dumps({**payload, "violations": kept}).encode("utf-8")) > max_bytes:
        kept = kept[:-1]
    return {**payload, "violations": kept, "truncated": True, "total": total}
```

**Step 4: Run** — PASS.

**Step 5: Commit**

```bash
git add cits_validator/mcp/security.py tests/validator/test_mcp_security.py
git commit -m "feat(mcp): add token gate, path allowlist, output cap guards"
```

---

### Task 4: Rule catalog export (`cits_validator/rules/export.py` + `BaseRule.metadata()`)

**Files:**
- Modify: `cits_validator/core/registry.py` (add `metadata()` to `BaseRule`)
- Create: `cits_validator/rules/export.py`
- Modify: `cits_validator/cli/export.py` (add `--rules-json`)
- Test: `tests/validator/test_rule_export.py`

**Step 1: Write the failing test**

```python
from cits_validator.rules.export import export_rule_catalog


def test_catalog_lists_all_rules_with_ids():
    catalog = export_rule_catalog()
    ids = {r["rule_id"] for r in catalog["rules"]}
    assert {"R01", "R02", "R03", "R04", "R05", "R06"} <= ids
    assert all({"rule_id", "name", "description", "metadata"} <= set(r) for r in catalog["rules"])
```

**Step 2: Run** — FAIL.

**Step 3: Implement.** In `core/registry.py`, add to `BaseRule`:

```python
    def metadata(self) -> dict[str, Any]:
        """Machine-readable descriptors for codegen and tooling. Empty by default."""
        return {}
```

In `rules/r03_topology.py` override it to include the chord bound:

```python
    def metadata(self) -> dict[str, Any]:
        return {"max_stopline_chord_meters": self.max_stopline_chord_meters}
```

Create `cits_validator/rules/export.py`:

```python
from __future__ import annotations

from typing import Any

from cits_validator import __version__
from cits_validator.cli.main import build_default_registry


def export_rule_catalog() -> dict[str, Any]:
    """Machine-readable rule catalog — the M1 contract consumed by Milestone 3 codegen."""
    registry = build_default_registry()
    return {
        "version": __version__,
        "rules": [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "metadata": r.metadata(),
            }
            for r in registry.list_rules()
        ],
    }
```

In `cli/export.py` `run_cli`, add the flag and an early branch:

```python
    parser.add_argument("--rules-json", action="store_true",
                        help="Emit the machine-readable rule catalog as JSON and exit")
```

```python
    if args.rules_json:
        from cits_validator.rules.export import export_rule_catalog
        print(json.dumps(export_rule_catalog(), indent=2))
        return 0
```

**Step 4: Run** — PASS. Also verify CLI manually: `python -m cits_validator.cli.export --rules-json`.

**Step 5: Commit**

```bash
git add cits_validator/core/registry.py cits_validator/rules/export.py cits_validator/rules/r03_topology.py cits_validator/cli/export.py tests/validator/test_rule_export.py
git commit -m "feat(rules): machine-readable rule catalog + cits-export --rules-json"
```

---

### Task 5: Wire profile + security into `McpServer` (opt-in, backward-compatible)

**Files:**
- Modify: `cits_validator/mcp/server.py`
- Test: `tests/validator/test_mcp_server_profiles.py`

**Step 1: Write the failing test**

```python
import json
import pytest
from cits_validator.mcp.server import McpServer
from cits_validator.mcp.config import Settings


def _server(**env):
    return McpServer(settings=Settings.from_env(env))


def test_default_server_unchanged_exposes_all_tools():
    tools = _server().handle_request({"id": 1, "method": "tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "cits_export_kml" in names and "cits_decode_pdu" in names


def test_device_profile_hides_export_and_marks_readonly():
    tools = _server(CITS_MCP_PROFILE="device").handle_request(
        {"id": 1, "method": "tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "cits_export_kml" not in names
    assert "cits_inspect_hex" in names


def test_tool_failure_is_result_iserror_not_jsonrpc_error():
    s = _server()
    resp = s.handle_request({
        "id": 2, "method": "tools/call",
        "params": {"name": "cits_validate_pcap",
                   "arguments": {"file_path": "C:/definitely/missing.pcap"}},
    })
    assert "error" not in resp
    assert resp["result"]["isError"] is True


def test_path_outside_root_refused_under_device(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    s = _server(CITS_MCP_PROFILE="device", CITS_MCP_ROOTS=str(root))
    resp = s.handle_request({
        "id": 3, "method": "tools/call",
        "params": {"name": "cits_validate_pcap",
                   "arguments": {"file_path": str(tmp_path / "out.pcap")}},
    })
    assert resp["result"]["isError"] is True
```

**Step 2: Run** — FAIL.

**Step 3: Implement (minimal changes to `server.py`)**

1. `McpServer.__init__(self, settings: Settings | None = None)` → store `self.settings = settings or Settings.from_env()` and `self.profile = get_profile(self.settings.profile)`.
2. At start of `run_stdio()`: `require_token_if_remote(self.settings.bind_host, self.settings.token)`.
3. In `tools/list`: wrap `self.TOOL_DEFINITIONS` with `self.profile.filter_tools([t["name"] for t in ...])` and add annotations per tool (`"annotations": {"readOnlyHint": True}` for read-only tools).
4. In `tools/call`, before dispatch: if `self.settings.profile == "device" and "file_path" in tool_args`: `ensure_path_allowed(Path(tool_args["file_path"]), self.settings.roots)`.
5. Wrap the handler result:
   - on tool exception: return `{"result": {"content": [...], "isError": True}}` (NOT JSON-RPC `error`);
   - on success: `cap_output(res, self.settings.max_output_bytes)` before serialising.
6. Register `cits_selftest` (Task 6) in `TOOL_DEFINITIONS` + handlers.

**Step 4: Run** — PASS. Then run the full suite to confirm no regression:
`python -m pytest -q --cov=cits_validator --cov-fail-under=85`

**Step 5: Commit**

```bash
git add cits_validator/mcp/server.py tests/validator/test_mcp_server_profiles.py
git commit -m "feat(mcp): profile-scoped tools, guards and corrected tool-error semantics"
```

---

### Task 6: `cits_selftest` tool + `cits://` resources (`mcp/resources.py`)

**Files:**
- Create: `cits_validator/mcp/resources.py`
- Modify: `cits_validator/mcp/tools.py` (add `cits_selftest`)
- Modify: `cits_validator/mcp/server.py` (`resources/list`, `resources/read`)
- Test: `tests/validator/test_mcp_resources.py`

**Step 1: Write the failing test**

```python
import json
from cits_validator.mcp.server import McpServer


def test_selftest_reports_profile_and_version():
    s = McpServer()
    resp = s.handle_request({"id": 1, "method": "tools/call",
                             "params": {"name": "cits_selftest", "arguments": {}}})
    data = json.loads(resp["result"]["content"][0]["text"])
    assert data["ok"] is True
    assert data["profile"] == "host"
    assert "version" in data


def test_resources_list_and_read_rules():
    s = McpServer()
    lst = s.handle_request({"id": 2, "method": "resources/list"})["result"]["resources"]
    uris = {r["uri"] for r in lst}
    assert "cits://rules" in uris and "cits://version" in uris
    read = s.handle_request({"id": 3, "method": "resources/read",
                             "params": {"uri": "cits://rules"}})["result"]
    assert "R01" in read["contents"][0]["text"]
```

**Step 2: Run** — FAIL.

**Step 3: Implement**

`resources.py`:

```python
from __future__ import annotations

import json

from cits_validator import __version__
from cits_validator.rules.export import export_rule_catalog

RESOURCES = [
    {"uri": "cits://rules", "name": "Rule catalog", "mimeType": "application/json"},
    {"uri": "cits://version", "name": "Server version", "mimeType": "application/json"},
]


def read_resource(uri: str) -> str:
    if uri == "cits://rules":
        return json.dumps(export_rule_catalog(), indent=2)
    if uri == "cits://version":
        return json.dumps({"version": __version__})
    raise ValueError(f"unknown resource: {uri}")
```

`tools.py` — add:

```python
def cits_selftest(profile: str = "host") -> dict[str, Any]:
    """Liveness/health probe for the edge daemon."""
    from cits_validator import __version__
    return {"ok": True, "profile": profile, "version": __version__}
```

`server.py` — handle `resources/list` and `resources/read`; register `cits_selftest` in `TOOL_DEFINITIONS` and `tool_handlers` (pass `self.settings.profile`).

**Step 4: Run** — PASS.

**Step 5: Commit**

```bash
git add cits_validator/mcp/resources.py cits_validator/mcp/tools.py cits_validator/mcp/server.py tests/validator/test_mcp_resources.py
git commit -m "feat(mcp): cits_selftest tool and cits:// resources"
```

---

### Task 7: `cits-edge` zipapp + systemd template

**Files:**
- Create: `scripts/build_edge_zipapp.py`
- Create: `packaging/cits-edge.service`
- Test: `tests/validator/test_edge_zipapp.py`

**Step 1: Write the failing test**

```python
import subprocess, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_zipapp_builds_and_runs_without_asn1(tmp_path):
    out = tmp_path / "cits-edge.pyz"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_edge_zipapp.py"),
                    "--output", str(out)], check=True)
    assert out.is_file()
    # Device profile must not require asn1tools.
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    assert not any("asn1tools" in n for n in names)
    proc = subprocess.run([sys.executable, str(out), "selftest"],
                          capture_output=True, text=True, cwd=str(ROOT))
    assert proc.returncode == 0
```

**Step 2: Run** — FAIL.

**Step 3: Implement**

`scripts/build_edge_zipapp.py` — collects `cits_validator/` **excluding** `asn1/` and `rules/r06_asn1_conformance.py`, writes a `__main__.py` that starts `McpServer` with `CITS_MCP_PROFILE=device` (or runs `selftest` when argv[1]=="selftest"), then `zipapp.create_archive`.

`packaging/cits-edge.service`:

```ini
[Unit]
Description=C-ITS MCP edge daemon (device profile)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/cits-edge/cits-edge.pyz
Environment=CITS_MCP_PROFILE=device
Environment=CITS_MCP_BIND_HOST=127.0.0.1
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Step 4: Run** — PASS.

**Step 5: Commit**

```bash
git add scripts/build_edge_zipapp.py packaging/cits-edge.service tests/validator/test_edge_zipapp.py
git commit -m "feat(packaging): cits-edge zipapp (device profile, no asn1) + systemd unit"
```

---

### Task 8: CI embedded gate + docs

**Files:**
- Modify: `.github/workflows/validate-skill.yml`
- Modify: `README.md` (MCP section: profiles, security env vars, edge zipapp)
- Modify: `CHANGELOG.md` (`## [Unreleased]` → Added entries)

**Step 1:** Add a CI job that builds the zipapp and runs the device-profile smoke test **without** installing `.[asn1]`:

```yaml
  edge-zipapp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e .
      - run: python scripts/build_edge_zipapp.py --output cits-edge.pyz
      - run: python cits-edge.pyz selftest
```

**Step 2:** Document `CITS_MCP_PROFILE`, `CITS_MCP_TOKEN`, `CITS_MCP_BIND_HOST`, `CITS_MCP_ROOTS`, `CITS_MCP_MAX_OUTPUT_BYTES` and the zipapp in the README MCP section.

**Step 3:** Add Unreleased entries to CHANGELOG.

**Step 4: Run full suite + gates**

Run: `python -m pytest -q --cov=cits_validator --cov-fail-under=85 && ruff check . && mypy cits_validator`
Expected: PASS (≥ 85 % coverage).

**Step 5: Commit**

```bash
git add .github/workflows/validate-skill.yml README.md CHANGELOG.md
git commit -m "ci/docs(mcp): embedded zipapp gate, profile + security documentation"
```

---

## Definition of Done (Milestone 1)

- All existing 225 tests green; coverage ≥ 85 %.
- `device` profile exposes only the six read-only tools; `cits_export_kml` hidden.
- Non-loopback bind without `CITS_MCP_TOKEN` refuses to start; `file_path` outside `CITS_MCP_ROOTS` refused.
- Tool faults return `result.isError: true`; protocol faults stay JSON-RPC errors.
- Oversized results carry `truncated: true` and `total`.
- `cits-edge.pyz` builds and runs `selftest` with no `asn1tools` present.
- `cits-export --rules-json` emits the rule catalog.
- No change to rule logic; `cits_validator` core remains the single source of truth.

## Explicitly out of scope (M2/M3)

HTTP/SSE transport, progress/cancellation, `cits_stream_frames`, `cits_diff_captures`,
`cits_decode_*` in the device profile, native C/Rust codegen, ETSI TS 103 097 PKI.
