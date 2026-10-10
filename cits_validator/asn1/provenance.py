"""Provenance for the vendored ASN.1 modules.

Every module the conformance core compiles is recorded with the standard,
version and origin it came from. A decoded field can therefore be traced back to
the specification that defines it, and `cits-lint` can report the exact standard
a PDU was validated against — which is the point of validating at all.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

STANDARDS_DIR = Path(__file__).resolve().parent / "standards"
MANIFEST_PATH = STANDARDS_DIR / "manifest.json"


def module_digest(data: bytes) -> str:
    """SHA-256 of a module with line endings normalised to LF.

    Git checks the same text out as CRLF on Windows and LF elsewhere; the digest must not
    depend on that, or a correct module would fail verification on another platform."""
    return hashlib.sha256(data.replace(bytes([13, 10]), bytes([10]))).hexdigest()


@dataclass(frozen=True)
class ModuleProvenance:
    file: str
    release: str
    standard: str
    version: str
    scope: str
    source_url: str
    source_path: str = ""
    sha256: str = ""
    license: str = ""

    @property
    def path(self) -> Path:
        return STANDARDS_DIR / self.file

    def to_dict(self) -> dict[str, str]:
        return {
            "file": self.file,
            "release": self.release,
            "standard": self.standard,
            "version": self.version,
            "scope": self.scope,
            "source_url": self.source_url,
        }


def load_manifest(path: Path | None = None) -> list[ModuleProvenance]:
    """Reads the vendored-module manifest. Returns [] when it is absent."""
    manifest_path = path or MANIFEST_PATH
    if not manifest_path.is_file():
        return []
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return [ModuleProvenance(**entry) for entry in data.get("modules", [])]


def modules_for_release(release: str, manifest_path: Path | None = None) -> list[Path]:
    """Returns the vendored module paths belonging to one release baseline."""
    return [m.path for m in load_manifest(manifest_path) if m.release == release]


def provenance_for_file(name: str, manifest_path: Path | None = None) -> ModuleProvenance | None:
    for module in load_manifest(manifest_path):
        if module.file.endswith(name):
            return module
    return None


def standards_summary(manifest_path: Path | None = None) -> list[dict[str, str]]:
    """Unique (standard, version, release) triples, for reporting."""
    seen: dict[tuple[str, str, str], dict[str, str]] = {}
    for m in load_manifest(manifest_path):
        seen[(m.release, m.standard, m.version)] = {
            "release": m.release,
            "standard": m.standard,
            "version": m.version,
        }
    return sorted(seen.values(), key=lambda d: (d["release"], d["standard"], d["version"]))
