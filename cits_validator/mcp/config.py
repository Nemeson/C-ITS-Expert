from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

VALID_PROFILES = ("device", "host", "ci")
DEFAULT_MAX_OUTPUT_BYTES = 262144
DEFAULT_MAX_FILE_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class Settings:
    profile: str
    bind_host: str
    token: str | None
    max_output_bytes: int
    roots: tuple[Path, ...]
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

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
            max_file_bytes=int(e.get("CITS_MCP_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES)),
        )
