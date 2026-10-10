from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

VALID_PROFILES = ("device", "host", "ci")
DEFAULT_MAX_OUTPUT_BYTES = 262144
DEFAULT_MAX_FILE_BYTES = 256 * 1024 * 1024
MIN_LIMIT_BYTES = 1024


def _limit(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if value < MIN_LIMIT_BYTES:
        raise ValueError(f"{name} must be at least {MIN_LIMIT_BYTES}, got {value}")
    return value


def _parse_roots(raw: str | None) -> tuple[Path, ...]:
    if not raw:
        roots: tuple[Path, ...] = (Path.cwd(),)
    else:
        roots = tuple(Path(p) for p in raw.split(os.pathsep) if p.strip())
    for root in roots:
        resolved = root.resolve()
        if resolved == resolved.parent:
            raise ValueError(f"refusing filesystem root as allowed root: {resolved}")
    return roots


@dataclass(frozen=True)
class Settings:
    profile: str
    bind_host: str
    token: str | None
    max_output_bytes: int
    roots: tuple[Path, ...]
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        profile = e.get("CITS_MCP_PROFILE", "host").strip().lower()
        if profile not in VALID_PROFILES:
            raise ValueError(
                f"CITS_MCP_PROFILE must be one of {VALID_PROFILES}, got {profile!r}"
            )
        roots = _parse_roots(e.get("CITS_MCP_ROOTS"))
        return cls(
            profile=profile,
            bind_host=e.get("CITS_MCP_BIND_HOST", "127.0.0.1"),
            token=e.get("CITS_MCP_TOKEN") or None,
            max_output_bytes=_limit(e, "CITS_MCP_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES),
            roots=roots,
            max_file_bytes=_limit(e, "CITS_MCP_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES),
        )
