from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}

_TRUNCATABLE_LIST_KEYS = ("violations", "features", "contents")


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


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload).encode("utf-8"))


def cap_output(payload: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    # 1. Fits → return unchanged.
    if _encoded_size(payload) <= max_bytes:
        return payload

    # 2. Truncate the LONGEST truncatable top-level list from the tail.
    candidates: list[tuple[str, list[Any]]] = []
    for key in _TRUNCATABLE_LIST_KEYS:
        items = payload.get(key)
        if isinstance(items, list):
            candidates.append((key, items))
    if candidates:
        key, items = max(candidates, key=lambda pair: len(pair[1]))
        total = len(items)
        kept = list(items)
        while kept and _encoded_size({**payload, key: kept}) > max_bytes:
            kept = kept[:-1]
        return {**payload, key: kept, "truncated": True, "total": total}

    # 3. Truncate a top-level string value that alone exceeds max_bytes.
    for key, value in payload.items():
        if isinstance(value, str) and len(value.encode("utf-8")) > max_bytes:
            truncated = value.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
            return {**payload, key: truncated, "truncated": True}

    # 4. Nothing safe to truncate → return unchanged (must not drop data).
    return payload
