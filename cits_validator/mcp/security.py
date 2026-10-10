from __future__ import annotations

import json
from collections.abc import Callable
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
    """Refuses a non-loopback bind without a token.

    The server speaks stdio only, so this is a guard for a future network
    transport; it does not authenticate anything by itself.
    """
    if bind_host not in _LOOPBACK and not token:
        raise PermissionError("binding to a non-loopback address requires CITS_MCP_TOKEN")


def dump_json(payload: dict[str, Any]) -> str:
    """The single serialisation used on the wire, so the cap measures what is sent."""
    return json.dumps(payload, indent=2)


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(dump_json(payload).encode("utf-8"))


def _largest_fitting(build: Callable[[int], dict[str, Any]], upper: int, max_bytes: int) -> int:
    """Largest n in [0, upper] with size(build(n)) <= max_bytes, or -1 if none fits.

    Binary search keeps this O(log n) serialisations instead of one per removed item.
    """
    lo, hi, best = 0, upper, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        if _encoded_size(build(mid)) <= max_bytes:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def _truncate_longest_list(payload: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    lists = [(k, payload[k]) for k in _TRUNCATABLE_LIST_KEYS if isinstance(payload.get(k), list)]
    if not lists:
        return payload
    key, items = max(lists, key=lambda pair: len(pair[1]))
    total = len(items)
    best = _largest_fitting(
        lambda n: {**payload, key: items[:n], "truncated": True, "total": total}, total, max_bytes
    )
    return {**payload, key: items[: max(best, 0)], "truncated": True, "total": total}


def _truncate_longest_string(payload: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    strings = [(k, v) for k, v in payload.items() if isinstance(v, str)]
    if not strings:
        return payload
    key, value = max(strings, key=lambda pair: len(pair[1]))
    best = _largest_fitting(
        lambda n: {**payload, key: value[:n], "truncated": True}, len(value), max_bytes
    )
    return {**payload, key: value[: max(best, 0)], "truncated": True}


def cap_output(payload: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Returns ``payload`` or a truncated copy whose wire size is <= ``max_bytes``.

    Truncates the longest list, then the longest string. If that is not enough
    (e.g. deeply nested data) the result is an explicit error object, so data is
    never dropped silently and the cap always holds.
    """
    if _encoded_size(payload) <= max_bytes:
        return payload

    result = _truncate_longest_list(payload, max_bytes)
    if _encoded_size(result) > max_bytes:
        result = _truncate_longest_string(result, max_bytes)
    if _encoded_size(result) <= max_bytes:
        return result

    return {"error": "output too large", "truncated": True, "max_bytes": max_bytes}
