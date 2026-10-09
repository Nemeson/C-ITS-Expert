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
