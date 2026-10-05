"""UPER decoder for C-ITS PDUs, built on the vendored ETSI/ISO ASN.1 modules.

Design rules, learned from the failure modes this repository exists to prevent:

* A decoder is compiled from real standard modules, never hand-written bit
  arithmetic, so an extension marker that is actually present cannot be missed.
* When no decoder is available for a message (dependency missing, unknown type),
  the result says so. It never falls back to a plausible-looking partial decode.
* The release baseline is chosen explicitly. Release 1 and Release 2 differ in
  their CDD module and therefore in their decoders; guessing would silently
  mis-decode a field.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from cits_validator.asn1.provenance import STANDARDS_DIR, load_manifest

# Message types this core can decode, keyed by the name callers use.
MESSAGE_TYPES = ("CAM", "DENM", "MAPEM", "SPATEM", "SREM", "SSEM")

RELEASES = ("r1", "r2")

# Which vendored modules each (release, message) pair needs. The compiled spec
# gets exactly these files, so an unexpected import surfaces as a CompileError
# instead of being silently satisfied by a wrong module.
_MODULE_SETS: dict[tuple[str, str], tuple[str, ...]] = {
    ("r1", "CAM"): ("ITS-Container.asn", "CAM-PDU-Descriptions.asn"),
    ("r1", "DENM"): ("ITS-Container.asn", "DENM-PDU-Descriptions.asn"),
    (
        "r1",
        "SPATEM",
    ): (
        "ITS-Container.asn",
        "ISO-TS-19091-DSRC.raw.asn",
        "ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
        "SPATEM-PDU-Descriptions.asn",
    ),
    (
        "r1",
        "MAPEM",
    ): (
        "ITS-Container.asn",
        "ISO-TS-19091-DSRC.raw.asn",
        "ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
        "MAPEM-PDU-Descriptions.asn",
    ),
    (
        "r1",
        "SREM",
    ): (
        "ITS-Container.asn",
        "ISO-TS-19091-DSRC.raw.asn",
        "ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
        "SREM-PDU-Descriptions.asn",
    ),
    (
        "r1",
        "SSEM",
    ): (
        "ITS-Container.asn",
        "ISO-TS-19091-DSRC.raw.asn",
        "ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
        "SSEM-PDU-Descriptions.asn",
    ),
    ("r2", "CAM"): ("ETSI-ITS-CDD.asn", "CAM-PDU-Descriptions.asn"),
    ("r2", "DENM"): ("ETSI-ITS-CDD.asn", "DENM-PDU-Descriptions.asn"),
    ("r2", "SPATEM"): ("ETSI-ITS-CDD.asn", "DSRC.asn", "SPATEM-PDU-Descriptions.asn"),
    ("r2", "MAPEM"): ("ETSI-ITS-CDD.asn", "DSRC.asn", "MAPEM-PDU-Descriptions.asn"),
    ("r2", "SREM"): ("ETSI-ITS-CDD.asn", "DSRC.asn", "SREM-PDU-Descriptions.asn"),
    ("r2", "SSEM"): ("ETSI-ITS-CDD.asn", "DSRC.asn", "SSEM-PDU-Descriptions.asn"),
}


class PduDecodeError(Exception):
    """Raised when a PDU cannot be decoded. Never carries a partial result."""


@dataclass
class DecodeResult:
    message_type: str
    release: str
    value: dict[str, Any]
    byte_length: int
    standards: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_type": self.message_type,
            "release": self.release,
            "byte_length": self.byte_length,
            "standards": self.standards,
            "value": _jsonable(self.value),
        }


def is_available() -> bool:
    """True when the optional asn1tools dependency is importable."""
    try:
        import asn1tools  # noqa: F401
    except ImportError:
        return False
    return True


def _jsonable(value: Any) -> Any:
    """Converts asn1tools output (bytes, tuples) into JSON-serialisable values."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _module_paths(release: str, message_type: str) -> list[Path]:
    if release not in RELEASES:
        raise PduDecodeError(f"Unknown release '{release}' (expected one of {RELEASES})")
    if message_type not in MESSAGE_TYPES:
        raise PduDecodeError(
            f"Unsupported message type '{message_type}' (expected one of {MESSAGE_TYPES})"
        )
    names = _MODULE_SETS[(release, message_type)]
    paths = [STANDARDS_DIR / release / name for name in names]
    missing = [p.name for p in paths if not p.is_file()]
    if missing:
        raise PduDecodeError(
            "Vendored ASN.1 modules missing: "
            + ", ".join(missing)
            + ". Run scripts/vendor_asn1.py."
        )
    return paths


@lru_cache(maxsize=32)
def _compile(release: str, message_type: str) -> Any:
    import asn1tools

    paths = _module_paths(release, message_type)
    try:
        return asn1tools.compile_files([str(p) for p in paths], "uper")
    except Exception as exc:  # asn1tools raises CompileError / FileNotFoundError
        raise PduDecodeError(
            f"Failed to compile ASN.1 modules for {release}/{message_type}: {exc}"
        ) from exc


def standards_for(release: str, message_type: str) -> list[str]:
    """'Standard version' labels of the modules used for a decode."""
    wanted = set(_MODULE_SETS.get((release, message_type), ()))
    labels = [
        f"{m.standard} {m.version}"
        for m in load_manifest()
        if m.release == release and Path(m.file).name in wanted
    ]
    return sorted(set(labels))


def decode_pdu(
    data: bytes,
    message_type: str,
    release: str = "r1",
) -> DecodeResult:
    """Decodes one C-ITS PDU from raw UPER bytes.

    Args:
        data: The ASN.1 UPER payload, beginning at the ``ItsPduHeader``.
        message_type: One of :data:`MESSAGE_TYPES`.
        release: ``"r1"`` (EN 302 637-x / TS 103 301 v1.3.1) or ``"r2"``.

    Raises:
        PduDecodeError: encoding fault, unavailable decoder, or missing dependency.
            The exception never carries a partial decode.
    """
    if not is_available():
        raise PduDecodeError(
            "asn1tools is not installed. Install the ASN.1 extra: pip install -e '.[asn1]'"
        )
    if not data:
        raise PduDecodeError("Empty PDU payload")

    message_type = message_type.upper()
    spec = _compile(release, message_type)

    try:
        value = spec.decode(message_type, data)
    except Exception as exc:
        raise PduDecodeError(
            f"{message_type} ({release}) failed to decode: {type(exc).__name__}: {exc}"
        ) from exc

    return DecodeResult(
        message_type=message_type,
        release=release,
        value=value,
        byte_length=len(data),
        standards=standards_for(release, message_type),
    )


def release_for_message_id(message_id: int) -> str | None:
    """Best-effort release hint from the ItsPduHeader messageID.

    Both releases share message IDs (cam=2, denm=1, spatem=4, mapem=5, srem=9,
    ssem=10), so the ID alone cannot decide the release; it only confirms the
    message family. Returns None for an unknown ID.
    """
    return {1: "DENM", 2: "CAM", 4: "SPATEM", 5: "MAPEM", 9: "SREM", 10: "SSEM"}.get(
        message_id, None
    )


def peek_message_id(data: bytes) -> int | None:
    """Reads messageID from a plaintext UPER ItsPduHeader.

    The header is ``protocolVersion`` (8 bits), ``messageID`` (8 bits),
    ``stationID`` (32 bits), so the ID is byte 1 when the payload starts at the
    header. Returns None when the payload is too short.
    """
    if len(data) < 2:
        return None
    return data[1]


def describe_standards() -> list[dict[str, str]]:
    """The vendored standards catalogue (release, standard, version)."""
    return json.loads(json.dumps(_standards_payload()))


def _standards_payload() -> list[dict[str, str]]:
    from cits_validator.asn1.provenance import standards_summary

    return standards_summary()
