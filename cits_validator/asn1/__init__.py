"""ASN.1 / UPER conformance core for C-ITS PDUs.

Decodes the ASN.1 payload of CAM, DENM, MAPEM, SPATEM, SREM and SSEM messages
from raw UPER bytes against the vendored ETSI/ISO modules. The dependency
(`asn1tools`) is optional: importing this package without the `[asn1]` extra is
harmless, and the link-layer and anti-hallucination rules keep working. Callers
that need decoding check :func:`is_available` first.
"""

from __future__ import annotations

from cits_validator.asn1.decoder import (
    MESSAGE_TYPES,
    PduDecodeError,
    decode_pdu,
    is_available,
)
from cits_validator.asn1.provenance import (
    ModuleProvenance,
    load_manifest,
    modules_for_release,
    standards_summary,
)

__all__ = [
    "MESSAGE_TYPES",
    "ModuleProvenance",
    "PduDecodeError",
    "decode_pdu",
    "is_available",
    "load_manifest",
    "modules_for_release",
    "standards_summary",
]
