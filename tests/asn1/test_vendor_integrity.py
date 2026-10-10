"""Vendored ASN.1 modules are verified against the manifest before they are compiled."""

from __future__ import annotations

import hashlib
import json
import shutil

import pytest

from cits_validator.asn1 import decoder, is_available
from cits_validator.asn1.decoder import DecoderUnavailableError
from cits_validator.asn1.provenance import MANIFEST_PATH, STANDARDS_DIR, load_manifest


def test_every_vendored_module_matches_its_manifest_checksum():
    modules = load_manifest()
    assert modules

    for module in modules:
        assert module.sha256, f"{module.file} has no sha256 in the manifest"
        actual = hashlib.sha256(module.path.read_bytes()).hexdigest()
        assert actual == module.sha256, module.file


def test_manifest_does_not_leak_a_local_absolute_path():
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert "source" not in data or not str(data["source"]).startswith(("C:", "/"))


@pytest.mark.skipif(not is_available(), reason="asn1tools not installed")
def test_tampered_module_is_refused_before_compiling(monkeypatch, tmp_path):
    shutil.copytree(STANDARDS_DIR, tmp_path / "standards")
    victim = tmp_path / "standards" / "r1" / decoder._MODULE_SETS[("r1", "CAM")][0]
    victim.write_bytes(victim.read_bytes() + b"\n-- tampered\n")
    monkeypatch.setattr(decoder, "STANDARDS_DIR", tmp_path / "standards")
    monkeypatch.setattr(
        decoder, "load_manifest", lambda: load_manifest(MANIFEST_PATH)
    )  # keep original hashes
    decoder._compile.cache_clear()
    try:
        with pytest.raises(DecoderUnavailableError, match="checksum"):
            decoder.decode_pdu(b"\x01\x02", "CAM", "r1")
    finally:
        decoder._compile.cache_clear()


def test_manifest_is_read_once_per_message_type(monkeypatch):
    calls = []
    real = decoder.load_manifest
    monkeypatch.setattr(decoder, "load_manifest", lambda: calls.append(1) or real())
    decoder.standards_for.cache_clear()

    decoder.standards_for("r1", "CAM")
    decoder.standards_for("r1", "CAM")

    assert len(calls) == 1
