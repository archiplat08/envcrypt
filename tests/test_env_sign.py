"""Tests for envcrypt.env_sign."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envcrypt.env_sign import SignError, sign_vault, verify_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted-content-abc")
    return p


def test_sign_vault_creates_sig_file(vault_file: Path) -> None:
    info = sign_vault(vault_file)
    sig = vault_file.with_suffix(".sig.json")
    assert sig.exists()
    assert info.sha256 != ""
    assert info.vault == vault_file.name


def test_sign_vault_records_signer(vault_file: Path) -> None:
    info = sign_vault(vault_file, signer="alice")
    assert info.signer == "alice"
    data = json.loads(vault_file.with_suffix(".sig.json").read_text())
    assert data["signer"] == "alice"


def test_sign_vault_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SignError, match="Vault not found"):
        sign_vault(tmp_path / "missing.age")


def test_verify_vault_success(vault_file: Path) -> None:
    sign_vault(vault_file)
    info = verify_vault(vault_file)
    assert info.vault == vault_file.name


def test_verify_vault_detects_tampering(vault_file: Path) -> None:
    sign_vault(vault_file)
    vault_file.write_bytes(b"tampered-content")
    with pytest.raises(SignError, match="Signature mismatch"):
        verify_vault(vault_file)


def test_verify_vault_no_sig_file_raises(vault_file: Path) -> None:
    with pytest.raises(SignError, match="No signature file found"):
        verify_vault(vault_file)


def test_verify_vault_corrupt_sig_raises(vault_file: Path) -> None:
    sig_path = vault_file.with_suffix(".sig.json")
    sig_path.write_text("not-json{{{")
    with pytest.raises(SignError, match="Corrupt signature file"):
        verify_vault(vault_file)


def test_sign_sig_contains_timestamp(vault_file: Path) -> None:
    info = sign_vault(vault_file)
    assert "T" in info.timestamp  # ISO-8601 format
