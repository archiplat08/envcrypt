"""Tests for envcrypt.env_checksum."""

from __future__ import annotations

import json

import pytest

from envcrypt.env_checksum import (
    ChecksumError,
    _checksum_path,
    compute_checksum,
    load_checksum,
    save_checksum,
    verify_checksum,
)


@pytest.fixture()
def vault_file(tmp_path):
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted-content-abc")
    return p


def test_compute_checksum_returns_hex_digest(vault_file):
    digest = compute_checksum(vault_file)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_compute_checksum_missing_vault_raises(tmp_path):
    with pytest.raises(ChecksumError, match="Vault not found"):
        compute_checksum(tmp_path / "missing.age")


def test_save_checksum_creates_file(vault_file):
    digest = save_checksum(vault_file)
    cp = _checksum_path(vault_file)
    assert cp.exists()
    data = json.loads(cp.read_text())
    assert data["sha256"] == digest
    assert data["vault"] == vault_file.name


def test_save_checksum_returns_digest(vault_file):
    digest = save_checksum(vault_file)
    assert digest == compute_checksum(vault_file)


def test_load_checksum_returns_none_when_no_file(vault_file):
    assert load_checksum(vault_file) is None


def test_load_checksum_returns_saved_digest(vault_file):
    digest = save_checksum(vault_file)
    assert load_checksum(vault_file) == digest


def test_load_checksum_raises_on_corrupt_file(vault_file):
    _checksum_path(vault_file).write_text("not-json")
    with pytest.raises(ChecksumError, match="Corrupt"):
        load_checksum(vault_file)


def test_verify_checksum_returns_true_when_unchanged(vault_file):
    save_checksum(vault_file)
    assert verify_checksum(vault_file) is True


def test_verify_checksum_returns_false_when_content_changed(vault_file):
    save_checksum(vault_file)
    vault_file.write_bytes(b"tampered-content")
    assert verify_checksum(vault_file) is False


def test_verify_checksum_raises_when_no_saved_checksum(vault_file):
    with pytest.raises(ChecksumError, match="No checksum on record"):
        verify_checksum(vault_file)
