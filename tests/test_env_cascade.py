"""Tests for envcrypt.env_cascade."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envcrypt.env_cascade import CascadeError, CascadeResult, cascade_vaults


@pytest.fixture()
def vault_a(tmp_path: Path) -> Path:
    p = tmp_path / "a.env.age"
    p.write_bytes(b"placeholder")
    return p


@pytest.fixture()
def vault_b(tmp_path: Path) -> Path:
    p = tmp_path / "b.env.age"
    p.write_bytes(b"placeholder")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(a_env: str, b_env: str):
    call_count = 0
    values = [a_env, b_env]

    def fake_decrypt(vault_path, identity_path):
        nonlocal call_count
        result = values[call_count % len(values)]
        call_count += 1
        return result

    return fake_decrypt


def test_cascade_last_vault_wins(tmp_path, vault_a, vault_b, identity_file):
    fake_decrypt = _patch_crypto("KEY=from_a\nSHARED=a_val\n", "KEY=from_b\nEXTRA=extra_val\n")
    output = tmp_path / "merged.env.age"
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1...")

    with patch("envcrypt.env_cascade.decrypt", side_effect=fake_decrypt), \
         patch("envcrypt.env_cascade.encrypt_env_file") as mock_enc:
        result = cascade_vaults([vault_a, vault_b], identity_file, output, recipients)

    assert result.merged["KEY"] == "from_b"
    assert result.merged["SHARED"] == "a_val"
    assert result.merged["EXTRA"] == "extra_val"
    mock_enc.assert_called_once()


def test_cascade_overridden_tracks_conflicts(tmp_path, vault_a, vault_b, identity_file):
    fake_decrypt = _patch_crypto("KEY=a\n", "KEY=b\n")
    output = tmp_path / "merged.env.age"
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1...")

    with patch("envcrypt.env_cascade.decrypt", side_effect=fake_decrypt), \
         patch("envcrypt.env_cascade.encrypt_env_file"):
        result = cascade_vaults([vault_a, vault_b], identity_file, output, recipients)

    assert "KEY" in result.overridden
    assert len(result.overridden["KEY"]) == 2


def test_cascade_no_vaults_raises(tmp_path, identity_file):
    output = tmp_path / "merged.env.age"
    with pytest.raises(CascadeError, match="At least one"):
        cascade_vaults([], identity_file, output)


def test_cascade_missing_vault_raises(tmp_path, identity_file):
    missing = tmp_path / "missing.env.age"
    output = tmp_path / "merged.env.age"
    with pytest.raises(CascadeError, match="Vault not found"):
        cascade_vaults([missing], identity_file, output)


def test_cascade_decrypt_failure_raises(tmp_path, vault_a, identity_file):
    output = tmp_path / "merged.env.age"
    with patch("envcrypt.env_cascade.decrypt", side_effect=RuntimeError("bad key")), \
         pytest.raises(CascadeError, match="Failed to decrypt"):
        cascade_vaults([vault_a], identity_file, output)


def test_cascade_summary_format(tmp_path, vault_a, vault_b, identity_file):
    fake_decrypt = _patch_crypto("A=1\nB=2\n", "B=3\nC=4\n")
    output = tmp_path / "merged.env.age"
    recipients = tmp_path / ".recipients"
    recipients.write_text("age1...")

    with patch("envcrypt.env_cascade.decrypt", side_effect=fake_decrypt), \
         patch("envcrypt.env_cascade.encrypt_env_file"):
        result = cascade_vaults([vault_a, vault_b], identity_file, output, recipients)

    summary = result.summary()
    assert "3 keys merged" in summary
    assert "1 keys overridden" in summary
