"""Tests for envcrypt.env_dedup."""

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_dedup import DedupError, DedupResult, dedup_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    return tmp_path / "secrets.env.age"


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(plaintext: str, vault: Path):
    """Return context managers that stub decrypt and encrypt."""
    decrypt_patch = patch(
        "envcrypt.env_dedup.decrypt",
        return_value=plaintext,
    )
    encrypt_patch = patch("envcrypt.env_dedup.encrypt")
    recipients_patch = patch(
        "envcrypt.env_dedup.load_recipients",
        return_value=["age1recipient"],
    )
    return decrypt_patch, encrypt_patch, recipients_patch


def test_dedup_removes_duplicate_values(vault_file, identity_file):
    plaintext = "KEY_A=hello\nKEY_B=world\nKEY_C=hello\n"
    dp, ep, rp = _patch_crypto(plaintext, vault_file)
    vault_file.write_bytes(b"dummy")
    with dp, ep as mock_enc, rp:
        result = dedup_vault(vault_file, identity_file)
    assert result.removed == ["KEY_C"]
    assert "KEY_A" in result.kept
    assert "KEY_B" in result.kept
    assert "KEY_C" not in result.kept
    assert mock_enc.called


def test_dedup_no_duplicates_returns_empty_result(vault_file, identity_file):
    plaintext = "KEY_A=alpha\nKEY_B=beta\nKEY_C=gamma\n"
    dp, ep, rp = _patch_crypto(plaintext, vault_file)
    vault_file.write_bytes(b"dummy")
    with dp, ep as mock_enc, rp:
        result = dedup_vault(vault_file, identity_file)
    assert result.count == 0
    assert not mock_enc.called  # no re-encryption needed


def test_dedup_dry_run_does_not_encrypt(vault_file, identity_file):
    plaintext = "A=same\nB=same\n"
    dp, ep, rp = _patch_crypto(plaintext, vault_file)
    vault_file.write_bytes(b"dummy")
    with dp, ep as mock_enc, rp:
        result = dedup_vault(vault_file, identity_file, dry_run=True)
    assert result.removed == ["B"]
    assert not mock_enc.called


def test_dedup_custom_output_path(vault_file, identity_file, tmp_path):
    plaintext = "X=dup\nY=dup\n"
    out = tmp_path / "clean.env.age"
    dp, ep, rp = _patch_crypto(plaintext, vault_file)
    vault_file.write_bytes(b"dummy")
    with dp, ep as mock_enc, rp:
        dedup_vault(vault_file, identity_file, output_path=out)
    args, _ = mock_enc.call_args
    assert args[1] == out


def test_dedup_missing_vault_raises(tmp_path, identity_file):
    missing = tmp_path / "nope.age"
    with pytest.raises(DedupError, match="Vault not found"):
        dedup_vault(missing, identity_file)


def test_dedup_result_summary_with_removals():
    r = DedupResult(removed=["KEY_C", "KEY_D"], kept={"KEY_A": "v"})
    assert "2" in r.summary()
    assert "KEY_C" in r.summary()


def test_dedup_result_summary_no_removals():
    r = DedupResult()
    assert "No duplicate" in r.summary()
