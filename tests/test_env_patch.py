"""Tests for envcrypt.env_patch."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envcrypt.env_patch import PatchError, PatchResult, patch_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    f = tmp_path / "secrets.env.age"
    f.write_bytes(b"encrypted")
    return f


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    f = tmp_path / "key.txt"
    f.write_text("AGE-SECRET-KEY-1...")
    return f


def _patch_crypto(plaintext: str, recipients: list[str] | None = None):
    """Return a context manager that stubs decrypt/encrypt/load_recipients."""
    _recipients = recipients or ["age1abc"]
    return (
        patch("envcrypt.env_patch.decrypt", return_value=plaintext),
        patch("envcrypt.env_patch.encrypt"),
        patch("envcrypt.env_patch.load_recipients", return_value=_recipients),
    )


def test_patch_vault_set_new_key(vault_file: Path, identity_file: Path) -> None:
    with _patch_crypto("EXISTING=hello\n")[0], \
         _patch_crypto("EXISTING=hello\n")[1], \
         _patch_crypto("EXISTING=hello\n")[2]:
        dec, enc, rec = _patch_crypto("EXISTING=hello\n")
        with dec, enc, rec:
            result = patch_vault(vault_file, identity_file, set_pairs={"NEW_KEY": "world"})

    assert "NEW_KEY" in result.set_keys
    assert result.unset_keys == []
    assert result.skipped_keys == []


def test_patch_vault_overwrite_key(vault_file: Path, identity_file: Path) -> None:
    dec, enc, rec = _patch_crypto("DB_PASS=old\n")
    with dec, enc, rec:
        result = patch_vault(vault_file, identity_file, set_pairs={"DB_PASS": "new"})

    assert "DB_PASS" in result.set_keys


def test_patch_vault_unset_existing_key(vault_file: Path, identity_file: Path) -> None:
    dec, enc, rec = _patch_crypto("TOKEN=abc\nOTHER=x\n")
    with dec, enc, rec:
        result = patch_vault(vault_file, identity_file, unset_keys=["TOKEN"])

    assert "TOKEN" in result.unset_keys
    assert result.skipped_keys == []


def test_patch_vault_unset_absent_key_is_skipped(vault_file: Path, identity_file: Path) -> None:
    dec, enc, rec = _patch_crypto("FOO=bar\n")
    with dec, enc, rec:
        result = patch_vault(vault_file, identity_file, unset_keys=["MISSING"])

    assert "MISSING" in result.skipped_keys
    assert result.unset_keys == []


def test_patch_vault_missing_vault_raises(tmp_path: Path, identity_file: Path) -> None:
    with pytest.raises(PatchError, match="Vault not found"):
        patch_vault(tmp_path / "ghost.age", identity_file, set_pairs={"K": "v"})


def test_patch_vault_no_recipients_raises(vault_file: Path, identity_file: Path) -> None:
    with patch("envcrypt.env_patch.load_recipients", return_value=[]), \
         patch("envcrypt.env_patch.decrypt", return_value=""):
        with pytest.raises(PatchError, match="No recipients"):
            patch_vault(vault_file, identity_file, set_pairs={"K": "v"})


def test_patch_result_summary_all_operations() -> None:
    r = PatchResult(set_keys=["A"], unset_keys=["B"], skipped_keys=["C"])
    summary = r.summary()
    assert "set: A" in summary
    assert "unset: B" in summary
    assert "skipped" in summary


def test_patch_result_summary_no_changes() -> None:
    r = PatchResult()
    assert r.summary() == "no changes"
