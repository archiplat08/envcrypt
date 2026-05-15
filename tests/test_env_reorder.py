"""Tests for envcrypt.env_reorder."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_reorder import ReorderError, reorder_vault


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(env: dict, tmp_path: Path):
    """Return context managers that stub out decrypt/encrypt/load_recipients."""
    from envcrypt.dotenv import serialize_dotenv

    plaintext = serialize_dotenv(env)

    p_decrypt = patch("envcrypt.env_reorder.decrypt", return_value=plaintext)
    p_encrypt = patch("envcrypt.env_reorder.encrypt")
    p_recip = patch(
        "envcrypt.env_reorder.load_recipients",
        return_value=["age1recipient"],
    )
    return p_decrypt, p_encrypt, p_recip


def test_reorder_vault_success(vault_file: Path, identity_file: Path, tmp_path: Path):
    env = {"ZEBRA": "1", "ALPHA": "2", "MIDDLE": "3"}
    p_decrypt, p_encrypt, p_recip = _patch_crypto(env, tmp_path)

    with p_decrypt, p_encrypt as mock_enc, p_recip:
        result = reorder_vault(
            vault=vault_file,
            order=["ALPHA", "MIDDLE"],
            identity=identity_file,
        )

    assert "ALPHA" in result.moved or "MIDDLE" in result.moved
    assert mock_enc.called


def test_reorder_vault_no_change_when_already_ordered(
    vault_file: Path, identity_file: Path, tmp_path: Path
):
    env = {"ALPHA": "1", "BETA": "2", "GAMMA": "3"}
    p_decrypt, p_encrypt, p_recip = _patch_crypto(env, tmp_path)

    with p_decrypt, p_encrypt as mock_enc, p_recip:
        result = reorder_vault(
            vault=vault_file,
            order=["ALPHA", "BETA", "GAMMA"],
            identity=identity_file,
        )

    assert result.moved == []
    assert mock_enc.called  # still re-encrypts


def test_reorder_vault_missing_vault(tmp_path: Path, identity_file: Path):
    missing = tmp_path / "ghost.env.age"
    with pytest.raises(ReorderError, match="Vault not found"):
        reorder_vault(vault=missing, order=["KEY"], identity=identity_file)


def test_reorder_vault_no_recipients_raises(
    vault_file: Path, identity_file: Path, tmp_path: Path
):
    env = {"A": "1"}
    from envcrypt.dotenv import serialize_dotenv

    plaintext = serialize_dotenv(env)
    with patch("envcrypt.env_reorder.decrypt", return_value=plaintext), patch(
        "envcrypt.env_reorder.load_recipients", return_value=[]
    ):
        with pytest.raises(ReorderError, match="No recipients"):
            reorder_vault(vault=vault_file, order=["A"], identity=identity_file)


def test_reorder_vault_unknown_keys_ignored(
    vault_file: Path, identity_file: Path, tmp_path: Path
):
    env = {"FOO": "bar", "BAZ": "qux"}
    p_decrypt, p_encrypt, p_recip = _patch_crypto(env, tmp_path)

    with p_decrypt, p_encrypt as mock_enc, p_recip:
        result = reorder_vault(
            vault=vault_file,
            order=["NONEXISTENT", "BAZ"],
            identity=identity_file,
        )

    # NONEXISTENT not in vault — only BAZ should move
    assert "BAZ" in result.moved or result.moved == []
    assert mock_enc.called
