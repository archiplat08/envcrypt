"""Tests for envcrypt.env_split."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_split import SplitError, split_vault


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


def _patch_crypto(decrypt_data: dict):
    """Return a context manager that patches decrypt and encrypt."""
    from envcrypt.dotenv import serialize_dotenv

    plaintext = serialize_dotenv(decrypt_data).encode()

    decrypt_mock = patch("envcrypt.env_split.decrypt", return_value=plaintext)
    encrypt_mock = patch("envcrypt.env_split.encrypt")
    return decrypt_mock, encrypt_mock


def test_split_vault_success(tmp_path, vault_file, identity_file):
    env = {"APP_HOST": "localhost", "APP_PORT": "8080", "DB_URL": "postgres://"}
    dm, em = _patch_crypto(env)
    with dm, em as mock_enc:
        with patch("envcrypt.env_split.load_recipients", return_value=["age1abc"]):
            result = split_vault(vault_file, identity_file, ["APP", "DB"], output_dir=tmp_path)

    assert "APP" in result.outputs
    assert "DB" in result.outputs
    assert result.key_counts["APP"] == 2
    assert result.key_counts["DB"] == 1
    assert result.leftover_count == 0
    assert mock_enc.call_count == 2


def test_split_vault_leftover_written(tmp_path, vault_file, identity_file):
    env = {"APP_KEY": "val", "OTHER": "x"}
    dm, em = _patch_crypto(env)
    with dm, em as mock_enc:
        with patch("envcrypt.env_split.load_recipients", return_value=["age1abc"]):
            result = split_vault(vault_file, identity_file, ["APP"], output_dir=tmp_path)

    assert "leftover" in result.outputs
    assert result.leftover_count == 1
    assert mock_enc.call_count == 2


def test_split_vault_no_leftover_flag(tmp_path, vault_file, identity_file):
    env = {"APP_KEY": "val", "OTHER": "x"}
    dm, em = _patch_crypto(env)
    with dm, em as mock_enc:
        with patch("envcrypt.env_split.load_recipients", return_value=["age1abc"]):
            result = split_vault(
                vault_file, identity_file, ["APP"], output_dir=tmp_path, keep_leftover=False
            )

    assert "leftover" not in result.outputs
    assert result.leftover_count == 0
    assert mock_enc.call_count == 1


def test_split_vault_no_recipients_raises(tmp_path, vault_file, identity_file):
    env = {"APP_KEY": "val"}
    dm, em = _patch_crypto(env)
    with dm, em:
        with patch("envcrypt.env_split.load_recipients", return_value=[]):
            with pytest.raises(SplitError, match="No recipients"):
                split_vault(vault_file, identity_file, ["APP"], output_dir=tmp_path)


def test_split_vault_missing_vault_raises(tmp_path, identity_file):
    with pytest.raises(SplitError, match="Vault not found"):
        split_vault(tmp_path / "nope.age", identity_file, ["APP"])


def test_split_vault_missing_identity_raises(tmp_path, vault_file):
    with pytest.raises(SplitError, match="Identity file not found"):
        split_vault(vault_file, tmp_path / "nope.txt", ["APP"])


def test_split_result_summary_no_keys():
    from envcrypt.env_split import SplitResult
    r = SplitResult()
    assert r.summary() == "no keys split"


def test_split_result_summary_with_leftover(tmp_path):
    from envcrypt.env_split import SplitResult
    r = SplitResult(
        outputs={"APP": tmp_path / "app.env.age", "leftover": tmp_path / "leftover.env.age"},
        key_counts={"APP": 3, "leftover": 1},
        leftover_count=1,
    )
    assert "APP=3 keys" in r.summary()
    assert "leftover=1 keys" in r.summary()
