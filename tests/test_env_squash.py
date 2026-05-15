"""Tests for envcrypt.env_squash."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from envcrypt.env_squash import SquashError, squash_vaults


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "test.env.age"
    p.write_bytes(b"placeholder")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-1...")
    return p


def _patch_crypto(decrypt_map: dict, recipients=None):
    """Return a context manager tuple patching decrypt, encrypt, load_recipients."""
    if recipients is None:
        recipients = ["age1abc"]

    def fake_decrypt(src, _identity):
        return decrypt_map.get(str(src), "")

    return (
        patch("envcrypt.env_squash.decrypt", side_effect=fake_decrypt),
        patch("envcrypt.env_squash.encrypt"),
        patch("envcrypt.env_squash.load_recipients", return_value=recipients),
    )


def test_squash_vaults_success(tmp_path, vault_file, identity_file):
    vault2 = tmp_path / "second.env.age"
    vault2.write_bytes(b"placeholder")

    contents = {
        str(vault_file): "KEY_A=first\nKEY_B=shared_old\n",
        str(vault2): "KEY_B=shared_new\nKEY_C=third\n",
    }
    p1, p2, p3 = _patch_crypto(contents)
    with p1, p2 as mock_enc, p3:
        result = squash_vaults([vault_file, vault2], identity_file)

    assert result.keys_merged == 3
    assert result.keys_overwritten == 1
    assert mock_enc.called


def test_squash_vaults_first_wins(tmp_path, vault_file, identity_file):
    vault2 = tmp_path / "second.env.age"
    vault2.write_bytes(b"placeholder")

    contents = {
        str(vault_file): "KEY_A=original\n",
        str(vault2): "KEY_A=override\n",
    }
    p1, p2, p3 = _patch_crypto(contents)
    with p1 as mock_dec, p2, p3:
        result = squash_vaults([vault_file, vault2], identity_file, last_wins=False)

    assert result.keys_overwritten == 0


def test_squash_vaults_no_sources_raises(identity_file):
    with pytest.raises(SquashError, match="At least one source"):
        squash_vaults([], identity_file)


def test_squash_vaults_missing_source_raises(tmp_path, identity_file):
    missing = tmp_path / "ghost.env.age"
    with pytest.raises(SquashError, match="not found"):
        squash_vaults([missing], identity_file)


def test_squash_vaults_no_recipients_raises(vault_file, identity_file):
    p1, p2, p3 = _patch_crypto({str(vault_file): "K=V\n"}, recipients=[])
    with p1, p2, p3:
        with pytest.raises(SquashError, match="No recipients"):
            squash_vaults([vault_file], identity_file)


def test_squash_vaults_custom_output(tmp_path, vault_file, identity_file):
    out = tmp_path / "squashed.age"
    contents = {str(vault_file): "K=V\n"}
    p1, p2, p3 = _patch_crypto(contents)
    with p1, p2, p3:
        result = squash_vaults([vault_file], identity_file, output=out)

    assert result.output == out


def test_squash_result_summary(tmp_path, vault_file, identity_file):
    contents = {str(vault_file): "A=1\nB=2\n"}
    p1, p2, p3 = _patch_crypto(contents)
    with p1, p2, p3:
        result = squash_vaults([vault_file], identity_file)

    summary = result.summary()
    assert "1 vault" in summary
    assert "2 keys" in summary
