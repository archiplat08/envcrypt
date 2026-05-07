"""Tests for envcrypt.env_set."""
from pathlib import Path
from unittest.mock import patch

import pytest

from envcrypt.env_set import SetError, set_keys


@pytest.fixture()
def vault_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env.age"
    p.write_bytes(b"encrypted")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "key.txt"
    p.write_text("AGE-SECRET-KEY-1FAKE")
    return p


def _patch_crypto(decrypt_data: str, recipients=None):
    """Return a context manager that stubs crypto + recipients."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with (
            patch("envcrypt.env_set.decrypt", return_value=decrypt_data),
            patch("envcrypt.env_set.encrypt") as mock_enc,
            patch(
                "envcrypt.env_set.load_recipients",
                return_value=recipients or ["age1abc"],
            ),
        ):
            yield mock_enc

    return _ctx()


def test_set_keys_adds_new_key(vault_file, identity_file):
    with _patch_crypto("EXISTING=hello\n") as mock_enc:
        result = set_keys(vault_file, {"NEW_KEY": "world"}, identity_file)

    assert "NEW_KEY" in result.added
    assert result.updated == []
    mock_enc.assert_called_once()
    encrypted_plain = mock_enc.call_args[0][0]
    assert "NEW_KEY=world" in encrypted_plain
    assert "EXISTING=hello" in encrypted_plain


def test_set_keys_updates_existing_key(vault_file, identity_file):
    with _patch_crypto("TOKEN=old\n") as mock_enc:
        result = set_keys(vault_file, {"TOKEN": "new"}, identity_file)

    assert "TOKEN" in result.updated
    assert result.added == []
    plain = mock_enc.call_args[0][0]
    assert "TOKEN=new" in plain
    assert "TOKEN=old" not in plain


def test_set_keys_multiple_pairs(vault_file, identity_file):
    with _patch_crypto("A=1\n") as mock_enc:
        result = set_keys(vault_file, {"A": "2", "B": "3"}, identity_file)

    assert "A" in result.updated
    assert "B" in result.added


def test_set_keys_missing_vault_raises(tmp_path, identity_file):
    with pytest.raises(SetError, match="Vault not found"):
        set_keys(tmp_path / "missing.age", {"K": "v"}, identity_file)


def test_set_keys_empty_pairs_raises(vault_file, identity_file):
    with pytest.raises(SetError, match="No key=value pairs"):
        set_keys(vault_file, {}, identity_file)


def test_set_keys_no_recipients_raises(vault_file, identity_file):
    with (
        patch("envcrypt.env_set.decrypt", return_value="K=v\n"),
        patch("envcrypt.env_set.load_recipients", return_value=[]),
    ):
        with pytest.raises(SetError, match="No recipients"):
            set_keys(vault_file, {"K": "v"}, identity_file)


def test_set_keys_custom_output(vault_file, identity_file, tmp_path):
    out = tmp_path / "out.age"
    with _patch_crypto("X=1\n") as mock_enc:
        set_keys(vault_file, {"Y": "2"}, identity_file, output=out)

    assert mock_enc.call_args[0][2] == out


def test_summary_reports_correctly(vault_file, identity_file):
    with _patch_crypto("OLD=1\n"):
        result = set_keys(vault_file, {"OLD": "2", "NEW": "3"}, identity_file)

    summary = result.summary()
    assert "added" in summary
    assert "updated" in summary
