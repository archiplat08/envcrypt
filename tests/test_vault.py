"""Tests for envcrypt.vault."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envcrypt.dotenv import DotEnvError
from envcrypt.vault import decrypt_env_file, encrypt_env_file

_PUBKEY = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
_PLAINTEXT = b"API_KEY=secret\nDB_URL=postgres://localhost/db\n"
_CIPHERTEXT = b"-----BEGIN AGE ENCRYPTED FILE-----\nfakedata\n-----END AGE ENCRYPTED FILE-----\n"


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text("API_KEY=secret\nDB_URL=postgres://localhost/db\n", encoding="utf-8")
    return p


@pytest.fixture()
def identity_file(tmp_path: Path) -> Path:
    p = tmp_path / "identity.txt"
    p.write_text("AGE-SECRET-KEY-fake", encoding="utf-8")
    return p


def test_encrypt_env_file_creates_output(tmp_path, env_file):
    with patch("envcrypt.vault.encrypt", return_value=_CIPHERTEXT) as mock_enc:
        out = encrypt_env_file(env_file, extra_recipients=[_PUBKEY])
    mock_enc.assert_called_once()
    assert out.exists()
    assert out.suffix == ".age"
    assert out.read_bytes() == _CIPHERTEXT


def test_encrypt_env_file_custom_output(tmp_path, env_file):
    custom_out = tmp_path / "secrets.age"
    with patch("envcrypt.vault.encrypt", return_value=_CIPHERTEXT):
        out = encrypt_env_file(env_file, output_path=custom_out, extra_recipients=[_PUBKEY])
    assert out == custom_out


def test_encrypt_env_file_no_recipients_raises(env_file):
    with pytest.raises(DotEnvError, match="No recipients"):
        encrypt_env_file(env_file)


def test_encrypt_env_file_uses_recipients_file(tmp_path, env_file):
    rec_file = tmp_path / "recipients.txt"
    rec_file.write_text(_PUBKEY + "\n", encoding="utf-8")
    with patch("envcrypt.vault.encrypt", return_value=_CIPHERTEXT) as mock_enc:
        encrypt_env_file(env_file, recipients_file=rec_file)
    args, _ = mock_enc.call_args
    assert _PUBKEY in args[1]


def test_decrypt_env_file_creates_output(tmp_path, identity_file):
    enc_file = tmp_path / ".env.age"
    enc_file.write_bytes(_CIPHERTEXT)
    with patch("envcrypt.vault.decrypt", return_value=_PLAINTEXT):
        out = decrypt_env_file(enc_file, identity_file)
    assert out.name == ".env"
    assert out.read_text(encoding="utf-8").startswith("API_KEY=")


def test_decrypt_env_file_custom_output(tmp_path, identity_file):
    enc_file = tmp_path / ".env.age"
    enc_file.write_bytes(_CIPHERTEXT)
    custom_out = tmp_path / "decrypted.env"
    with patch("envcrypt.vault.decrypt", return_value=_PLAINTEXT):
        out = decrypt_env_file(enc_file, identity_file, output_path=custom_out)
    assert out == custom_out
