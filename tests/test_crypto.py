"""Tests for envcrypt.crypto encryption/decryption module."""

import pytest
from unittest.mock import patch, MagicMock

from envcrypt.crypto import encrypt, decrypt, AgeEncryptionError


FAKE_PUBKEY = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
FAKE_IDENTITY = "~/.age/key.txt"
FAKE_CIPHERTEXT = b"-----BEGIN AGE ENCRYPTED FILE-----\nfakedata\n-----END AGE ENCRYPTED FILE-----\n"


def _mock_version_ok():
    m = MagicMock()
    m.returncode = 0
    m.stdout = "age v1.1.1"
    return m


@patch("envcrypt.crypto.subprocess.run")
def test_encrypt_success(mock_run):
    version_result = _mock_version_ok()
    encrypt_result = MagicMock(returncode=0, stdout=FAKE_CIPHERTEXT.decode())
    mock_run.side_effect = [version_result, encrypt_result]

    result = encrypt("SECRET=hello", [FAKE_PUBKEY])
    assert result == FAKE_CIPHERTEXT


@patch("envcrypt.crypto.subprocess.run")
def test_encrypt_no_recipients_raises(mock_run):
    mock_run.return_value = _mock_version_ok()
    with pytest.raises(AgeEncryptionError, match="At least one recipient"):
        encrypt("SECRET=hello", [])


@patch("envcrypt.crypto.subprocess.run")
def test_encrypt_age_failure_raises(mock_run):
    version_result = _mock_version_ok()
    fail_result = MagicMock(returncode=1, stderr="invalid recipient")
    mock_run.side_effect = [version_result, fail_result]

    with pytest.raises(AgeEncryptionError, match="Encryption failed"):
        encrypt("SECRET=hello", [FAKE_PUBKEY])


@patch("envcrypt.crypto.os.unlink")
@patch("envcrypt.crypto.Path.exists", return_value=True)
@patch("envcrypt.crypto.subprocess.run")
def test_decrypt_success(mock_run, mock_exists, mock_unlink):
    version_result = _mock_version_ok()
    decrypt_result = MagicMock(returncode=0, stdout="SECRET=hello\n")
    mock_run.side_effect = [version_result, decrypt_result]

    result = decrypt(FAKE_CIPHERTEXT, FAKE_IDENTITY)
    assert result == "SECRET=hello\n"


@patch("envcrypt.crypto.Path.exists", return_value=False)
@patch("envcrypt.crypto.subprocess.run")
def test_decrypt_missing_identity_raises(mock_run, mock_exists):
    mock_run.return_value = _mock_version_ok()
    with pytest.raises(AgeEncryptionError, match="Identity file not found"):
        decrypt(FAKE_CIPHERTEXT, "/nonexistent/key.txt")


@patch("envcrypt.crypto.subprocess.run")
def test_age_not_installed_raises(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stderr="not found")
    with pytest.raises(AgeEncryptionError, match="'age' binary not found"):
        encrypt("SECRET=hello", [FAKE_PUBKEY])
