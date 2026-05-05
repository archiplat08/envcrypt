"""Tests for envcrypt.keys module."""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from envcrypt.keys import (
    generate_key_pair,
    load_public_key_from_file,
    _parse_public_key,
    _parse_private_key,
    AgeKeyPair,
)
from envcrypt.crypto import AgeEncryptionError


FAKE_KEYGEN_OUTPUT = (
    "# created: 2024-01-01T00:00:00Z\n"
    "# public key: age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq\n"
    "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYS\n"
)


def _mock_version_ok():
    m = MagicMock()
    m.stdout = "age v1.1.1\n"
    return m


@patch("envcrypt.keys.subprocess.run")
def test_generate_key_pair_success(mock_run):
    mock_run.side_effect = [
        _mock_version_ok(),
        MagicMock(stdout=FAKE_KEYGEN_OUTPUT, stderr="", returncode=0),
    ]

    pair = generate_key_pair()

    assert isinstance(pair, AgeKeyPair)
    assert pair.public_key.startswith("age1")
    assert pair.private_key.startswith("AGE-SECRET-KEY-")
    assert pair.key_file is None


@patch("envcrypt.keys.subprocess.run")
def test_generate_key_pair_with_output_file(mock_run, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(FAKE_KEYGEN_OUTPUT)

    mock_run.side_effect = [
        _mock_version_ok(),
        MagicMock(stdout="", stderr=FAKE_KEYGEN_OUTPUT, returncode=0),
    ]

    pair = generate_key_pair(output_file=key_file)

    assert pair.key_file == key_file
    assert pair.private_key.startswith("AGE-SECRET-KEY-")


@patch("envcrypt.keys.subprocess.run")
def test_generate_key_pair_failure_raises(mock_run):
    mock_run.side_effect = [
        _mock_version_ok(),
        subprocess.CalledProcessError(1, "age-keygen", stderr="error"),
    ]

    with pytest.raises(AgeEncryptionError, match="age-keygen failed"):
        generate_key_pair()


def test_load_public_key_from_file(tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(FAKE_KEYGEN_OUTPUT)

    pub = load_public_key_from_file(key_file)
    assert pub.startswith("age1")


def test_load_public_key_missing_file():
    with pytest.raises(AgeEncryptionError, match="Key file not found"):
        load_public_key_from_file(Path("/nonexistent/key.txt"))


def test_parse_public_key():
    assert _parse_public_key(FAKE_KEYGEN_OUTPUT).startswith("age1")
    assert _parse_public_key("no key here") == ""


def test_parse_private_key():
    assert _parse_private_key(FAKE_KEYGEN_OUTPUT).startswith("AGE-SECRET-KEY-")
    assert _parse_private_key("nothing") == ""
