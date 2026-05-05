"""Tests for envcrypt.cli_keys CLI commands."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from envcrypt.cli_keys import keys
from envcrypt.keys import AgeKeyPair

FAKE_PRIVATE = "AGE-SECRET-KEY-1ABCDEF"
FAKE_PUBLIC = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgp"
FAKE_PAIR = AgeKeyPair(public_key=FAKE_PUBLIC, private_key=FAKE_PRIVATE)


@pytest.fixture
def runner():
    return CliRunner()


def test_generate_prints_keys(runner, tmp_path):
    with patch("envcrypt.cli_keys.generate_key_pair", return_value=FAKE_PAIR):
        result = runner.invoke(keys, ["generate"])
    assert result.exit_code == 0
    assert FAKE_PUBLIC in result.output
    assert FAKE_PRIVATE in result.output


def test_generate_with_output_file(runner, tmp_path):
    out_file = tmp_path / "key.txt"
    with patch("envcrypt.cli_keys.generate_key_pair", return_value=FAKE_PAIR) as mock_gen:
        result = runner.invoke(keys, ["generate", "--output", str(out_file)])
    assert result.exit_code == 0
    mock_gen.assert_called_once_with(output_file=out_file)
    assert str(out_file) in result.output


def test_generate_adds_to_recipients(runner, tmp_path):
    rec_file = tmp_path / "recipients.txt"
    with patch("envcrypt.cli_keys.generate_key_pair", return_value=FAKE_PAIR), \
         patch("envcrypt.cli_keys.add_recipient") as mock_add:
        result = runner.invoke(keys, ["generate", "--add-to-recipients", str(rec_file)])
    assert result.exit_code == 0
    mock_add.assert_called_once_with(rec_file, FAKE_PUBLIC)
    assert "added to recipients" in result.output


def test_add_recipient_from_raw_key(runner, tmp_path):
    rec_file = tmp_path / "recipients.txt"
    rec_file.write_text("")
    with patch("envcrypt.cli_keys.add_recipient") as mock_add:
        result = runner.invoke(keys, ["add-recipient", str(rec_file), FAKE_PUBLIC])
    assert result.exit_code == 0
    mock_add.assert_called_once_with(rec_file, FAKE_PUBLIC)
    assert FAKE_PUBLIC in result.output


def test_add_recipient_from_pub_file(runner, tmp_path):
    rec_file = tmp_path / "recipients.txt"
    rec_file.write_text("")
    pub_file = tmp_path / "key.pub"
    pub_file.write_text(FAKE_PUBLIC)
    with patch("envcrypt.cli_keys.load_public_key_from_file", return_value=FAKE_PUBLIC) as mock_load, \
         patch("envcrypt.cli_keys.add_recipient") as mock_add:
        result = runner.invoke(keys, ["add-recipient", str(rec_file), str(pub_file)])
    assert result.exit_code == 0
    mock_load.assert_called_once()
    mock_add.assert_called_once_with(rec_file, FAKE_PUBLIC)


def test_list_recipients(runner, tmp_path):
    rec_file = tmp_path / "recipients.txt"
    rec_file.write_text("")
    with patch("envcrypt.cli_keys.load_recipients", return_value=[FAKE_PUBLIC, "age1other"]):
        result = runner.invoke(keys, ["list-recipients", str(rec_file)])
    assert result.exit_code == 0
    assert FAKE_PUBLIC in result.output
    assert "age1other" in result.output


def test_list_recipients_empty(runner, tmp_path):
    rec_file = tmp_path / "recipients.txt"
    rec_file.write_text("")
    with patch("envcrypt.cli_keys.load_recipients", return_value=[]):
        result = runner.invoke(keys, ["list-recipients", str(rec_file)])
    assert result.exit_code == 0
    assert "No recipients found" in result.output


def test_remove_recipient(runner, tmp_path):
    rec_file = tmp_path / "recipients.txt"
    rec_file.write_text(FAKE_PUBLIC + "\n")
    with patch("envcrypt.cli_keys.remove_recipient") as mock_remove:
        result = runner.invoke(keys, ["remove-recipient", str(rec_file), FAKE_PUBLIC])
    assert result.exit_code == 0
    mock_remove.assert_called_once_with(rec_file, FAKE_PUBLIC)
    assert "Removed" in result.output
