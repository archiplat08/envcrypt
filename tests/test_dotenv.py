"""Tests for envcrypt.dotenv."""

from __future__ import annotations

import pytest
from pathlib import Path

from envcrypt.dotenv import (
    DotEnvError,
    parse_dotenv,
    serialize_dotenv,
    read_dotenv_file,
    write_dotenv_file,
)


def test_parse_simple_pairs():
    text = "KEY=value\nFOO=bar\n"
    result = parse_dotenv(text)
    assert result == {"KEY": "value", "FOO": "bar"}


def test_parse_ignores_comments_and_blank_lines():
    text = "# comment\n\nKEY=value\n"
    result = parse_dotenv(text)
    assert result == {"KEY": "value"}


def test_parse_strips_double_quotes():
    result = parse_dotenv('DB_URL="postgres://localhost/db"')
    assert result["DB_URL"] == "postgres://localhost/db"


def test_parse_strips_single_quotes():
    result = parse_dotenv("SECRET='hello world'")
    assert result["SECRET"] == "hello world"


def test_parse_invalid_line_raises():
    with pytest.raises(DotEnvError, match="Invalid syntax"):
        parse_dotenv("INVALID LINE")


def test_serialize_round_trip():
    env = {"KEY": "value", "FOO": "bar"}
    text = serialize_dotenv(env)
    assert parse_dotenv(text) == env


def test_serialize_quotes_values_with_spaces():
    text = serialize_dotenv({"MSG": "hello world"})
    assert '"hello world"' in text


def test_serialize_invalid_key_raises():
    with pytest.raises(DotEnvError, match="Invalid environment variable name"):
        serialize_dotenv({"123BAD": "value"})


def test_read_dotenv_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=production\n", encoding="utf-8")
    result = read_dotenv_file(env_file)
    assert result == {"APP_ENV": "production"}


def test_read_dotenv_file_missing_raises(tmp_path):
    with pytest.raises(DotEnvError, match="Cannot read file"):
        read_dotenv_file(tmp_path / "nonexistent.env")


def test_write_dotenv_file(tmp_path):
    env_file = tmp_path / ".env"
    write_dotenv_file(env_file, {"KEY": "val"})
    assert env_file.read_text(encoding="utf-8") == "KEY=val\n"
