"""Tests for envcrypt.import_env and envcrypt.cli_import."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envcrypt.cli_import import imp
from envcrypt.import_env import ImportError  # noqa: A004
from envcrypt.import_env import import_from_dotenv, import_from_json, import_from_shell_env


@pytest.fixture()
def recipients_file(tmp_path: Path) -> Path:
    r = tmp_path / ".recipients"
    r.write_text("age1abc123\n")
    return r


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# import_from_dotenv
# ---------------------------------------------------------------------------

def test_import_dotenv_success(tmp_path: Path, recipients_file: Path) -> None:
    src = tmp_path / ".env"
    src.write_text("KEY=value\n")
    out = tmp_path / "out.env.age"

    with patch("envcrypt.import_env.encrypt_env_file") as mock_enc:
        result = import_from_dotenv(src, recipients_file, out)

    mock_enc.assert_called_once_with(src, recipients_file, out)
    assert result == out


def test_import_dotenv_missing_source_raises(tmp_path: Path, recipients_file: Path) -> None:
    with pytest.raises(ImportError, match="Source file not found"):
        import_from_dotenv(tmp_path / "missing.env", recipients_file)


# ---------------------------------------------------------------------------
# import_from_json
# ---------------------------------------------------------------------------

def test_import_json_success(tmp_path: Path, recipients_file: Path) -> None:
    src = tmp_path / "secrets.json"
    src.write_text(json.dumps({"DB_URL": "postgres://localhost", "PORT": 5432}))
    out = tmp_path / "out.env.age"

    with patch("envcrypt.import_env.encrypt_env_file") as mock_enc:
        result = import_from_json(src, recipients_file, out)

    mock_enc.assert_called_once()
    assert result == out


def test_import_json_invalid_json_raises(tmp_path: Path, recipients_file: Path) -> None:
    src = tmp_path / "bad.json"
    src.write_text("not json{")
    with pytest.raises(ImportError, match="Invalid JSON"):
        import_from_json(src, recipients_file)


def test_import_json_nested_raises(tmp_path: Path, recipients_file: Path) -> None:
    src = tmp_path / "nested.json"
    src.write_text(json.dumps({"DB": {"host": "localhost"}}))
    with pytest.raises(ImportError, match="Nested values"):
        import_from_json(src, recipients_file)


# ---------------------------------------------------------------------------
# import_from_shell_env
# ---------------------------------------------------------------------------

def test_import_shell_env_success(tmp_path: Path, recipients_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "hunter2")
    out = tmp_path / "shell.env.age"

    with patch("envcrypt.import_env.encrypt_env_file") as mock_enc:
        result = import_from_shell_env(["MY_SECRET"], recipients_file, out)

    mock_enc.assert_called_once()
    assert result == out


def test_import_shell_env_missing_key_raises(tmp_path: Path, recipients_file: Path) -> None:
    with pytest.raises(ImportError, match="Keys not found in environment"):
        import_from_shell_env(["DEFINITELY_NOT_SET_XYZ"], recipients_file, tmp_path / "out.age")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_dotenv_cmd(tmp_path: Path, runner: CliRunner) -> None:
    src = tmp_path / ".env"
    src.write_text("X=1\n")
    rec = tmp_path / ".recipients"
    rec.write_text("age1abc\n")
    out = tmp_path / "out.env.age"

    with patch("envcrypt.cli_import.import_from_dotenv") as mock_fn:
        mock_fn.return_value = out
        result = runner.invoke(imp, ["dotenv", str(src), "--recipients", str(rec), "--output", str(out)])

    assert result.exit_code == 0
    assert str(out) in result.output


def test_cli_json_cmd_error(tmp_path: Path, runner: CliRunner) -> None:
    src = tmp_path / "bad.json"
    src.write_text("{}")
    rec = tmp_path / ".recipients"
    rec.write_text("age1abc\n")

    with patch("envcrypt.cli_import.import_from_json", side_effect=ImportError("bad")):
        result = runner.invoke(imp, ["json", str(src), "--recipients", str(rec)])

    assert result.exit_code == 1
    assert "Error" in result.output
