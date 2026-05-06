"""Tests for envcrypt.export and envcrypt.cli_export."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envcrypt.export import ExportError, export_env, export_vault
from envcrypt.cli_export import export

_SAMPLE_ENV = {"DB_HOST": "localhost", "DB_PASS": 'p@ss"word', "PORT": "5432"}


# ---------------------------------------------------------------------------
# export_env unit tests
# ---------------------------------------------------------------------------

def test_export_env_shell_format():
    result = export_env({"FOO": "bar", "BAZ": "qux"}, fmt="shell")
    assert 'export FOO="bar"' in result
    assert 'export BAZ="qux"' in result


def test_export_env_shell_escapes_double_quotes():
    result = export_env({"KEY": 'say "hi"'}, fmt="shell")
    assert r'say \"hi\"' in result


def test_export_env_json_format():
    import json
    result = export_env({"A": "1", "B": "2"}, fmt="json")
    parsed = json.loads(result)
    assert parsed == {"A": "1", "B": "2"}


def test_export_env_docker_format():
    result = export_env({"FOO": "bar"}, fmt="docker")
    assert "FOO=bar" in result
    assert "export" not in result


def test_export_env_docker_replaces_newlines():
    result = export_env({"MSG": "line1\nline2"}, fmt="docker")
    assert "\n" not in result.split("=", 1)[1]


def test_export_env_unknown_format_raises():
    with pytest.raises(ExportError, match="Unknown export format"):
        export_env({"K": "v"}, fmt="yaml")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# export_vault unit tests
# ---------------------------------------------------------------------------

def _patch_decrypt(env):
    return patch("envcrypt.export.decrypt_env_file", return_value=env)


def test_export_vault_returns_rendered_string(tmp_path):
    vault = tmp_path / "secrets.age"
    vault.touch()
    identity = tmp_path / "key.txt"
    identity.touch()
    with _patch_decrypt({"X": "1"}):
        result = export_vault(vault, identity, fmt="shell")
    assert 'export X="1"' in result


def test_export_vault_writes_output_file(tmp_path):
    vault = tmp_path / "secrets.age"
    vault.touch()
    identity = tmp_path / "key.txt"
    identity.touch()
    out = tmp_path / "env.sh"
    with _patch_decrypt({"Y": "2"}):
        export_vault(vault, identity, fmt="shell", output_path=out)
    assert out.exists()
    assert 'export Y="2"' in out.read_text()


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner():
    return CliRunner()


def test_cli_export_prints_to_stdout(runner, tmp_path):
    vault = tmp_path / "v.age"
    vault.touch()
    ident = tmp_path / "k.txt"
    ident.touch()
    with _patch_decrypt({"HELLO": "world"}):
        result = runner.invoke(export, ["run", str(vault), str(ident), "--format", "shell"])
    assert result.exit_code == 0
    assert 'export HELLO="world"' in result.output


def test_cli_export_writes_file(runner, tmp_path):
    vault = tmp_path / "v.age"
    vault.touch()
    ident = tmp_path / "k.txt"
    ident.touch()
    out = tmp_path / "out.json"
    with _patch_decrypt({"K": "v"}):
        result = runner.invoke(
            export,
            ["run", str(vault), str(ident), "--format", "json", "--output", str(out)],
        )
    assert result.exit_code == 0
    assert "Exported to" in result.output
    assert out.exists()
