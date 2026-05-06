"""CLI commands for validating .env files against a schema."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.validate import validate_env_file


@click.group()
def validate() -> None:
    """Validate .env files against a required-keys schema."""


@validate.command("check")
@click.argument("env_file", type=click.Path(exists=True, path_type=Path))
@click.argument("schema_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--allow-empty",
    is_flag=True,
    default=False,
    help="Allow keys to be present but empty.",
)
def check_cmd(env_file: Path, schema_file: Path, allow_empty: bool) -> None:
    """Check ENV_FILE against SCHEMA_FILE.

    SCHEMA_FILE is a plain-text file with one required key per line.
    Lines starting with '#' and blank lines are ignored.
    """
    result = validate_env_file(env_file, schema_file, allow_empty=allow_empty)
    if result.ok:
        click.secho(str(result), fg="green")
    else:
        click.secho(str(result), fg="red", err=True)
        raise SystemExit(1)
