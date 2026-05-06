"""CLI commands for importing env variables into a vault."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.import_env import ImportError  # noqa: A004
from envcrypt.import_env import import_from_dotenv, import_from_json, import_from_shell_env


@click.group()
def imp() -> None:
    """Import env variables from external sources."""


@imp.command("dotenv")
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--recipients",
    "-r",
    default=".recipients",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Recipients file for encryption.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(path_type=Path),
    help="Output vault file path.",
)
def dotenv_cmd(source: Path, recipients: Path, output: Path | None) -> None:
    """Import a plain .env file and encrypt it."""
    try:
        out = import_from_dotenv(source, recipients, output)
        click.echo(f"Imported and encrypted to {out}")
    except ImportError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@imp.command("json")
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--recipients",
    "-r",
    default=".recipients",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Recipients file for encryption.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(path_type=Path),
    help="Output vault file path.",
)
def json_cmd(source: Path, recipients: Path, output: Path | None) -> None:
    """Import a JSON key/value file and encrypt it."""
    try:
        out = import_from_json(source, recipients, output)
        click.echo(f"Imported and encrypted to {out}")
    except ImportError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@imp.command("shell")
@click.argument("keys", nargs=-1, required=True)
@click.option(
    "--recipients",
    "-r",
    default=".recipients",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Recipients file for encryption.",
)
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(path_type=Path),
    help="Output vault file path.",
)
def shell_cmd(keys: tuple[str, ...], recipients: Path, output: Path) -> None:
    """Import specific keys from the current shell environment."""
    try:
        out = import_from_shell_env(list(keys), recipients, output)
        click.echo(f"Imported {len(keys)} key(s) and encrypted to {out}")
    except ImportError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
