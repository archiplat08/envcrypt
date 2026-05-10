"""CLI commands for vault cloning."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_clone import CloneError, clone_vault


@click.group()
def clone() -> None:
    """Clone a vault to a new file."""


@clone.command("run")
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.argument("destination", type=click.Path(path_type=Path))
@click.option(
    "--identity", "-i",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Age identity (private key) file.",
)
@click.option(
    "--recipients-file", "-r",
    type=click.Path(path_type=Path),
    default=None,
    help="Recipients file for the cloned vault (defaults to source's .recipients).",
)
@click.option(
    "--include", "-k",
    multiple=True,
    metavar="KEY",
    help="Keys to include (repeatable). Mutually exclusive with --exclude.",
)
@click.option(
    "--exclude", "-x",
    multiple=True,
    metavar="KEY",
    help="Keys to exclude (repeatable). Mutually exclusive with --include.",
)
def run_cmd(
    source: Path,
    destination: Path,
    identity: Path,
    recipients_file: Path | None,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> None:
    """Clone SOURCE vault to DESTINATION, re-encrypting for current recipients."""
    try:
        result = clone_vault(
            source,
            destination,
            identity,
            include=include or None,
            exclude=exclude or None,
            recipients_file=recipients_file,
        )
    except CloneError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(result.summary())
    if result.keys_skipped:
        click.echo(f"  Skipped: {', '.join(sorted(result.keys_skipped))}")
