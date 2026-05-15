"""CLI commands for reordering keys inside a vault."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.env_reorder import ReorderError, reorder_vault


@click.group()
def reorder() -> None:
    """Reorder keys inside an encrypted vault."""


@reorder.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("keys", nargs=-1, required=True)
@click.option(
    "--identity",
    "-i",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Age identity (private key) file.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output vault path (defaults to overwriting the source vault).",
)
@click.option(
    "--recipients",
    "-r",
    type=click.Path(path_type=Path),
    default=None,
    help="Recipients file (defaults to .recipients next to vault).",
)
def run_cmd(
    vault: Path,
    keys: tuple,
    identity: Path,
    output: Optional[Path],
    recipients: Optional[Path],
) -> None:
    """Reorder KEYS to the top of VAULT, preserving remaining keys."""
    try:
        result = reorder_vault(
            vault=vault,
            order=list(keys),
            identity=identity,
            output=output,
            recipients_file=recipients,
        )
    except ReorderError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.moved:
        click.echo(f"Moved to front: {', '.join(result.moved)}")
    else:
        click.echo("No keys were reordered.")
    click.echo(result.summary())
