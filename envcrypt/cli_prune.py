"""CLI commands for pruning unused keys from a vault."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_prune import PruneError, prune_vault


@click.group()
def prune() -> None:
    """Prune unused keys from a vault."""


@prune.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("identity", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--keep",
    "keep_keys",
    multiple=True,
    required=True,
    help="Key name to keep (repeatable).",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Output vault path (defaults to in-place).",
)
@click.option(
    "--recipients",
    "recipients_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to recipients file.",
)
def run_cmd(
    vault: Path,
    identity: Path,
    keep_keys: tuple[str, ...],
    output_path: Path | None,
    recipients_path: Path | None,
) -> None:
    """Remove keys from VAULT that are not listed via --keep."""
    try:
        result = prune_vault(
            vault,
            identity,
            keep_keys,
            output_path=output_path,
            recipients_path=recipients_path,
        )
    except PruneError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.removed:
        click.echo(result.summary())
    else:
        click.echo("Nothing to prune — all keys are in the keep list.")
