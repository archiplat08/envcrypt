"""CLI commands for vault splitting."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.env_split import SplitError, split_vault


@click.group("split")
def split() -> None:
    """Split a vault into multiple smaller vaults."""


@split.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("prefixes", nargs=-1, required=True)
@click.option(
    "--identity", "-i",
    type=click.Path(path_type=Path),
    default=Path.home() / ".config" / "envcrypt" / "identity.txt",
    show_default=True,
    help="Age identity file for decryption.",
)
@click.option(
    "--output-dir", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory to write split vaults (defaults to vault directory).",
)
@click.option(
    "--recipients", "-r",
    type=click.Path(path_type=Path),
    default=None,
    help="Recipients file for re-encryption.",
)
@click.option(
    "--no-leftover",
    is_flag=True,
    default=False,
    help="Discard keys that don't match any prefix.",
)
def run_cmd(
    vault: Path,
    prefixes: tuple,
    identity: Path,
    output_dir: Optional[Path],
    recipients: Optional[Path],
    no_leftover: bool,
) -> None:
    """Split VAULT by PREFIXES into separate encrypted files."""
    try:
        result = split_vault(
            vault=vault,
            identity=identity,
            prefixes=list(prefixes),
            output_dir=output_dir,
            recipients_file=recipients,
            keep_leftover=not no_leftover,
        )
    except SplitError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if not result.outputs:
        click.echo("No keys matched the given prefixes.")
        return

    for label, path in result.outputs.items():
        count = result.key_counts.get(label, 0)
        click.echo(f"  {label}: {path}  ({count} keys)")

    click.echo(f"Done. {result.summary()}")
