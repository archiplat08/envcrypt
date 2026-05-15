"""CLI commands for vault squashing."""
from __future__ import annotations

from pathlib import Path
from typing import List

import click

from envcrypt.env_squash import SquashError, squash_vaults


@click.group()
def squash() -> None:
    """Squash multiple vaults into one."""


@squash.command("run")
@click.argument("sources", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--identity", required=True, type=click.Path(exists=True, path_type=Path), help="Age identity file.")
@click.option("-o", "--output", default=None, type=click.Path(path_type=Path), help="Output vault path.")
@click.option("--recipients-file", default=None, type=click.Path(path_type=Path), help="Recipients file.")
@click.option("--first-wins", is_flag=True, default=False, help="Keep first value on conflict instead of last.")
def run_cmd(
    sources: List[Path],
    identity: Path,
    output: Path | None,
    recipients_file: Path | None,
    first_wins: bool,
) -> None:
    """Squash SOURCE vaults into a single encrypted vault."""
    try:
        result = squash_vaults(
            sources=list(sources),
            identity=identity,
            output=output,
            recipients_file=recipients_file,
            last_wins=not first_wins,
        )
    except SquashError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(result.summary())
    click.echo(f"Output: {result.output}")
