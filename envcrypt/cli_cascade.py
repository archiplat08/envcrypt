"""CLI commands for vault cascade (priority merge) operations."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from envcrypt.env_cascade import CascadeError, cascade_vaults


@click.group("cascade")
def cascade() -> None:
    """Merge multiple vaults with priority ordering."""


@cascade.command("run")
@click.argument("vaults", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--identity", required=True, type=click.Path(exists=True, path_type=Path), help="Age identity file.")
@click.option("-o", "--output", required=True, type=click.Path(path_type=Path), help="Output vault file.")
@click.option("-r", "--recipients", default=None, type=click.Path(path_type=Path), help="Recipients file for re-encryption.")
@click.option("--verbose", is_flag=True, default=False, help="Show per-key source information.")
def run_cmd(
    vaults: tuple,
    identity: Path,
    output: Path,
    recipients: Optional[Path],
    verbose: bool,
) -> None:
    """Cascade VAULTS in order (last file wins) into OUTPUT."""
    try:
        result = cascade_vaults(
            vault_paths=list(vaults),
            identity_path=identity,
            output_path=output,
            recipients_path=recipients,
        )
    except CascadeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    click.echo(result.summary())

    if verbose:
        click.echo("\nKey sources:")
        for key, src in sorted(result.sources.items()):
            overrides = result.overridden.get(key)
            if overrides and len(overrides) > 1:
                shadowed = ", ".join(overrides[:-1])
                click.echo(f"  {key}  <-  {src}  (overrides: {shadowed})")
            else:
                click.echo(f"  {key}  <-  {src}")

    if result.overridden:
        click.echo(f"\n{len(result.overridden)} key(s) were overridden.")
