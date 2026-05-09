"""CLI commands for vault formatting."""
from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_fmt import FmtError, format_vault


@click.group("fmt")
def fmt() -> None:
    """Format and normalise vault env files."""


@fmt.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--identity", "-i",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Age identity (private key) file.",
)
@click.option(
    "--recipients", "-r",
    default=".recipients",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Recipients file used to re-encrypt.",
)
@click.option("--no-sort", is_flag=True, default=False, help="Do not sort keys alphabetically.")
@click.option("--no-normalize", is_flag=True, default=False, help="Do not normalise quote style.")
@click.option("--dry-run", is_flag=True, default=False, help="Show diff only; do not write changes.")
def run_cmd(
    vault: Path,
    identity: Path,
    recipients: Path,
    no_sort: bool,
    no_normalize: bool,
    dry_run: bool,
) -> None:
    """Format VAULT in-place (or preview with --dry-run)."""
    try:
        result = format_vault(
            vault,
            identity,
            recipients,
            sort_keys=not no_sort,
            normalize_quotes=not no_normalize,
            dry_run=dry_run,
        )
    except FmtError as exc:
        raise click.ClickException(str(exc)) from exc

    if dry_run and result.changed:
        click.echo("--- original")
        click.echo("+++ formatted")
        orig_lines = result.original.splitlines()
        fmt_lines = result.formatted.splitlines()
        for line in fmt_lines:
            prefix = "+" if line not in orig_lines else " "
            click.echo(f"{prefix} {line}")
        click.echo("(dry-run) Changes detected — vault NOT modified.")
    elif dry_run:
        click.echo("(dry-run) Already formatted — no changes needed.")
    else:
        click.echo(result.summary())
