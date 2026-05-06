"""CLI commands for searching vault files."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.search import SearchError, search_vault, search_vaults


@click.group()
def search() -> None:
    """Search keys and values inside encrypted vault files."""


@search.command("find")
@click.argument("pattern")
@click.option(
    "--vault",
    "vault_files",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Vault file(s) to search.",
)
@click.option(
    "--identity",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Age identity (private key) file.",
)
@click.option("--values", is_flag=True, default=False, help="Also search in values.")
@click.option("--case-sensitive", is_flag=True, default=False)
@click.option("--regex", "use_regex", is_flag=True, default=False, help="Treat pattern as regex.")
def find_cmd(
    pattern: str,
    vault_files: tuple,
    identity: Path,
    values: bool,
    case_sensitive: bool,
    use_regex: bool,
) -> None:
    """Search PATTERN across vault file(s)."""
    try:
        result = search_vaults(
            list(vault_files),
            identity,
            pattern,
            search_values=values,
            case_sensitive=case_sensitive,
            use_regex=use_regex,
        )
    except SearchError as exc:
        raise click.ClickException(str(exc)) from exc

    if not result.matches:
        click.echo(f"No matches found in {result.searched_files} file(s).")
        return

    click.echo(f"Found {result.total} match(es) in {result.searched_files} file(s):")
    for match in result.matches:
        click.echo(f"  [{match.vault_file}] {match.key}={match.value}")
