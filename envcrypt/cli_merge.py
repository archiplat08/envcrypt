"""CLI commands for merging encrypted .env vaults."""

from pathlib import Path

import click

from envcrypt.merge import ConflictStrategy, MergeError, merge_vault_files


@click.group()
def merge() -> None:
    """Merge two encrypted .env vault files."""


@merge.command("run")
@click.argument("base_vault", type=click.Path(exists=True, path_type=Path))
@click.argument("other_vault", type=click.Path(exists=True, path_type=Path))
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
    help="Output vault path (defaults to BASE_VAULT).",
)
@click.option(
    "--recipients",
    "-r",
    type=click.Path(path_type=Path),
    default=None,
    help="Recipients file (defaults to .recipients next to BASE_VAULT).",
)
@click.option(
    "--strategy",
    "-s",
    type=click.Choice([s.value for s in ConflictStrategy], case_sensitive=False),
    default=ConflictStrategy.OURS.value,
    show_default=True,
    help="Conflict resolution strategy.",
)
def merge_cmd(
    base_vault: Path,
    other_vault: Path,
    identity: Path,
    output: Path | None,
    recipients: Path | None,
    strategy: str,
) -> None:
    """Merge OTHER_VAULT into BASE_VAULT and re-encrypt."""
    try:
        result = merge_vault_files(
            base_vault=base_vault,
            other_vault=other_vault,
            identity_file=identity,
            output=output,
            recipients_file=recipients,
            strategy=ConflictStrategy(strategy),
        )
    except MergeError as exc:
        raise click.ClickException(str(exc)) from exc

    dest = output or base_vault
    click.echo(f"Merged vault written to {dest}")
    if result.added_keys:
        click.echo(f"  Added   : {', '.join(result.added_keys)}")
    if result.conflicts:
        click.echo(
            f"  Conflicts ({strategy}): {', '.join(result.conflicts)}"
        )
    if not result.added_keys and not result.conflicts:
        click.echo("  No conflicts or new keys.")
