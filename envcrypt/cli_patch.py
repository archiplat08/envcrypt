"""CLI commands for patching individual keys in an encrypted vault."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.env_patch import PatchError, patch_vault


@click.group("patch")
def patch() -> None:
    """Set or unset individual keys in an encrypted vault."""


@patch.command("set")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("identity", type=click.Path(exists=True, path_type=Path))
@click.argument("assignments", nargs=-1, required=True, metavar="KEY=VALUE...")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output path (defaults to overwriting the vault).")
@click.option("--recipients", "-r", type=click.Path(path_type=Path), default=None,
              help="Recipients file (default: .env.recipients next to vault).")
def set_cmd(
    vault: Path,
    identity: Path,
    assignments: tuple[str, ...],
    output: Path | None,
    recipients: Path | None,
) -> None:
    """Set KEY=VALUE pairs in the vault."""
    pairs: dict[str, str] = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise click.BadParameter(f"Expected KEY=VALUE, got: {assignment!r}")
        key, _, value = assignment.partition("=")
        pairs[key.strip()] = value

    try:
        result = patch_vault(
            vault, identity,
            set_pairs=pairs,
            recipients_path=recipients,
            output_path=output,
        )
        click.echo(f"Patched vault: {result.summary()}")
    except PatchError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@patch.command("unset")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("identity", type=click.Path(exists=True, path_type=Path))
@click.argument("keys", nargs=-1, required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output path (defaults to overwriting the vault).")
@click.option("--recipients", "-r", type=click.Path(path_type=Path), default=None,
              help="Recipients file (default: .env.recipients next to vault).")
def unset_cmd(
    vault: Path,
    identity: Path,
    keys: tuple[str, ...],
    output: Path | None,
    recipients: Path | None,
) -> None:
    """Remove keys from the vault."""
    try:
        result = patch_vault(
            vault, identity,
            unset_keys=list(keys),
            recipients_path=recipients,
            output_path=output,
        )
        click.echo(f"Patched vault: {result.summary()}")
    except PatchError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
