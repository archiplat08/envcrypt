"""CLI commands for signing and verifying vault files."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from envcrypt.env_sign import SignError, sign_vault, verify_vault


@click.group("sign")
def sign() -> None:
    """Sign and verify encrypted vault files."""


@sign.command("sign")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.option("--signer", default=None, help="Identity label of the signer.")
def sign_cmd(vault: Path, signer: str | None) -> None:
    """Sign a vault file and write a .sig.json alongside it."""
    try:
        info = sign_vault(vault, signer=signer)
    except SignError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Signed {info.vault}")
    click.echo(f"  sha256   : {info.sha256}")
    if info.signer:
        click.echo(f"  signer   : {info.signer}")
    click.echo(f"  timestamp: {info.timestamp}")


@sign.command("verify")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
def verify_cmd(vault: Path) -> None:
    """Verify the integrity of a signed vault file."""
    try:
        info = verify_vault(vault)
    except SignError as exc:
        click.echo(f"Verification FAILED: {exc}", err=True)
        sys.exit(1)

    click.echo(f"OK  {info.vault}")
    click.echo(f"  sha256   : {info.sha256}")
    if info.signer:
        click.echo(f"  signer   : {info.signer}")
    click.echo(f"  timestamp: {info.timestamp}")
