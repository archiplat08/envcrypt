"""CLI commands for vault encrypt/decrypt operations."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import click

from envcrypt.crypto import AgeEncryptionError
from envcrypt.dotenv import DotEnvError
from envcrypt.vault import decrypt_env_file, encrypt_env_file


@click.group()
def vault() -> None:
    """Encrypt and decrypt .env files."""


@vault.command("encrypt")
@click.argument("env_file", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output path for the encrypted file.")
@click.option("-r", "--recipient", "recipients", multiple=True,
              help="Public key recipient (repeatable).")
@click.option("--recipients-file", type=click.Path(exists=True, path_type=Path),
              default=None, help="Path to a recipients file.")
def encrypt_cmd(
    env_file: Path,
    output: Optional[Path],
    recipients: List[str],
    recipients_file: Optional[Path],
) -> None:
    """Encrypt ENV_FILE using age encryption."""
    try:
        out = encrypt_env_file(
            env_file,
            output_path=output,
            recipients_file=recipients_file,
            extra_recipients=list(recipients),
        )
        click.echo(f"Encrypted: {out}")
    except (DotEnvError, AgeEncryptionError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@vault.command("decrypt")
@click.argument("encrypted_file", type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--identity", "identity_file",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to age identity (private key) file.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output path for the decrypted .env file.")
def decrypt_cmd(
    encrypted_file: Path,
    identity_file: Path,
    output: Optional[Path],
) -> None:
    """Decrypt ENCRYPTED_FILE using the given identity."""
    try:
        out = decrypt_env_file(encrypted_file, identity_file, output_path=output)
        click.echo(f"Decrypted: {out}")
    except (DotEnvError, AgeEncryptionError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
