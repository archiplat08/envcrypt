"""CLI commands for vault key rotation."""

import click

from envcrypt.rotate import RotationError, rotate_vault


@click.group()
def rotate() -> None:
    """Rotate encryption keys for a vault file."""


@rotate.command("run")
@click.argument("vault_file", default=".env.age")
@click.option(
    "--identity",
    "-i",
    required=True,
    help="Path to age private key used to decrypt the vault.",
)
@click.option(
    "--recipients-file",
    "-r",
    default=".env.recipients",
    show_default=True,
    help="Path to recipients file.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output path (defaults to overwriting VAULT_FILE).",
)
@click.option(
    "--actor",
    default=None,
    help="Label to record in the audit log (e.g. your name or email).",
)
def rotate_cmd(
    vault_file: str,
    identity: str,
    recipients_file: str,
    output: str | None,
    actor: str | None,
) -> None:
    """Re-encrypt VAULT_FILE with the current recipients list.

    Use this after adding or removing a recipient to ensure the vault
    can only be decrypted by the intended set of keys.
    """
    try:
        out = rotate_vault(
            vault_file,
            identity,
            recipients_file=recipients_file,
            output_file=output,
            actor=actor,
        )
        click.echo(f"Rotated vault written to: {out}")
    except RotationError as exc:
        raise click.ClickException(str(exc)) from exc
