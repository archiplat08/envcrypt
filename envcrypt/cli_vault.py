import click
from pathlib import Path
from envcrypt.vault import encrypt_env_file, decrypt_env_file
from envcrypt.recipients import load_recipients


@click.group()
def vault():
    """Encrypt and decrypt .env files."""
    pass


@vault.command("encrypt")
@click.argument("env_file", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    default=None,
    help="Output path for the encrypted file (default: <env_file>.age)",
)
@click.option(
    "--recipients-file", "-r",
    default=".env.recipients",
    show_default=True,
    help="Path to the recipients file.",
)
def encrypt_cmd(env_file, output, recipients_file):
    """Encrypt ENV_FILE using recipients from the recipients file."""
    recipients = load_recipients(recipients_file)
    if not recipients:
        raise click.ClickException(
            f"No recipients found in '{recipients_file}'. "
            "Add recipients with: envcrypt keys add"
        )
    out_path = encrypt_env_file(
        env_file,
        recipients=recipients,
        output_path=output,
    )
    click.echo(f"Encrypted: {out_path}")


@vault.command("decrypt")
@click.argument("encrypted_file", type=click.Path(exists=True))
@click.option(
    "--identity", "-i",
    required=True,
    help="Path to the age identity (private key) file.",
    type=click.Path(exists=True),
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output path for the decrypted .env file (default: .env).",
)
def decrypt_cmd(encrypted_file, identity, output):
    """Decrypt ENCRYPTED_FILE to a .env file using an age identity."""
    out_path = decrypt_env_file(
        encrypted_file,
        identity_path=identity,
        output_path=output,
    )
    click.echo(f"Decrypted: {out_path}")
