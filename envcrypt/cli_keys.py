"""CLI commands for managing age key pairs."""

import click
from pathlib import Path

from envcrypt.keys import generate_key_pair, load_public_key_from_file, AgeKeyPair
from envcrypt.recipients import add_recipient, load_recipients, remove_recipient


@click.group(name="keys")
def keys():
    """Manage age key pairs and recipients."""
    pass


@keys.command(name="generate")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Write private key to this file (default: print to stdout).",
)
@click.option(
    "--add-to-recipients",
    "-r",
    default=None,
    metavar="RECIPIENTS_FILE",
    help="Automatically add the new public key to a recipients file.",
)
def generate_cmd(output, add_to_recipients):
    """Generate a new age key pair."""
    output_path = Path(output) if output else None
    key_pair: AgeKeyPair = generate_key_pair(output_file=output_path)

    if output_path:
        click.echo(f"Private key written to: {output_path}")
    else:
        click.echo(f"Private key: {key_pair.private_key}")

    click.echo(f"Public key:  {key_pair.public_key}")

    if add_to_recipients:
        recipients_path = Path(add_to_recipients)
        add_recipient(recipients_path, key_pair.public_key)
        click.echo(f"Public key added to recipients: {recipients_path}")


@keys.command(name="add-recipient")
@click.argument("recipients_file", type=click.Path())
@click.argument("public_key_or_file")
def add_recipient_cmd(recipients_file, public_key_or_file):
    """Add a public key to a recipients file.

    PUBLIC_KEY_OR_FILE can be a raw age public key or a path to a .pub file.
    """
    recipients_path = Path(recipients_file)
    key_path = Path(public_key_or_file)

    if key_path.exists():
        public_key = load_public_key_from_file(key_path)
    else:
        public_key = public_key_or_file

    add_recipient(recipients_path, public_key)
    click.echo(f"Added recipient to {recipients_path}: {public_key}")


@keys.command(name="list-recipients")
@click.argument("recipients_file", type=click.Path(exists=True))
def list_recipients_cmd(recipients_file):
    """List all public keys in a recipients file."""
    recipients = load_recipients(Path(recipients_file))
    if not recipients:
        click.echo("No recipients found.")
    else:
        for key in recipients:
            click.echo(key)


@keys.command(name="remove-recipient")
@click.argument("recipients_file", type=click.Path(exists=True))
@click.argument("public_key")
def remove_recipient_cmd(recipients_file, public_key):
    """Remove a public key from a recipients file."""
    recipients_path = Path(recipients_file)
    remove_recipient(recipients_path, public_key)
    click.echo(f"Removed recipient from {recipients_path}: {public_key}")
