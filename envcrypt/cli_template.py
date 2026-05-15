"""CLI commands for .env.example template generation."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.template import TemplateError, generate_template_from_vault


@click.group()
def template() -> None:
    """Generate .env.example templates from encrypted vaults."""


@template.command("generate")
@click.argument("vault", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--identity",
    "-i",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to age private key file.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(dir_okay=False),
    help="Output path (default: <vault>.example).",
)
@click.option(
    "--keep-values",
    is_flag=True,
    default=False,
    help="Preserve original values instead of replacing with placeholders.",
)
@click.option(
    "--header",
    default=None,
    help="Comment header text to prepend to the template.",
)
def generate_cmd(
    vault: str,
    identity: str,
    output: str | None,
    keep_values: bool,
    header: str | None,
) -> None:
    """Generate a .env.example template from an encrypted VAULT file."""
    try:
        out_path = generate_template_from_vault(
            vault,
            identity,
            output_path=output,
            keep_values=keep_values,
            comment_header=header,
        )
        click.echo(f"Template written to {out_path}")
    except TemplateError as exc:
        raise click.ClickException(str(exc)) from exc
    except FileNotFoundError as exc:
        raise click.ClickException(f"File not found: {exc.filename}") from exc
    except PermissionError as exc:
        raise click.ClickException(
            f"Permission denied writing to output path: {exc.filename}"
        ) from exc
