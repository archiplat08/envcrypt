"""CLI sub-command: envcrypt export."""

from __future__ import annotations

from pathlib import Path

import click

from envcrypt.export import ExportError, export_vault


@click.group()
def export() -> None:
    """Export decrypted env vars to various formats."""


@export.command("run")
@click.argument("vault", type=click.Path(exists=True, path_type=Path))
@click.argument("identity", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["shell", "json", "docker"], case_sensitive=False),
    default="shell",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
def run_cmd(
    vault: Path,
    identity: Path,
    fmt: str,
    output_path: Path | None,
) -> None:
    """Decrypt VAULT with IDENTITY and print env vars in the chosen format."""
    try:
        rendered = export_vault(
            vault_path=vault,
            identity_path=identity,
            fmt=fmt,  # type: ignore[arg-type]
            output_path=output_path,
        )
    except ExportError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_path is None:
        click.echo(rendered)
    else:
        click.echo(f"Exported to {output_path}")
