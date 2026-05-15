"""Register cascade commands with the main CLI.

Import this module in cli_main.py to attach the cascade group::

    from envcrypt.cli_main_cascade_registration import register
    register(cli)
"""
from __future__ import annotations

import click

from envcrypt.cli_cascade import cascade


def register(cli: click.Group) -> None:  # pragma: no cover
    """Attach the cascade command group to *cli*."""
    cli.add_command(cascade)
