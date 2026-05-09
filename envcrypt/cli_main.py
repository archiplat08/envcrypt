"""Main CLI entry point for envcrypt."""

from __future__ import annotations

import click

from envcrypt.cli_audit import audit
from envcrypt.cli_export import export
from envcrypt.cli_group import group
from envcrypt.cli_history import history
from envcrypt.cli_import import imp
from envcrypt.cli_keys import keys
from envcrypt.cli_lint import lint
from envcrypt.cli_lock import lock
from envcrypt.cli_merge import merge
from envcrypt.cli_patch import patch
from envcrypt.cli_rename import rename
from envcrypt.cli_rotate import rotate
from envcrypt.cli_search import search
from envcrypt.cli_share import share
from envcrypt.cli_sign import sign
from envcrypt.cli_template import template
from envcrypt.cli_validate import validate
from envcrypt.cli_vault import vault
from envcrypt.cli_docs import docs
from envcrypt.cli_expire import expire
from envcrypt.cli_copy import copy


@click.group()
@click.version_option(package_name="envcrypt")
def cli() -> None:
    """envcrypt — encrypt and manage .env files with age."""


cli.add_command(vault)
cli.add_command(keys)
cli.add_command(audit)
cli.add_command(rotate)
cli.add_command(share)
cli.add_command(lint)
cli.add_command(merge)
cli.add_command(template)
cli.add_command(history)
cli.add_command(validate)
cli.add_command(search)
cli.add_command(export)
cli.add_command(imp)
cli.add_command(rename)
cli.add_command(lock)
cli.add_command(sign)
cli.add_command(patch)
cli.add_command(copy)
cli.add_command(docs)
cli.add_command(expire)
cli.add_command(group)
