"""Helper to verify cli_split integrates with the main CLI.

This module is intentionally thin — it just imports the split group so that
``cli_main.py`` can register it with a single ``cli.add_command(split)`` call.
It is kept separate to avoid circular imports and to follow the pattern used
by the other CLI sub-modules in this project.
"""
from envcrypt.cli_split import split  # noqa: F401 – re-exported for convenience

__all__ = ["split"]
