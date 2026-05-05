"""Key management utilities for age encryption."""

import subprocess
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from envcrypt.crypto import AgeEncryptionError, _check_age_installed


@dataclass
class AgeKeyPair:
    public_key: str
    private_key: str
    key_file: Optional[Path] = None


def generate_key_pair(output_file: Optional[Path] = None) -> AgeKeyPair:
    """Generate a new age key pair using age-keygen.

    Args:
        output_file: Optional path to write the private key file.

    Returns:
        AgeKeyPair containing the public and private keys.

    Raises:
        AgeEncryptionError: If age-keygen is not installed or key generation fails.
    """
    _check_age_installed()

    cmd = ["age-keygen"]
    if output_file:
        cmd += ["-o", str(output_file)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise AgeEncryptionError(
            f"age-keygen failed: {exc.stderr.strip()}"
        ) from exc

    output = result.stderr if output_file else result.stdout
    public_key = _parse_public_key(output)
    private_key = _parse_private_key(output) if not output_file else ""

    if output_file and output_file.exists():
        raw = output_file.read_text()
        private_key = _parse_private_key(raw)

    return AgeKeyPair(
        public_key=public_key,
        private_key=private_key,
        key_file=output_file,
    )


def load_public_key_from_file(key_file: Path) -> str:
    """Extract the public key from an age private key file.

    Args:
        key_file: Path to the age private key file.

    Returns:
        The public key string.

    Raises:
        AgeEncryptionError: If the file cannot be read or parsed.
    """
    if not key_file.exists():
        raise AgeEncryptionError(f"Key file not found: {key_file}")

    content = key_file.read_text()
    public_key = _parse_public_key(content)
    if not public_key:
        raise AgeEncryptionError(
            f"No public key found in key file: {key_file}"
        )
    return public_key


def _parse_public_key(text: str) -> str:
    match = re.search(r"# public key: (age1[a-z0-9]+)", text, re.IGNORECASE)
    return match.group(1) if match else ""


def _parse_private_key(text: str) -> str:
    match = re.search(r"(AGE-SECRET-KEY-[A-Z0-9]+)", text)
    return match.group(1) if match else ""
