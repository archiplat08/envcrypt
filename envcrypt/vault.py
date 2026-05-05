"""High-level encrypt/decrypt operations for .env files (the vault)."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from envcrypt.crypto import decrypt, encrypt
from envcrypt.dotenv import DotEnvError, read_dotenv_file, serialize_dotenv, parse_dotenv
from envcrypt.recipients import load_recipients

_ENCRYPTED_SUFFIX = ".age"


def encrypt_env_file(
    env_path: Path,
    output_path: Optional[Path] = None,
    recipients_file: Optional[Path] = None,
    extra_recipients: Optional[List[str]] = None,
) -> Path:
    """Encrypt *env_path* and write ciphertext to *output_path*.

    Returns the path of the encrypted file.
    """
    env = read_dotenv_file(env_path)
    plaintext = serialize_dotenv(env)

    recipients: List[str] = list(extra_recipients or [])
    if recipients_file is not None:
        recipients.extend(load_recipients(recipients_file))

    if not recipients:
        raise DotEnvError(
            "No recipients specified. Provide a recipients file or extra_recipients."
        )

    ciphertext = encrypt(plaintext.encode(), recipients)

    if output_path is None:
        output_path = env_path.with_suffix(env_path.suffix + _ENCRYPTED_SUFFIX)

    output_path.write_bytes(ciphertext)
    return output_path


def decrypt_env_file(
    encrypted_path: Path,
    identity_file: Path,
    output_path: Optional[Path] = None,
) -> Path:
    """Decrypt *encrypted_path* using *identity_file* and write plaintext.

    Returns the path of the decrypted .env file.
    """
    ciphertext = encrypted_path.read_bytes()
    plaintext_bytes = decrypt(ciphertext, identity_file)

    env = parse_dotenv(plaintext_bytes.decode())

    if output_path is None:
        stem = encrypted_path.stem  # strips .age
        output_path = encrypted_path.with_name(stem)

    from envcrypt.dotenv import write_dotenv_file
    write_dotenv_file(output_path, env)
    return output_path
