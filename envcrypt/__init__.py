"""envcrypt — Lightweight utility to encrypt and manage .env files using age encryption."""

from envcrypt.crypto import encrypt, decrypt, AgeEncryptionError

__version__ = "0.1.0"
__all__ = ["encrypt", "decrypt", "AgeEncryptionError"]
