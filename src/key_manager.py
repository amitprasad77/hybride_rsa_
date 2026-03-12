"""
key_manager.py — Secure Key Lifecycle Management (Section V-D & VI-D).
"""

import os
import time
import logging
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .hybrid_crypto import generate_rsa_keypair

logger = logging.getLogger(__name__)


class KeyManager:
    """
    Manages RSA key lifecycle: generation, storage, rotation, secure disposal.

    Directory layout:
        <key_dir>/public_key.pem        -- active RSA public key
        <key_dir>/private_key.pem       -- active RSA private key
        <key_dir>/archive/              -- rotated (old) keys
    """

    def __init__(self, key_dir: str = "keys"):
        self.key_dir     = Path(key_dir)
        self.archive_dir = self.key_dir / "archive"
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def generate_and_save(self, passphrase: Optional[str] = None) -> None:
        """
        Generate 2048-bit RSA key pair and persist to disk (Section V-A).
        Private key is passphrase-encrypted when passphrase is provided.
        """
        pub_pem, priv_pem = generate_rsa_keypair()

        if passphrase:
            priv_key = serialization.load_pem_private_key(
                priv_pem, password=None, backend=default_backend()
            )
            priv_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    passphrase.encode()
                )
            )

        (self.key_dir / "public_key.pem").write_bytes(pub_pem)
        (self.key_dir / "private_key.pem").write_bytes(priv_pem)
        logger.info("Keys saved to %s", self.key_dir)

    def load_public_key(self) -> bytes:
        path = self.key_dir / "public_key.pem"
        if not path.exists():
            raise FileNotFoundError(f"Run generate_and_save() first.")
        return path.read_bytes()

    def load_private_key(self, passphrase: Optional[str] = None) -> bytes:
        path = self.key_dir / "private_key.pem"
        if not path.exists():
            raise FileNotFoundError(f"Run generate_and_save() first.")
        raw = path.read_bytes()
        if passphrase:
            # Decrypt & re-export without passphrase for use in hybrid_crypto
            key = serialization.load_pem_private_key(
                raw, password=passphrase.encode(), backend=default_backend()
            )
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        return raw

    def rotate_keys(self, passphrase: Optional[str] = None) -> None:
        """
        Archive current keys and generate a fresh pair (Section VI-D).
        "RSA keys are periodically refreshed to strengthen long-term resilience."
        """
        ts = int(time.time())
        for name in ("public_key.pem", "private_key.pem"):
            src = self.key_dir / name
            if src.exists():
                dst = self.archive_dir / f"{name.replace('.pem', '')}_{ts}.pem"
                src.rename(dst)
                logger.info("Archived %s -> %s", src.name, dst.name)
        self.generate_and_save(passphrase)
        logger.info("Key rotation complete.")

    def list_archived_keys(self) -> list:
        return sorted(self.archive_dir.glob("*.pem"))

    def has_keys(self) -> bool:
        return (
            (self.key_dir / "public_key.pem").exists() and
            (self.key_dir / "private_key.pem").exists()
        )
