"""
hybrid_crypto.py
================
Core implementation of the Hybrid RSA-AES Cryptographic Framework.

Paper: "Strengthening RSA Encryption via Hybrid Cryptosystem and Key Management"
       Amit Prasad et al., IEEE ICIDCA-2025

Algorithm 1 (from paper):
  Encryption:
    1. KAES <- CSPRNG(128 bits)
    2. IV   <- CSPRNG(128 bits)
    3. CAES <- EncAES-CBC(KAES, IV, M)
    4. CRSA <- EncRSA-OAEP(Kpub, KAES)
    5. C    <- CRSA || IV || CAES

  Decryption:
    1. Parse C -> (CRSA, IV, CAES)
    2. KAES <- DecRSA-OAEP(Kpriv, CRSA)
    3. M    <- DecAES-CBC(KAES, IV, CAES)
"""

import os
import struct
import logging
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ── Constants (Section IV of paper) ──────────────────────────────────────────
RSA_KEY_BITS   = 2048   # "2048-bit RSA key pair"
AES_KEY_BYTES  = 16     # "128-bit AES session key"
AES_BLOCK_SIZE = 16
IV_BYTES       = 16     # "128-bit IV"
RSA_BLOB_BYTES = 256    # 2048-bit RSA output = 256 bytes (fixed, no length prefix needed)


def _oaep_padding():
    """OAEP padding with SHA-256 (Section IV: 'OAEP Padding')."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )


# ── Key Generation ───────────────────────────────────────────────────────────

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a 2048-bit RSA key pair using CSPRNG (Section V-A).
    Returns (public_key_pem, private_key_pem).
    """
    logger.info("Generating 2048-bit RSA key pair ...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.info("RSA key pair generated.")
    return public_pem, private_pem


def _generate_aes_session_key() -> bytes:
    """
    128-bit AES session key via CSPRNG (Section V-A).
    Fresh key per session -- never reused.
    """
    return os.urandom(AES_KEY_BYTES)


def _generate_iv() -> bytes:
    """128-bit IV via CSPRNG."""
    return os.urandom(IV_BYTES)


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK_SIZE:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def _secure_erase(buf: bytearray) -> None:
    """Overwrite key material in memory (Section V-D: secure disposal)."""
    for i in range(len(buf)):
        buf[i] = 0


# ── Encryption ───────────────────────────────────────────────────────────────

def encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """
    Hybrid RSA-AES encryption (Algorithm 1, Section V-B).

    Package layout:
        [RSA-encrypted session key 256B] [IV 16B] [AES-CBC ciphertext]
    """
    aes_key = bytearray(_generate_aes_session_key())
    iv      = _generate_iv()

    try:
        # Step 2: AES-128-CBC encrypt
        cipher  = Cipher(algorithms.AES(bytes(aes_key)), modes.CBC(iv), backend=default_backend())
        enc     = cipher.encryptor()
        aes_ct  = enc.update(_pkcs7_pad(plaintext)) + enc.finalize()

        # Step 3: RSA-OAEP encrypt the session key
        pub_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        rsa_ct  = pub_key.encrypt(bytes(aes_key), _oaep_padding())

        # Step 4: Package = CRSA || IV || CAES
        package = rsa_ct + iv + aes_ct

        logger.info(
            "Encrypted %d bytes -> package %d bytes (RSA blob %d B, AES-CT %d B)",
            len(plaintext), len(package), len(rsa_ct), len(aes_ct)
        )
        return package

    finally:
        _secure_erase(aes_key)


# ── Decryption ───────────────────────────────────────────────────────────────

def decrypt(ciphertext_package: bytes, private_key_pem: bytes) -> bytes:
    """
    Hybrid RSA-AES decryption (Algorithm 1, Section V-C).
    """
    # Step 1: Parse (RSA blob is always RSA_BLOB_BYTES = 256 for 2048-bit RSA)
    rsa_ct = ciphertext_package[:RSA_BLOB_BYTES]
    iv     = ciphertext_package[RSA_BLOB_BYTES : RSA_BLOB_BYTES + IV_BYTES]
    aes_ct = ciphertext_package[RSA_BLOB_BYTES + IV_BYTES:]

    aes_key = bytearray(AES_KEY_BYTES)

    try:
        # Step 2: RSA-OAEP decrypt
        priv_key = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        aes_key = bytearray(priv_key.decrypt(rsa_ct, _oaep_padding()))

        # Step 3: AES-128-CBC decrypt
        cipher    = Cipher(algorithms.AES(bytes(aes_key)), modes.CBC(iv), backend=default_backend())
        dec       = cipher.decryptor()
        plaintext = _pkcs7_unpad(dec.update(aes_ct) + dec.finalize())

        logger.info("Decrypted %d bytes -> %d bytes plaintext.", len(aes_ct), len(plaintext))
        return plaintext

    finally:
        _secure_erase(aes_key)
