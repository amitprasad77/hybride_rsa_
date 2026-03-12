"""
traditional_rsa.py
==================
Traditional RSA-only encryption — for benchmark comparison.
Uses cryptography library.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )


def encrypt_rsa_only(plaintext: bytes, public_key) -> bytes:
    """
    Encrypt plaintext using RSA-OAEP only (no AES).
    For data > ~190 bytes, splits into chunks (slow and unscalable).
    """
    max_chunk = 190
    chunks = [plaintext[i:i+max_chunk] for i in range(0, len(plaintext), max_chunk)]
    result = b""
    for chunk in chunks:
        ec = public_key.encrypt(chunk, _oaep())
        result += len(ec).to_bytes(2, "big") + ec
    return result


def decrypt_rsa_only(ciphertext: bytes, private_key) -> bytes:
    offset = 0
    plaintext = b""
    while offset < len(ciphertext):
        chunk_len = int.from_bytes(ciphertext[offset:offset+2], "big")
        offset += 2
        chunk = ciphertext[offset:offset+chunk_len]
        offset += chunk_len
        plaintext += private_key.decrypt(chunk, _oaep())
    return plaintext
