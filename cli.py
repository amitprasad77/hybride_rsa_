#!/usr/bin/env python3
"""
cli.py — Command-line interface for the Hybrid RSA-AES framework.

Usage examples:
  python cli.py keygen
  python cli.py encrypt "My secret message"
  python cli.py decrypt <hex_ciphertext>
  python cli.py rotate
  python cli.py benchmark
"""

import sys, os, argparse
from src.hybrid_crypto import generate_rsa_keypair, encrypt, decrypt
from src.key_manager import KeyManager

KEY_DIR = "keys"


def cmd_keygen(args):
    km = KeyManager(KEY_DIR)
    km.generate_and_save(passphrase=args.passphrase or None)
    print("[+] RSA key pair generated and saved to ./keys/")


def cmd_encrypt(args):
    km = KeyManager(KEY_DIR)
    if not km.has_keys():
        print("[!] No keys found. Run: python cli.py keygen"); sys.exit(1)
    pub = km.load_public_key()
    plaintext = args.message.encode()
    ct = encrypt(plaintext, pub)
    print(f"Ciphertext (hex):\n{ct.hex()}")


def cmd_decrypt(args):
    km = KeyManager(KEY_DIR)
    if not km.has_keys():
        print("[!] No keys found. Run: python cli.py keygen"); sys.exit(1)
    priv = km.load_private_key(passphrase=args.passphrase or None)
    ct = bytes.fromhex(args.ciphertext)
    plaintext = decrypt(ct, priv)
    print(f"Decrypted message:\n{plaintext.decode()}")


def cmd_rotate(args):
    km = KeyManager(KEY_DIR)
    km.rotate_keys(passphrase=args.passphrase or None)
    print("[+] Keys rotated. Old keys archived in ./keys/archive/")


def cmd_benchmark(args):
    from src.benchmark import run_benchmark, print_benchmark_table
    print("[*] Running benchmark (this may take ~30s)...")
    results = run_benchmark()
    print_benchmark_table(results)


def main():
    parser = argparse.ArgumentParser(
        description="Hybrid RSA-AES Encryption CLI (IEEE ICIDCA-2025)"
    )
    sub = parser.add_subparsers(dest="command")

    p_kg = sub.add_parser("keygen", help="Generate RSA key pair")
    p_kg.add_argument("--passphrase", help="Optional passphrase for private key")

    p_enc = sub.add_parser("encrypt", help="Encrypt a message")
    p_enc.add_argument("message", help="Plaintext message to encrypt")

    p_dec = sub.add_parser("decrypt", help="Decrypt a hex ciphertext")
    p_dec.add_argument("ciphertext", help="Hex-encoded ciphertext")
    p_dec.add_argument("--passphrase", help="Private key passphrase (if set)")

    p_rot = sub.add_parser("rotate", help="Rotate RSA keys")
    p_rot.add_argument("--passphrase", help="Passphrase for new private key")

    sub.add_parser("benchmark", help="Run performance benchmark")

    args = parser.parse_args()
    dispatch = {
        "keygen": cmd_keygen, "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt, "rotate": cmd_rotate,
        "benchmark": cmd_benchmark,
    }
    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
