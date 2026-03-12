"""
benchmark.py — Performance benchmarking (Section IX & X).
Reproduces paper Table II: Hybrid vs RSA-Only comparison.
"""

import time
import os
import statistics
from typing import List, Dict

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from .hybrid_crypto import encrypt, decrypt, generate_rsa_keypair, _oaep_padding

CHUNK_SIZE = 190  # Safe max for 2048-bit RSA-OAEP


def _rsa_only_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """Traditional RSA-only (chunked) — paper baseline."""
    pub = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    chunks = [plaintext[i:i+CHUNK_SIZE] for i in range(0, len(plaintext), CHUNK_SIZE)]
    return b"".join(pub.encrypt(c, _oaep_padding()) for c in chunks)


def _rsa_only_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    priv   = serialization.load_pem_private_key(ciphertext[:0] or private_key_pem,
                                                 password=None, backend=default_backend())
    priv   = serialization.load_pem_private_key(private_key_pem, password=None,
                                                 backend=default_backend())
    chunks = [ciphertext[i:i+256] for i in range(0, len(ciphertext), 256)]
    return b"".join(priv.decrypt(c, _oaep_padding()) for c in chunks)


def run_benchmark(message_sizes: List[int] = None, runs: int = 3) -> Dict:
    if message_sizes is None:
        message_sizes = [128, 256, 512, 1024, 2048, 4096, 5120, 10240]

    pub_pem, priv_pem = generate_rsa_keypair()

    results = {
        "message_sizes":     message_sizes,
        "hybrid_enc_ms":     [],
        "hybrid_dec_ms":     [],
        "rsa_only_enc_ms":   [],
        "rsa_only_dec_ms":   [],
        "hybrid_ct_sizes":   [],
        "rsa_only_ct_sizes": [],
    }

    for size in message_sizes:
        plaintext = os.urandom(size)

        # Hybrid
        enc_t, dec_t = [], []
        for _ in range(runs):
            t0 = time.perf_counter(); ct = encrypt(plaintext, pub_pem)
            enc_t.append((time.perf_counter()-t0)*1000)
            t0 = time.perf_counter(); decrypt(ct, priv_pem)
            dec_t.append((time.perf_counter()-t0)*1000)
        results["hybrid_enc_ms"].append(round(statistics.median(enc_t), 2))
        results["hybrid_dec_ms"].append(round(statistics.median(dec_t), 2))
        results["hybrid_ct_sizes"].append(len(encrypt(plaintext, pub_pem)))

        # RSA-Only
        enc_t, dec_t = [], []
        for _ in range(runs):
            t0 = time.perf_counter(); ct_r = _rsa_only_encrypt(plaintext, pub_pem)
            enc_t.append((time.perf_counter()-t0)*1000)
            t0 = time.perf_counter(); _rsa_only_decrypt(ct_r, priv_pem)
            dec_t.append((time.perf_counter()-t0)*1000)
        results["rsa_only_enc_ms"].append(round(statistics.median(enc_t), 2))
        results["rsa_only_dec_ms"].append(round(statistics.median(dec_t), 2))
        results["rsa_only_ct_sizes"].append(len(_rsa_only_encrypt(plaintext, pub_pem)))

    return results


def print_benchmark_table(results: Dict) -> None:
    sizes = results["message_sizes"]
    print("\n" + "="*80)
    print("PERFORMANCE BENCHMARK  (reproducing paper Section X — Table II)")
    print("="*80)
    print(f"{'Size (B)':<12} {'Hybrid Enc':<14} {'RSA-Only Enc':<16} "
          f"{'Hybrid Dec':<14} {'RSA-Only Dec'}")
    print(f"{'':12} {'(ms)':<14} {'(ms)':<16} {'(ms)':<14} {'(ms)'}")
    print("-"*80)
    for i, s in enumerate(sizes):
        print(f"{s:<12} "
              f"{results['hybrid_enc_ms'][i]:<14} "
              f"{results['rsa_only_enc_ms'][i]:<16} "
              f"{results['hybrid_dec_ms'][i]:<14} "
              f"{results['rsa_only_dec_ms'][i]}")
    print("="*80)
    avg_speedup = statistics.mean([
        results['rsa_only_enc_ms'][i] / max(results['hybrid_enc_ms'][i], 0.01)
        for i in range(len(sizes))
    ])
    print(f"\nAverage encryption speedup  (Hybrid vs RSA-Only): {avg_speedup:.1f}x")
    print("Paper reports ~5x improvement (Section X)\n")
