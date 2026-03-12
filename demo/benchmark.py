"""
benchmark.py
============
Reproduces performance results from Table II of the paper:
  "Strengthening RSA Encryption via Hybrid Cryptosystem and Key Management"

Measures encryption/decryption time across message sizes for:
  - Traditional RSA-only
  - Proposed Hybrid RSA-AES

Saves results to results/ directory as CSV + PNG plots.
"""

import time
import os
import csv
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.hybrid_crypto import generate_rsa_keypair, encrypt, decrypt
from src.traditional_rsa import encrypt_rsa_only, decrypt_rsa_only

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False
    print("[Warning] matplotlib not found — skipping plots.")


# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────

MESSAGE_SIZES = [128, 256, 512, 1024, 2048, 4096, 5120]  # bytes
RUNS_PER_SIZE = 5   # average over N runs for stability
RESULTS_DIR   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")


# ──────────────────────────────────────────────
#  Timing Helper
# ──────────────────────────────────────────────

def measure_ms(fn, *args) -> float:
    """Run fn(*args) RUNS_PER_SIZE times and return average ms."""
    times = []
    for _ in range(RUNS_PER_SIZE):
        t0 = time.perf_counter()
        result = fn(*args)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    return sum(times) / len(times), result


# ──────────────────────────────────────────────
#  Main Benchmark
# ──────────────────────────────────────────────

def run_benchmark():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 60)
    print("  Hybrid RSA-AES vs Traditional RSA — Benchmark")
    print("  Reproducing Table II from ICIDCA-2025 paper")
    print("=" * 60)

    print("\n[1/2] Generating 2048-bit RSA key pair...")
    private_key, public_key = generate_rsa_keypair(2048)
    print("      Done.\n")

    rows = []  # for CSV

    hybrid_enc_times = []
    hybrid_dec_times = []
    rsa_enc_times    = []
    rsa_dec_times    = []
    hybrid_sizes     = []
    rsa_sizes        = []

    print(f"{'Size (B)':>10}  {'Hybrid Enc':>12}  {'Hybrid Dec':>12}  {'RSA Enc':>10}  {'RSA Dec':>10}  {'Speedup':>8}")
    print("-" * 72)

    for size in MESSAGE_SIZES:
        plaintext = os.urandom(size)

        # Hybrid
        h_enc_ms, ciphertext_h = measure_ms(encrypt, plaintext, public_key)
        h_dec_ms, _            = measure_ms(decrypt, ciphertext_h, private_key)

        # Traditional RSA
        r_enc_ms, ciphertext_r = measure_ms(encrypt_rsa_only, plaintext, public_key)
        r_dec_ms, _            = measure_ms(decrypt_rsa_only, ciphertext_r, private_key)

        speedup = r_enc_ms / h_enc_ms

        hybrid_enc_times.append(h_enc_ms)
        hybrid_dec_times.append(h_dec_ms)
        rsa_enc_times.append(r_enc_ms)
        rsa_dec_times.append(r_dec_ms)
        hybrid_sizes.append(len(ciphertext_h))
        rsa_sizes.append(len(ciphertext_r))

        print(f"{size:>10}  {h_enc_ms:>10.2f}ms  {h_dec_ms:>10.2f}ms  "
              f"{r_enc_ms:>8.2f}ms  {r_dec_ms:>8.2f}ms  {speedup:>6.1f}x")

        rows.append({
            "size_bytes":    size,
            "hybrid_enc_ms": round(h_enc_ms, 3),
            "hybrid_dec_ms": round(h_dec_ms, 3),
            "rsa_enc_ms":    round(r_enc_ms, 3),
            "rsa_dec_ms":    round(r_dec_ms, 3),
            "speedup_x":     round(speedup, 2),
        })

    # ── Save CSV ──────────────────────────────
    csv_path = os.path.join(RESULTS_DIR, "benchmark_results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[CSV] Results saved → {csv_path}")

    # ── Paper summary (Table II) ───────────────
    avg_h_enc = sum(hybrid_enc_times) / len(hybrid_enc_times)
    avg_h_dec = sum(hybrid_dec_times) / len(hybrid_dec_times)
    avg_r_enc = sum(rsa_enc_times)    / len(rsa_enc_times)
    avg_r_dec = sum(rsa_dec_times)    / len(rsa_dec_times)

    print("\n" + "=" * 45)
    print("  TABLE II — Performance Comparison (paper)")
    print("=" * 45)
    print(f"  {'Metric':<22} {'RSA Only':>9}  {'Hybrid':>9}")
    print(f"  {'-'*42}")
    print(f"  {'Enc. Time (ms)':<22} {avg_r_enc:>9.1f}  {avg_h_enc:>9.1f}")
    print(f"  {'Dec. Time (ms)':<22} {avg_r_dec:>9.1f}  {avg_h_dec:>9.1f}")
    print(f"  {'Security':<22} {'Low':>9}  {'High':>9}")
    print("=" * 45)

    # ── Plots ──────────────────────────────────
    if HAS_PLOT:
        _plot_results(
            MESSAGE_SIZES,
            hybrid_enc_times, hybrid_dec_times,
            rsa_enc_times, rsa_dec_times,
            hybrid_sizes
        )
    else:
        print("\n[Plot] Install matplotlib to generate graphs: pip install matplotlib")

    return rows


def _plot_results(sizes, h_enc, h_dec, r_enc, r_dec, h_out_sizes):
    """Generate Figure 2 from the paper — time vs size & output size vs length."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Hybrid RSA-AES Performance (Replicating Figure 2 — ICIDCA-2025)",
                 fontsize=13, fontweight="bold")

    # Left: Encryption & Decryption Time vs Message Size
    ax1.plot(sizes, h_enc, "b-o", label="Hybrid — Encryption", linewidth=2)
    ax1.plot(sizes, h_dec, "b--s", label="Hybrid — Decryption", linewidth=2)
    ax1.plot(sizes, r_enc, "r-o", label="RSA Only — Encryption", linewidth=2)
    ax1.plot(sizes, r_dec, "r--s", label="RSA Only — Decryption", linewidth=2)
    ax1.set_xlabel("Message Size (bytes)", fontsize=11)
    ax1.set_ylabel("Time (ms)", fontsize=11)
    ax1.set_title("Encryption & Decryption Time vs Message Size", fontsize=11)
    ax1.legend(fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Right: Encrypted Output Size vs Message Length
    ax2.plot(sizes, h_out_sizes, "g-o", label="Hybrid Output Size", linewidth=2)
    ax2.set_xlabel("Message Length (bytes)", fontsize=11)
    ax2.set_ylabel("Encrypted Output Size (bytes)", fontsize=11)
    ax2.set_title("Encrypted Output Size vs Message Length", fontsize=11)
    ax2.legend(fontsize=9)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plot_path = os.path.join(RESULTS_DIR, "benchmark_plot.png")
    plt.savefig(plot_path, dpi=150, bbox_inches="tight")
    print(f"[Plot] Graph saved → {plot_path}")
    plt.close()


if __name__ == "__main__":
    run_benchmark()
