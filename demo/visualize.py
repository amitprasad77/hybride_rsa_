"""
visualize.py
============
Generate performance graphs reproducing Figure 2 from the paper:
  Left  — Encryption & Decryption Time vs Message Size
  Right — Encrypted Output Size vs Message Length
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.benchmark import run_benchmark

def plot_results(output_path: str = "docs/performance_graphs.png") -> None:
    sizes   = [128, 256, 512, 1024, 2048, 4096, 5120, 10240]
    results = run_benchmark(message_sizes=sizes, runs=3)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle(
        "Hybrid RSA-AES Performance (Reproducing Fig. 2 — IEEE ICIDCA-2025)",
        fontsize=12, fontweight="bold"
    )

    # ── Left: Time vs Size ──────────────────────────────────────────────────
    ax1.plot(sizes, results["hybrid_enc_ms"],   "b-o", label="Hybrid Enc")
    ax1.plot(sizes, results["hybrid_dec_ms"],   "b--s", label="Hybrid Dec")
    ax1.plot(sizes, results["rsa_only_enc_ms"], "r-o", label="RSA-Only Enc")
    ax1.plot(sizes, results["rsa_only_dec_ms"], "r--s", label="RSA-Only Dec")
    ax1.set_xlabel("Message Size (bytes)")
    ax1.set_ylabel("Time (ms)")
    ax1.set_title("Encryption & Decryption Time vs Message Size")
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    # ── Right: Output size vs Length ────────────────────────────────────────
    ax2.plot(sizes, results["hybrid_ct_sizes"],   "b-o", label="Hybrid Ciphertext")
    ax2.plot(sizes, results["rsa_only_ct_sizes"], "r-o", label="RSA-Only Ciphertext")
    ax2.plot(sizes, sizes, "g--", label="Original size", alpha=0.5)
    ax2.set_xlabel("Message Length (bytes)")
    ax2.set_ylabel("Encrypted Output Size (bytes)")
    ax2.set_title("Encrypted Output Size vs Message Length")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"[+] Graph saved to {output_path}")
    plt.close()


if __name__ == "__main__":
    plot_results()
