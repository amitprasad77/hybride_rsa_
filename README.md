Hybrid RSA-AES Cryptographic Framework

Implementation of the IEEE ICIDCA-2025 paper:
"Strengthening RSA Encryption via Hybrid Cryptosystem and Key Management"
Amit Prasad, Chandramadi, Dr Vinoth Kumar M, Ankit Raj Singh
RV Institute of Technology and Management, Bangalore, India


What This Project Achieves
This project implements and demonstrates five core objectives from the paper:
#ObjectivePaper Section1Hybrid RSA-AES encryption & decryption (Algorithm 1)§IV, §V2Non-determinism & forward secrecy via ephemeral session keys§VII-A, §VII-D3Secure key lifecycle management (generation, storage, rotation)§V-D, §VI-D4Large payload encryption with constant RSA overhead§IX-C5Performance benchmark reproducing Table II & Figure 2 (~5× speedup)§IX, §X

System Architecture
┌───────────────────────────────────────────────────────────┐
│                  ENCRYPTION SIDE                          │
│                                                           │
│  Plaintext ──► AES-128-CBC (PKCS7) ──► AES Ciphertext    │
│                     ▲                                     │
│              128-bit Session Key (CSPRNG)                 │
│                     │                                     │
│              RSA-2048-OAEP encrypt ──► Encrypted Key      │
│                     ▲                                     │
│               RSA Public Key                              │
│                                                           │
│  Package = [RSA-enc key] ‖ [IV] ‖ [AES ciphertext]       │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│                  DECRYPTION SIDE                          │
│                                                           │
│  Package ──► RSA-OAEP decrypt ──► AES Session Key         │
│                                        │                  │
│  AES Ciphertext ──► AES-CBC decrypt ──► Plaintext         │
│                          ▲                                │
│                   IV + Session Key                        │
│                                                           │
│  Session key securely erased from memory after use        │
└───────────────────────────────────────────────────────────┘

Security Properties
PropertyMechanismPaper ReferenceCCA2 ResistanceRSA-OAEP padding (Bellare & Rogaway)§VII-ATiming Attack DefenseRSA blinding via Web Crypto API / cryptography lib§VII-BKey Exposure PreventionCSPRNG session keys + secure memory erase§VII-CForward SecrecyEphemeral AES keys, never tied to RSA private key§VII-DNon-DeterminismOAEP randomness — same plaintext → different ciphertext§VII-A

Performance (Table II Reproduction)
MetricRSA OnlyHybridEncryption Time~115 ms~20 msDecryption Time~125 ms~23 msSecurity LevelLowHigh

The hybrid model achieves ~5× speedup because RSA only encrypts the 16-byte
session key, while AES handles all bulk data using hardware-accelerated operations.


Project Structure
hybrid-rsa-aes/
├── ui/
│   └── index.html         # Interactive web demo (open in browser)
├── src/
│   ├── hybrid_crypto.py   # Core encrypt/decrypt (Algorithm 1)
│   ├── key_manager.py     # Key lifecycle: generate, store, rotate
│   └── benchmark.py       # Performance comparison: Hybrid vs RSA-Only
├── tests/
│   └── test_hybrid_crypto.py  # Unit tests (correctness, tampering, forward secrecy)
├── demo/
│   ├── demo.py            # Full walkthrough of all 5 objectives
│   └── visualize.py       # Reproduce Figure 2 (performance graphs)
├── docs/
├── cli.py                 # Command-line interface
├── requirements.txt
└── README.md

UI (Web Demo)
Open ui/index.html directly in your browser — no server, no install needed.
bash# Mac
open ui/index.html

# Or right-click ui/index.html in VS Code → Open with Live Server
Features:

🔑 Generate / Rotate RSA-2048 keys (live PEM preview)
🔒 Encrypt any message → live hex ciphertext + timing stats
🔓 Decrypt ciphertext back to plaintext + integrity check
📊 Benchmark chart: Hybrid vs RSA-Only (reproduces Table II)
✅ Security properties panel (CCA2, Forward Secrecy, Non-Determinism, Timing Safe)


Quick Start
Prerequisites

Mac users: use python3 instead of python

1. Set up virtual environment
bash# Mac / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
2. Install dependencies
bashpip install -r requirements.txt
3. Run the full demo (all 5 objectives)
bashpython3 demo/demo.py
4. Run unit tests
bashpytest tests/ -v
5. Generate performance graphs (Figure 2)
bashpython3 demo/visualize.py
# Output: docs/performance_graphs.png
6. Use the CLI
bash# Generate RSA keys
python3 cli.py keygen

# Encrypt a message
python3 cli.py encrypt "My secret message"

# Decrypt (paste hex output from encrypt)
python3 cli.py decrypt <hex_ciphertext>

# Rotate keys
python3 cli.py rotate

# Run benchmark
python3 cli.py benchmark

Algorithm (from paper)
ENCRYPTION:
  KAES ← CSPRNG(128 bits)          # Fresh session key
  IV   ← CSPRNG(128 bits)          # Random IV
  CAES ← AES-CBC(KAES, IV, M)      # Encrypt message
  CRSA ← RSA-OAEP(Kpub, KAES)      # Encrypt session key
  C    ← CRSA ‖ IV ‖ CAES           # Package

DECRYPTION:
  Parse C → (CRSA, IV, CAES)
  KAES ← RSA-OAEP-Dec(Kpriv, CRSA) # Recover session key
  M    ← AES-CBC-Dec(KAES, IV, CAES)# Recover plaintext
  Erase KAES from memory            # Secure disposal

Limitations (from paper §XI)

Vulnerable to quantum attacks (Shor's algorithm) — future work: post-quantum RSA alternatives
Slightly higher overhead than pure symmetric systems
Depends on correct OAEP and secure key disposal implementation

