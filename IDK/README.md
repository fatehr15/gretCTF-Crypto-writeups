# GreyCTF Challenge Writeup: IDK

## Challenge Overview
The challenge involves breaking an RSA cryptosystem by exploiting a flaw in a zero-knowledge proof implementation. The proof is designed to verify knowledge of the prime factors of the modulus `N` without revealing them. However, two execution traces (`dump1.txt` and `dump2.txt`) leak enough information to factor `N` and decrypt the flag.

**Key Files Provided:**
- `message.txt`: Contains RSA modulus `N`, public exponent `e = 65537`, and ciphertext `c`.
- `prover.py`: Script that generates a proof of factorization using secret primes `p` and `q`.
- `verifier.py`: Script that validates the proof.
- `dump1.txt` and `dump2.txt`: Outputs from two separate runs of `prover.py`.

---

## Vulnerability Analysis
The prover's algorithm has a critical flaw in how it generates square roots for quadratic residues. For each residue `θ_j`, the prover computes a square root `μ_j` modulo `N` using the Chinese Remainder Theorem (CRT). With a 50% probability, it flips the sign of the root modulo `p` (but not modulo `q`).

When the prover runs twice for the same `θ_j`, the two resulting `μ_j` values may differ if one run flipped the sign and the other did not. Specifically:

- If the sign flip occurred in only one run:
