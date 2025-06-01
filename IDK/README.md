# GreyCTF Challenge Writeup: IDK
By : zor_4n6

## Challenge Overview

**Challenge Name:** Idk 
**Category:** Cryptography

**Author:** Iscara

**Difficulty:** Medium  

**Description:**  
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
  μ_j^(1) ≡ -μ_j^(2) (mod p) and μ_j^(1) ≡ μ_j^(2) (mod q)


  This implies:
- `μ_j^(1) + μ_j^(2)` is divisible by `p`.
- `μ_j^(1) - μ_j^(2)` is divisible by `q`.

By computing the GCD of `N` with these sums or differences, we can recover the prime factors `p` and `q`.

---

## Exploitation Steps

1. **Extract Parameters:**
 - Parse `N`, `e`, and `c` from `message.txt`.
 - Calculate parameters `m1` and `m2` (number of proof elements) using the same logic as `prover.py` and `verifier.py`.

2. **Process Dump Files:**
 - Read `μ_j` values from `dump1.txt` and `dump2.txt`.

3. **Factor `N`:**
 - For each index `j`, if both `μ_j` values are non-zero and not identical:
   1. Compute 
      ```
      diff = |μ_j^(1) - μ_j^(2)|
      g1 = GCD(diff, N)
      ```
      If `g1` is non-trivial (neither 1 nor `N`), then `g1` is a factor.
   2. Otherwise, compute 
      ```
      sum_ = μ_j^(1) + μ_j^(2)
      g2 = GCD(sum_, N)
      ```
      If `g2` is non-trivial, then `g2` is a factor.

4. **Decrypt the Flag:**
 - Use the recovered primes `p` and `q` to compute φ(`N`) = (p − 1)(q − 1).
 - Compute the private exponent `d` = `e⁻¹ mod φ(N)`.
 - Decrypt the ciphertext `c`:
   ```
   flag = c^d mod N
   ```

---

## Solution Code
```python
import math

def extended_gcd(a, b):
  if a == 0:
      return b, 0, 1
  g, y, x = extended_gcd(b % a, a)
  return g, x - (b // a) * y, y

def inverse(a, n):
  g, x, _ = extended_gcd(a, n)
  if g != 1:
      return None
  return x % n

def long_to_bytes(x):
  return x.to_bytes((x.bit_length() + 7) // 8, "big")

# Read parameters from message.txt
with open("message.txt") as f:
  data = f.read().splitlines()
  N = int(data[0].split(" = ")[1])
  e = int(data[1].split(" = ")[1])
  c = int(data[2].split(" = ")[1])

# Calculate m1 and m2 as in prover.py
kappa = 128
alpha = 65537
m1 = math.ceil(kappa / math.log(alpha, 2))
m2 = math.ceil(kappa * 32 * 0.69314718056)

def parse_dump(filename):
  with open(filename) as f:
      lines = [line.strip() for line in f.readlines()]
  # μ_j values start at line index (1 + m1), each in hex
  mus = [int(lines[i], 16) for i in range(1 + m1, 1 + m1 + m2)]
  return mus

mus1 = parse_dump("dump1.txt")
mus2 = parse_dump("dump2.txt")

p = q = None

for j in range(m2):
  mu1 = mus1[j]
  mu2 = mus2[j]
  if mu1 == 0 or mu2 == 0 or mu1 == mu2:
      continue

  # Try GCD of difference
  diff = abs(mu1 - mu2)
  g1 = math.gcd(diff, N)
  if g1 not in (1, N):
      p = g1
      q = N // g1
      break

  # Try GCD of sum
  s = mu1 + mu2
  g2 = math.gcd(s, N)
  if g2 not in (1, N):
      p = g2
      q = N // g2
      break

# Compute φ(N) and private exponent d
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# Decrypt the flag
flag = pow(c, d, N)
print(long_to_bytes(flag).decode())

  ```

## Script Output:

```bash
$ python solve.py
grey{how_i_swear_you_shouldve_had_0_knowledge}

```

## Flag :
```txt
grey{how_i_swear_you_shouldve_had_0_knowledge}
```
