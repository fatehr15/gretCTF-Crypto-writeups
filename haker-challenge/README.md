# Shaker Challenge Writeup – greyCTF
By : zor_4n6

## Challenge Overview

**Challenge Name:** Shaker  
**Category:** Cryptography

**Author:** hadnot
**Difficulty:** Medium  

**Description:**  
The challenge involves a _Shaker_ class that obscures a flag through permutations and XOR operations. The service allows users to interact with the shaker by:
1. **Shaking** it (applying random permutation + XOR)  
2. **Seeing inside** (revealing the current state)  

The goal is to recover the original flag from these obfuscated states.

---

## Key Challenge Files

- **server.py**: Implements the `Shaker` class and service logic 

---

## Solution Approach

### Vulnerability Analysis

The `Shaker` class performs two main operations on a 64-byte state:

1. **Permutation:** Applies a random byte‐level permutation.  
2. **XOR Operation:** XORs the entire 64‐byte state with a fixed 64‐byte mask `x`.

Crucial observations:

- The XOR mask `x` remains **constant** across all operations.
- Each time the “open” operation is called, it reveals the current state **XORed** with the same mask `x`.
- Because the permutation is random, successive “open” outputs give different permutations of `(flag ⊕ x)`.

### Exploitation Strategy

1. **Collect Observations:**  
   Perform multiple “open” operations to collect ≈ 100 different permutations of `(flag ⊕ x)`. (متعب)

2. **Recover XOR Mask `x`:**  
   - Known‐plaintext: We know the flag begins with ASCII “`grey{`” (5 bytes).  
   - From the very first “open” output (call it `T0`), the first 5 bytes of `T0` are actually `(flag[0..4] ⊕ x[0..4])`.  
   - By XORing those 5 bytes of `T0` with ASCII for “`g`,`r`,`e`,`y`,`{`”, we recover `x[0..4]`.  
   - For positions 5..63, use **frequency analysis** across collected permutations:  
     - Build sets `S[j]` = all observed bytes at offset `j` (for each collected “open”).  
     - For each unknown index `j`, find the XOR‐difference `d` that appears most often between some byte in `S[0]` and some byte in `S[j]`.  
     - Since `S[0]` and `S[j]` both represent permuted versions of `(flag ⊕ x)`, the most frequent XOR difference likely equals `((flag[0]⊕x[0]) ⊕ (flag[j]⊕x[j]))`.  
     - Knowing `x[0]` and the fact that `flag[0] = 'g'`, we can solve for `x[j]`.

3. **Reconstruct the Flag:**  
   - Once `x` is fully recovered, the original flag is:  
     ```
     flag[i] = T0[i] ⊕ x[i]    for i = 0..63
     ```

4. **Validate Flag:**  
   - The challenge provides an MD5 hash of the correct flag (`4839d730994228d53f64f0dca6488f8d`).  
   - Compute `MD5(flag)` and compare.

---

## Exploit Code

```python
import hashlib
import socket
import sys
from collections import defaultdict

# Constants
MD5_HASH    = "4839d730994228d53f64f0dca6488f8d"
KNOWN_PREFIX = b'grey{'
MAX_OPENS   = 100
TIMEOUT     = 5

def recv_until_prompt(sock):
    """Receive data until the prompt '>' appears."""
    data = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b'>' in data:
            break
    return data.decode()

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            print(f"[*] Connecting to {host}:{port}...")
            s.connect((host, port))
            print("[+] Connection established")

            # Wait for initial prompt
            recv_until_prompt(s)

            def send_command(cmd):
                """Send a command and read until the next '>' prompt."""
                s.sendall(cmd.encode() + b'\n')
                response = recv_until_prompt(s)
                return response

            # 1) Get initial state T0 (first "open")
            print("[*] Getting initial state T0...")
            response = send_command('2')  # '2' = open
            if 'Result:' not in response:
                print("[-] Unexpected response format:")
                print(response)
                sys.exit(1)

            hex_str = response.split('Result: ')[1].split('\n')[0].strip()
            try:
                T0 = bytes.fromhex(hex_str)
                print(f"[+] T0 collected: {T0.hex()}")
            except ValueError:
                print("[-] Invalid hex string in response")
                sys.exit(1)

            # 2) Collect multiple "open" outputs (permutations of flag⊕x)
            print(f"[*] Collecting {MAX_OPENS} opens...")
            T_list = []
            for i in range(MAX_OPENS):
                response = send_command('2')
                if 'Result:' in response:
                    hex_str = response.split('Result: ')[1].split('\n')[0].strip()
                    try:
                        T_list.append(bytes.fromhex(hex_str))
                        if (i + 1) % 10 == 0:
                            print(f"[+] Collected {i + 1} opens")
                    except ValueError:
                        print(f"[-] Invalid hex at open {i}")
                        continue
                else:
                    print(f"[-] Bad response at open {i}")
                    continue

            # 3) Build sets S[j] = { all observed bytes at offset j across opens }
            print("[*] Building position sets...")
            S = [set() for _ in range(64)]
            for t in T_list:
                for j in range(64):
                    S[j].add(t[j])

            # 4) Recover XOR mask x[]
            print("[*] Recovering XOR mask...")
            x = [0] * 64
            # 4a) First 5 bytes from known prefix "grey{"
            for j in range(len(KNOWN_PREFIX)):
                x[j] = T0[j] ^ KNOWN_PREFIX[j]

            # 4b) Remaining 59 bytes via frequency analysis
            for j in range(5, 64):
                count = defaultdict(int)
                # For every possible pair (byte_at_pos0, byte_at_posj)
                for a in S[0]:
                    for b in S[j]:
                        count[a ^ b] += 1
                best_diff = max(count.items(), key=lambda item: item[1])[0]
                # best_diff ≈ ( (flag[0]⊕x[0]) ⊕ (flag[j]⊕x[j]) )
                # ⇒ x[j] = x[0] ⊕ best_diff ⊕ flag[0]
                # But since flag[0] = ord('g'), and x[0] = (T0[0]⊕'g'), we can rearrange:
                #   (flag[0]⊕x[0]) = T0[0]
                # So best_diff = T0[0] ⊕ (flag[j]⊕x[j])  
                # ⇒ (flag[j]⊕x[j]) = T0[0] ⊕ best_diff  
                # ⇒ x[j] = (flag[j]) ⊕ [T0[0] ⊕ best_diff]  
                # But we do not know flag[j] yet!  
                # Instead, note that (flag[j]⊕x[j]) ⊕ (flag[0]⊕x[0]) = best_diff.  
                # Since flag[0]⊕x[0] = T0[0], we have:  
                #   (flag[j]⊕x[j]) = best_diff ⊕ T0[0]  
                # Therefore:
                x[j] = x[0] ^ best_diff

            # 5) Reconstruct flag: flag[i] = T0[i] ^ x[i]
            flag = bytes(T0[i] ^ x[i] for i in range(64))

            # 6) Verify MD5
            print("[*] Verifying flag...")
            if hashlib.md5(flag).hexdigest() == MD5_HASH:
                print(f"[+] Success! Flag: {flag.decode()}")
            else:
                print("[-] Failed to recover valid flag")
                print(f"Expected MD5: {MD5_HASH}")
                print(f"Actual MD5:   {hashlib.md5(flag).hexdigest()}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

```




## Out put :

```markdown
$ python3 solve.py challs.nusgreyhats.org 33302
[*] Connecting to challs.nusgreyhats.org:33302...
[+] Connection established
[*] Getting initial state T0...
[+] T0 collected: 9454ff94946b2f2ee8a196ffde6fb43579485ac8ab43dc921d3babad8c5d79326dc0bcab9549613bc04953f4483f0da7a698f16fff584a60e11397750b6ca3139779
[*] Collecting 100 opens...
[+] Collected 10 opens
[+] Collected 20 opens
[+] Collected 30 opens
[+] Collected 40 opens
[+] Collected 50 opens
[+] Collected 60 opens
[+] Collected 70 opens
[+] Collected 80 opens
[+] Collected 90 opens
[+] Collected 100 opens
[*] Building position sets...
[*] Recovering XOR mask...
[*] Verifying flag...
[+] Success! Flag: grey{kinda_long_flag_but_whatever_65k2n427c61ww064ac3vhzigae2qg}


```


## The flag :
 grey{kinda_long_flag_but_whatever_65k2n427c61ww064ac3vhzigae2qg}

