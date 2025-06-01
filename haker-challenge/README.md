Shaker Challenge Writeup - greyCTF
Challenge Overview
Challenge Name: Shaker
Category: Cryptography/Reverse Engineering
Difficulty: Medium
Description:
The challenge involves a "Shaker" class that obscures a flag through permutations and XOR operations. The service allows users to interact with the shaker by shaking it (applying transformations) or seeing inside (revealing the current state). The goal is to recover the original flag from these obfuscated states.

Key Challenge Files
server.py: Implements the Shaker class and service logic

flag.txt: Contains the flag to be recovered (not provided)

Solution Approach
Vulnerability Analysis
The Shaker class has two main operations:

XOR Operation: XORs the state with a fixed 64-byte mask x

Permutation: Applies a random permutation to the bytes

The critical vulnerabilities are:

The XOR mask x remains constant across operations

The "open" operation reveals the current state XORed with x

Multiple "open" operations provide different permutations of flag XOR x

Exploitation Strategy
Collect Observations:

Perform multiple "open" operations to collect different permutations of flag XOR x

Recover XOR Mask:

Use the known flag prefix "grey{" to determine the first 5 bytes of x

For other positions, use frequency analysis to find XOR differences between positions

Reconstruct Flag:

Apply the recovered XOR mask to the initial observation to obtain the flag

Exploit Code
python
import hashlib
import socket
import sys
from collections import defaultdict

# Constants
MD5_HASH = "4839d730994228d53f64f0dca6488f8d"
KNOWN_PREFIX = b'grey{'
MAX_OPENS = 100
TIMEOUT = 5

def recv_until_prompt(sock):
    """Receive data until the prompt '>' appears"""
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

            # Get initial prompt
            recv_until_prompt(s)

            def send_command(cmd):
                """Send command and receive response until next prompt"""
                s.sendall(cmd.encode() + b'\n')
                response = recv_until_prompt(s)
                return response

            # Get initial state (T0)
            print("[*] Getting initial state T0...")
            response = send_command('2')
            
            # Parse response
            if 'Result:' in response:
                hex_str = response.split('Result: ')[1].split('\n')[0].strip()
                try:
                    T0 = bytes.fromhex(hex_str)
                    print(f"[+] T0 collected: {T0.hex()}")
                except ValueError:
                    print("[-] Invalid hex string in response")
                    sys.exit(1)
            else:
                print("[-] Unexpected response format:")
                print(response)
                sys.exit(1)

            # Collect multiple opens
            print(f"[*] Collecting {MAX_OPENS} opens...")
            T_list = []
            for i in range(MAX_OPENS):
                response = send_command('2')
                if 'Result:' in response:
                    hex_str = response.split('Result: ')[1].split('\n')[0].strip()
                    try:
                        T_list.append(bytes.fromhex(hex_str))
                        if (i+1) % 10 == 0:
                            print(f"[+] Collected {i+1} opens")
                    except ValueError:
                        print(f"[-] Invalid hex at open {i}")
                        continue
                else:
                    print(f"[-] Bad response at open {i}")
                    continue

            # Build position sets
            print("[*] Building position sets...")
            S = [set() for _ in range(64)]
            for t in T_list:
                for j in range(64):
                    S[j].add(t[j])

            # Recover XOR mask
            print("[*] Recovering XOR mask...")
            x = [0] * 64
            for j in range(len(KNOWN_PREFIX)):
                x[j] = T0[j] ^ KNOWN_PREFIX[j]

            # Recover remaining bytes using frequency analysis
            for j in range(5, 64):
                count = defaultdict(int)
                for a in S[0]:
                    for b in S[j]:
                        count[a ^ b] += 1
                best_d = max(count.items(), key=lambda x: x[1])[0]
                x[j] = x[0] ^ best_d

            # Reconstruct flag
            flag = bytes(T0[i] ^ x[i] for i in range(64))
            
            # Validate flag
            print("[*] Verifying flag...")
            if hashlib.md5(flag).hexdigest() == MD5_HASH:
                print(f"[+] Success! Flag: {flag.decode()}")
            else:
                print("[-] Failed to recover valid flag")
                print(f"Expected MD5: {MD5_HASH}")
                print(f"Actual MD5: {hashlib.md5(flag).hexdigest()}")

    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
How to Run the Exploit
Install Dependencies:

bash
# No additional dependencies required beyond Python standard libraries
Run the Exploit:

bash
python solve.py challs.nusgreyhats.org 33302
Expected Output:

[*] Connecting to challs.nusgreyhats.org:33302...
[+] Connection established
[*] Getting initial state T0...
[+] T0 collected: 1a3f... (hex representation)
[*] Collecting 100 opens...
[+] Collected 10 opens
[+] Collected 20 opens
... (progress updates)
[*] Building position sets...
[*] Recovering XOR mask...
[*] Verifying flag...
[+] Success! Flag: grey{...}
Flag
The recovered flag is:

grey{...}
Lessons Learned
Constant XOR Keys: When XOR keys remain static across operations, they can be recovered through statistical analysis

Permutation Limitations: Random permutations alone don't provide sufficient security when combined with static keys

Known Plaintext Attacks: Knowledge of even small plaintext segments (like flag prefixes) can be leveraged to break cryptographic systems

Side-Channel Leaks: Multiple observations of transformed data can reveal relationships that compromise the system

Mitigation Strategies
Dynamic Keys: Generate new XOR keys for each operation

Stronger Obfuscation: Combine multiple cryptographic primitives (e.g., AES encryption)

Rate Limiting: Restrict the number of "open" operations allowed

State Reset: Change the XOR mask after each "open" operation
