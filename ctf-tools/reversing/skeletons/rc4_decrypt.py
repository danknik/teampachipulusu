#!/usr/bin/env python3
"""
RC4 Decrypt
=============
RC4 (ARC4) stream cipher implementation for CTF decryption.

Usage:
    python3 rc4_decrypt.py <encrypted_file> <key_hex_or_string>
    python3 rc4_decrypt.py data.enc "secretkey"
    python3 rc4_decrypt.py data.enc 4141424243
"""
import sys

def rc4_ksa(key):
    """Key Scheduling Algorithm (KSA)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, n):
    """Pseudo-Random Generation Algorithm (PRGA)."""
    i = j = 0
    keystream = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)

def rc4_crypt(data, key):
    """RC4 encrypt/decrypt (symmetric — same operation)."""
    if isinstance(key, str):
        key = key.encode()
    S = rc4_ksa(key)
    keystream = rc4_prga(S, len(data))
    return bytes([d ^ k for d, k in zip(data, keystream)])

def rc4_drop(data, key, drop=0):
    """RC4 with key drop (skip first N keystream bytes)."""
    if isinstance(key, str):
        key = key.encode()
    S = rc4_ksa(key)
    # Drop first N bytes
    rc4_prga(S, drop)
    # Generate keystream for actual data
    keystream = rc4_prga(S, len(data))
    return bytes([d ^ k for d, k in zip(data, keystream)])

# ─── Modified RC4 variants (common in CTF) ────────────────
def rc4_modified_swap(data, key):
    """RC4 variant where KSA uses different swap logic."""
    if isinstance(key, str):
        key = key.encode()
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Modified PRGA (XOR with index too)
    i = j = 0
    result = []
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k ^ (idx & 0xff))  # Extra XOR with index
    return bytes(result)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <file> <key>')
        print(f'  key can be: "string" or hex bytes (e.g., 41424344)')
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    key_str = sys.argv[2]
    # Detect hex vs string key
    try:
        if all(c in '0123456789abcdefABCDEF' for c in key_str) and len(key_str) % 2 == 0:
            key = bytes.fromhex(key_str)
            print(f'[*] Key (hex): {key.hex()}')
        else:
            key = key_str.encode()
            print(f'[*] Key (str): {key_str}')
    except:
        key = key_str.encode()

    result = rc4_crypt(data, key)
    print(f'[+] Decrypted ({len(result)} bytes):')
    print(result.decode(errors='replace'))

    outfile = sys.argv[1] + '.dec'
    with open(outfile, 'wb') as f:
        f.write(result)
    print(f'[*] Saved to: {outfile}')
