#!/usr/bin/env python3
"""
XOR Decrypt — All Variants
=============================
Single-byte, multi-byte, rolling XOR, and brute-force.

Usage:
    python3 xor_decrypt.py <file> [key]
    python3 xor_decrypt.py encrypted.bin 0x42
    python3 xor_decrypt.py encrypted.bin "KEY"
    python3 xor_decrypt.py encrypted.bin         # brute-force single byte
"""
import sys
from itertools import cycle

# ─── SINGLE-BYTE XOR ───────────────────────────────────────
def xor_single(data, key):
    """XOR every byte with a single key byte."""
    return bytes([b ^ key for b in data])

def xor_single_brute(data, known_prefix=b''):
    """Brute-force single-byte XOR key."""
    results = []
    for key in range(256):
        decrypted = xor_single(data, key)
        if known_prefix and decrypted.startswith(known_prefix):
            results.append((key, decrypted))
            print(f'[+] Key=0x{key:02x} ({chr(key) if 0x20 <= key <= 0x7e else "?"}): {decrypted[:80]}')
        elif not known_prefix:
            # Check if output is mostly printable ASCII
            printable = sum(1 for b in decrypted if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d, 0x09))
            ratio = printable / len(decrypted) if decrypted else 0
            if ratio > 0.8:
                results.append((key, decrypted))
    
    if not known_prefix:
        results.sort(key=lambda x: sum(1 for b in x[1] if 0x20 <= b <= 0x7e), reverse=True)
        for key, dec in results[:5]:
            print(f'[+] Key=0x{key:02x}: {dec[:80]}')
    
    return results

# ─── MULTI-BYTE XOR ────────────────────────────────────────
def xor_multi(data, key):
    """XOR with a multi-byte repeating key."""
    if isinstance(key, str):
        key = key.encode()
    return bytes([b ^ k for b, k in zip(data, cycle(key))])

# ─── ROLLING XOR ───────────────────────────────────────────
def xor_rolling(data, initial_key=0):
    """Each byte XOR'd with previous plaintext byte."""
    result = []
    prev = initial_key
    for b in data:
        decrypted = b ^ prev
        result.append(decrypted)
        prev = decrypted  # or prev = b, depending on algorithm
    return bytes(result)

def xor_rolling_cipher(data, initial_key=0):
    """Each byte XOR'd with previous ciphertext byte."""
    result = []
    prev = initial_key
    for b in data:
        decrypted = b ^ prev
        result.append(decrypted)
        prev = b  # use ciphertext for next
    return bytes(result)

# ─── INCREMENTAL XOR ──────────────────────────────────────
def xor_incremental(data, start_key=0, step=1):
    """Key increments each byte: key, key+1, key+2, ..."""
    return bytes([b ^ ((start_key + i * step) & 0xff) for i, b in enumerate(data)])

# ─── XOR WITH INDEX ───────────────────────────────────────
def xor_index(data):
    """XOR each byte with its index: data[i] ^ i."""
    return bytes([b ^ (i & 0xff) for i, b in enumerate(data)])

# ─── KEY LENGTH DETECTION (Kasiski / IC) ──────────────────
def detect_key_length(ciphertext, max_len=32):
    """Estimate repeating XOR key length using Index of Coincidence."""
    best_len = 1
    best_ic = 0

    for kl in range(1, max_len + 1):
        # Split into columns
        columns = [[] for _ in range(kl)]
        for i, b in enumerate(ciphertext):
            columns[i % kl].append(b)

        # Calculate average IC for all columns
        total_ic = 0
        for col in columns:
            if len(col) < 2:
                continue
            freq = [0] * 256
            for b in col:
                freq[b] += 1
            n = len(col)
            ic = sum(f * (f - 1) for f in freq) / (n * (n - 1)) if n > 1 else 0
            total_ic += ic

        avg_ic = total_ic / kl
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = kl

    return best_len

def recover_key(ciphertext, key_len, known_char_freq=None):
    """Recover key bytes using frequency analysis (assumes English text)."""
    # English letter frequency for XOR key recovery
    ENGLISH_FREQ = {ord(' '): 0.17, ord('e'): 0.12, ord('t'): 0.09, ord('a'): 0.08,
                    ord('o'): 0.08, ord('i'): 0.07, ord('n'): 0.07, ord('s'): 0.06}

    key = []
    for col_idx in range(key_len):
        column = [ciphertext[i] for i in range(col_idx, len(ciphertext), key_len)]
        best_key_byte = 0
        best_score = -1

        for k in range(256):
            decrypted = [b ^ k for b in column]
            score = sum(1 for b in decrypted if 0x20 <= b <= 0x7e)
            # Bonus for common English characters
            score += sum(3 for b in decrypted if b in ENGLISH_FREQ)
            if score > best_score:
                best_score = score
                best_key_byte = k

        key.append(best_key_byte)

    return bytes(key)

# ─── KNOWN PLAINTEXT ATTACK ──────────────────────────────
def xor_known_plaintext(ciphertext, known_plain, offset=0):
    """Recover key from known plaintext at known offset."""
    key_fragment = bytes([c ^ p for c, p in zip(ciphertext[offset:], known_plain)])
    print(f'[+] Key fragment at offset {offset}: {key_fragment}')
    print(f'[+] Key hex: {key_fragment.hex()}')
    return key_fragment

# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <file> [key]')
        print(f'       {sys.argv[0]} <file>           # brute single-byte')
        print(f'       {sys.argv[0]} <file> 0x42       # single-byte key')
        print(f'       {sys.argv[0]} <file> "SECRET"   # multi-byte key')
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print(f'[*] Data: {len(data)} bytes')

    if len(sys.argv) >= 3:
        key_str = sys.argv[2]
        if key_str.startswith('0x'):
            key = int(key_str, 16)
            result = xor_single(data, key)
            print(f'[+] XOR with 0x{key:02x}:')
        else:
            result = xor_multi(data, key_str)
            print(f'[+] XOR with "{key_str}":')
        print(result.decode(errors='replace'))
        with open(sys.argv[1] + '.dec', 'wb') as f:
            f.write(result)
        print(f'[*] Written to {sys.argv[1]}.dec')
    else:
        print('[*] Brute-forcing single-byte XOR...')
        xor_single_brute(data)

        print(f'\n[*] Detecting key length...')
        kl = detect_key_length(data)
        print(f'[+] Estimated key length: {kl}')

        if kl > 1:
            key = recover_key(data, kl)
            print(f'[+] Recovered key: {key} (hex: {key.hex()})')
            decrypted = xor_multi(data, key)
            print(f'[+] Decrypted: {decrypted[:200]}')
