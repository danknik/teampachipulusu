#!/usr/bin/env python3
"""
Custom Cipher Template
========================
Template for reversing and implementing custom encryption algorithms.
Covers common patterns found in CTF rev challenges.

Workflow:
    1. Identify the algorithm in disassembly/decompiler
    2. Implement the encrypt function (copy from decompiler)
    3. Write the inverse (decrypt) function
    4. Test encrypt matches expected output, then decrypt
"""
import struct

# ═══════════════════════════════════════════════════════════
# COMMON BUILDING BLOCKS (copy-paste these as needed)
# ═══════════════════════════════════════════════════════════

def rol(val, n, bits=32):
    """Rotate left."""
    n %= bits
    return ((val << n) | (val >> (bits - n))) & ((1 << bits) - 1)

def ror(val, n, bits=32):
    """Rotate right."""
    n %= bits
    return ((val >> n) | (val << (bits - n))) & ((1 << bits) - 1)

def swap_nibbles(b):
    """Swap high and low nibbles of a byte."""
    return ((b << 4) | (b >> 4)) & 0xff

def reverse_bits(b, bits=8):
    """Reverse bits of a value."""
    result = 0
    for _ in range(bits):
        result = (result << 1) | (b & 1)
        b >>= 1
    return result

def sub_bytes(data, sbox):
    """Substitution box lookup."""
    return bytes([sbox[b] for b in data])

def inv_sub_bytes(data, sbox):
    """Inverse substitution box (build inverse, then lookup)."""
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return bytes([inv_sbox[b] for b in data])

def permute(data, perm_table):
    """Permute/shuffle bytes according to a table."""
    return bytes([data[perm_table[i]] for i in range(len(data))])

def inv_permute(data, perm_table):
    """Inverse permutation."""
    result = bytearray(len(data))
    for i, p in enumerate(perm_table):
        result[p] = data[i]
    return bytes(result)

# ═══════════════════════════════════════════════════════════
# TEMPLATE: Custom Feistel Cipher
# ═══════════════════════════════════════════════════════════
def feistel_round(block_l, block_r, round_key):
    """Single Feistel round: L' = R, R' = L ^ F(R, key)."""
    # F function — CUSTOMIZE THIS based on challenge:
    f_out = (block_r * round_key + 0x13) & 0xffffffff
    f_out = rol(f_out, 7, 32) ^ round_key
    new_l = block_r
    new_r = block_l ^ f_out
    return new_l, new_r

def feistel_encrypt(plaintext, keys, rounds=16):
    """Feistel encryption with N rounds."""
    L = int.from_bytes(plaintext[:4], 'little')
    R = int.from_bytes(plaintext[4:8], 'little')
    for i in range(rounds):
        L, R = feistel_round(L, R, keys[i])
    return struct.pack('<II', L, R)

def feistel_decrypt(ciphertext, keys, rounds=16):
    """Feistel decryption: reverse key order, swap L/R."""
    L = int.from_bytes(ciphertext[:4], 'little')
    R = int.from_bytes(ciphertext[4:8], 'little')
    for i in range(rounds - 1, -1, -1):
        # Inverse: R' = L, L' = R ^ F(L, key)
        f_out = (L * keys[i] + 0x13) & 0xffffffff
        f_out = rol(f_out, 7, 32) ^ keys[i]
        new_r = L
        new_l = R ^ f_out
        L, R = new_l, new_r
    return struct.pack('<II', L, R)

# ═══════════════════════════════════════════════════════════
# TEMPLATE: Byte-by-byte transformation
# ═══════════════════════════════════════════════════════════
def custom_encrypt(plaintext, key):
    """
    Example custom encryption — REPLACE WITH YOUR CHALLENGE'S ALGORITHM.

    Common patterns from decompiler:
        for i in range(len(plaintext)):
            c[i] = ((p[i] ^ key[i % key_len]) + i) & 0xff
            c[i] = rol(c[i], 3, 8)
    """
    key_bytes = key if isinstance(key, bytes) else key.encode()
    ciphertext = bytearray()

    for i, b in enumerate(plaintext):
        # Step 1: XOR with key byte
        c = b ^ key_bytes[i % len(key_bytes)]
        # Step 2: Add index
        c = (c + i) & 0xff
        # Step 3: Rotate left 3
        c = rol(c, 3, 8)
        ciphertext.append(c)

    return bytes(ciphertext)

def custom_decrypt(ciphertext, key):
    """
    Inverse of custom_encrypt — reverse each step in reverse order.
    """
    key_bytes = key if isinstance(key, bytes) else key.encode()
    plaintext = bytearray()

    for i, c in enumerate(ciphertext):
        # Reverse Step 3: Rotate right 3
        b = ror(c, 3, 8)
        # Reverse Step 2: Subtract index
        b = (b - i) & 0xff
        # Reverse Step 1: XOR with key byte
        b = b ^ key_bytes[i % len(key_bytes)]
        plaintext.append(b)

    return bytes(plaintext)

# ═══════════════════════════════════════════════════════════
# TEMPLATE: TEA / XTEA (common in CTF)
# ═══════════════════════════════════════════════════════════
def tea_encrypt(v0, v1, key):
    """TEA encryption (Tiny Encryption Algorithm)."""
    k0, k1, k2, k3 = key
    delta = 0x9e3779b9
    s = 0
    for _ in range(32):
        s = (s + delta) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xffffffff
    return v0, v1

def tea_decrypt(v0, v1, key):
    """TEA decryption."""
    k0, k1, k2, k3 = key
    delta = 0x9e3779b9
    s = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xffffffff
        s = (s - delta) & 0xffffffff
    return v0, v1

def xtea_decrypt(v0, v1, key, rounds=32):
    """XTEA decryption."""
    delta = 0x9e3779b9
    s = (delta * rounds) & 0xffffffff
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + key[(s >> 11) & 3]))) & 0xffffffff
        s = (s - delta) & 0xffffffff
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + key[s & 3]))) & 0xffffffff
    return v0, v1

# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    # Test custom cipher
    key = b'CTFkey'
    original = b'inctf{test_flag_here}'
    encrypted = custom_encrypt(original, key)
    decrypted = custom_decrypt(encrypted, key)
    print(f'Original:  {original}')
    print(f'Encrypted: {encrypted.hex()}')
    print(f'Decrypted: {decrypted}')
    assert original == decrypted, "Decrypt failed!"
    print('[+] Custom cipher test passed!')

    # Test TEA
    k = (0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210)
    v0, v1 = 0x41414141, 0x42424242
    ev0, ev1 = tea_encrypt(v0, v1, k)
    dv0, dv1 = tea_decrypt(ev0, ev1, k)
    assert (dv0, dv1) == (v0, v1), "TEA decrypt failed!"
    print('[+] TEA test passed!')
