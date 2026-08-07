#!/usr/bin/env python3
"""
AES Decrypt — ECB / CBC / CTR
================================
AES decryption for CTF challenges.

Install: pip3 install pycryptodome

Usage:
    python3 aes_decrypt.py <encrypted_file> <key_hex> [iv_hex] [mode]
"""
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad
    except ImportError:
        print("[!] Install: pip3 install pycryptodome")
        sys.exit(1)

# ─── AES-ECB ──────────────────────────────────────────────
def aes_ecb_decrypt(ciphertext, key):
    """AES-ECB decryption (no IV needed)."""
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    try:
        return unpad(plaintext, AES.block_size)
    except:
        return plaintext  # no padding or custom padding

def aes_ecb_encrypt(plaintext, key):
    """AES-ECB encryption."""
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))

# ─── AES-CBC ──────────────────────────────────────────────
def aes_cbc_decrypt(ciphertext, key, iv):
    """AES-CBC decryption."""
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        return unpad(plaintext, AES.block_size)
    except:
        return plaintext

def aes_cbc_encrypt(plaintext, key, iv):
    """AES-CBC encryption."""
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

# ─── AES-CTR ──────────────────────────────────────────────
def aes_ctr_decrypt(ciphertext, key, nonce):
    """AES-CTR decryption (same as encryption — XOR stream)."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# ─── Manual AES-ECB block-by-block ────────────────────────
def aes_ecb_blocks(ciphertext, key):
    """Decrypt ECB block by block (useful for analysis)."""
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    result = b''
    for i, block in enumerate(blocks):
        dec = cipher.decrypt(block)
        print(f'  Block {i}: {block.hex()} → {dec.hex()} ({dec})')
        result += dec
    return result

# ─── Manual AES-CBC (for understanding) ──────────────────
def aes_cbc_manual(ciphertext, key, iv):
    """Manual CBC decryption for educational/debugging purposes."""
    cipher = AES.new(key, AES.MODE_ECB)  # use ECB internally
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    prev = iv
    result = b''
    for block in blocks:
        dec = cipher.decrypt(block)
        plaintext_block = bytes([d ^ p for d, p in zip(dec, prev)])
        result += plaintext_block
        prev = block
    return result

# ─── CBC Padding Oracle ──────────────────────────────────
def cbc_padding_oracle_block(oracle_fn, prev_block, cipher_block):
    """
    Decrypt one CBC block using a padding oracle.

    oracle_fn(iv + ciphertext) → True if padding is valid.
    """
    intermediary = [0] * 16
    plaintext = [0] * 16

    for byte_pos in range(15, -1, -1):
        padding_byte = 16 - byte_pos

        # Set known bytes
        crafted = [0] * 16
        for k in range(byte_pos + 1, 16):
            crafted[k] = intermediary[k] ^ padding_byte

        for guess in range(256):
            crafted[byte_pos] = guess
            test_iv = bytes(crafted)

            if oracle_fn(test_iv + cipher_block):
                intermediary[byte_pos] = guess ^ padding_byte
                plaintext[byte_pos] = intermediary[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)

# ─── Detect ECB mode ─────────────────────────────────────
def detect_ecb(ciphertext):
    """Detect if AES-ECB is used (duplicate blocks)."""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    unique = set(blocks)
    if len(blocks) != len(unique):
        dupes = len(blocks) - len(unique)
        print(f'[+] ECB detected! {dupes} duplicate block(s)')
        return True
    print('[-] No duplicate blocks (probably not ECB)')
    return False

# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <file> <key_hex> [iv_hex] [ecb|cbc|ctr]')
        print(f'  {sys.argv[0]} data.enc 000102030405060708090a0b0c0d0e0f')
        print(f'  {sys.argv[0]} data.enc "16-byte-key!!" 00000000000000000000000000000000 cbc')
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    # Parse key
    key_arg = sys.argv[2]
    if all(c in '0123456789abcdefABCDEF' for c in key_arg):
        key = bytes.fromhex(key_arg)
    else:
        key = key_arg.encode()

    print(f'[*] Key ({len(key)} bytes): {key.hex()}')
    print(f'[*] Data: {len(data)} bytes')

    # Detect ECB
    detect_ecb(data)

    # Parse IV and mode
    iv = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b'\x00' * 16
    mode = sys.argv[4] if len(sys.argv) > 4 else 'ecb'

    if mode == 'ecb':
        result = aes_ecb_decrypt(data, key)
    elif mode == 'cbc':
        result = aes_cbc_decrypt(data, key, iv)
    elif mode == 'ctr':
        result = aes_ctr_decrypt(data, key, iv[:8])  # CTR uses 8-byte nonce
    else:
        print(f'Unknown mode: {mode}')
        sys.exit(1)

    print(f'[+] Decrypted:')
    print(result.decode(errors='replace'))
