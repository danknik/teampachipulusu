#!/usr/bin/env python3
"""
String Extractor — Smart string extraction with encoding detection
====================================================================
Extract and decode embedded strings from binaries.

Better than `strings` command: detects XOR'd strings, base64, hex, wide strings.
"""
import sys
import base64
import re

def extract_ascii(data, min_len=4):
    """Extract printable ASCII strings."""
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    return [(m.start(), m.group()) for m in pattern.finditer(data)]

def extract_wide_strings(data, min_len=4):
    """Extract UTF-16LE (wide) strings — common in Windows binaries."""
    pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len)
    results = []
    for m in pattern.finditer(data):
        try:
            decoded = m.group().decode('utf-16-le')
            results.append((m.start(), decoded))
        except:
            pass
    return results

def find_base64(data):
    """Find and decode base64-encoded strings."""
    pattern = re.compile(rb'[A-Za-z0-9+/]{16,}={0,2}')
    results = []
    for m in pattern.finditer(data):
        try:
            decoded = base64.b64decode(m.group())
            if all(0x20 <= b <= 0x7e or b in (0x0a, 0x0d) for b in decoded):
                results.append((m.start(), m.group(), decoded))
        except:
            pass
    return results

def find_hex_strings(data):
    """Find hex-encoded strings."""
    pattern = re.compile(rb'(?:[0-9a-fA-F]{2}){8,}')
    results = []
    for m in pattern.finditer(data):
        try:
            decoded = bytes.fromhex(m.group().decode())
            printable = sum(1 for b in decoded if 0x20 <= b <= 0x7e)
            if printable / len(decoded) > 0.7:
                results.append((m.start(), m.group(), decoded))
        except:
            pass
    return results

def find_xor_strings(data, known=b'flag{', max_key=256):
    """Brute-force single-byte XOR to find known plaintext."""
    results = []
    for key in range(1, max_key):
        decoded = bytes([b ^ key for b in data])
        idx = decoded.find(known)
        while idx != -1:
            # Extract surrounding context
            start = max(0, idx - 10)
            end = min(len(decoded), idx + 50)
            context = decoded[start:end]
            results.append((idx, key, context))
            idx = decoded.find(known, idx + 1)
    return results

def find_flag_patterns(data):
    """Search for common CTF flag patterns."""
    patterns = [
        rb'[Ii][Nn][Cc][Tt][Ff]\{[^\}]*\}',       # inctf{...}
        rb'[Ff][Ll][Aa][Gg]\{[^\}]*\}',             # flag{...}
        rb'[Cc][Tt][Ff]\{[^\}]*\}',                  # ctf{...}
        rb'[Ii][Nn][Cc][Tt][Ff]\{',                  # partial inctf{
        rb'[Ff][Ll][Aa][Gg]\{',                      # partial flag{
    ]
    results = []
    for pat in patterns:
        for m in re.finditer(pat, data):
            results.append((m.start(), m.group()))
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <binary> [min_str_len]')
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else 6

    print(f'[*] Analyzing: {sys.argv[1]} ({len(data)} bytes)\n')

    # Flag patterns (highest priority)
    flags = find_flag_patterns(data)
    if flags:
        print('═══ FLAG PATTERNS ═══')
        for offset, s in flags:
            print(f'  [{hex(offset)}] {s}')
        print()

    # Interesting strings
    print('═══ INTERESTING STRINGS ═══')
    for offset, s in extract_ascii(data, min_len):
        s_lower = s.lower()
        if any(kw in s_lower for kw in [b'flag', b'key', b'pass', b'secret', b'correct',
                                         b'wrong', b'error', b'success', b'ctf', b'admin',
                                         b'input', b'enter', b'check', b'verify']):
            print(f'  [{hex(offset)}] {s.decode(errors="replace")}')

    # Wide strings
    wide = extract_wide_strings(data, min_len)
    if wide:
        print(f'\n═══ WIDE (UTF-16) STRINGS ═══')
        for offset, s in wide[:20]:
            print(f'  [{hex(offset)}] {s}')

    # Base64
    b64 = find_base64(data)
    if b64:
        print(f'\n═══ BASE64 STRINGS ═══')
        for offset, enc, dec in b64[:10]:
            print(f'  [{hex(offset)}] {enc[:60]} → {dec}')

    # XOR-hidden flags
    print(f'\n═══ XOR-HIDDEN FLAG SEARCH ═══')
    for prefix in [b'inctf{', b'flag{', b'CTF{']:
        xor_results = find_xor_strings(data, prefix)
        for offset, key, context in xor_results:
            print(f'  [XOR key=0x{key:02x}] offset={hex(offset)}: {context}')

    if not flags and not b64 and not xor_results:
        print('  (none found)')
