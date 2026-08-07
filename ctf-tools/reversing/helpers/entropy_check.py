#!/usr/bin/env python3
"""
Entropy Check — Detect packing/encryption
============================================
Analyzes file entropy to detect packed, encrypted, or compressed sections.

High entropy (>7.0) → likely packed/encrypted
Normal code entropy: 5.0-6.5
Plain text: 3.0-5.0

Usage:
    python3 entropy_check.py <binary>
"""
import sys
import math
import struct

def calc_entropy(data):
    """Calculate Shannon entropy of data (0-8 bits)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy

def analyze_file(filepath, block_size=256):
    """Analyze file entropy block-by-block."""
    with open(filepath, 'rb') as f:
        data = f.read()

    total_entropy = calc_entropy(data)
    print(f'[*] File: {filepath}')
    print(f'[*] Size: {len(data)} bytes')
    print(f'[*] Overall entropy: {total_entropy:.4f} / 8.0')
    print()

    # Verdict
    if total_entropy > 7.5:
        print('[!] VERY HIGH entropy → likely encrypted or compressed')
    elif total_entropy > 7.0:
        print('[!] HIGH entropy → likely packed (UPX, custom packer)')
    elif total_entropy > 6.0:
        print('[*] MODERATE entropy → normal compiled binary')
    elif total_entropy > 4.0:
        print('[*] LOW-MODERATE entropy → may contain significant data/strings')
    else:
        print('[*] LOW entropy → text-heavy file')

    return total_entropy

def analyze_elf_sections(filepath):
    """Parse ELF sections and calculate per-section entropy."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # Quick ELF check
    if data[:4] != b'\x7fELF':
        print('[-] Not an ELF file')
        return

    # Parse ELF header
    is_64 = data[4] == 2
    if is_64:
        e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
        e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    else:
        e_shoff = struct.unpack_from('<I', data, 0x20)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x2e)[0]
        e_shnum = struct.unpack_from('<H', data, 0x30)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]

    # Get section name string table
    if is_64:
        shstr_offset = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    else:
        shstr_offset = struct.unpack_from('<I', data, e_shoff + e_shstrndx * e_shentsize + 0x10)[0]

    print(f'\n{"Section":<20} {"Offset":>10} {"Size":>10} {"Entropy":>10} {"Assessment":<20}')
    print('─' * 72)

    high_entropy_sections = []

    for i in range(e_shnum):
        sh_entry = e_shoff + i * e_shentsize
        if is_64:
            sh_name_idx = struct.unpack_from('<I', data, sh_entry)[0]
            sh_offset = struct.unpack_from('<Q', data, sh_entry + 0x18)[0]
            sh_size = struct.unpack_from('<Q', data, sh_entry + 0x20)[0]
        else:
            sh_name_idx = struct.unpack_from('<I', data, sh_entry)[0]
            sh_offset = struct.unpack_from('<I', data, sh_entry + 0x10)[0]
            sh_size = struct.unpack_from('<I', data, sh_entry + 0x14)[0]

        # Get section name
        name_end = data.find(b'\x00', shstr_offset + sh_name_idx)
        name = data[shstr_offset + sh_name_idx:name_end].decode('ascii', errors='replace')

        if sh_size > 0 and sh_offset + sh_size <= len(data):
            section_data = data[sh_offset:sh_offset + sh_size]
            entropy = calc_entropy(section_data)

            if entropy > 7.0:
                assessment = '⚠ PACKED/ENCRYPTED'
                high_entropy_sections.append(name)
            elif entropy > 6.0:
                assessment = 'Normal code'
            elif entropy > 4.0:
                assessment = 'Data/strings'
            else:
                assessment = 'Low entropy'

            print(f'{name:<20} {hex(sh_offset):>10} {sh_size:>10} {entropy:>10.4f} {assessment:<20}')

    if high_entropy_sections:
        print(f'\n[!] Suspicious sections: {", ".join(high_entropy_sections)}')

def entropy_histogram(filepath, block_size=1024):
    """Print entropy histogram (visual representation)."""
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f'\n─── Entropy Histogram (block={block_size}B) ───')
    print(f'{"Offset":>10}  {"Ent":>5}  {"Bar":<40}')

    for offset in range(0, len(data), block_size):
        block = data[offset:offset + block_size]
        ent = calc_entropy(block)
        bar_len = int(ent / 8.0 * 40)
        bar = '█' * bar_len + '░' * (40 - bar_len)
        marker = ' ⚠' if ent > 7.0 else ''
        print(f'{hex(offset):>10}  {ent:>5.2f}  {bar}{marker}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <binary>')
        sys.exit(1)

    filepath = sys.argv[1]
    analyze_file(filepath)
    analyze_elf_sections(filepath)
    entropy_histogram(filepath)
