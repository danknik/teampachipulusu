#!/usr/bin/env python3
"""
Binary Patcher for Reversing
===============================
NOP jumps, patch conditionals, bypass checks in rev challenges.

Usage:
    python3 patch_binary.py <action> <binary> <args...>
"""
import sys
import struct
import shutil

def read_binary(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())

def write_binary(path, data):
    with open(path, 'wb') as f:
        f.write(data)

def backup(path):
    bak = path + '.bak'
    shutil.copy2(path, bak)
    print(f'[*] Backup: {bak}')

# ─── COMMON PATCHES ────────────────────────────────────────

def nop_range(data, start, end):
    """NOP out bytes from start to end (exclusive)."""
    for i in range(start, end):
        data[i] = 0x90
    print(f'[+] NOP {end-start} bytes: {hex(start)}-{hex(end)}')
    return data

def patch_je_to_jne(data, offset):
    """Swap JE ↔ JNE (toggle conditional)."""
    if data[offset] == 0x74:
        data[offset] = 0x75
        print(f'[+] JE → JNE at {hex(offset)}')
    elif data[offset] == 0x75:
        data[offset] = 0x74
        print(f'[+] JNE → JE at {hex(offset)}')
    elif data[offset] == 0x0f:
        if data[offset+1] == 0x84:
            data[offset+1] = 0x85
            print(f'[+] JE(near) → JNE(near) at {hex(offset)}')
        elif data[offset+1] == 0x85:
            data[offset+1] = 0x84
            print(f'[+] JNE(near) → JE(near) at {hex(offset)}')
    return data

def patch_jmp_unconditional(data, offset):
    """Replace conditional jump with unconditional JMP."""
    if data[offset] in range(0x70, 0x80):  # short conditional
        data[offset] = 0xeb  # JMP short
        print(f'[+] Conditional → JMP at {hex(offset)}')
    elif data[offset] == 0x0f and data[offset+1] in range(0x80, 0x90):
        # Near conditional → JMP near
        data[offset] = 0xe9
        # Shift displacement
        data[offset+1:offset+5] = data[offset+2:offset+6]
        data[offset+5] = 0x90  # NOP extra byte
        print(f'[+] Near conditional → JMP at {hex(offset)}')
    return data

def patch_call_to_nop(data, offset):
    """NOP out a CALL instruction (5 bytes: E8 XX XX XX XX)."""
    if data[offset] == 0xe8:
        for i in range(5):
            data[offset + i] = 0x90
        print(f'[+] NOP CALL at {hex(offset)}')
    return data

def patch_ret_value(data, offset, value):
    """
    Replace function body with: mov eax, value; ret
    Useful for bypassing check functions (return 1 for success).
    """
    # mov eax, imm32 = B8 XX XX XX XX
    # ret = C3
    data[offset] = 0xb8
    struct.pack_into('<I', data, offset + 1, value)
    data[offset + 5] = 0xc3
    print(f'[+] Function at {hex(offset)} now returns {value}')
    return data

def patch_bytes_at(data, offset, new_bytes):
    """Write raw bytes at offset."""
    if isinstance(new_bytes, str):
        new_bytes = bytes.fromhex(new_bytes)
    old = bytes(data[offset:offset+len(new_bytes)])
    data[offset:offset+len(new_bytes)] = new_bytes
    print(f'[+] {hex(offset)}: {old.hex()} → {new_bytes.hex()}')
    return data

def find_pattern(data, pattern):
    """Find byte pattern in binary."""
    if isinstance(pattern, str):
        pattern = bytes.fromhex(pattern.replace(' ', ''))
    offset = 0
    results = []
    while True:
        idx = data.find(pattern, offset)
        if idx == -1:
            break
        results.append(idx)
        offset = idx + 1
    return results

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage:')
        print(f'  {sys.argv[0]} nop <binary> <start_hex> <end_hex>')
        print(f'  {sys.argv[0]} flipjmp <binary> <offset_hex>       # JE↔JNE')
        print(f'  {sys.argv[0]} forcejmp <binary> <offset_hex>      # cond→JMP')
        print(f'  {sys.argv[0]} nopcall <binary> <offset_hex>       # NOP a CALL')
        print(f'  {sys.argv[0]} retval <binary> <offset_hex> <value># make func return value')
        print(f'  {sys.argv[0]} write <binary> <offset_hex> <hex>   # raw byte write')
        print(f'  {sys.argv[0]} find <binary> <hex_pattern>         # find pattern')
        sys.exit(1)

    action = sys.argv[1]
    binary = sys.argv[2]
    data = read_binary(binary)

    if action != 'find':
        backup(binary)

    if action == 'nop':
        start = int(sys.argv[3], 16)
        end = int(sys.argv[4], 16)
        data = nop_range(data, start, end)
    elif action == 'flipjmp':
        data = patch_je_to_jne(data, int(sys.argv[3], 16))
    elif action == 'forcejmp':
        data = patch_jmp_unconditional(data, int(sys.argv[3], 16))
    elif action == 'nopcall':
        data = patch_call_to_nop(data, int(sys.argv[3], 16))
    elif action == 'retval':
        data = patch_ret_value(data, int(sys.argv[3], 16), int(sys.argv[4]))
    elif action == 'write':
        data = patch_bytes_at(data, int(sys.argv[3], 16), sys.argv[4])
    elif action == 'find':
        results = find_pattern(data, sys.argv[3])
        print(f'[*] Pattern found at: {[hex(r) for r in results]}')
        sys.exit(0)
    else:
        print(f'Unknown action: {action}')
        sys.exit(1)

    write_binary(binary, data)
    print(f'[+] Patched: {binary}')
