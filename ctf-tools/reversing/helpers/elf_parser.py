#!/usr/bin/env python3
"""
ELF Parser — Quick ELF header/section analysis
=================================================
Parse ELF binaries for quick analysis during CTFs.
"""
import sys
import struct

def parse_elf(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        print('[-] Not an ELF file')
        return

    # ELF class
    is_64 = data[4] == 2
    endian = '<' if data[5] == 1 else '>'

    print(f'═══ ELF Header ═══')
    print(f'  Class:      {"64-bit" if is_64 else "32-bit"}')
    print(f'  Endian:     {"Little" if data[5] == 1 else "Big"}')
    print(f'  OS/ABI:     {data[7]}')

    # ELF type
    e_type = struct.unpack_from(endian + 'H', data, 16)[0]
    types = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN (PIE/shared)', 4: 'CORE'}
    print(f'  Type:       {types.get(e_type, hex(e_type))}')

    # Machine
    e_machine = struct.unpack_from(endian + 'H', data, 18)[0]
    machines = {3: 'x86', 40: 'ARM', 62: 'x86_64', 183: 'AArch64', 8: 'MIPS'}
    print(f'  Machine:    {machines.get(e_machine, hex(e_machine))}')

    # Entry point
    if is_64:
        e_entry = struct.unpack_from(endian + 'Q', data, 24)[0]
        e_phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
        e_shoff = struct.unpack_from(endian + 'Q', data, 40)[0]
        e_phentsize = struct.unpack_from(endian + 'H', data, 54)[0]
        e_phnum = struct.unpack_from(endian + 'H', data, 56)[0]
        e_shentsize = struct.unpack_from(endian + 'H', data, 58)[0]
        e_shnum = struct.unpack_from(endian + 'H', data, 60)[0]
        e_shstrndx = struct.unpack_from(endian + 'H', data, 62)[0]
    else:
        e_entry = struct.unpack_from(endian + 'I', data, 24)[0]
        e_phoff = struct.unpack_from(endian + 'I', data, 28)[0]
        e_shoff = struct.unpack_from(endian + 'I', data, 32)[0]
        e_phentsize = struct.unpack_from(endian + 'H', data, 42)[0]
        e_phnum = struct.unpack_from(endian + 'H', data, 44)[0]
        e_shentsize = struct.unpack_from(endian + 'H', data, 46)[0]
        e_shnum = struct.unpack_from(endian + 'H', data, 48)[0]
        e_shstrndx = struct.unpack_from(endian + 'H', data, 50)[0]

    print(f'  Entry:      {hex(e_entry)}')
    print(f'  PH offset:  {hex(e_phoff)} ({e_phnum} entries)')
    print(f'  SH offset:  {hex(e_shoff)} ({e_shnum} entries)')

    # PIE detection
    if e_type == 3:
        print(f'  PIE:        YES (DYN type)')
    elif e_type == 2:
        print(f'  PIE:        NO (EXEC type)')

    # Section names string table
    if is_64:
        shstr_off = struct.unpack_from(endian + 'Q', data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    else:
        shstr_off = struct.unpack_from(endian + 'I', data, e_shoff + e_shstrndx * e_shentsize + 16)[0]

    # Sections
    print(f'\n═══ Sections ═══')
    print(f'  {"Name":<20} {"Type":<12} {"Addr":>12} {"Offset":>10} {"Size":>10} {"Flags":<8}')
    print('  ' + '─' * 74)

    sh_types = {0:'NULL', 1:'PROGBITS', 2:'SYMTAB', 3:'STRTAB', 4:'RELA', 5:'HASH',
                6:'DYNAMIC', 7:'NOTE', 8:'NOBITS', 9:'REL', 11:'DYNSYM', 14:'INIT_ARRAY',
                15:'FINI_ARRAY'}

    interesting_sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is_64:
            sh_name_idx = struct.unpack_from(endian + 'I', data, off)[0]
            sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
            sh_flags = struct.unpack_from(endian + 'Q', data, off + 8)[0]
            sh_addr = struct.unpack_from(endian + 'Q', data, off + 16)[0]
            sh_offset = struct.unpack_from(endian + 'Q', data, off + 24)[0]
            sh_size = struct.unpack_from(endian + 'Q', data, off + 32)[0]
        else:
            sh_name_idx = struct.unpack_from(endian + 'I', data, off)[0]
            sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
            sh_flags = struct.unpack_from(endian + 'I', data, off + 8)[0]
            sh_addr = struct.unpack_from(endian + 'I', data, off + 12)[0]
            sh_offset = struct.unpack_from(endian + 'I', data, off + 16)[0]
            sh_size = struct.unpack_from(endian + 'I', data, off + 20)[0]

        name_end = data.find(b'\x00', shstr_off + sh_name_idx)
        name = data[shstr_off + sh_name_idx:name_end].decode('ascii', errors='replace')

        flag_str = ''
        if sh_flags & 0x1: flag_str += 'W'
        if sh_flags & 0x2: flag_str += 'A'
        if sh_flags & 0x4: flag_str += 'X'

        type_str = sh_types.get(sh_type, hex(sh_type))
        print(f'  {name:<20} {type_str:<12} {hex(sh_addr):>12} {hex(sh_offset):>10} {sh_size:>10} {flag_str:<8}')

        if name in ['.got', '.got.plt', '.bss', '.data', '.rodata', '.text', '.plt']:
            interesting_sections.append((name, sh_addr, sh_offset, sh_size))

    # Print key addresses
    if interesting_sections:
        print(f'\n═══ Key Addresses ═══')
        for name, addr, offset, size in interesting_sections:
            print(f'  {name:<12}: addr={hex(addr):<14} offset={hex(offset):<10} size={hex(size)}')

    # Check for stack canary
    print(f'\n═══ Security (quick) ═══')
    if b'__stack_chk_fail' in data:
        print(f'  Stack canary: YES (__stack_chk_fail found)')
    else:
        print(f'  Stack canary: NO')

    if e_type == 3:
        print(f'  PIE: YES')
    else:
        print(f'  PIE: NO')

    # Check NX via program headers (PT_GNU_STACK)
    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        if is_64:
            p_type = struct.unpack_from(endian + 'I', data, ph_off)[0]
            p_flags = struct.unpack_from(endian + 'I', data, ph_off + 4)[0]
        else:
            p_type = struct.unpack_from(endian + 'I', data, ph_off)[0]
            p_flags = struct.unpack_from(endian + 'I', data, ph_off + 24)[0]

        if p_type == 0x6474e551:  # PT_GNU_STACK
            if p_flags & 0x1:  # PF_X
                print(f'  NX: DISABLED (stack executable!)')
            else:
                print(f'  NX: ENABLED')
            break

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <elf_binary>')
        sys.exit(1)
    parse_elf(sys.argv[1])
