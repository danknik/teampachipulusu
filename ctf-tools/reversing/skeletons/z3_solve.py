#!/usr/bin/env python3
"""
Z3 Constraint Solver Template
================================
Solve math puzzles, logic constraints, and equation systems.

Common CTF patterns:
    - Check function with multiple conditions on input bytes
    - Matrix/linear equations
    - Bit operations (xor, shift, rotate)
    - Modular arithmetic

Install: pip3 install z3-solver
"""
from z3 import *
import sys

# ═══════════════════════════════════════════════════════════
# METHOD 1: Byte-by-byte constraints (most common)
# ═══════════════════════════════════════════════════════════
def solve_bytes():
    """
    Solve for individual bytes with constraints.
    Model: flag = [b0, b1, b2, ..., bn]
    """
    FLAG_LEN = 32

    s = Solver()

    # Create symbolic bytes
    flag = [BitVec(f'b{i}', 8) for i in range(FLAG_LEN)]

    # ─── Printable ASCII constraint ─────────────────────────
    for b in flag:
        s.add(b >= 0x20, b <= 0x7e)

    # ─── Flag format: inctf{...} ────────────────────────────
    prefix = b'inctf{'
    for i, c in enumerate(prefix):
        s.add(flag[i] == c)
    s.add(flag[FLAG_LEN - 1] == ord('}'))

    # ─── ADD YOUR CONSTRAINTS HERE ──────────────────────────
    # From reverse engineering the check function:
    #
    # Example: flag[6] + flag[7] == 0xd5
    # s.add(flag[6] + flag[7] == 0xd5)
    #
    # Example: flag[8] ^ flag[9] == 0x42
    # s.add(flag[8] ^ flag[9] == 0x42)
    #
    # Example: flag[10] * 3 + flag[11] == 0x1a2
    # s.add(flag[10] * 3 + flag[11] == 0x1a2)

    # ─── Solve ──────────────────────────────────────────────
    if s.check() == sat:
        m = s.model()
        solution = bytes([m[b].as_long() for b in flag])
        print(f'[+] Flag: {solution.decode(errors="replace")}')
        return solution
    else:
        print('[-] UNSAT — no solution exists')
        return None

# ═══════════════════════════════════════════════════════════
# METHOD 2: Integer/BitVec equations
# ═══════════════════════════════════════════════════════════
def solve_equations():
    """Solve system of equations (32-bit or 64-bit values)."""
    s = Solver()

    # 32-bit variables
    x = BitVec('x', 32)
    y = BitVec('y', 32)
    z = BitVec('z', 32)

    # Add equations (from disassembly)
    s.add(x + y == 0xdeadbeef)
    s.add(x ^ z == 0xcafebabe)
    s.add(y - z == 0x12345678)

    if s.check() == sat:
        m = s.model()
        print(f'[+] x = {hex(m[x].as_long())}')
        print(f'[+] y = {hex(m[y].as_long())}')
        print(f'[+] z = {hex(m[z].as_long())}')
        return m
    else:
        print('[-] UNSAT')
        return None

# ═══════════════════════════════════════════════════════════
# METHOD 3: Matrix / linear algebra
# ═══════════════════════════════════════════════════════════
def solve_matrix():
    """
    Solve: M * flag_vec = target_vec (mod 256 or mod 2^32)
    Common in rev challenges with transformation matrices.
    """
    s = Solver()

    N = 4  # vector size

    # Symbolic flag bytes
    flag = [BitVec(f'f{i}', 32) for i in range(N)]

    # Transformation matrix (from disassembly)
    M = [
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        [9, 10, 11, 12],
        [13, 14, 15, 16],
    ]

    # Target values (expected output)
    target = [0x11, 0x22, 0x33, 0x44]

    # Matrix multiplication constraints
    for row in range(N):
        expr = sum(M[row][col] * flag[col] for col in range(N))
        s.add((expr & 0xff) == target[row])  # mod 256

    # Printable constraint
    for f in flag:
        s.add(f >= 0x20, f <= 0x7e)

    if s.check() == sat:
        m = s.model()
        solution = bytes([m[f].as_long() for f in flag])
        print(f'[+] Solution: {solution}')
        return solution
    return None

# ═══════════════════════════════════════════════════════════
# METHOD 4: Bit rotation / custom operations
# ═══════════════════════════════════════════════════════════
def solve_bitops():
    """Solve with custom bit operations (rotate, permute, etc.)."""
    s = Solver()

    FLAG_LEN = 16
    flag = [BitVec(f'b{i}', 8) for i in range(FLAG_LEN)]

    # Helper: rotate left
    def rol(val, n, bits=8):
        return ((val << n) | LShR(val, bits - n)) & ((1 << bits) - 1)

    # Helper: rotate right
    def ror(val, n, bits=8):
        return (LShR(val, n) | (val << (bits - n))) & ((1 << bits) - 1)

    # Example constraints with rotations
    target = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]

    for i in range(FLAG_LEN):
        # Example: each byte is ROL'd by 3 then XOR'd with 0x42
        s.add(rol(flag[i], 3) ^ 0x42 == target[i])

    for b in flag:
        s.add(b >= 0x20, b <= 0x7e)

    if s.check() == sat:
        m = s.model()
        solution = bytes([m[b].as_long() for b in flag])
        print(f'[+] Solution: {solution.decode(errors="replace")}')
        return solution
    return None

# ═══════════════════════════════════════════════════════════
# METHOD 5: Multiple solutions / enumerate
# ═══════════════════════════════════════════════════════════
def enumerate_solutions(max_count=10):
    """Find multiple valid solutions."""
    s = Solver()

    FLAG_LEN = 8
    flag = [BitVec(f'b{i}', 8) for i in range(FLAG_LEN)]

    # Add your constraints
    for b in flag:
        s.add(b >= 0x20, b <= 0x7e)
    # ... more constraints ...

    count = 0
    while s.check() == sat and count < max_count:
        m = s.model()
        sol = bytes([m[b].as_long() for b in flag])
        print(f'[{count}] {sol.decode(errors="replace")}')

        # Block this solution
        s.add(Or([flag[i] != m[flag[i]].as_long() for i in range(FLAG_LEN)]))
        count += 1

    print(f'[*] Found {count} solutions')

# ═══════════════════════════════════════════════════════════
# QUICK SOLVE: paste constraints from decompiler
# ═══════════════════════════════════════════════════════════
def quick_solve():
    """
    Quick template: just paste your constraints.

    From IDA/Ghidra decompiler output like:
        if (input[0] * 3 + input[1] == 295) ...
        if (input[2] ^ input[3] == 0x37) ...
    """
    s = Solver()

    # Create N byte variables
    N = 32
    b = [BitVec(f'b{i}', 8) for i in range(N)]

    # Printable
    for x in b:
        s.add(x >= 0x20, x <= 0x7e)

    # ═══ PASTE CONSTRAINTS BELOW ═══
    # s.add(b[0] * 3 + b[1] == 295)
    # s.add(b[2] ^ b[3] == 0x37)
    # ═══ END CONSTRAINTS ═══

    if s.check() == sat:
        m = s.model()
        result = ''.join(chr(m[x].as_long()) for x in b)
        print(f'[+] {result}')
    else:
        print('[-] UNSAT')

if __name__ == '__main__':
    solve_bytes()
    # solve_equations()
    # solve_matrix()
    # solve_bitops()
    # quick_solve()
