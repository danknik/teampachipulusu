# Reversing Cheatsheet — Quick Reference

## 🔥 First Steps (ALWAYS do these)
```bash
file ./chall                         # file type, arch, linking
strings -n 6 ./chall | less          # readable strings
strings ./chall | grep -iE "flag|correct|wrong|key|pass|secret"
ltrace -s 200 ./chall                # library calls (strcmp!)
strace ./chall                       # system calls
readelf -h ./chall                   # ELF header
```

## Identify Binary Type
| file output | Type | Tools |
|-------------|------|-------|
| ELF 64-bit | Linux binary | Ghidra, IDA, GDB |
| ELF 32-bit | Linux binary | Ghidra, IDA, GDB |
| PE32/PE32+ | Windows .exe | Ghidra, IDA, x64dbg |
| Mach-O | macOS binary | Ghidra, Hopper |
| Java | .class/.jar | JD-GUI, CFR, jadx |
| .NET | C# assembly | dnSpy, ILSpy, dotPeek |
| Python | .pyc compiled | uncompyle6, decompyle3 |
| Go | Go binary | Ghidra + GoReSym |
| Rust | Rust binary | Ghidra (large, hard to read) |

## Decompiler Shortcuts

### Ghidra
```
L           → rename variable/function
T           → change type
;           → add comment
G           → goto address
Ctrl+Shift+E → show references to
X           → cross-references
D           → disassemble
Space       → toggle listing/graph view
```

### IDA
```
N           → rename
Y           → change type
/           → add comment
G           → goto address
X           → cross-references
H           → toggle hex/decimal
Tab         → toggle text/graph
F5          → decompile (with Hex-Rays)
```

## Common CTF Rev Patterns

### 1. Simple Comparison
```c
// Look for: strcmp, memcmp, strncmp
if (strcmp(input, "s3cr3t_p4ss") == 0)
    printf("Correct!\n");
```
**Solve:** `ltrace ./chall` → see strcmp argument

### 2. XOR Encryption
```c
for (int i = 0; i < len; i++)
    enc[i] = input[i] ^ key[i % keylen];
```
**Solve:** `python3 xor_decrypt.py data.enc KEY`

### 3. Custom Check Function
```c
int check(char *input) {
    if (input[0] * 3 + input[1] != 295) return 0;
    if (input[2] ^ input[3] != 0x37) return 0;
    // ...
}
```
**Solve:** Z3 solver → paste constraints

### 4. Lookup Table / S-box
```c
char sbox[] = {0x63, 0x7c, 0x77, ...};
for (int i = 0; i < len; i++)
    output[i] = sbox[input[i]];
```
**Solve:** Build inverse S-box, look up target values

### 5. Multi-round Cipher (TEA/XTEA/Feistel)
```c
for (int r = 0; r < 32; r++) {
    v0 += ((v1<<4)+k0) ^ (v1+sum) ^ ((v1>>5)+k1);
    // ...
}
```
**Solve:** Implement decrypt (reverse rounds) → `custom_cipher_template.py`

### 6. Anti-Debug
```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
    exit(1);  // debugger detected
```
**Solve:** NOP the check, or `LD_PRELOAD` hook

## Python Bytecode (.pyc)
```bash
# Decompile .pyc back to .py:
pip3 install uncompyle6
uncompyle6 challenge.pyc > challenge.py

# Python 3.9+: try pycdc
# https://github.com/zrax/pycdc
./pycdc challenge.pyc

# Manual: dis module
python3 -c "import dis, marshal; f=open('challenge.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"
```

## Rust Binary Tips
- Very large binaries (static linking)
- Mangled names: `_ZN4main...` → demangle with `c++filt` or `rustfilt`
- Look for `main` in symbol table
- String constants in `.rodata`
- Error handling code bloats disassembly → focus on main logic

## Common Encodings
```python
import base64, codecs

# Base64
base64.b64decode('aW5jdGZ7...')

# Base32
base64.b32decode('INCTF...')

# Hex
bytes.fromhex('696e637466')

# ROT13
codecs.decode('vapgs{...}', 'rot_13')

# URL encoding
from urllib.parse import unquote
unquote('%69%6e%63%74%66')

# Binary
int('01101001', 2)  # → 105 → 'i'
```

## angr Quick Start
```python
import angr
p = angr.Project('./chall', auto_load_libs=False)
s = p.factory.entry_state()
sm = p.factory.simulation_manager(s)
sm.explore(find=0x401234, avoid=[0x401256])
if sm.found:
    print(sm.found[0].posix.dumps(0))
```

## Z3 Quick Start
```python
from z3 import *
s = Solver()
x = BitVec('x', 8)
s.add(x * 3 + 5 == 77)
s.add(x >= 0x20, x <= 0x7e)
if s.check() == sat:
    print(chr(s.model()[x].as_long()))
```

## Assembly Quick Reference

### x86_64 Common Instructions
```
mov rdi, rax    ; rdi = rax
lea rdi, [rsp]  ; rdi = address of rsp (NOT value at rsp)
push rax        ; push rax onto stack
pop rdi         ; pop stack into rdi
call func       ; push return addr, jmp to func
ret             ; pop rip (return)
xor eax, eax    ; eax = 0 (common idiom)
test eax, eax   ; set flags based on eax (ZF=1 if eax==0)
cmp rax, rbx    ; compare (sets flags)
je/jne/jg/jl    ; conditional jumps based on flags
syscall         ; invoke system call (rax=number)
```

### Common Function Prologue/Epilogue
```asm
; Prologue:
push rbp
mov rbp, rsp
sub rsp, 0x40      ; allocate 64 bytes for locals

; Epilogue:
leave               ; mov rsp, rbp; pop rbp
ret
```

## Useful Commands
```bash
objdump -d ./chall | less               # disassemble
objdump -M intel -d ./chall | less      # Intel syntax
readelf -s ./chall                       # symbol table
readelf -r ./chall                       # relocations
nm ./chall                               # symbols
rabin2 -z ./chall                        # strings (radare2)
rabin2 -i ./chall                        # imports
rabin2 -E ./chall                        # exports
```
