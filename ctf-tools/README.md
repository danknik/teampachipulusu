# 🏴 CTF Toolkit — Pwn & Reversing

**InCTF Nationals 2026 — Ready-to-use exploit templates and reversing scripts.**

> Clone this repo, copy a template, fill in the challenge specifics, run.

---

## 📁 Quick Navigation

### Binary Exploit Skeletons — `binary_exploit/skeletons/`
| Script | When to Use |
|--------|-------------|
| [exploit_template.py](binary_exploit/skeletons/exploit_template.py) | **START HERE** — generic skeleton with local/remote/GDB |
| [bof_ret2win.py](binary_exploit/skeletons/bof_ret2win.py) | Simple overflow → jump to win function |
| [bof_ret2libc.py](binary_exploit/skeletons/bof_ret2libc.py) | Leak libc via puts → `system("/bin/sh")` |
| [bof_rop_chain.py](binary_exploit/skeletons/bof_rop_chain.py) | Full ROP: auto-ROP, execve, mprotect, ret2csu |
| [bof_ret2shellcode.py](binary_exploit/skeletons/bof_ret2shellcode.py) | NX off → shellcode on stack/BSS/jmp_rsp |
| [fmt_string_leak.py](binary_exploit/skeletons/fmt_string_leak.py) | Format string → auto-leak & classify addresses |
| [fmt_string_write.py](binary_exploit/skeletons/fmt_string_write.py) | Format string → GOT overwrite, arbitrary write |
| [heap_tcache_poison.py](binary_exploit/skeletons/heap_tcache_poison.py) | Tcache poisoning (glibc ≥2.27, safe-linking ≥2.32) |
| [heap_fastbin_dup.py](binary_exploit/skeletons/heap_fastbin_dup.py) | Fastbin double-free (old + new glibc) |
| [heap_house_of_force.py](binary_exploit/skeletons/heap_house_of_force.py) | Top chunk overflow → arbitrary alloc |
| [heap_uaf.py](binary_exploit/skeletons/heap_uaf.py) | Use-After-Free → leak, fptr hijack, tcache poison |
| [sigreturn_srop.py](binary_exploit/skeletons/sigreturn_srop.py) | SROP: sigreturn frame → execve/mprotect/ORW |
| [stack_pivot.py](binary_exploit/skeletons/stack_pivot.py) | leave;ret / pop rsp / partial overwrite pivots |
| [seccomp_bypass.py](binary_exploit/skeletons/seccomp_bypass.py) | Seccomp ORW: open→read→write flag (+ openat) |
| [shellcode_collection.py](binary_exploit/skeletons/shellcode_collection.py) | Ready shellcodes: execve, ORW, reverse shell |
| [one_gadget_finder.py](binary_exploit/skeletons/one_gadget_finder.py) | Find one-gadget magic addresses in libc |

### Binary Exploit Helpers — `binary_exploit/helpers/`
| Script | What it Does |
|--------|-------------|
| [libc_finder.py](binary_exploit/helpers/libc_finder.py) | Identify libc from leaked addresses (local + libc.rip) |
| [rop_gadget_finder.sh](binary_exploit/helpers/rop_gadget_finder.sh) | Auto-dump common ROP gadgets |
| [checksec_all.sh](binary_exploit/helpers/checksec_all.sh) | Run checksec on all binaries in a directory |
| [patch_binary.py](binary_exploit/helpers/patch_binary.py) | patchelf wrapper + byte-level binary patching |
| [gdb_scripts.py](binary_exploit/helpers/gdb_scripts.py) | GDB/pwndbg command reference & templates |
| [canary_bruteforce.py](binary_exploit/helpers/canary_bruteforce.py) | Byte-by-byte canary brute-force (forking servers) |

### 📖 [Binary Exploit Cheatsheet](binary_exploit/cheatsheet.md) — Offsets, syscalls, calling convention, GDB commands

---

### Reversing Skeletons — `reversing/skeletons/`
| Script | When to Use |
|--------|-------------|
| [angr_solve.py](reversing/skeletons/angr_solve.py) | **angr auto-solver** — stdin, argv, output matching, hooks |
| [z3_solve.py](reversing/skeletons/z3_solve.py) | Z3 constraints — bytes, equations, matrix, bit ops |
| [xor_decrypt.py](reversing/skeletons/xor_decrypt.py) | XOR: single, multi-byte, rolling, brute-force, key detect |
| [rc4_decrypt.py](reversing/skeletons/rc4_decrypt.py) | RC4 decrypt with KSA/PRGA |
| [aes_decrypt.py](reversing/skeletons/aes_decrypt.py) | AES-ECB/CBC/CTR + padding oracle + ECB detection |
| [custom_cipher_template.py](reversing/skeletons/custom_cipher_template.py) | Custom cipher: Feistel, TEA/XTEA, byte transforms |
| [anti_debug_bypass.py](reversing/skeletons/anti_debug_bypass.py) | Detect & bypass ptrace, timing, signal anti-debug |
| [unpack_upx.sh](reversing/skeletons/unpack_upx.sh) | UPX unpacker + packing detection |
| [dotnet_decompile.sh](reversing/skeletons/dotnet_decompile.sh) | .NET decompilation workflow |
| [java_decompile.sh](reversing/skeletons/java_decompile.sh) | Java JAR/class decompilation |
| [golang_reversing.md](reversing/skeletons/golang_reversing.md) | Go binary reversing tips & tools |

### Reversing Helpers — `reversing/helpers/`
| Script | What it Does |
|--------|-------------|
| [string_extract.py](reversing/helpers/string_extract.py) | Smart strings: ASCII, wide, base64, XOR-hidden flags |
| [entropy_check.py](reversing/helpers/entropy_check.py) | Detect packing via entropy analysis |
| [patch_binary.py](reversing/helpers/patch_binary.py) | NOP jumps, flip conditions, force returns |
| [dynamic_trace.sh](reversing/helpers/dynamic_trace.sh) | ltrace/strace with useful filters |
| [elf_parser.py](reversing/helpers/elf_parser.py) | Quick ELF header/section/security analysis |

### 📖 [Reversing Cheatsheet](reversing/cheatsheet.md) — Patterns, assembly reference, tool shortcuts

---

### Shared — `shared/`
| Script | What it Does |
|--------|-------------|
| [flag_finder.sh](shared/flag_finder.sh) | Search for flag patterns everywhere |
| [setup_env.sh](shared/setup_env.sh) | Install all CTF tools in WSL/Linux |
| [solve_wrapper.py](shared/solve_wrapper.py) | Local/remote/GDB connection handler |

---

## 🚀 Workflow

### Binary Exploit Challenge
```bash
# 1. Recon
file ./chall && checksec ./chall
strings ./chall | grep -iE "flag|win|shell"

# 2. Copy template
cp ctf-toolkit/binary_exploit/skeletons/exploit_template.py exploit.py

# 3. Edit: set BINARY, HOST, PORT, fill exploit()
vim exploit.py

# 4. Test locally
python3 exploit.py local
python3 exploit.py gdb    # with debugger

# 5. Run remote
python3 exploit.py
```

### Reversing Challenge
```bash
# 1. Recon
file ./chall
python3 ctf-toolkit/reversing/helpers/string_extract.py ./chall
python3 ctf-toolkit/reversing/helpers/entropy_check.py ./chall
ltrace -s 200 ./chall

# 2. If packed → unpack
./ctf-toolkit/reversing/skeletons/unpack_upx.sh ./chall

# 3. Open in Ghidra/IDA, identify algorithm

# 4. If constraint-based → Z3
cp ctf-toolkit/reversing/skeletons/z3_solve.py solve.py

# 5. If complex → angr
cp ctf-toolkit/reversing/skeletons/angr_solve.py solve.py
```

## ⚡ Decision Tree

```
Got a binary? → checksec
  │
  ├─ NX disabled?     → ret2shellcode
  ├─ No canary, no PIE? → ret2win or ret2libc
  ├─ Format string?   → fmt_string_leak → fmt_string_write
  ├─ Heap challenge?   → heap_uaf / heap_tcache_poison
  ├─ Seccomp?          → seccomp_bypass (ORW)
  ├─ Limited gadgets?  → SROP or ret2csu
  └─ Forking server?   → canary_bruteforce
```
