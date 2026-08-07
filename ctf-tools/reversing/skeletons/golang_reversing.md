# Go Binary Reversing Tips

## Identification
```bash
file ./chall                    # shows "Go" in output
strings ./chall | grep "go.go"  # Go source paths
strings ./chall | grep "main."  # Go function names
```

## Key Characteristics
- **Statically linked**: all libraries bundled → large binary (5-20MB)
- **Goroutines**: concurrent execution, channels
- **Strings NOT null-terminated**: stored as (pointer, length) pairs
- **No standard C calling convention**: args/returns via stack (pre-Go 1.17) or registers (Go 1.17+)
- **Function names preserved**: `main.main`, `main.checkFlag`, etc. (unless stripped)

## Quick Analysis

### Find main function
```bash
# Function list
strings ./chall | grep "^main\."    # Go functions
# or in GDB:
# info functions main.
```

### String extraction (Go-style)
```bash
# Go strings are (ptr, len) pairs, not null-terminated
# strings command may miss some; look for cross-references in IDA/Ghidra
strings -n 4 ./chall | grep -iE "flag|correct|wrong|key"
```

### Ghidra tips
1. **Install Go extensions**: GoReSym, go-utils for Ghidra
2. **Function recovery**: Look for `runtime.gopanic`, `runtime.goexit` patterns
3. **String recovery**: Go strings are at `go.string.*` labels
4. **Struct recovery**: Look at `go.itab.*` for interface tables

### IDA tips
1. **IDAGolangHelper**: https://github.com/sibears/IDAGolangHelper
2. Run the script → recovers function names, strings, types
3. Start from `main.main`

## Common Patterns in CTF Go Rev

### String comparison
```go
// Decompiler shows something like:
// runtime.memequal(input_ptr, expected_ptr, length)
// or
// for i := 0; i < len(expected); i++ { if input[i] != expected[i] ... }
```
→ Look for `runtime.memequal` or byte-by-byte XREFs

### Crypto
```go
// Go uses standard library:
// crypto/aes, crypto/cipher, crypto/sha256, encoding/base64
```
→ Search strings for `crypto/` or `encoding/`

### Flag check function
```bash
# Typically: main.checkFlag or main.verify
strings ./chall | grep "main\." | sort -u
```

## Debugging Go in GDB
```bash
gdb ./chall
# Go-aware GDB (if Go installed):
# source /usr/local/go/src/runtime/runtime-gdb.py

b main.main
r

# Print Go string (ptr + len on stack):
x/s *(char**)($rsp+8)

# Go 1.17+ register ABI:
# arg1 = rax, arg2 = rbx, arg3 = rcx, etc.
# return = rax, rbx, ...
```

## Stripped Go Binary Recovery
```bash
# GoReSym: recover function names from stripped binaries
# https://github.com/mandiant/GoReSym
GoReSym -d ./chall

# Output: JSON with recovered functions, types, source paths
# Then import into IDA/Ghidra
```

## Common Go Obfuscation
1. **garble**: Obfuscates names, strings. Look for `GARBLE` env var.
   - Strings may be XOR'd at runtime
   - Function names replaced with hashes
2. **gobfuscate**: Similar name mangling
3. **Custom encryption**: Strings decrypted in `init()` functions

## Quick Decode Patterns
```python
# If Go binary XORs strings at runtime (garble-style):
# Set breakpoint AFTER string decryption, read from memory
# In GDB: b main.init.0  → strings are decrypted by init
```
