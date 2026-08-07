#!/bin/bash
# Dynamic Tracing — ltrace/strace wrapper
# Usage: ./dynamic_trace.sh <binary> [args...]

BINARY="${1:?Usage: $0 <binary> [args...]}"
shift
ARGS="$@"

echo "═══════════════════════════════════════════"
echo "  Dynamic Analysis: $BINARY $ARGS"
echo "═══════════════════════════════════════════"

echo ""
echo "─── File Info ───"
file "$BINARY"
echo ""

echo "─── 1. strace (system calls) ───"
echo "Command: strace -f -o strace.log ./$BINARY $ARGS"
echo ""
if command -v strace &>/dev/null; then
    echo "[*] Quick strace (first 100 lines):"
    timeout 5 strace -f "./$BINARY" $ARGS 2>&1 | tail -100
    echo ""
fi

echo "─── 2. ltrace (library calls) ───"
echo "Command: ltrace -f -o ltrace.log ./$BINARY $ARGS"
echo ""
if command -v ltrace &>/dev/null; then
    echo "[*] Quick ltrace (first 50 lines):"
    timeout 5 ltrace -f "./$BINARY" $ARGS 2>&1 | tail -50
    echo ""
fi

echo "═══════════════════════════════════════════"
echo "  Useful strace filters:"
echo "═══════════════════════════════════════════"
echo ""
echo "  # File operations only:"
echo "  strace -e trace=file ./$BINARY"
echo ""
echo "  # Network operations:"
echo "  strace -e trace=network ./$BINARY"
echo ""
echo "  # Read/write calls (see what it reads/writes):"
echo "  strace -e trace=read,write -s 200 ./$BINARY"
echo ""
echo "  # Open calls (what files it touches):"
echo "  strace -e trace=open,openat ./$BINARY"
echo ""
echo "  # Memory operations:"
echo "  strace -e trace=mmap,mprotect,brk ./$BINARY"
echo ""
echo "═══════════════════════════════════════════"
echo "  Useful ltrace filters:"
echo "═══════════════════════════════════════════"
echo ""
echo "  # String functions (find comparisons):"
echo "  ltrace -e strcmp+strcpy+strncmp+memcmp ./$BINARY"
echo ""
echo "  # All string comparisons:"
echo "  ltrace -e '*cmp*+*str*' ./$BINARY"
echo ""
echo "  # Crypto functions:"
echo "  ltrace -e '*crypt*+*aes*+*sha*+*md5*' ./$BINARY"
echo ""
echo "  # With string length:"
echo "  ltrace -s 200 ./$BINARY"
