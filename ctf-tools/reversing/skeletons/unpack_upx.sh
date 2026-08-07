#!/bin/bash
# UPX Unpacker + Generic Unpacking Notes
# Usage: ./unpack_upx.sh <binary>

BINARY="${1:?Usage: $0 <binary>}"

echo "═══════════════════════════════════════════"
echo "  Unpacking: $BINARY"
echo "═══════════════════════════════════════════"

# Check if UPX packed
if strings "$BINARY" | grep -q "UPX!"; then
    echo "[+] UPX signature found!"
    
    # Backup
    cp "$BINARY" "${BINARY}.packed"
    echo "[*] Backup: ${BINARY}.packed"
    
    # Try UPX unpack
    if command -v upx &>/dev/null; then
        echo "[*] Running: upx -d $BINARY"
        upx -d "$BINARY"
        echo "[+] Unpacked! Check with: file $BINARY"
    else
        echo "[!] UPX not installed. Install: apt install upx-ucl"
        echo "[!] Alternative: upx -d can be downloaded from https://github.com/upx/upx/releases"
    fi
else
    echo "[-] No UPX signature found"
fi

echo ""
echo "─── Packing detection ───"

# Check for common packers
if strings "$BINARY" | grep -qi "UPX"; then
    echo "[!] UPX detected"
fi
if strings "$BINARY" | grep -qi "ASPack"; then
    echo "[!] ASPack detected"
fi
if strings "$BINARY" | grep -qi "PECompact"; then
    echo "[!] PECompact detected"
fi
if strings "$BINARY" | grep -qi "Themida"; then
    echo "[!] Themida detected"
fi
if strings "$BINARY" | grep -qi "VMProtect"; then
    echo "[!] VMProtect detected"
fi

# Check entropy (high entropy = packed/encrypted)
echo ""
echo "─── Section entropy (high = likely packed) ───"
if command -v rabin2 &>/dev/null; then
    rabin2 -S "$BINARY" 2>/dev/null | head -20
elif command -v readelf &>/dev/null; then
    readelf -S "$BINARY" 2>/dev/null | grep -E '^\s+\[' | head -20
fi

echo ""
echo "─── Manual unpacking tips ───"
echo "  1. Run in GDB, break at OEP (Original Entry Point)"
echo "  2. After unpacking stub runs, dump memory:"
echo "     gdb> dump binary memory unpacked.bin 0x400000 0x500000"
echo "  3. Fix ELF headers if needed"
echo "  4. For Windows PE: use x64dbg + Scylla to dump & fix IAT"
echo ""
echo "  GDB method:"
echo "    starti                    # stop at very first instruction"
echo "    b *entry_point_after_unpack"
echo "    c"
echo "    dump binary memory out.bin <start> <end>"
