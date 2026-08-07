#!/bin/bash
# .NET Decompilation Workflow
# Usage: ./dotnet_decompile.sh <binary.exe>

BINARY="${1:?Usage: $0 <binary.exe|binary.dll>}"

echo "═══════════════════════════════════════════"
echo "  .NET Decompilation: $BINARY"
echo "═══════════════════════════════════════════"

# Detect .NET
if file "$BINARY" | grep -qi "\.NET\|Mono\|CLR\|MSIL\|PE32.*assembly"; then
    echo "[+] .NET assembly detected"
elif strings "$BINARY" | grep -q "mscoree\|mscorlib\|System.Runtime"; then
    echo "[+] .NET indicators found in strings"
else
    echo "[-] May not be a .NET binary"
fi

echo ""
echo "─── Quick Analysis ───"
echo "[*] Strings containing 'flag', 'password', 'key', 'secret':"
strings "$BINARY" | grep -iE "flag|password|key|secret|ctf|correct|wrong" | head -20

echo ""
echo "─── Decompilation Options ───"
echo ""
echo "  1. dnSpy (Windows, GUI — BEST for .NET):"
echo "     - Download: https://github.com/dnSpy/dnSpy/releases"
echo "     - Open .exe/.dll → browse classes → read C# source"
echo "     - Can EDIT and recompile!"
echo ""
echo "  2. ILSpy (Cross-platform):"
echo "     - dotnet tool install -g ilspycmd"
echo "     - ilspycmd $BINARY > decompiled.cs"
echo ""
echo "  3. dotPeek (Windows, JetBrains):"
echo "     - Free, good decompilation quality"
echo ""
echo "  4. monodis (Linux CLI):"
if command -v monodis &>/dev/null; then
    echo "     [+] monodis available!"
    echo "     Running: monodis --method-list $BINARY"
    monodis "$BINARY" 2>/dev/null | head -50
else
    echo "     [!] Install: apt install mono-utils"
    echo "     monodis $BINARY  # decompile to IL"
fi

echo ""
echo "  5. Python approach (if dotnet not available):"
echo '     # pip install dnfile'
echo '     import dnfile'
echo '     pe = dnfile.dnPE("'$BINARY'")'
echo '     for row in pe.net.mdtables.MethodDef:'
echo '         print(row.Name)'
