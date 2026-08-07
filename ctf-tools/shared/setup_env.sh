#!/bin/bash
# CTF Environment Setup — Run in WSL to install common tools
# Usage: ./setup_env.sh

echo "═══════════════════════════════════════════"
echo "  CTF Environment Setup"
echo "═══════════════════════════════════════════"

echo "[*] Updating package lists..."
sudo apt update -qq

# ─── Core tools ─────────────────────────────────────────
echo ""
echo "─── Core Tools ───"
TOOLS_CORE="python3 python3-pip gdb git curl wget netcat-openbsd socat file binutils"
for tool in $TOOLS_CORE; do
    if ! dpkg -l | grep -q " $tool "; then
        echo "[*] Installing $tool..."
        sudo apt install -y -qq "$tool"
    else
        echo "[+] $tool: already installed"
    fi
done

# ─── Python packages ───────────────────────────────────
echo ""
echo "─── Python Packages ───"
pip3 install --quiet pwntools z3-solver pycryptodome requests ropper 2>/dev/null || \
pip3 install --quiet --break-system-packages pwntools z3-solver pycryptodome requests ropper 2>/dev/null

# angr is large (~500MB) — install separately if needed
echo "[*] angr: pip3 install angr  (run manually, ~500MB)"

# ─── Binary analysis tools ─────────────────────────────
echo ""
echo "─── Binary Analysis ───"
TOOLS_BIN="checksec ltrace strace upx-ucl"
for tool in $TOOLS_BIN; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[*] Installing $tool..."
        sudo apt install -y -qq "$tool" 2>/dev/null
    else
        echo "[+] $tool: available"
    fi
done

# ROPgadget
if ! command -v ROPgadget &>/dev/null; then
    echo "[*] Installing ROPgadget..."
    pip3 install --quiet ROPgadget 2>/dev/null
else
    echo "[+] ROPgadget: available"
fi

# one_gadget (Ruby)
if command -v gem &>/dev/null; then
    if ! command -v one_gadget &>/dev/null; then
        echo "[*] Installing one_gadget..."
        sudo gem install one_gadget 2>/dev/null
    else
        echo "[+] one_gadget: available"
    fi
else
    echo "[-] Ruby not found — skipping one_gadget"
fi

# seccomp-tools (Ruby)
if command -v gem &>/dev/null; then
    if ! command -v seccomp-tools &>/dev/null; then
        echo "[*] Installing seccomp-tools..."
        sudo gem install seccomp-tools 2>/dev/null
    else
        echo "[+] seccomp-tools: available"
    fi
fi

# patchelf
if ! command -v patchelf &>/dev/null; then
    echo "[*] Installing patchelf..."
    sudo apt install -y -qq patchelf 2>/dev/null
else
    echo "[+] patchelf: available"
fi

# ─── Verify ────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════"
echo "  Verification"
echo "═══════════════════════════════════════════"
echo -n "python3:     "; python3 --version 2>&1
echo -n "pwntools:    "; python3 -c "import pwn; print(pwn.version)" 2>/dev/null || echo "NOT FOUND"
echo -n "z3:          "; python3 -c "import z3; print('OK')" 2>/dev/null || echo "NOT FOUND"
echo -n "gdb:         "; gdb --version 2>&1 | head -1
echo -n "ROPgadget:   "; ROPgadget --version 2>/dev/null || echo "NOT FOUND"
echo -n "checksec:    "; checksec --version 2>/dev/null || echo "NOT FOUND"
echo -n "patchelf:    "; patchelf --version 2>/dev/null || echo "NOT FOUND"
echo -n "one_gadget:  "; one_gadget --version 2>/dev/null || echo "NOT FOUND"
printf "seccomp-tools:"; seccomp-tools --version 2>/dev/null || printf " NOT FOUND\n"

echo ""
echo "[+] Setup complete! Run 'pip3 install angr' separately if needed."
