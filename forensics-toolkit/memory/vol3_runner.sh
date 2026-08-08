#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAG_PATTERNS="${FLAG_PATTERNS:-flag\{[^}]*\}|CTF\{[^}]*\}|ctf\{[^}]*\}|FLAG:.*|picoCTF\{[^}]*\}|HTB\{[^}]*\}}"
TOOLKIT_ROOT="$(pwd)"
OUT_DIR="${OUT_DIR:-${TOOLKIT_ROOT}/output}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
TSHARK="${TSHARK:-tshark}"
VOL3="${VOL3:-vol}"
BINWALK="${BINWALK:-binwalk}"
FOREMOST="${FOREMOST:-foremost}"
EXIFTOOL="${EXIFTOOL:-exiftool}"
PHOTOREC="${PHOTOREC:-photorec}"
ZSTEG="${ZSTEG:-zsteg}"
STEGHIDE="${STEGHIDE:-steghide}"
STEGSEEK="${STEGSEEK:-stegseek}"
BULK_EXTRACTOR="${BULK_EXTRACTOR:-bulk_extractor}"
TCPFLOW="${TCPFLOW:-tcpflow}"
FLS="${FLS:-fls}"
MACTIME="${MACTIME:-mactime}"
STEGO_WORDLIST="${STEGO_WORDLIST:-/usr/share/wordlists/rockyou.txt}"
MAX_CARVE_DEPTH="${MAX_CARVE_DEPTH:-3}"
RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
CYAN='[0;36m'
MAGENTA='[0;35m'
BOLD='[1m'
NC='[0m'
banner() { echo -e "${CYAN}${BOLD}
==============================================================
  $1
==============================================================${NC}"; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; }
highlight(){ echo -e "${MAGENTA}[*]${NC} $*"; }
section() { echo -e "
${CYAN}${BOLD}── $* ──${NC}"; }
require_tool() {
    local tool="$1"
    local var_name="$2"
    local cmd="${!var_name:-$tool}"
    if ! command -v "$cmd" &>/dev/null; then
        warn "Tool not found: ${tool} (looked for: ${cmd}). Some features may be unavailable."
        return 1
    fi
    return 0
}
make_output_dir() {
    local category="$1"
    local dir="${OUT_DIR}/${category}/${TIMESTAMP}"
    mkdir -p "$dir"
    echo "$dir"
}
file_summary() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        local count
        count=$(find "$dir" -type f 2>/dev/null | wc -l)
        info "Extracted ${count} file(s) to ${dir}"
    fi
}
run_flag_grep() {
    local target="$1"
    local extra="${2:-}"
    local combined_pattern="${FLAG_PATTERNS}"
    if [[ -n "$extra" ]]; then combined_pattern="${combined_pattern}|${extra}"; fi
    if [[ ! -e "$target" ]]; then return 1; fi
    banner "FLAG GREP — Scanning: $(basename "$target")"
    local found=0
    section "Pass 1: Direct text grep"
    local results
    results=$(grep -rEaoI "${combined_pattern}" "$target" 2>/dev/null || true)
    if [[ -n "$results" ]]; then
        echo "$results" | sort -u | while IFS= read -r line; do highlight "FOUND: ${line}"; done
        found=1
    fi
    section "Pass 2: Strings extraction on binaries"
    if command -v strings &>/dev/null; then
        while IFS= read -r -d '' file; do
            local local_size
            local_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
            if (( local_size > 104857600 )); then continue; fi
            local str_results
            str_results=$(strings -a "$file" 2>/dev/null | grep -Eo "${combined_pattern}" 2>/dev/null || true)
            if [[ -n "$str_results" ]]; then
                echo "$str_results" | sort -u | while IFS= read -r line; do highlight "FOUND (strings): ${file}: ${line}"; done
                found=1
            fi
        done < <(find "$target" -type f -print0 2>/dev/null)
    fi
    section "Pass 3: Base64 decode check"
    while IFS= read -r -d '' file; do
        local b64
        b64=$(grep -oEI '[A-Za-z0-9+/]{20,}={0,2}' "$file" 2>/dev/null | head -100 || true)
        if [[ -n "$b64" ]]; then
            while IFS= read -r blob; do
                local decoded
                decoded=$(echo "$blob" | base64 -d 2>/dev/null || true)
                local match
                match=$(echo "$decoded" | grep -Eo "${combined_pattern}" 2>/dev/null || true)
                if [[ -n "$match" ]]; then
                    highlight "FOUND (base64): ${file}: ${match}"
                    found=1
                fi
            done <<< "$b64"
        fi
    done < <(find "$target" -type f -size -10M -print0 2>/dev/null)
    echo ""
    if [[ $found -eq 1 ]]; then
        echo -e "${GREEN}${BOLD}[✓] Flag patterns detected! Check highlights above.${NC}"
    else
        info "No flag patterns found in this pass."
    fi
}

usage() {
    echo "Usage: $(basename "$0") <memory_dump> [output_dir]"
    echo ""
    echo "  memory_dump   Path to the RAM dump file"
    echo "  output_dir    Optional output directory"
    echo ""
    echo "Auto-detects OS and runs the standard Volatility 3 plugin battery."
    echo ""
    echo "Environment:"
    echo "  VOL3          Path to Volatility 3 CLI (default: vol)"
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

DUMP="$1"
[[ ! -f "$DUMP" ]] && { error "Memory dump not found: ${DUMP}"; exit 1; }

OUT="${2:-$(make_output_dir memory)/vol3_plugins}"
mkdir -p "$OUT"

require_tool "$VOL3" VOL3 || {
    for alt in vol vol.py vol3 python3\ -m\ volatility3; do
        if command -v $alt &>/dev/null; then
            VOL3="$alt"
            break
        fi
    done
    command -v $VOL3 &>/dev/null || { error "Volatility 3 not found. Install: pip install volatility3"; exit 1; }
}

banner "VOLATILITY 3 RUNNER â€” $(basename "$DUMP")"
info "Using: $($VOL3 --help 2>&1 | head -1 || echo "$VOL3")"
info "Output: ${OUT}"

section "Detecting OS type"

detect_os() {
    if $VOL3 -f "$DUMP" windows.info 2>/dev/null | grep -qi "windows\|ntoskrnl\|ntkrnl"; then
        echo "windows"
        return
    fi
    if $VOL3 -f "$DUMP" linux.pslist 2>/dev/null | head -5 | grep -qi "PID\|COMM"; then
        echo "linux"
        return
    fi
    if $VOL3 -f "$DUMP" mac.pslist 2>/dev/null | head -5 | grep -qi "PID\|COMM"; then
        echo "mac"
        return
    fi
    echo "unknown"
}

OS_TYPE=$(detect_os)
info "Detected OS: ${OS_TYPE}"
echo "$OS_TYPE" > "${OUT}/os_type.txt"

declare -a PLUGINS

case "$OS_TYPE" in
    windows)
        PLUGINS=(
            "windows.pslist"
            "windows.pstree"
            "windows.cmdline"
            "windows.netscan"
            "windows.netstat"
            "windows.filescan"
            "windows.malfind"
            "windows.dlllist"
            "windows.hashdump"
            "windows.registry.printkey"
            "windows.registry.hivelist"
            "windows.envars"
            "windows.svcscan"
            "windows.handles"
            "windows.info"
            "windows.modules"
            "windows.driverscan"
            "windows.ssdt"
            "windows.mutantscan"
        )
        ;;
    linux)
        PLUGINS=(
            "linux.pslist"
            "linux.pstree"
            "linux.bash"
            "linux.check_syscall"
            "linux.lsof"
            "linux.mount"
            "linux.tty_check"
            "linux.elfs"
            "linux.proc.Maps"
            "linux.check_modules"
            "linux.sockstat"
        )
        ;;
    mac)
        PLUGINS=(
            "mac.pslist"
            "mac.pstree"
            "mac.bash"
            "mac.lsof"
            "mac.mount"
            "mac.netstat"
            "mac.check_syscall"
            "mac.ifconfig"
        )
        ;;
    *)
        warn "Could not detect OS. Trying common Windows plugins..."
        OS_TYPE="windows"
        PLUGINS=(
            "windows.pslist"
            "windows.pstree"
            "windows.cmdline"
            "windows.netscan"
            "windows.filescan"
            "windows.malfind"
        )
        ;;
esac

section "Running ${#PLUGINS[@]} plugins"

FAILED=0
SUCCESS=0

for plugin in "${PLUGINS[@]}"; do
    PLUGIN_NAME=$(echo "$plugin" | tr '.' '_')
    OUTFILE="${OUT}/${PLUGIN_NAME}.txt"

    echo -ne "  Running ${plugin}... "

    if $VOL3 -f "$DUMP" "$plugin" > "$OUTFILE" 2>"${OUT}/${PLUGIN_NAME}.err"; then
        SIZE=$(wc -l < "$OUTFILE")
        if [[ $SIZE -gt 1 ]]; then
            echo -e "${GREEN}OK${NC} (${SIZE} lines)"
            ((SUCCESS++))
        else
            echo -e "${YELLOW}empty${NC}"
            rm -f "$OUTFILE"
        fi
    else
        echo -e "${RED}failed${NC}"
        ((FAILED++))
        rm -f "$OUTFILE"
    fi
done

section "Plugin Summary"
info "Successful: ${SUCCESS}/${#PLUGINS[@]}"
[[ $FAILED -gt 0 ]] && warn "Failed: ${FAILED}/${#PLUGINS[@]} (check .err files for details)"

section "Quick Analysis"

if [[ -f "${OUT}/windows_pslist.txt" ]]; then
    info "Process list (first 30):"
    head -32 "${OUT}/windows_pslist.txt"
fi

if [[ -f "${OUT}/windows_cmdline.txt" ]]; then
    echo ""
    info "Command lines:"
    cat "${OUT}/windows_cmdline.txt" | grep -v "^$" | head -30
fi

if [[ -f "${OUT}/windows_netscan.txt" ]]; then
    echo ""
    info "Network connections:"
    head -20 "${OUT}/windows_netscan.txt"
fi

if [[ -f "${OUT}/windows_malfind.txt" ]]; then
    MALFIND_COUNT=$(grep -c "^0x" "${OUT}/windows_malfind.txt" 2>/dev/null || echo 0)
    if [[ $MALFIND_COUNT -gt 0 ]]; then
        warn "Malfind flagged ${MALFIND_COUNT} suspicious memory region(s)!"
    fi
fi

section "Flag scan on plugin output"
run_flag_grep "$OUT"

info "Volatility 3 analysis complete. Output: ${OUT}"
