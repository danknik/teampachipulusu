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
    echo "Usage: $(basename "$0") <memory_dump> <vol3_output_dir> [output_dir]"
    echo ""
    echo "  memory_dump      Path to the RAM dump file"
    echo "  vol3_output_dir  Directory containing vol3_runner.sh output"
    echo "  output_dir       Optional output directory for extracted files"
    echo ""
    echo "Extracts all file objects found via filescan from the memory dump."
    exit 1
}

[[ $# -lt 2 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

DUMP="$1"
VOL_OUT="$2"
[[ ! -f "$DUMP" ]] && { error "Memory dump not found: ${DUMP}"; exit 1; }
[[ ! -d "$VOL_OUT" ]] && { error "Vol3 output dir not found: ${VOL_OUT}"; exit 1; }

OUT="${3:-$(make_output_dir memory)/extracted_files}"
mkdir -p "$OUT"

require_tool "$VOL3" VOL3 || { error "Volatility 3 not found"; exit 1; }

banner "FILE EXTRACTOR â€” $(basename "$DUMP")"

OS_TYPE="windows"
[[ -f "${VOL_OUT}/os_type.txt" ]] && OS_TYPE=$(cat "${VOL_OUT}/os_type.txt")

FILESCAN="${VOL_OUT}/${OS_TYPE}_filescan.txt"

if [[ ! -f "$FILESCAN" ]]; then
    section "Running filescan (not found in vol3 output)"
    $VOL3 -f "$DUMP" "${OS_TYPE}.filescan" > "$FILESCAN" 2>/dev/null || {
        error "filescan failed"; exit 1;
    }
fi

TOTAL_FILES=$(tail -n +3 "$FILESCAN" | grep -c "0x" 2>/dev/null || echo 0)
info "Total file objects in memory: ${TOTAL_FILES}"

section "Extracting file objects"

OFFSETS=$(awk '/^0x/{print $1}' "$FILESCAN" 2>/dev/null | sort -u)
OFFSET_COUNT=$(echo "$OFFSETS" | grep -c "0x" 2>/dev/null || echo 0)

info "Attempting to dump ${OFFSET_COUNT} file object(s)..."

echo -ne "  Running dumpfiles... "
$VOL3 -f "$DUMP" -o "$OUT" "${OS_TYPE}.dumpfiles" \
    > "${OUT}/dumpfiles.log" 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}partial${NC}"

EXTRACTED=$(find "$OUT" -type f -not -name "*.log" -not -name "*.txt" | wc -l)
info "Successfully extracted: ${EXTRACTED} file(s)"

section "Identifying extracted file types"
FILE_TYPES="${OUT}/file_types.txt"
> "$FILE_TYPES"

find "$OUT" -type f -not -name "*.log" -not -name "*.txt" | while read -r f; do
    TYPE=$(file -b "$f" 2>/dev/null || echo "unknown")
    SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "?")
    echo "$(basename "$f") | ${SIZE} bytes | ${TYPE}" | tee -a "$FILE_TYPES"
done

section "Categorizing interesting files"

info "Executables:"
find "$OUT" -type f | while read -r f; do
    if file -b "$f" 2>/dev/null | grep -qiE "executable|ELF|PE32|Mach-O|DLL"; then
        warn "  EXE/DLL: $(basename "$f") â€” $(file -b "$f" 2>/dev/null | head -c 80)"
    fi
done

info "Documents/Archives:"
find "$OUT" -type f | while read -r f; do
    if file -b "$f" 2>/dev/null | grep -qiE "PDF|Office|Word|Excel|Zip|RAR|7-zip|gzip|text"; then
        info "  DOC: $(basename "$f") â€” $(file -b "$f" 2>/dev/null | head -c 80)"
    fi
done

info "Images:"
find "$OUT" -type f | while read -r f; do
    if file -b "$f" 2>/dev/null | grep -qiE "image|JPEG|PNG|GIF|BMP|TIFF"; then
        info "  IMG: $(basename "$f") â€” $(file -b "$f" 2>/dev/null | head -c 80)"
    fi
done

section "Flag scan on extracted files"
run_flag_grep "$OUT"

section "Strings scan on small extracted files"
find "$OUT" -type f -size -5M -not -name "*.log" -not -name "*.txt" -not -name "*.strings" | while read -r f; do
    MATCH=$(strings -a "$f" 2>/dev/null | grep -Eo "${FLAG_PATTERNS}" 2>/dev/null || true)
    if [[ -n "$MATCH" ]]; then
        highlight "FLAG in $(basename "$f"): ${MATCH}"
    fi
done

info "File extraction complete. Output: ${OUT}"
