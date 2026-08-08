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
    echo "Usage: $(basename "$0") <disk_image> [output_dir]"
    echo ""
    echo "  disk_image    Path to disk image / suspicious file"
    echo "  output_dir    Optional output directory"
    echo ""
    echo "Environment:"
    echo "  MAX_CARVE_DEPTH   Recursion depth limit (default: ${MAX_CARVE_DEPTH})"
    echo ""
    echo "Recursively carves files from disk images using binwalk + foremost."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

IMAGE="$1"
[[ ! -f "$IMAGE" ]] && { error "Image not found: ${IMAGE}"; exit 1; }

OUT="${2:-$(make_output_dir disk)/carved}"
mkdir -p "$OUT"

banner "RECURSIVE CARVER â€” $(basename "$IMAGE")"
info "Max recursion depth: ${MAX_CARVE_DEPTH}"

TOTAL_CARVED=0

carve_recursive() {
    local target="$1"
    local depth="$2"
    local out_base="$3"

    if [[ $depth -gt $MAX_CARVE_DEPTH ]]; then
        warn "Max recursion depth (${MAX_CARVE_DEPTH}) reached at: $(basename "$target")"
        return
    fi

    local indent=""
    for ((i=0; i<depth; i++)); do indent+="  "; done

    echo -e "${indent}${CYAN}[depth ${depth}]${NC} Carving: $(basename "$target")"

    local carve_dir="${out_base}/depth_${depth}/$(basename "$target" | tr ' ' '_')_carved"
    mkdir -p "$carve_dir"

    local new_files=()

    if command -v "$BINWALK" &>/dev/null; then
        echo -ne "${indent}  binwalk... "
        local bw_dir="${carve_dir}/binwalk"
        mkdir -p "$bw_dir"

        $BINWALK -e -C "$bw_dir" "$target" > "${carve_dir}/binwalk.log" 2>&1 || true

        local bw_count
        bw_count=$(find "$bw_dir" -type f 2>/dev/null | wc -l)
        echo -e "${GREEN}${bw_count} file(s)${NC}"

        if [[ $bw_count -gt 0 ]]; then
            while IFS= read -r -d '' f; do
                new_files+=("$f")
            done < <(find "$bw_dir" -type f -size +0c -print0 2>/dev/null)
            TOTAL_CARVED=$((TOTAL_CARVED + bw_count))
        fi

        $BINWALK -E -C "$bw_dir" "$target" > "${carve_dir}/entropy.log" 2>&1 || true
    fi

    if command -v "$FOREMOST" &>/dev/null; then
        echo -ne "${indent}  foremost... "
        local fm_dir="${carve_dir}/foremost"
        mkdir -p "$fm_dir"

        $FOREMOST -i "$target" -o "$fm_dir" -T > /dev/null 2>&1 || true

        local fm_count
        fm_count=$(find "$fm_dir" -type f -not -name "audit.txt" 2>/dev/null | wc -l)
        echo -e "${GREEN}${fm_count} file(s)${NC}"

        if [[ $fm_count -gt 0 ]]; then
            while IFS= read -r -d '' f; do
                new_files+=("$f")
            done < <(find "$fm_dir" -type f -size +0c -not -name "audit.txt" -print0 2>/dev/null)
            TOTAL_CARVED=$((TOTAL_CARVED + fm_count))
        fi
    fi

    if command -v scalpel &>/dev/null; then
        echo -ne "${indent}  scalpel... "
        local sc_dir="${carve_dir}/scalpel"
        mkdir -p "$sc_dir"

        scalpel -o "$sc_dir" "$target" > /dev/null 2>&1 || true

        local sc_count
        sc_count=$(find "$sc_dir" -type f -not -name "audit.txt" 2>/dev/null | wc -l)
        echo -e "${GREEN}${sc_count} file(s)${NC}"
        TOTAL_CARVED=$((TOTAL_CARVED + sc_count))
    fi

    MATCH=$(grep -rEao "${FLAG_PATTERNS}" "$carve_dir" 2>/dev/null || true)
    if [[ -n "$MATCH" ]]; then
        echo "$MATCH" | sort -u | while IFS= read -r line; do
            highlight "${indent}  FLAG: ${line}"
        done
    fi

    local next_depth=$((depth + 1))
    for f in "${new_files[@]}"; do
        local fsize
        fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
        if [[ $fsize -gt 100 ]]; then
            local ftype
            ftype=$(file -b "$f" 2>/dev/null || echo "")
            if echo "$ftype" | grep -qiE "archive|zip|gzip|bzip|xz|tar|compress|image|firmware|filesystem|data|executable"; then
                carve_recursive "$f" "$next_depth" "$out_base"
            fi
        fi
    done
}

section "Starting recursive carve"
carve_recursive "$IMAGE" 0 "$OUT"

section "Carving Summary"
info "Total files carved (all depths): ${TOTAL_CARVED}"
file_summary "$OUT"

section "Final flag scan on all carved output"
run_flag_grep "$OUT"

info "Carving complete. Output: ${OUT}"
