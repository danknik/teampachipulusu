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
    echo "  disk_image    Path to the disk image"
    echo "  output_dir    Optional output directory"
    echo ""
    echo "Recovers deleted files using photorec and tsk_recover."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

IMAGE="$1"
[[ ! -f "$IMAGE" ]] && { error "Image not found: ${IMAGE}"; exit 1; }

OUT="${2:-$(make_output_dir disk)/recovered}"
mkdir -p "$OUT"

banner "DELETED FILE RECOVERY â€” $(basename "$IMAGE")"

RECOVERED=0

if command -v "$PHOTOREC" &>/dev/null; then
    section "Running photorec"
    PR_OUT="${OUT}/photorec"
    mkdir -p "$PR_OUT"

    info "Starting photorec in non-interactive mode..."
    info "This may take a while for large images..."

    $PHOTOREC /d "$PR_OUT" /cmd "$IMAGE" partition_none,options,mode_ext2,fileopt,everything,enable,search \
        > "${OUT}/photorec.log" 2>&1 || {
        warn "Primary photorec invocation failed, trying alternate..."
        $PHOTOREC /d "$PR_OUT" /cmd "$IMAGE" search \
            > "${OUT}/photorec.log" 2>&1 || warn "photorec failed (check ${OUT}/photorec.log)"
    }

    PR_COUNT=$(find "$PR_OUT" -type f 2>/dev/null | wc -l)
    if [[ $PR_COUNT -gt 0 ]]; then
        info "photorec recovered ${PR_COUNT} file(s)"
        RECOVERED=$((RECOVERED + PR_COUNT))

        section "Recovered file types (photorec)"
        find "$PR_OUT" -type f | xargs file 2>/dev/null \
            | awk -F: '{print $2}' | sort | uniq -c | sort -rn | head -20
    else
        info "photorec recovered no files"
    fi
else
    warn "photorec not found. Install: apt install testdisk"
fi

if command -v tsk_recover &>/dev/null; then
    section "Running tsk_recover"
    TSK_OUT="${OUT}/tsk_recover"
    mkdir -p "$TSK_OUT"

    echo -ne "  tsk_recover (all files)... "
    tsk_recover -a "$IMAGE" "$TSK_OUT" > "${OUT}/tsk_recover.log" 2>&1 \
        && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}failed${NC}"

    TSK_COUNT=$(find "$TSK_OUT" -type f 2>/dev/null | wc -l)
    if [[ $TSK_COUNT -gt 0 ]]; then
        info "tsk_recover extracted ${TSK_COUNT} file(s)"
        RECOVERED=$((RECOVERED + TSK_COUNT))
    fi
else
    info "tsk_recover not found â€” skipping (part of Sleuthkit)"
fi

if command -v icat &>/dev/null && command -v "$FLS" &>/dev/null; then
    section "Recovering deleted files via icat"
    ICAT_OUT="${OUT}/icat_recovered"
    mkdir -p "$ICAT_OUT"

    DELETED_LIST=$($FLS -r -d "$IMAGE" 2>/dev/null || true)
    if [[ -n "$DELETED_LIST" ]]; then
        ICAT_COUNT=0
        echo "$DELETED_LIST" | head -200 | while IFS= read -r line; do
            INODE=$(echo "$line" | grep -oP '\*?\s*\K\d+(?=(-\d+)?(-\d+)?\s*:)' 2>/dev/null || true)
            FNAME=$(echo "$line" | grep -oP ':\s*\K.*' 2>/dev/null || true)

            if [[ -n "$INODE" ]]; then
                SAFE_NAME=$(echo "$FNAME" | tr -c 'a-zA-Z0-9._-' '_' | head -c 100)
                [[ -z "$SAFE_NAME" ]] && SAFE_NAME="inode_${INODE}"

                icat "$IMAGE" "$INODE" > "${ICAT_OUT}/${SAFE_NAME}" 2>/dev/null || true

                if [[ ! -s "${ICAT_OUT}/${SAFE_NAME}" ]]; then
                    rm -f "${ICAT_OUT}/${SAFE_NAME}"
                else
                    ((ICAT_COUNT++)) || true
                fi
            fi
        done

        ICAT_TOTAL=$(find "$ICAT_OUT" -type f 2>/dev/null | wc -l)
        info "Recovered ${ICAT_TOTAL} deleted file(s) via icat"
        RECOVERED=$((RECOVERED + ICAT_TOTAL))
    fi
fi

section "Recovery Summary"
info "Total recovered files: ${RECOVERED}"

if [[ $RECOVERED -gt 0 ]]; then
    section "All recovered file types"
    find "$OUT" -type f -not -name "*.log" -not -name "*.txt" | head -500 \
        | xargs file 2>/dev/null | awk -F: '{print $2}' | sort | uniq -c | sort -rn | head -20
fi

section "Flag scan on recovered files"
run_flag_grep "$OUT"

info "Recovery complete. Output: ${OUT}"
