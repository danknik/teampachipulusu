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
    echo "Usage: $(basename "$0") <target_dir> [output_dir]"
    echo ""
    echo "  target_dir    Directory of files to scan metadata"
    echo "  output_dir    Optional output directory"
    echo ""
    echo "Extracts and searches all file metadata for flags and interesting data."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

TARGET="$1"
[[ ! -e "$TARGET" ]] && { error "Target not found: ${TARGET}"; exit 1; }

OUT="${2:-$(make_output_dir disk)/metadata}"
mkdir -p "$OUT"

require_tool "$EXIFTOOL" EXIFTOOL || { error "exiftool is required. Install: apt install libimage-exiftool-perl"; exit 1; }

FILE_COUNT=$(find "$TARGET" -type f 2>/dev/null | wc -l)
banner "METADATA SWEEP â€” ${FILE_COUNT} file(s)"

section "Extracting all metadata"
echo -ne "  Running exiftool -r... "
$EXIFTOOL -r "$TARGET" > "${OUT}/all_metadata.txt" 2>/dev/null || true
META_LINES=$(wc -l < "${OUT}/all_metadata.txt")
echo -e "${GREEN}OK${NC} (${META_LINES} lines)"

echo -ne "  JSON export... "
$EXIFTOOL -r -j "$TARGET" > "${OUT}/all_metadata.json" 2>/dev/null || true
echo -e "${GREEN}OK${NC}"

section "Flag patterns in metadata"
FOUND_FLAGS=$(grep -Eo "${FLAG_PATTERNS}" "${OUT}/all_metadata.txt" 2>/dev/null || true)
if [[ -n "$FOUND_FLAGS" ]]; then
    echo "$FOUND_FLAGS" | sort -u | while IFS= read -r flag; do
        highlight "FLAG IN METADATA: ${flag}"
    done
else
    info "No flag patterns in metadata"
fi

section "Comment fields"
grep -iE "^(Comment|User Comment|Image Description|Description|XP Comment|Notes)" \
    "${OUT}/all_metadata.txt" 2>/dev/null | sort -u | tee "${OUT}/comments.txt" || true

COMMENT_COUNT=$(wc -l < "${OUT}/comments.txt" 2>/dev/null || echo 0)
if [[ $COMMENT_COUNT -gt 0 ]]; then
    warn "Found ${COMMENT_COUNT} comment field(s) â€” check for hidden data!"
else
    info "No comment fields found"
fi

section "Author / Creator fields"
grep -iE "^(Author|Creator|Artist|Copyright|Owner|Producer|Created By)" \
    "${OUT}/all_metadata.txt" 2>/dev/null | sort -u | tee "${OUT}/authors.txt" || true

section "GPS / Location data"
grep -iE "^(GPS|Location|Country|City|State|Province)" \
    "${OUT}/all_metadata.txt" 2>/dev/null | sort -u | tee "${OUT}/gps_data.txt" || true

GPS_COUNT=$(wc -l < "${OUT}/gps_data.txt" 2>/dev/null || echo 0)
if [[ $GPS_COUNT -gt 0 ]]; then
    warn "Found ${GPS_COUNT} GPS/location field(s)"
fi

section "Interesting timestamps"
grep -iE "^(Date|Create Date|Modify Date|File Modification|Metadata Date)" \
    "${OUT}/all_metadata.txt" 2>/dev/null | sort -u | head -30 | tee "${OUT}/timestamps.txt" || true

section "Software / Tool information"
grep -iE "^(Software|Creator Tool|Producer|Encoding|Encoder|Application)" \
    "${OUT}/all_metadata.txt" 2>/dev/null | sort -u | tee "${OUT}/software.txt" || true

section "Extracting embedded thumbnails"
THUMB_DIR="${OUT}/thumbnails"
mkdir -p "$THUMB_DIR"

find "$TARGET" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.tiff" \) | while read -r img; do
    BASENAME=$(basename "$img" | tr ' ' '_')
    $EXIFTOOL -b -ThumbnailImage "$img" > "${THUMB_DIR}/${BASENAME}_thumb.jpg" 2>/dev/null || true
    [[ ! -s "${THUMB_DIR}/${BASENAME}_thumb.jpg" ]] && rm -f "${THUMB_DIR}/${BASENAME}_thumb.jpg"
done

THUMB_COUNT=$(find "$THUMB_DIR" -type f 2>/dev/null | wc -l)
if [[ $THUMB_COUNT -gt 0 ]]; then
    info "Extracted ${THUMB_COUNT} thumbnail(s) â€” sometimes thumbnails show original (unredacted) image!"
    run_flag_grep "$THUMB_DIR"
fi

section "All unique metadata field names"
awk -F: 'NF>=2 {gsub(/^[ \t]+/, "", $1); print $1}' "${OUT}/all_metadata.txt" 2>/dev/null \
    | sort -u > "${OUT}/field_names.txt"

info "Unique metadata fields: $(wc -l < "${OUT}/field_names.txt")"

grep -iE "secret|hidden|flag|password|key|encrypt|custom|user|note|embed" \
    "${OUT}/field_names.txt" 2>/dev/null | while IFS= read -r field; do
    warn "Unusual metadata field: ${field}"
    grep "^${field}" "${OUT}/all_metadata.txt" 2>/dev/null | head -5
done || true

section "Summary"
info "Total files scanned: ${FILE_COUNT}"
info "Metadata lines: ${META_LINES}"
info "Comments found: ${COMMENT_COUNT}"
info "GPS entries: ${GPS_COUNT}"
info "Thumbnails extracted: ${THUMB_COUNT}"
info "Output: ${OUT}"
