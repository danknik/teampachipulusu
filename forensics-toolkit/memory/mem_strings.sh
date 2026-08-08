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
    echo "Performs comprehensive string/regex search across the memory dump."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

DUMP="$1"
[[ ! -f "$DUMP" ]] && { error "Memory dump not found: ${DUMP}"; exit 1; }

OUT="${2:-$(make_output_dir memory)/strings}"
mkdir -p "$OUT"

DUMP_SIZE=$(stat -c%s "$DUMP" 2>/dev/null || stat -f%z "$DUMP" 2>/dev/null || echo "unknown")
banner "MEMORY STRINGS â€” $(basename "$DUMP") (${DUMP_SIZE} bytes)"

section "Extracting ASCII strings"
echo -ne "  Running strings -a... "
strings -a "$DUMP" > "${OUT}/strings_ascii.txt" 2>/dev/null
ASCII_COUNT=$(wc -l < "${OUT}/strings_ascii.txt")
echo -e "${GREEN}OK${NC} (${ASCII_COUNT} strings)"

section "Extracting Unicode (UTF-16LE) strings"
echo -ne "  Running strings -el... "
strings -a -el "$DUMP" > "${OUT}/strings_unicode.txt" 2>/dev/null
UNI_COUNT=$(wc -l < "${OUT}/strings_unicode.txt")
echo -e "${GREEN}OK${NC} (${UNI_COUNT} strings)"

section "Searching for flag patterns"
{
    grep -Eo "${FLAG_PATTERNS}" "${OUT}/strings_ascii.txt" 2>/dev/null || true
    grep -Eo "${FLAG_PATTERNS}" "${OUT}/strings_unicode.txt" 2>/dev/null || true
} | sort -u > "${OUT}/flags_found.txt"

FLAG_COUNT=$(wc -l < "${OUT}/flags_found.txt")
if [[ $FLAG_COUNT -gt 0 ]]; then
    highlight "Found ${FLAG_COUNT} potential flag(s)!"
    cat "${OUT}/flags_found.txt" | while IFS= read -r flag; do
        highlight "  ${flag}"
    done
else
    info "No flag patterns found in strings"
fi

section "Extracting base64 blobs"
grep -oE '[A-Za-z0-9+/]{30,}={0,2}' "${OUT}/strings_ascii.txt" 2>/dev/null \
    | sort -u > "${OUT}/base64_blobs.txt" || true

B64_COUNT=$(wc -l < "${OUT}/base64_blobs.txt")
info "Found ${B64_COUNT} potential base64 blob(s)"

if [[ $B64_COUNT -gt 0 ]]; then
    > "${OUT}/base64_decoded.txt"
    head -200 "${OUT}/base64_blobs.txt" | while IFS= read -r blob; do
        DECODED=$(echo "$blob" | base64 -d 2>/dev/null || true)
        if [[ -n "$DECODED" ]]; then
            echo "--- BLOB ---" >> "${OUT}/base64_decoded.txt"
            echo "Encoded: ${blob:0:80}..." >> "${OUT}/base64_decoded.txt"
            echo "Decoded: ${DECODED:0:200}" >> "${OUT}/base64_decoded.txt"
            echo "" >> "${OUT}/base64_decoded.txt"

            MATCH=$(echo "$DECODED" | grep -Eo "${FLAG_PATTERNS}" 2>/dev/null || true)
            if [[ -n "$MATCH" ]]; then
                highlight "FLAG in base64: ${MATCH}"
            fi
        fi
    done
fi

section "Extracting URLs"
grep -oEi 'https?://[^\s"<>]+' "${OUT}/strings_ascii.txt" 2>/dev/null \
    | sort -u > "${OUT}/urls.txt" || true
URL_COUNT=$(wc -l < "${OUT}/urls.txt")
info "Found ${URL_COUNT} URL(s)"
[[ $URL_COUNT -gt 0 ]] && head -30 "${OUT}/urls.txt"

section "Extracting IP addresses"
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${OUT}/strings_ascii.txt" 2>/dev/null \
    | sort | uniq -c | sort -rn > "${OUT}/ip_addresses.txt" || true
IP_COUNT=$(wc -l < "${OUT}/ip_addresses.txt")
info "Found ${IP_COUNT} unique IP address(es)"
[[ $IP_COUNT -gt 0 ]] && head -20 "${OUT}/ip_addresses.txt"

section "Extracting email addresses"
grep -oEi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "${OUT}/strings_ascii.txt" 2>/dev/null \
    | sort -u > "${OUT}/emails.txt" || true
EMAIL_COUNT=$(wc -l < "${OUT}/emails.txt")
info "Found ${EMAIL_COUNT} email address(es)"
[[ $EMAIL_COUNT -gt 0 ]] && cat "${OUT}/emails.txt"

section "Searching for credential-like strings"
grep -iE 'password|passwd|pwd|secret|token|api.key|authorization|bearer|private.key' \
    "${OUT}/strings_ascii.txt" 2>/dev/null \
    | sort -u | head -50 > "${OUT}/credential_strings.txt" || true
CRED_COUNT=$(wc -l < "${OUT}/credential_strings.txt")
if [[ $CRED_COUNT -gt 0 ]]; then
    warn "Found ${CRED_COUNT} credential-like string(s)"
    head -20 "${OUT}/credential_strings.txt"
fi

section "Extracting file paths"
grep -oE '([A-Z]:\\[^\s"]{5,}|/[a-z][^\s"]{5,})' "${OUT}/strings_ascii.txt" 2>/dev/null \
    | sort -u | head -100 > "${OUT}/file_paths.txt" || true
PATH_COUNT=$(wc -l < "${OUT}/file_paths.txt")
info "Found ${PATH_COUNT} file path(s)"

if command -v "$BULK_EXTRACTOR" &>/dev/null; then
    section "Running bulk_extractor"
    BE_OUT="${OUT}/bulk_extractor"
    mkdir -p "$BE_OUT"

    echo -ne "  bulk_extractor running... "
    $BULK_EXTRACTOR -o "$BE_OUT" "$DUMP" > "${BE_OUT}/be.log" 2>&1 \
        && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}completed with warnings${NC}"

    run_flag_grep "$BE_OUT"
else
    info "bulk_extractor not found â€” skipping (install: apt install bulk-extractor)"
fi

section "Summary"
info "ASCII strings:   ${ASCII_COUNT}"
info "Unicode strings: ${UNI_COUNT}"
info "Flags found:     ${FLAG_COUNT}"
info "Base64 blobs:    ${B64_COUNT}"
info "URLs:            ${URL_COUNT}"
info "IPs:             ${IP_COUNT}"
info "Emails:          ${EMAIL_COUNT}"
info "Cred strings:    ${CRED_COUNT}"
info "File paths:      ${PATH_COUNT}"
info "Output:          ${OUT}"
