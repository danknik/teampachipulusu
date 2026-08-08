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
    echo "Usage: $(basename "$0") <pcap_file> [options]"
    echo ""
    echo "  pcap_file        Path to the PCAP/PCAPNG capture file"
    echo ""
    echo "Options:"
    echo "  --skip-streams   Skip stream reassembly (faster, for huge captures)"
    echo "  --dry-run        Print commands without executing"
    echo "  --help, -h       Show this help"
    echo ""
    echo "Master orchestrator â€” runs all network analysis scripts in sequence."
    exit 1
}

PCAP=""
SKIP_STREAMS=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-streams) SKIP_STREAMS=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --help|-h)      usage ;;
        *)              PCAP="$1"; shift ;;
    esac
done

[[ -z "$PCAP" ]] && usage
[[ ! -f "$PCAP" ]] && { error "PCAP file not found: ${PCAP}"; exit 1; }

RUN_OUT=$(make_output_dir network)
info "Output directory: ${RUN_OUT}"

banner "NETWORK FORENSICS â€” $(basename "$PCAP")"
echo -e "  PCAP:   ${PCAP}"
echo -e "  Output: ${RUN_OUT}"
echo -e "  Time:   $(date)"
echo ""

START_TIME=$(date +%s)

run_script() {
    local name="$1"
    local script="$2"
    shift 2

    section "Running: ${name}"
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would execute: ${script} $*"
        return
    fi

    if [[ -x "$script" ]]; then
        "$script" "$@" 2>&1 | tee "${RUN_OUT}/${name}.log" || warn "${name} completed with errors"
    else
        bash "$script" "$@" 2>&1 | tee "${RUN_OUT}/${name}.log" || warn "${name} completed with errors"
    fi
    echo ""
}

run_script "conv_stats" "${SCRIPT_DIR}/conv_stats.sh" "$PCAP" "${RUN_OUT}/conv_stats"

run_script "export_objects" "${SCRIPT_DIR}/export_objects.sh" "$PCAP" "${RUN_OUT}/exported_objects"

run_script "cred_grabber" "${SCRIPT_DIR}/cred_grabber.sh" "$PCAP" "${RUN_OUT}/credentials"

run_script "dns_exfil" "${SCRIPT_DIR}/dns_exfil.sh" "$PCAP" "${RUN_OUT}/dns_exfil"

if [[ "$SKIP_STREAMS" == false ]]; then
    run_script "stream_extract" "${SCRIPT_DIR}/stream_extract.sh" "$PCAP" "${RUN_OUT}/streams"
else
    info "Skipping stream extraction (--skip-streams)"
fi

section "FINAL FLAG SCAN"
run_flag_grep "$RUN_OUT"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

banner "NETWORK ANALYSIS COMPLETE"
echo -e "  Duration: ${ELAPSED}s"
echo -e "  Output:   ${RUN_OUT}"
echo ""

TOTAL_FILES=$(find "$RUN_OUT" -type f 2>/dev/null | wc -l)
info "Total output files: ${TOTAL_FILES}"

echo ""
section "Flags found across all analysis"
grep -rEh "${FLAG_PATTERNS}" "${RUN_OUT}" 2>/dev/null | sort -u | while IFS= read -r line; do
    highlight "$line"
done || info "No flags found in this run"
