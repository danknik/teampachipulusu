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
    echo "Usage: $(basename "$0") <pcap_file> [output_dir]"
    echo ""
    echo "  pcap_file    Path to the PCAP/PCAPNG capture file"
    echo "  output_dir   Optional output directory"
    echo ""
    echo "Reassembles all TCP streams and searches for flags/interesting data."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

PCAP="$1"
[[ ! -f "$PCAP" ]] && { error "PCAP file not found: ${PCAP}"; exit 1; }

OUT="${2:-$(make_output_dir network)/streams}"
mkdir -p "$OUT/tcp" "$OUT/udp"

require_tool tshark TSHARK || { error "tshark is required"; exit 1; }

banner "STREAM EXTRACTOR â€” $(basename "$PCAP")"

section "Enumerating TCP streams"
MAX_TCP=$($TSHARK -r "$PCAP" -T fields -e tcp.stream 2>/dev/null \
    | sort -un | tail -1 || echo "-1")

if [[ "$MAX_TCP" == "-1" || -z "$MAX_TCP" ]]; then
    info "No TCP streams found"
    MAX_TCP=-1
else
    info "Found TCP streams: 0 to ${MAX_TCP}"
fi

if [[ $MAX_TCP -ge 0 ]]; then
    section "Reassembling TCP streams"

    STREAM_LIMIT=$((MAX_TCP > 500 ? 500 : MAX_TCP))
    [[ $MAX_TCP -gt 500 ]] && warn "Capping at 500 streams (total: $((MAX_TCP+1)))"

    for i in $(seq 0 "$STREAM_LIMIT"); do
        STREAM_FILE="${OUT}/tcp/stream_${i}.txt"
        STREAM_RAW="${OUT}/tcp/stream_${i}.raw"

        $TSHARK -r "$PCAP" -z "follow,tcp,ascii,${i}" -q 2>/dev/null > "$STREAM_FILE" 2>/dev/null || true

        $TSHARK -r "$PCAP" -z "follow,tcp,raw,${i}" -q 2>/dev/null > "$STREAM_RAW" 2>/dev/null || true

        if [[ ! -s "$STREAM_FILE" ]] || [[ $(wc -c < "$STREAM_FILE") -lt 50 ]]; then
            rm -f "$STREAM_FILE" "$STREAM_RAW"
            continue
        fi

        MATCH=$(grep -Eo "${FLAG_PATTERNS}" "$STREAM_FILE" 2>/dev/null || true)
        if [[ -n "$MATCH" ]]; then
            highlight "FLAG in TCP stream #${i}: ${MATCH}"
        fi

        STR_MATCH=$(strings -a "$STREAM_RAW" 2>/dev/null | grep -Eo "${FLAG_PATTERNS}" 2>/dev/null || true)
        if [[ -n "$STR_MATCH" ]]; then
            highlight "FLAG (strings) in TCP stream #${i}: ${STR_MATCH}"
        fi

        if (( i % 50 == 0 && i > 0 )); then
            info "Processed ${i}/${STREAM_LIMIT} streams..."
        fi
    done

    EXTRACTED=$(find "${OUT}/tcp" -type f -name "*.txt" | wc -l)
    info "Extracted ${EXTRACTED} non-empty TCP stream(s)"
fi

section "Enumerating UDP streams"
MAX_UDP=$($TSHARK -r "$PCAP" -T fields -e udp.stream 2>/dev/null \
    | sort -un | tail -1 || echo "-1")

if [[ "$MAX_UDP" == "-1" || -z "$MAX_UDP" ]]; then
    info "No UDP streams found"
else
    info "Found UDP streams: 0 to ${MAX_UDP}"

    UDP_LIMIT=$((MAX_UDP > 200 ? 200 : MAX_UDP))
    [[ $MAX_UDP -gt 200 ]] && warn "Capping at 200 UDP streams (total: $((MAX_UDP+1)))"

    for i in $(seq 0 "$UDP_LIMIT"); do
        STREAM_FILE="${OUT}/udp/stream_${i}.txt"
        $TSHARK -r "$PCAP" -z "follow,udp,ascii,${i}" -q 2>/dev/null > "$STREAM_FILE" 2>/dev/null || true

        if [[ ! -s "$STREAM_FILE" ]] || [[ $(wc -c < "$STREAM_FILE") -lt 20 ]]; then
            rm -f "$STREAM_FILE"
            continue
        fi

        MATCH=$(grep -Eo "${FLAG_PATTERNS}" "$STREAM_FILE" 2>/dev/null || true)
        if [[ -n "$MATCH" ]]; then
            highlight "FLAG in UDP stream #${i}: ${MATCH}"
        fi
    done

    EXTRACTED_UDP=$(find "${OUT}/udp" -type f -name "*.txt" | wc -l)
    info "Extracted ${EXTRACTED_UDP} non-empty UDP stream(s)"
fi

if command -v "$TCPFLOW" &>/dev/null; then
    section "Running tcpflow for full reassembly"
    TCPFLOW_DIR="${OUT}/tcpflow"
    mkdir -p "$TCPFLOW_DIR"
    $TCPFLOW -r "$PCAP" -o "$TCPFLOW_DIR" 2>/dev/null || warn "tcpflow failed"
    file_summary "$TCPFLOW_DIR"

    run_flag_grep "$TCPFLOW_DIR"
else
    info "tcpflow not found â€” skipping (install with: apt install tcpflow)"
fi

section "Final flag scan on all streams"
run_flag_grep "$OUT"

info "Stream extraction complete. Output: ${OUT}"
