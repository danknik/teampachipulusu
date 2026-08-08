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
    echo "Generates conversation tables and protocol hierarchy statistics."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

PCAP="$1"
[[ ! -f "$PCAP" ]] && { error "PCAP file not found: ${PCAP}"; exit 1; }

OUT="${2:-$(make_output_dir network)/conv_stats}"
mkdir -p "$OUT"

require_tool tshark TSHARK || { error "tshark is required"; exit 1; }

banner "CONVERSATION & STATS â€” $(basename "$PCAP")"

section "Capture File Info"
$TSHARK -r "$PCAP" -z "capinfos" 2>/dev/null | tee "${OUT}/capinfo.txt" || true
echo ""
if command -v capinfos &>/dev/null; then
    capinfos "$PCAP" 2>/dev/null | tee "${OUT}/capinfo_detail.txt"
fi

section "Protocol Hierarchy"
$TSHARK -r "$PCAP" -z io,phs -q 2>/dev/null | tee "${OUT}/protocol_hierarchy.txt"
echo ""

section "Endpoints (IP)"
$TSHARK -r "$PCAP" -z endpoints,ip -q 2>/dev/null | tee "${OUT}/endpoints_ip.txt"
echo ""

section "TCP Conversations (sorted by bytes)"
$TSHARK -r "$PCAP" -z conv,tcp -q 2>/dev/null | tee "${OUT}/conv_tcp.txt"
echo ""

section "UDP Conversations"
$TSHARK -r "$PCAP" -z conv,udp -q 2>/dev/null | tee "${OUT}/conv_udp.txt"
echo ""

section "HTTP Request Summary"
$TSHARK -r "$PCAP" -z http,tree -q 2>/dev/null | tee "${OUT}/http_tree.txt" || true
echo ""

$TSHARK -r "$PCAP" -z http_req,tree -q 2>/dev/null | tee "${OUT}/http_requests.txt" || true
echo ""

section "DNS Statistics"
$TSHARK -r "$PCAP" -z dns,tree -q 2>/dev/null | tee "${OUT}/dns_stats.txt" || true
echo ""

section "Port Analysis â€” Unusual Ports"

COMMON_PORTS="20|21|22|23|25|53|67|68|80|110|123|143|161|162|389|443|445|465|514|587|636|993|995|1433|1521|3306|3389|5432|5900|8080|8443"

info "Non-standard ports in use:"
$TSHARK -r "$PCAP" -T fields -e tcp.dstport -e udp.dstport 2>/dev/null \
    | tr '\t' '\n' | sort -un | grep -vE "^($COMMON_PORTS)$" | grep -v '^$' \
    | while read -r port; do
        COUNT=$($TSHARK -r "$PCAP" -Y "tcp.dstport==${port} or udp.dstport==${port}" 2>/dev/null | wc -l)
        if [[ $COUNT -gt 0 ]]; then
            warn "  Port ${port}: ${COUNT} packets"
        fi
    done | tee "${OUT}/unusual_ports.txt"

section "Top 10 Largest TCP Streams"
$TSHARK -r "$PCAP" -T fields -e tcp.stream -e frame.len 2>/dev/null \
    | awk -F'\t' 'NF==2 && $1!="" {bytes[$1]+=$2; count[$1]++} END {for(s in bytes) print bytes[s], count[s], s}' \
    | sort -rn | head -10 | while read -r bytes pkts stream; do
        echo "  Stream #${stream}: ${bytes} bytes, ${pkts} packets"
    done | tee "${OUT}/largest_streams.txt"

echo ""
info "Stats output saved to: ${OUT}"
info "Look for: unusual ports, huge single conversations, odd protocols in hierarchy."
