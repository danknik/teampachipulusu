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
    echo "Extracts credentials from various protocols in the capture."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

PCAP="$1"
[[ ! -f "$PCAP" ]] && { error "PCAP file not found: ${PCAP}"; exit 1; }

OUT="${2:-$(make_output_dir network)/credentials}"
mkdir -p "$OUT"

require_tool tshark TSHARK || { error "tshark is required"; exit 1; }

banner "CREDENTIAL GRABBER â€” $(basename "$PCAP")"

CRED_FILE="${OUT}/credentials_summary.txt"
> "$CRED_FILE"

section "FTP Credentials"
FTP_CREDS=$($TSHARK -r "$PCAP" -Y "ftp.request.command==USER or ftp.request.command==PASS" \
    -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$FTP_CREDS" ]]; then
    echo "=== FTP Credentials ===" >> "$CRED_FILE"
    echo "$FTP_CREDS" | while IFS='|' read -r frame src dst cmd arg; do
        echo "  Frame ${frame}: ${src} â†’ ${dst} | ${cmd} ${arg}"
        echo "  Frame ${frame}: ${src} â†’ ${dst} | ${cmd} ${arg}" >> "$CRED_FILE"
    done
    echo "" >> "$CRED_FILE"
else
    info "No FTP credentials found"
fi

section "HTTP POST Data"
HTTP_POST=$($TSHARK -r "$PCAP" -Y "http.request.method==POST" \
    -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.uri \
    -e urlencoded-form.key -e urlencoded-form.value \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$HTTP_POST" ]]; then
    echo "=== HTTP POST Data ===" >> "$CRED_FILE"
    echo "$HTTP_POST" | while IFS='|' read -r frame src dst host uri keys values; do
        echo "  Frame ${frame}: ${src} â†’ ${host}${uri}"
        echo "    Keys:   ${keys}"
        echo "    Values: ${values}"
        echo "  Frame ${frame}: ${src} â†’ ${host}${uri}" >> "$CRED_FILE"
        echo "    Keys:   ${keys}" >> "$CRED_FILE"
        echo "    Values: ${values}" >> "$CRED_FILE"
    done
    echo "" >> "$CRED_FILE"
else
    info "No HTTP POST form data found"
fi

section "HTTP Basic Authentication"
HTTP_AUTH=$($TSHARK -r "$PCAP" -Y "http.authorization" \
    -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.authorization \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$HTTP_AUTH" ]]; then
    echo "=== HTTP Basic Auth ===" >> "$CRED_FILE"
    echo "$HTTP_AUTH" | while IFS='|' read -r frame src dst host auth; do
        B64=$(echo "$auth" | sed -n 's/Basic //p')
        DECODED=""
        if [[ -n "$B64" ]]; then
            DECODED=$(echo "$B64" | base64 -d 2>/dev/null || echo "[decode failed]")
        fi
        echo "  Frame ${frame}: ${src} â†’ ${host}"
        echo "    Raw:     ${auth}"
        echo "    Decoded: ${DECODED}"
        echo "  Frame ${frame}: ${src} â†’ ${host} | ${auth} | Decoded: ${DECODED}" >> "$CRED_FILE"
    done
    echo "" >> "$CRED_FILE"
else
    info "No HTTP Basic Auth headers found"
fi

section "Telnet Session Data"
TELNET=$($TSHARK -r "$PCAP" -Y "telnet.data" \
    -T fields -e frame.number -e ip.src -e ip.dst -e telnet.data \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$TELNET" ]]; then
    echo "=== Telnet Session Data ===" >> "$CRED_FILE"
    echo "$TELNET" >> "$CRED_FILE"
    info "Telnet data captured (check ${CRED_FILE})"
    $TSHARK -r "$PCAP" -Y "telnet" -T fields -e telnet.data 2>/dev/null \
        | tr -d '\n' | sed 's/,/\n/g' > "${OUT}/telnet_raw.txt" 2>/dev/null || true
else
    info "No Telnet session data found"
fi

section "SMTP Authentication"
SMTP_AUTH=$($TSHARK -r "$PCAP" -Y "smtp.req.command==AUTH" \
    -T fields -e frame.number -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$SMTP_AUTH" ]]; then
    echo "=== SMTP Auth ===" >> "$CRED_FILE"
    echo "$SMTP_AUTH" | while IFS='|' read -r frame src dst cmd param; do
        DECODED=$(echo "$param" | base64 -d 2>/dev/null || echo "$param")
        echo "  Frame ${frame}: ${src} â†’ ${dst} | ${cmd} ${param}"
        echo "    Decoded: ${DECODED}"
        echo "  Frame ${frame}: ${cmd} ${param} â†’ Decoded: ${DECODED}" >> "$CRED_FILE"
    done
    echo "" >> "$CRED_FILE"
else
    info "No SMTP AUTH data found"
fi

section "POP3 Credentials"
POP3=$($TSHARK -r "$PCAP" -Y "pop.request.command==USER or pop.request.command==PASS" \
    -T fields -e frame.number -e ip.src -e pop.request.command -e pop.request.parameter \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$POP3" ]]; then
    echo "=== POP3 Credentials ===" >> "$CRED_FILE"
    echo "$POP3" >> "$CRED_FILE"
    echo "$POP3"
else
    info "No POP3 credentials found"
fi

section "IMAP Login"
IMAP=$($TSHARK -r "$PCAP" -Y "imap.request contains \"LOGIN\"" \
    -T fields -e frame.number -e ip.src -e imap.request \
    -E separator='|' 2>/dev/null || true)

if [[ -n "$IMAP" ]]; then
    echo "=== IMAP Login ===" >> "$CRED_FILE"
    echo "$IMAP" >> "$CRED_FILE"
    echo "$IMAP"
else
    info "No IMAP login data found"
fi

section "Summary"
if [[ -s "$CRED_FILE" ]]; then
    highlight "Credentials saved to: ${CRED_FILE}"
    echo ""
    cat "$CRED_FILE"
else
    info "No credentials found in capture."
fi

run_flag_grep "$OUT"
