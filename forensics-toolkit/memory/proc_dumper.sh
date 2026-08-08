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
    echo "  output_dir       Optional output directory for dumped processes"
    echo ""
    echo "Identifies and dumps suspicious processes from memory."
    exit 1
}

[[ $# -lt 2 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

DUMP="$1"
VOL_OUT="$2"
[[ ! -f "$DUMP" ]] && { error "Memory dump not found: ${DUMP}"; exit 1; }
[[ ! -d "$VOL_OUT" ]] && { error "Vol3 output dir not found: ${VOL_OUT}"; exit 1; }

OUT="${3:-$(make_output_dir memory)/proc_dumps}"
mkdir -p "$OUT"

require_tool "$VOL3" VOL3 || { error "Volatility 3 not found"; exit 1; }

banner "PROCESS DUMPER â€” $(basename "$DUMP")"

OS_TYPE="windows"
[[ -f "${VOL_OUT}/os_type.txt" ]] && OS_TYPE=$(cat "${VOL_OUT}/os_type.txt")

section "Identifying suspicious processes"

declare -A SUSPICIOUS_PIDS

MALFIND_FILE="${VOL_OUT}/windows_malfind.txt"
[[ "$OS_TYPE" == "linux" ]] && MALFIND_FILE="${VOL_OUT}/linux_malfind.txt"

if [[ -f "$MALFIND_FILE" ]]; then
    while IFS= read -r pid; do
        [[ -n "$pid" ]] && SUSPICIOUS_PIDS["$pid"]="${SUSPICIOUS_PIDS[$pid]:-}malfind "
    done < <(grep -oP 'Pid\s+\K\d+|PID\s+\K\d+|\bpid:\s*\K\d+' "$MALFIND_FILE" 2>/dev/null | sort -u)
    info "Malfind flagged PIDs: ${!SUSPICIOUS_PIDS[*]:-none}"
fi

PSLIST_FILE="${VOL_OUT}/windows_pslist.txt"
[[ "$OS_TYPE" == "linux" ]] && PSLIST_FILE="${VOL_OUT}/linux_pslist.txt"

SUSPICIOUS_NAMES="cmd\.exe|powershell|pwsh|nc\.exe|ncat|netcat|meterpreter|reverse|shell|backdoor|mimikatz|procdump|lazagne|beacon|cobalt|inject|payload|exploit|hack|temp|tmp.*\.exe|svchost.*[^s]\.exe"

if [[ -f "$PSLIST_FILE" ]]; then
    while IFS= read -r line; do
        PID=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) {print $i; exit}}')
        NAME=$(echo "$line" | awk '{print $1}')
        if [[ -n "$PID" ]] && echo "$NAME" | grep -qiE "$SUSPICIOUS_NAMES"; then
            SUSPICIOUS_PIDS["$PID"]="${SUSPICIOUS_PIDS[$PID]:-}name:${NAME} "
        fi
    done < <(tail -n +3 "$PSLIST_FILE" 2>/dev/null)
fi

if [[ -f "$PSLIST_FILE" ]]; then
    while IFS= read -r line; do
        PID=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) {print $i; exit}}')
        PPID=$(echo "$line" | awk '{count=0; for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) {count++; if(count==2) {print $i; exit}}}')
        NAME=$(echo "$line" | awk '{print $1}')
        if [[ "$PPID" == "0" ]] && ! echo "$NAME" | grep -qiE "^(System|Idle|swapper|init|systemd|kernel)"; then
            [[ -n "$PID" ]] && SUSPICIOUS_PIDS["$PID"]="${SUSPICIOUS_PIDS[$PID]:-}orphan "
        fi
    done < <(tail -n +3 "$PSLIST_FILE" 2>/dev/null)
fi

section "Dumping ${#SUSPICIOUS_PIDS[@]} suspicious process(es)"

if [[ ${#SUSPICIOUS_PIDS[@]} -eq 0 ]]; then
    info "No suspicious processes identified. Dumping all processes with procdump..."
    $VOL3 -f "$DUMP" "${OS_TYPE}.pslist" --dump --pid 0 -o "$OUT" 2>/dev/null || true
else
    for PID in "${!SUSPICIOUS_PIDS[@]}"; do
        REASON="${SUSPICIOUS_PIDS[$PID]}"
        PID_DIR="${OUT}/pid_${PID}"
        mkdir -p "$PID_DIR"

        warn "PID ${PID} â€” Reason: ${REASON}"

        echo -ne "  Dumping PID ${PID} (procdump)... "
        $VOL3 -f "$DUMP" -o "$PID_DIR" "${OS_TYPE}.pslist" --pid "$PID" --dump \
            > "${PID_DIR}/procdump.log" 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}failed${NC}"

        echo -ne "  Dumping PID ${PID} (memmap)... "
        $VOL3 -f "$DUMP" -o "$PID_DIR" "${OS_TYPE}.memmap" --pid "$PID" --dump \
            > "${PID_DIR}/memmap.log" 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}failed${NC}"

        section "Strings analysis for PID ${PID}"
        find "$PID_DIR" -type f \( -name "*.dmp" -o -name "*.dat" -o -name "*.img" \) | while read -r dmpfile; do
            info "  Strings on: $(basename "$dmpfile")"
            strings -a "$dmpfile" > "${dmpfile}.strings.txt" 2>/dev/null || true
            strings -a -el "$dmpfile" >> "${dmpfile}.strings.txt" 2>/dev/null || true

            MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${dmpfile}.strings.txt" 2>/dev/null || true)
            if [[ -n "$MATCH" ]]; then
                highlight "FLAG in PID ${PID} dump: ${MATCH}"
            fi

            grep -iE "password|passwd|secret|token|key|admin|root|flag|base64" \
                "${dmpfile}.strings.txt" 2>/dev/null | head -20 > "${dmpfile}.interesting.txt" || true
        done
    done
fi

section "Summary"
for PID in "${!SUSPICIOUS_PIDS[@]}"; do
    REASON="${SUSPICIOUS_PIDS[$PID]}"
    FILE_COUNT=$(find "${OUT}/pid_${PID}" -type f 2>/dev/null | wc -l)
    info "PID ${PID} (${REASON}): ${FILE_COUNT} file(s) dumped"
done

run_flag_grep "$OUT"
info "Process dumps complete. Output: ${OUT}"
