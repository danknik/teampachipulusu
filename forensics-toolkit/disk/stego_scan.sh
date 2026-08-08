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
    echo "  target_dir    Directory of image/media files to scan"
    echo "  output_dir    Optional output directory"
    echo ""
    echo "Environment:"
    echo "  STEGO_WORDLIST   Wordlist for steghide (default: ${STEGO_WORDLIST})"
    echo ""
    echo "Runs stego tools on every image file found."
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "--help" || "$1" == "-h" ]] && usage

TARGET="$1"
[[ ! -e "$TARGET" ]] && { error "Target not found: ${TARGET}"; exit 1; }

OUT="${2:-$(make_output_dir disk)/stego}"
mkdir -p "$OUT"

banner "STEGO SCANNER â€” $(basename "$TARGET")"

TOTAL_IMAGES=0
STEGO_HITS=0

section "Collecting image/media files"

declare -a PNG_FILES=()
declare -a JPEG_FILES=()
declare -a BMP_FILES=()
declare -a WAV_FILES=()
declare -a OTHER_FILES=()

while IFS= read -r -d '' f; do
    MIME=$(file -b --mime-type "$f" 2>/dev/null || echo "unknown")
    case "$MIME" in
        image/png)                PNG_FILES+=("$f"); ((TOTAL_IMAGES++)) ;;
        image/jpeg)               JPEG_FILES+=("$f"); ((TOTAL_IMAGES++)) ;;
        image/bmp|image/x-ms-bmp) BMP_FILES+=("$f"); ((TOTAL_IMAGES++)) ;;
        audio/x-wav|audio/wav)    WAV_FILES+=("$f"); ((TOTAL_IMAGES++)) ;;
        image/*)                  OTHER_FILES+=("$f"); ((TOTAL_IMAGES++)) ;;
    esac
done < <(find "$TARGET" -type f -print0 2>/dev/null)

info "PNG: ${#PNG_FILES[@]}, JPEG: ${#JPEG_FILES[@]}, BMP: ${#BMP_FILES[@]}, WAV: ${#WAV_FILES[@]}, Other: ${#OTHER_FILES[@]}"
info "Total media files: ${TOTAL_IMAGES}"

if [[ ${#PNG_FILES[@]} -gt 0 ]]; then
    section "PNG Analysis"
    PNG_OUT="${OUT}/png"
    mkdir -p "$PNG_OUT"

    for img in "${PNG_FILES[@]}"; do
        BASENAME=$(basename "$img" | tr ' ' '_')
        IMG_OUT="${PNG_OUT}/${BASENAME}"
        mkdir -p "$IMG_OUT"

        echo -e "  ${CYAN}${BASENAME}${NC}"

        if command -v "$ZSTEG" &>/dev/null; then
            echo -ne "    zsteg... "
            $ZSTEG "$img" -a > "${IMG_OUT}/zsteg.txt" 2>&1 || true
            ZSTEG_HITS=$(grep -vE "^\s*$|^imagedata|^extradata:0" "${IMG_OUT}/zsteg.txt" 2>/dev/null \
                | grep -iE "text|flag|ctf|http|file" 2>/dev/null || true)
            if [[ -n "$ZSTEG_HITS" ]]; then
                echo -e "${RED}HITS!${NC}"
                echo "$ZSTEG_HITS" | head -10
                ((STEGO_HITS++))
            else
                echo -e "${GREEN}clean${NC}"
            fi

            MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${IMG_OUT}/zsteg.txt" 2>/dev/null || true)
            if [[ -n "$MATCH" ]]; then
                highlight "    FLAG (zsteg): ${MATCH}"
            fi
        fi

        if command -v pngcheck &>/dev/null; then
            echo -ne "    pngcheck... "
            pngcheck -v "$img" > "${IMG_OUT}/pngcheck.txt" 2>&1 || true
            if grep -qi "error\|warn\|additional" "${IMG_OUT}/pngcheck.txt" 2>/dev/null; then
                echo -e "${YELLOW}issues found${NC}"
                grep -i "error\|warn\|additional" "${IMG_OUT}/pngcheck.txt" | head -5
            else
                echo -e "${GREEN}OK${NC}"
            fi
        fi

        echo -ne "    binwalk... "
        if command -v "$BINWALK" &>/dev/null; then
            $BINWALK "$img" > "${IMG_OUT}/binwalk.txt" 2>/dev/null || true
            BW_LINES=$(wc -l < "${IMG_OUT}/binwalk.txt")
            if [[ $BW_LINES -gt 3 ]]; then
                echo -e "${YELLOW}embedded data!${NC}"
                cat "${IMG_OUT}/binwalk.txt"
                $BINWALK -e -C "$IMG_OUT" "$img" > /dev/null 2>&1 || true
                ((STEGO_HITS++))
            else
                echo -e "${GREEN}clean${NC}"
            fi
        else
            echo -e "skip"
        fi

        strings -a "$img" > "${IMG_OUT}/strings.txt" 2>/dev/null || true
        MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${IMG_OUT}/strings.txt" 2>/dev/null || true)
        if [[ -n "$MATCH" ]]; then
            highlight "    FLAG (strings): ${MATCH}"
        fi
    done
fi

if [[ ${#JPEG_FILES[@]} -gt 0 ]]; then
    section "JPEG Analysis"
    JPEG_OUT="${OUT}/jpeg"
    mkdir -p "$JPEG_OUT"

    for img in "${JPEG_FILES[@]}"; do
        BASENAME=$(basename "$img" | tr ' ' '_')
        IMG_OUT="${JPEG_OUT}/${BASENAME}"
        mkdir -p "$IMG_OUT"

        echo -e "  ${CYAN}${BASENAME}${NC}"

        if command -v "$STEGHIDE" &>/dev/null; then
            echo -ne "    steghide (empty pass)... "
            if $STEGHIDE extract -sf "$img" -p "" -xf "${IMG_OUT}/steghide_empty.bin" -f 2>/dev/null; then
                echo -e "${RED}EXTRACTED!${NC}"
                file "${IMG_OUT}/steghide_empty.bin"
                cat "${IMG_OUT}/steghide_empty.bin" 2>/dev/null | head -5
                ((STEGO_HITS++))
            else
                echo -e "${GREEN}no data${NC}"
            fi

            COMMON_PASS=("password" "123456" "secret" "flag" "ctf" "admin" "stego" "hidden")
            for pass in "${COMMON_PASS[@]}"; do
                if $STEGHIDE extract -sf "$img" -p "$pass" -xf "${IMG_OUT}/steghide_${pass}.bin" -f 2>/dev/null; then
                    highlight "    steghide extracted with password: '${pass}'"
                    file "${IMG_OUT}/steghide_${pass}.bin"
                    ((STEGO_HITS++))
                fi
            done
        fi

        if command -v "$STEGSEEK" &>/dev/null; then
            echo -ne "    stegseek... "
            if [[ -f "$STEGO_WORDLIST" ]]; then
                if $STEGSEEK "$img" "$STEGO_WORDLIST" "${IMG_OUT}/stegseek_out.bin" \
                    > "${IMG_OUT}/stegseek.log" 2>&1; then
                    echo -e "${RED}CRACKED!${NC}"
                    cat "${IMG_OUT}/stegseek.log"
                    ((STEGO_HITS++))
                else
                    echo -e "${GREEN}no match${NC}"
                fi
            else
                $STEGSEEK --crack "$img" -xf "${IMG_OUT}/stegseek_out.bin" \
                    > "${IMG_OUT}/stegseek.log" 2>&1 || true
                echo -e "${YELLOW}no wordlist${NC}"
            fi
        fi

        if command -v "$BINWALK" &>/dev/null; then
            echo -ne "    binwalk... "
            $BINWALK "$img" > "${IMG_OUT}/binwalk.txt" 2>/dev/null || true
            BW_LINES=$(wc -l < "${IMG_OUT}/binwalk.txt")
            if [[ $BW_LINES -gt 3 ]]; then
                echo -e "${YELLOW}embedded data!${NC}"
                $BINWALK -e -C "$IMG_OUT" "$img" > /dev/null 2>&1 || true
                ((STEGO_HITS++))
            else
                echo -e "${GREEN}clean${NC}"
            fi
        fi

        strings -a "$img" > "${IMG_OUT}/strings.txt" 2>/dev/null || true
        MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${IMG_OUT}/strings.txt" 2>/dev/null || true)
        if [[ -n "$MATCH" ]]; then
            highlight "    FLAG (strings): ${MATCH}"
        fi
    done
fi

if [[ ${#BMP_FILES[@]} -gt 0 ]]; then
    section "BMP Analysis"
    BMP_OUT="${OUT}/bmp"
    mkdir -p "$BMP_OUT"

    for img in "${BMP_FILES[@]}"; do
        BASENAME=$(basename "$img" | tr ' ' '_')
        IMG_OUT="${BMP_OUT}/${BASENAME}"
        mkdir -p "$IMG_OUT"

        echo -e "  ${CYAN}${BASENAME}${NC}"

        if command -v "$ZSTEG" &>/dev/null; then
            $ZSTEG "$img" -a > "${IMG_OUT}/zsteg.txt" 2>&1 || true
            MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${IMG_OUT}/zsteg.txt" 2>/dev/null || true)
            [[ -n "$MATCH" ]] && highlight "    FLAG (zsteg): ${MATCH}"
        fi

        strings -a "$img" > "${IMG_OUT}/strings.txt" 2>/dev/null || true
        MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${IMG_OUT}/strings.txt" 2>/dev/null || true)
        [[ -n "$MATCH" ]] && highlight "    FLAG (strings): ${MATCH}"
    done
fi

if [[ ${#WAV_FILES[@]} -gt 0 ]]; then
    section "WAV/Audio Analysis"
    WAV_OUT="${OUT}/wav"
    mkdir -p "$WAV_OUT"

    for audio in "${WAV_FILES[@]}"; do
        BASENAME=$(basename "$audio" | tr ' ' '_')
        AUD_OUT="${WAV_OUT}/${BASENAME}"
        mkdir -p "$AUD_OUT"

        echo -e "  ${CYAN}${BASENAME}${NC}"

        if command -v "$STEGHIDE" &>/dev/null; then
            echo -ne "    steghide (empty pass)... "
            if $STEGHIDE extract -sf "$audio" -p "" -xf "${AUD_OUT}/steghide.bin" -f 2>/dev/null; then
                echo -e "${RED}EXTRACTED!${NC}"
                ((STEGO_HITS++))
            else
                echo -e "${GREEN}no data${NC}"
            fi
        fi

        strings -a "$audio" > "${AUD_OUT}/strings.txt" 2>/dev/null || true
        MATCH=$(grep -Eo "${FLAG_PATTERNS}" "${AUD_OUT}/strings.txt" 2>/dev/null || true)
        [[ -n "$MATCH" ]] && highlight "    FLAG (strings): ${MATCH}"

        info "    Tip: Check spectrogram in Audacity/Sonic Visualiser for hidden images"
    done
fi

if command -v convert &>/dev/null; then
    section "LSB Bit-plane Extraction (ImageMagick)"
    LSB_OUT="${OUT}/lsb_planes"
    mkdir -p "$LSB_OUT"

    ALL_IMAGES=("${PNG_FILES[@]}" "${JPEG_FILES[@]}" "${BMP_FILES[@]}")
    LIMIT=$((${#ALL_IMAGES[@]} > 20 ? 20 : ${#ALL_IMAGES[@]}))

    for ((i=0; i<LIMIT; i++)); do
        img="${ALL_IMAGES[$i]}"
        BASENAME=$(basename "$img" | tr ' ' '_')

        convert "$img" -channel R -separate -threshold 1% "${LSB_OUT}/${BASENAME}_R_lsb.png" 2>/dev/null || true
        convert "$img" -channel G -separate -threshold 1% "${LSB_OUT}/${BASENAME}_G_lsb.png" 2>/dev/null || true
        convert "$img" -channel B -separate -threshold 1% "${LSB_OUT}/${BASENAME}_B_lsb.png" 2>/dev/null || true
    done

    LSB_COUNT=$(find "$LSB_OUT" -type f 2>/dev/null | wc -l)
    info "Generated ${LSB_COUNT} bit-plane images in ${LSB_OUT}"
    info "Visually inspect these for hidden messages"
fi

section "Summary"
info "Total media files scanned: ${TOTAL_IMAGES}"
if [[ $STEGO_HITS -gt 0 ]]; then
    highlight "STEGO HITS: ${STEGO_HITS} â€” check output directories!"
else
    info "No steganography detected"
fi

run_flag_grep "$OUT"

info "Stego scan complete. Output: ${OUT}"
