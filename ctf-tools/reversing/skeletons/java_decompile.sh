#!/bin/bash
# Java JAR Decompilation Workflow
# Usage: ./java_decompile.sh <file.jar|file.class>

FILE="${1:?Usage: $0 <file.jar|file.class>}"

echo "═══════════════════════════════════════════"
echo "  Java Decompilation: $FILE"
echo "═══════════════════════════════════════════"

EXT="${FILE##*.}"

if [ "$EXT" = "jar" ]; then
    echo "[*] JAR file detected"
    
    # List contents
    echo ""
    echo "─── JAR Contents ───"
    jar tf "$FILE" 2>/dev/null || unzip -l "$FILE" 2>/dev/null | head -30
    
    # Extract
    EXTRACT_DIR="${FILE%.jar}_extracted"
    mkdir -p "$EXTRACT_DIR"
    cd "$EXTRACT_DIR"
    jar xf "../$FILE" 2>/dev/null || unzip -o "../$FILE" 2>/dev/null
    cd ..
    echo "[+] Extracted to: $EXTRACT_DIR/"
    
    # Find main class
    echo ""
    echo "─── Manifest ───"
    cat "$EXTRACT_DIR/META-INF/MANIFEST.MF" 2>/dev/null
    
    # Quick strings search
    echo ""
    echo "─── Interesting strings ───"
    find "$EXTRACT_DIR" -name "*.class" -exec strings {} \; | grep -iE "flag|password|key|secret|correct|wrong|ctf" | sort -u | head -20
    
elif [ "$EXT" = "class" ]; then
    echo "[*] Class file detected"
else
    echo "[?] Unknown extension: $EXT"
fi

echo ""
echo "─── Decompilation Tools ───"
echo ""
echo "  1. CFR (recommended, Java CLI):"
echo "     java -jar cfr.jar $FILE > decompiled.java"
echo "     Download: https://github.com/leibnitz27/cfr/releases"
echo ""
echo "  2. Procyon:"
echo "     java -jar procyon.jar $FILE > decompiled.java"
echo ""
echo "  3. JD-GUI (GUI):"
echo "     Download: https://github.com/java-decompiler/jd-gui/releases"
echo "     Open JAR directly → browse source"
echo ""
echo "  4. jadx (for Android APK too):"
echo "     jadx -d output/ $FILE"
echo "     Download: https://github.com/skylot/jadx/releases"
echo ""
echo "  5. javap (built-in, bytecode only):"

if command -v javap &>/dev/null; then
    if [ "$EXT" = "class" ]; then
        echo "     [+] javap available, decompiling bytecode:"
        javap -c -p "$FILE" 2>/dev/null | head -50
    elif [ "$EXT" = "jar" ]; then
        # Find first .class file
        FIRST_CLASS=$(find "$EXTRACT_DIR" -name "*.class" | head -1)
        if [ -n "$FIRST_CLASS" ]; then
            echo "     [+] Bytecode for: $FIRST_CLASS"
            javap -c -p "$FIRST_CLASS" 2>/dev/null | head -50
        fi
    fi
else
    echo "     [!] javap not found (install JDK)"
fi

echo ""
echo "─── Running Java ───"
echo "  java -jar $FILE"
echo "  java -cp $FILE MainClass"
