#!/usr/bin/env python3
"""
Anti-Debug Bypass — Common Patterns
======================================
Identify and patch anti-debugging techniques.

Covers:
    - ptrace detection (Linux)
    - IsDebuggerPresent (Windows)
    - Timing checks (rdtsc, clock)
    - Self-hashing / integrity checks
    - Signal-based anti-debug
    - /proc/self/status TracerPid check

Usage:
    1. Identify anti-debug technique in disassembly
    2. Find the patch point (address/offset)
    3. Use patch_binary.py to NOP or modify
"""
import sys
import os

# ═══════════════════════════════════════════════════════════
# DETECTION SIGNATURES (search for these in disassembly)
# ═══════════════════════════════════════════════════════════

ANTI_DEBUG_SIGNATURES = {
    'Linux': {
        'ptrace(PTRACE_TRACEME)': {
            'description': 'Calls ptrace(0,0,0,0). If debugger attached, returns -1.',
            'signature': ['ptrace', 'PTRACE_TRACEME'],
            'bypass': [
                'NOP the ptrace call and force return value = 0',
                'Patch: change JNE/JE after ptrace check',
                'LD_PRELOAD: hook ptrace() to return 0',
                'GDB: catch syscall ptrace, then set $rax=0 and continue',
            ],
            'gdb_bypass': 'catch syscall ptrace\ncommands\nsilent\nset $rax = 0\ncontinue\nend',
        },
        '/proc/self/status': {
            'description': 'Reads TracerPid from /proc/self/status (non-zero = debugged).',
            'signature': ['/proc/self/status', 'TracerPid'],
            'bypass': [
                'NOP the open/read/check sequence',
                'Patch comparison to always pass',
                'Use: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope',
            ],
        },
        'SIGTRAP handler': {
            'description': 'Installs SIGTRAP handler. int3 triggers handler normally, but in debugger it stops.',
            'signature': ['signal', 'SIGTRAP', 'int3', '0xcc'],
            'bypass': [
                'NOP the int3 (0xcc) instructions',
                'Set the signal handler manually in GDB',
                'GDB: handle SIGTRAP nostop noprint pass',
            ],
        },
        'getppid / parent check': {
            'description': 'Checks if parent process is expected (e.g., not gdb).',
            'signature': ['getppid', '/proc/self/stat'],
            'bypass': ['NOP the check', 'Run via wrapper that forks first'],
        },
        'rdtsc timing': {
            'description': 'Uses rdtsc to measure execution time. Debugging = slow.',
            'signature': ['rdtsc', '0f31'],
            'bypass': [
                'NOP timing checks',
                'Patch comparison threshold to very large value',
                'GDB: set $edx:$eax after rdtsc',
            ],
        },
    },
    'Windows': {
        'IsDebuggerPresent': {
            'description': 'kernel32!IsDebuggerPresent returns 1 if debugged.',
            'signature': ['IsDebuggerPresent'],
            'bypass': [
                'Patch the call to return 0',
                'In x64dbg: PEB.BeingDebugged = 0',
                'ScyllaHide plugin for x64dbg/OllyDbg',
            ],
        },
        'NtQueryInformationProcess': {
            'description': 'ProcessDebugPort (7) returns non-zero if debugged.',
            'signature': ['NtQueryInformationProcess', 'ProcessDebugPort'],
            'bypass': ['Hook to return 0', 'Patch check'],
        },
        'CheckRemoteDebuggerPresent': {
            'description': 'Similar to IsDebuggerPresent but for remote debuggers.',
            'signature': ['CheckRemoteDebuggerPresent'],
            'bypass': ['Patch to return FALSE'],
        },
        'PEB.NtGlobalFlag': {
            'description': 'NtGlobalFlag at PEB+0x68 (32-bit) or PEB+0xBC (64-bit) != 0 if debugged.',
            'signature': ['NtGlobalFlag', 'fs:[0x30]', 'gs:[0x60]'],
            'bypass': ['Zero out NtGlobalFlag in PEB', 'Patch check'],
        },
    },
}

# ═══════════════════════════════════════════════════════════
# LD_PRELOAD bypass for Linux ptrace
# ═══════════════════════════════════════════════════════════
LD_PRELOAD_PTRACE = """
// Compile: gcc -shared -fPIC -o bypass_ptrace.so bypass_ptrace.c -ldl
// Use:     LD_PRELOAD=./bypass_ptrace.so ./chall

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>

long ptrace(int request, ...) {
    return 0;  // Always return success
}

// Also bypass common time checks
#include <time.h>
static time_t fake_time = 1000000;
time_t time(time_t *t) {
    if (t) *t = fake_time;
    return fake_time;
}
"""

# ═══════════════════════════════════════════════════════════
# GDB SCRIPTS for common bypasses
# ═══════════════════════════════════════════════════════════
GDB_PTRACE_BYPASS = """
# Paste into GDB to bypass ptrace anti-debug:
catch syscall ptrace
commands
silent
set $rax = 0
continue
end
"""

GDB_SIGTRAP_BYPASS = """
# Handle SIGTRAP without stopping:
handle SIGTRAP nostop noprint pass
"""

GDB_ALARM_BYPASS = """
# Bypass alarm() timeout:
catch syscall alarm
commands
silent
set $rax = 0
continue
end
"""

def scan_binary(filepath):
    """Scan binary for anti-debug patterns."""
    with open(filepath, 'rb') as f:
        data = f.read()

    data_str = data.decode('latin-1')

    print(f'[*] Scanning {filepath} for anti-debug patterns...\n')

    found = []
    for platform, techniques in ANTI_DEBUG_SIGNATURES.items():
        for name, info in techniques.items():
            for sig in info['signature']:
                if sig.encode() in data or sig in data_str:
                    found.append((platform, name, info))
                    print(f'[!] {platform}: {name}')
                    print(f'    Description: {info["description"]}')
                    print(f'    Bypass:')
                    for b in info['bypass']:
                        print(f'      - {b}')
                    print()
                    break

    if not found:
        print('[+] No common anti-debug patterns detected')
    else:
        print(f'[*] Found {len(found)} anti-debug technique(s)')

    return found

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <binary>')
        print(f'\nOr view bypass techniques:')
        print(f'  {sys.argv[0]} --list')
        print(f'\nGDB bypass scripts:')
        print(GDB_PTRACE_BYPASS)
        print(GDB_SIGTRAP_BYPASS)
        print(f'\nLD_PRELOAD source:')
        print(LD_PRELOAD_PTRACE)
        sys.exit(0)

    if sys.argv[1] == '--list':
        for platform, techniques in ANTI_DEBUG_SIGNATURES.items():
            print(f'\n═══ {platform} ═══')
            for name, info in techniques.items():
                print(f'\n  {name}:')
                print(f'    {info["description"]}')
                for b in info['bypass']:
                    print(f'    → {b}')
    else:
        scan_binary(sys.argv[1])
