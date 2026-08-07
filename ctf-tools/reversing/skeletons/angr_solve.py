#!/usr/bin/env python3
"""
angr Symbolic Execution Solver
=================================
Auto-solve CTF rev challenges using symbolic execution.

Common patterns:
    1. Find path to "success" / avoid "failure"
    2. Solve for stdin/argv input
    3. Constrain flag format
    4. Hook functions (scanf, printf, etc.)

Install: pip3 install angr
Warning: angr is ~500MB, pre-install before CTF!

Usage:
    python3 angr_solve.py
    Adjust BINARY, FIND_ADDR, AVOID_ADDR, then run.
"""
import angr
import claripy
import sys

BINARY = './chall'

# ─── ADDRESSES — find in disassembly ────────────────────────
FIND_ADDR  = 0x0      # address of "Correct!" / success path
AVOID_ADDR = [0x0]    # addresses of "Wrong!" / failure paths

# ═══════════════════════════════════════════════════════════
# METHOD 1: Basic — find/avoid with stdin
# ═══════════════════════════════════════════════════════════
def solve_stdin():
    """Solve for stdin input that reaches FIND_ADDR."""
    print(f'[*] Loading: {BINARY}')
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Create initial state
    state = proj.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)

    print(f'[*] Exploring: find={hex(FIND_ADDR)}, avoid={[hex(a) for a in AVOID_ADDR]}')
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if simgr.found:
        found = simgr.found[0]
        solution = found.posix.dumps(0)  # stdin (fd=0)
        print(f'[+] Solution (raw): {solution}')
        print(f'[+] Solution (str): {solution.decode(errors="replace")}')
        return solution
    else:
        print('[-] No solution found!')
        return None

# ═══════════════════════════════════════════════════════════
# METHOD 2: argv input
# ═══════════════════════════════════════════════════════════
def solve_argv(arg_len=32):
    """Solve for command-line argument."""
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Symbolic argv[1]
    arg = claripy.BVS('arg1', arg_len * 8)
    state = proj.factory.entry_state(
        args=[BINARY, arg],
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )

    # Constrain to printable ASCII
    for i in range(arg_len):
        byte = arg.get_byte(i)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(arg, cast_to=bytes)
        print(f'[+] argv[1] = {solution.decode(errors="replace")}')
        return solution
    else:
        print('[-] No solution found!')
        return None

# ═══════════════════════════════════════════════════════════
# METHOD 3: Known flag format constraint
# ═══════════════════════════════════════════════════════════
def solve_with_flag_format(flag_len=32, prefix=b'inctf{', suffix=b'}'):
    """Solve with flag format constraints (e.g., inctf{...})."""
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Symbolic stdin
    flag = claripy.BVS('flag', flag_len * 8)
    state = proj.factory.entry_state(
        stdin=flag,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )

    # Constrain prefix
    for i, c in enumerate(prefix):
        state.solver.add(flag.get_byte(i) == c)

    # Constrain suffix
    state.solver.add(flag.get_byte(flag_len - 1) == ord(suffix))

    # Constrain middle chars to printable ASCII
    for i in range(len(prefix), flag_len - 1):
        byte = flag.get_byte(i)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        print(f'[+] Flag: {solution.decode(errors="replace")}')
        return solution
    else:
        print('[-] No solution found!')
        return None

# ═══════════════════════════════════════════════════════════
# METHOD 4: Find by output string (no address needed!)
# ═══════════════════════════════════════════════════════════
def solve_by_output(success_str=b'Correct', fail_str=b'Wrong'):
    """Find input that produces success output string."""
    proj = angr.Project(BINARY, auto_load_libs=False)

    state = proj.factory.entry_state(
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )

    simgr = proj.factory.simulation_manager(state)

    def is_success(s):
        output = s.posix.dumps(1)  # stdout
        return success_str in output

    def is_fail(s):
        output = s.posix.dumps(1)
        return fail_str in output

    simgr.explore(find=is_success, avoid=is_fail)

    if simgr.found:
        found = simgr.found[0]
        solution = found.posix.dumps(0)
        print(f'[+] Solution: {solution.decode(errors="replace")}')
        print(f'[+] Output:   {found.posix.dumps(1).decode(errors="replace")}')
        return solution
    else:
        print('[-] No solution found!')
        return None

# ═══════════════════════════════════════════════════════════
# METHOD 5: Hook functions (scanf, ptrace, etc.)
# ═══════════════════════════════════════════════════════════
def solve_with_hooks():
    """Hook problematic functions before solving."""
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Hook ptrace (anti-debug) to return 0
    class PtraceHook(angr.SimProcedure):
        def run(self, request, pid, addr, data):
            return 0

    # Hook time-based functions
    class TimeHook(angr.SimProcedure):
        def run(self):
            return 0

    # Hook sleep
    class SleepHook(angr.SimProcedure):
        def run(self, seconds):
            return 0

    proj.hook_symbol('ptrace', PtraceHook())
    proj.hook_symbol('time', TimeHook())
    proj.hook_symbol('sleep', SleepHook())
    # proj.hook_symbol('alarm', SleepHook())

    state = proj.factory.entry_state(
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if simgr.found:
        solution = simgr.found[0].posix.dumps(0)
        print(f'[+] Solution: {solution.decode(errors="replace")}')
        return solution

    print('[-] No solution found')
    return None

# ═══════════════════════════════════════════════════════════
# METHOD 6: Start from specific address (skip init)
# ═══════════════════════════════════════════════════════════
def solve_from_addr(start_addr, input_len=32):
    """Start analysis from a specific function/address."""
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Create symbolic input buffer in memory
    flag = claripy.BVS('flag', input_len * 8)
    buf_addr = 0x600000  # pick unused address

    state = proj.factory.blank_state(addr=start_addr)
    state.memory.store(buf_addr, flag)

    # Set rdi to point to our buffer (first arg)
    state.regs.rdi = buf_addr

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        print(f'[+] Solution: {solution}')
        return solution
    return None

if __name__ == '__main__':
    # Choose your method:
    # solve_stdin()
    # solve_argv()
    # solve_with_flag_format()
    solve_by_output()
    # solve_with_hooks()
