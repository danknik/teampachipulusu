

## 🌐 Network Analysis (`network/`)


| Script | Description |
|--------|-------------|
| 🔹 `pcap_analyze.sh` | **Orchestrator:** Executes the entire network analysis pipeline sequentially against a capture file. Generates a consolidated, timestamped report. |
| 🔹 `conv_stats.sh` | **Traffic Profiling:** Analyzes protocol hierarchy, conversation tables, and I/O statistics to quickly isolate anomalous ports and high-volume streams. |
| 🔹 `export_objects.sh` | **Artifact Carver:** Extracts transferred files across multiple protocols (HTTP, SMB, FTP, etc.) and immediately scans them for targeted data patterns. |
| 🔹 `cred_grabber.sh` | **Auth Extraction:** Parses traffic for authentication material across standard cleartext and encoded protocols, generating a structured credentials summary. |
| 🔹 `dns_exfil.sh` | **OOB Detection:** Evaluates DNS queries for high-entropy subdomains and TXT record abuse to detect tunneling or out-of-band data exfiltration. |
| 🔹 `stream_extract.sh` | **Stream Reassembly:** Follows individual TCP/UDP streams, dumping their content to identify structured plaintext data transmissions. |

---

## 🧠 Memory Introspection (`memory/`)
*Volatile memory analysis and process extraction.*

| Script | Description |
|--------|-------------|
| 🔹 `mem_analyze.sh` | **Orchestrator:** Runs the full memory analysis suite against a memory dump, automatically identifying the host OS and managing output structure. |
| 🔹 `vol3_runner.sh` | **Framework Execution:** Deploys a comprehensive suite of memory introspection plugins (process lists, network connections, injections) tailored to the detected OS. |
| 🔹 `proc_dumper.sh` | **Process Isolation:** Identifies anomalous processes via memory heuristics and extracts their executable segments to disk for deep string analysis. |
| 🔹 `file_extractor.sh` | **Object Enumeration:** Locates and extracts cached file objects from the memory image, organizing them by type for subsequent scanning. |
| 🔹 `mem_strings.sh` | **Deep Search:** Performs exhaustive ASCII and Unicode string extraction across the raw dump, filtering for URLs, encodings, and structured targets. |

---

## 💾 Disk & Filesystem Analysis (`disk/`)


| Script | Description |
|--------|-------------|
| 🔹 `disk_analyze.sh` | **Orchestrator:** Automates the disk analysis workflow, managing the extraction directory and summarizing findings. |
| 🔹 `carve.sh` | **Recursive Extraction:** Identifies and carves embedded files, nested archives, and firmware blobs from raw data streams. |
| 🔹 `timeline.sh` | **Activity Reconstruction:** Builds a complete filesystem timeline based on MAC times, highlighting unallocated or recently modified entries. |
| 🔹 `recover_deleted.sh` | **Data Salvage:** Utilizes multiple carving and filesystem parsing techniques to recover deleted artifacts and bypass standard OS limitations. |
| 🔹 `metadata_sweep.sh` | **Metadata Profiling:** Extracts comprehensive file metadata (e.g., creation software, GPS coordinates, hidden comments) across all recovered files. |
| 🔹 `stego_scan.sh` | **Concealed Data Detection:** Analyzes image structures using least-significant-bit evaluation, dictionary attacks, and localized entropy checks. |

---

## ⚙️ Toolkit Core Utilities (`common/`)


| File | Description |
|------|-------------|
| 🔸 `flag_finder.sh` | **Target Locator:** Rapidly scans files, binaries, environment variables, and local ports for known structured data patterns. |
| 🔸 `setup_env.sh` | **Environment Bootstrap:** Prepares an analysis environment with necessary debuggers, constraint solvers, binary modifiers, and crypto libraries. |
| 🔸 `solve_wrapper.py` | **Execution Handler:** Drop-in Python module that manages local/remote connections, implements retry logic, and provides data packing helpers. |

---


| File | Description |
|------|-------------|
| 🔸 `exploit_template.py` | **Base Harness:** Standard template handling binary loading, connection routing, and basic I/O interaction. |
| 🔸 `bof_ret2win.py` | **Direct Redirection:** Calculates offsets to overwrite execution flow and jump directly to a target function. |
| 🔸 `bof_ret2shellcode.py` | **Code Injection:** Injects execution payloads into memory, aligns the stack, and redirects control flow (for unprotected binaries). |
| 🔸 `bof_ret2libc.py` | **Library Redirection:** Code-reuse template that leaks runtime addresses to bypass randomization and execute system commands. |
| 🔸 `bof_rop_chain.py` | **Chain Builder:** Automatically discovers execution gadgets and links them to perform arbitrary system calls without external code. |
| 🔸 `fmt_string_leak.py` | **Format Evaluation:** Iterates format string vulnerabilities to map memory contents and identify critical runtime addresses. |
| 🔸 `fmt_string_write.py` | **Format Manipulation:** Exploits format string vulnerabilities to perform arbitrary memory overwrites via crafted specifiers. |
| 🔸 `heap_fastbin_dup.py` | **Heap Poisoning:** Manipulates memory allocation structures via double-free conditions to control overlapping memory regions. |
| 🔸 `heap_tcache_poison.py` | **Modern Heap Manipulation:** Exploits thread-caching mechanisms to redirect allocations toward arbitrary execution hooks. |
| 🔸 `heap_uaf.py` | **Dangling Pointer Reuse:** Leverages prematurely freed memory pointers to corrupt internal structures or alter execution flow. |
| 🔸 `heap_house_of_force.py` | **Wilderness 
| 🔸 `sigreturn_srop.py` | **Context Restoration:** Forges a signal context frame to gain arbitrary register control when standard gadgets are unavailable. |
| 🔸 `seccomp_bypass.py` | **Sandbox Evasion:** Evaluates permitted system calls and constructs logic using only authorized operations. |
| 🔸 `shellcode_collection.py` | **Payload Library:** A collection of generic execution payloads for multiple architectures, including staged loaders. |
| 🔸 `stack_pivot.py` | **Stack Manipulation:** Modifies the stack pointer to redirect execution to a heavily controlled memory segment. |
| 🔸 `one_gadget_finder.py` | **Execution Vector Search:** Locates and tests single-instruction execution sequences within standard libraries. |

| File | Description |
|------|-------------|
| 🔸 `checksec_all.sh` | **Security Profiler:** Evaluates binary protection mechanisms (NX, PIE, RELRO, Canaries) across an entire directory. |
| 🔸 `rop_gadget_finder.sh` | **Gadget Locator:** Scans binaries for useful execution sequences (e.g., register pops, syscalls, stack manipulations). |
| 🔸 `canary_bruteforce.py` | **Cookie Recovery:** Automates byte-by-byte recovery of memory protection cookies by analyzing process crash behavior. |
| 🔸 `gdb_scripts.py` | **Dynamic Analysis Aids:** Scripts for memory inspection, execution tracing, and heap structure visualization. |
| 🔸 `libc_finder.py` | **Library Identifier:** Matches leaked addresses to specific library versions and calculates offsets for execution redirection. |
| 🔸 `patch_binary.py` | **Linkage Modifier:** Alters a binary's dynamic linkage to utilize specific local libraries for accurate environment replication. |

---


| File | Description |
|------|-------------|
| 🔸 `xor_decrypt.py` | **XOR Analysis:** Evaluates single/multi-byte keys using frequency and index-of-coincidence analysis to rank likely plaintexts. |
| 🔸 `aes_decrypt.py` | **Block Cipher Analysis:** Supports multiple operation modes and evaluates common weaknesses (e.g., fixed IVs, padding oracles). |
| 🔸 `rc4_decrypt.py` | **Stream Cipher Analysis:** Automates key and ciphertext transformations, including recovery loops for short key spaces. |
| 🔸 `custom_cipher_template.py` | **Algorithm Framework:** Provides byte-frequency analysis, difference tables, and differential cryptanalysis stubs for unknown ciphers. |
| 🔸 `angr_solve.py` | **Symbolic Execution:** Models program states to find input paths that reach success conditions while avoiding failure branches. |
| 🔸 `z3_solve.py` | **Constraint Solver:** Represents logic as mathematical constraints to recover valid inputs for algorithms and verification checks. |
| 🔸 `anti_debug_bypass.py` | **Instrumentation Evasion:** Disables common anti-analysis techniques such as timing checks and process status monitoring. |
| 🔸 `dotnet_decompile.sh` | **Managed Code Analysis:** Identifies .NET assemblies and provides workflows for decompilation and internal structure recovery. |
| 🔸 `java_decompile.sh` | **Bytecode Analysis:** Extracts Java archives and provides methods for source code reconstruction and manifest inspection. |
| 🔸 `unpack_upx.sh` | **Unpacking Utility:** Detects packed structures, evaluates section entropy, and provides routines for restoring the original executable. |
| 🔸 `golang_reversing.md` | **Go Reference:** Guidelines for analyzing Go binaries, including structural layout, string recovery, and function naming conventions. |

| File | Description |
|------|-------------|
| 🔸 `dynamic_trace.sh` | **Execution Tracer:** Monitors system and library calls, filtering logs to highlight file access, network activity, and cryptographic operations. |
| 🔸 `elf_parser.py` | **Format Inspector:** Parses executable headers, sections, and symbols to identify structural anomalies or hidden data. |
| 🔸 `entropy_check.py` | **Density Analysis:** Calculates data entropy across binary sections to rapidly identify packed, compressed, or encrypted regions. |
| 🔸 `patch_binary.py` | **Hex Modification:** Modifies executable instructions, allowing byte replacement and the inversion of conditional branches. |
| 🔸 `string_extract.py` | **Structured Text Extraction:** Filters, deduplicates, and highlights embedded data matching specific patterns (URLs, base64, target strings). |
