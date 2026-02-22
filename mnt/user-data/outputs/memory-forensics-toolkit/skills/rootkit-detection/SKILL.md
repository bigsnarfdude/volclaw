---
name: rootkit-detection
description: "Detect kernel-level and user-mode rootkits, DKOM attacks, syscall hooking, and other evasion techniques in memory dumps. Use when hidden processes, modules, or hooks are suspected, or during advanced threat hunting."
---

# Rootkit & Evasion Detection in Memory — Skill

## Purpose

Detect rootkits and advanced evasion techniques that hide malicious activity from standard OS tools. Memory forensics is uniquely effective here because rootkits can fool live system tools but cannot easily hide from raw memory analysis.

## Detection Techniques

### 1. Hidden Process Detection (DKOM)

Direct Kernel Object Manipulation (DKOM) unlinks processes from the kernel's active process list.

```bash
# Standard process list (walks linked list — rootkits can hide from this)
vol -f <image> windows.pslist -r csv > pslist.csv

# Pool scanner (scans memory pools for EPROCESS — cannot be hidden by DKOM)
vol -f <image> windows.psscan -r csv > psscan.csv

# Cross-view comparison
vol -f <image> windows.psxview
```

**Detection logic**: Any process found by `psscan` but NOT in `pslist` is likely hidden by a rootkit.

```bash
# Diff the two outputs
comm -23 <(awk -F',' '{print $1}' psscan.csv | sort) <(awk -F',' '{print $1}' pslist.csv | sort)
```

### 2. Hidden Kernel Modules

```bash
# List loaded kernel modules
vol -f <image> windows.modules

# Scan for module objects in memory (finds unlinked modules)
vol -f <image> windows.modscan

# Detect orphan kernel threads (threads without a parent module)
vol -f <image> windows.orphan_kernel_threads

# Linux: hidden modules detection
vol -f <image> linux.hidden_modules
vol -f <image> linux.lsmod           # Loaded modules from list
vol -f <image> linux.modxview        # Cross-reference module views
```

### 3. System Call Hooking

```bash
# Detect direct system calls (used by malware to bypass EDR hooks)
vol -f <image> windows.direct_system_calls

# Detect indirect system calls (another EDR evasion technique)
vol -f <image> windows.indirect_system_calls

# SSDT (System Service Descriptor Table) analysis
vol -f <image> windows.ssdt
```

### 4. Callback & Hook Detection

```bash
# Windows callback routines (process creation, image load, registry, etc.)
vol -f <image> windows.callbacks

# Debug registers (hardware breakpoints used for hooking)
vol -f <image> windows.debugregisters

# Timer-based persistence
vol -f <image> windows.timers
```

### 5. Driver Analysis

```bash
# List loaded drivers
vol -f <image> windows.driverscan

# Unloaded modules (evidence of load-unload rootkit technique)
vol -f <image> windows.unloadedmodules

# Check driver IRP hooks
vol -f <image> windows.driverirp
```

### 6. Linux-Specific Rootkit Detection

```bash
# Check for eBPF-based rootkits
vol -f <image> linux.ebpf

# Kernel tracing hooks
vol -f <image> linux.tracing.ftrace
vol -f <image> linux.tracing.tracepoints
vol -f <image> linux.tracing.perf_events

# Process call stacks (detect suspicious kernel activity)
vol -f <image> linux.pscallstack

# Kernel thread analysis
vol -f <image> linux.kthreads

# Compare PID hash table vs task list
vol -f <image> linux.pidhashtable
```

## Rootkit Investigation Playbook

```
1. Run pslist vs psscan → find hidden processes
2. Run modules vs modscan → find hidden kernel modules  
3. Run orphan_kernel_threads → find rootkit threads
4. Check SSDT for hooks → identify syscall interception
5. Analyze callbacks → find persistent notification routines
6. Check debug registers → detect hardware breakpoint hooks
7. On Linux: check eBPF, ftrace, kprobes for tracing-based rootkits
8. Dump and analyze any suspicious drivers/modules found
9. Cross-reference with known rootkit signatures (YARA)
```

## Known Rootkit Signatures

Common things to YARA scan for:
- `Turla` / `Snake` — Kernel-mode rootkit
- `Rustock` — Spam rootkit
- `TDSS/TDL` — Bootkit/rootkit family
- `ZeroAccess` — Kernel-mode rootkit
- `Necurs` — Rootkit component
- eBPF rootkits (`bpfdoor`, `pamspy`) on Linux
