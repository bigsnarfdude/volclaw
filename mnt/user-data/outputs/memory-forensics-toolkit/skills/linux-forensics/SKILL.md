---
name: linux-forensics
description: "Analyze Linux memory dumps including process enumeration, kernel module analysis, network connections, file recovery, and rootkit detection specific to Linux systems. Use for any Linux or container-based memory investigation."
---

# Linux Memory Forensics — Skill

## Purpose

Analyze Linux memory images using Volatility 3's Linux-specific plugins. Linux memory forensics has unique considerations around symbol tables, kernel modules, and container-aware analysis.

## Prerequisites

### Symbol Tables

Linux symbol tables must be generated per-kernel using `dwarf2json`:

```bash
# Check the volatility3-symbols repo first for pre-built tables
# https://github.com/volatilityfoundation/volatility3-symbols

# If not available, generate manually:
# 1. Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build

# 2. Generate from kernel debug info
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > linux-$(uname -r).json
xz linux-$(uname -r).json

# 3. Place in symbols directory
cp linux-$(uname -r).json.xz /path/to/volatility3/symbols/
```

## Core Analysis Plugins

### System Information

```bash
# Identify kernel version and banner
vol -f <image> banners.Banners

# System boot time
vol -f <image> linux.boottime

# Kernel log (dmesg) from memory
vol -f <image> linux.dmesg

# Kernel symbols
vol -f <image> linux.kallsyms

# VMcore info
vol -f <image> linux.vmcoreinfo
```

### Process Analysis

```bash
# List all processes
vol -f <image> linux.pslist

# Process tree
vol -f <image> linux.pstree

# Process scan (find hidden/exited processes)
vol -f <image> linux.psscan

# Process environment variables
vol -f <image> linux.envars

# Process command lines (from /proc)
vol -f <image> linux.psaux

# Process call stacks
vol -f <image> linux.pscallstack

# Ptrace relationships
vol -f <image> linux.ptrace
```

### Memory Maps & Libraries

```bash
# Process memory maps (equivalent to /proc/PID/maps)
vol -f <image> linux.proc.Maps --pid <PID>

# Loaded shared libraries
vol -f <image> linux.library_list

# ELF file analysis and dumping
vol -f <image> linux.elfs --dump -o ./dumps/

# VMA regex scan for patterns
vol -f <image> linux.vmaregexscan --pid <PID> --pattern "password"
```

### Kernel Modules

```bash
# List loaded kernel modules
vol -f <image> linux.lsmod

# Hidden module detection (cross-view)
vol -f <image> linux.hidden_modules
vol -f <image> linux.modxview

# Extract kernel modules
vol -f <image> linux.module_extract --mod-name <name> -o ./dumps/

# Kernel threads
vol -f <image> linux.kthreads
```

### Network Analysis

```bash
# Socket statistics
vol -f <image> linux.sockstat

# IP addresses and interfaces
vol -f <image> linux.ip.Addr
vol -f <image> linux.ip.Link

# Netfilter rules (iptables/nftables)
vol -f <image> linux.netfilter
```

### File System

```bash
# Mount points
vol -f <image> linux.mountinfo

# Page cache (files cached in memory)
vol -f <image> linux.pagecache

# File descriptors per process
vol -f <image> linux.lsof

# Inode analysis
vol -f <image> linux.iomem
```

### Malware & Rootkit Detection

```bash
# Detect injected code in process memory
vol -f <image> linux.malfind

# eBPF program analysis (modern rootkit vector)
vol -f <image> linux.ebpf

# Kernel tracing hooks (ftrace, tracepoints, perf)
vol -f <image> linux.tracing.ftrace
vol -f <image> linux.tracing.tracepoints
vol -f <image> linux.tracing.perf_events

# Compare PID hash table vs task list (DKOM detection)
vol -f <image> linux.pidhashtable

# Framebuffer devices (graphics subsystem)
vol -f <image> linux.graphics.fbdev
```

### Credential & Secret Recovery

```bash
# Bash history (if bash processes are in memory)
vol -f <image> linux.bash

# Environment variables (may contain tokens, API keys)
vol -f <image> linux.envars

# YARA scan for known credential patterns
vol -f <image> yarascan.YaraScan --yara-rules "BEGIN.*PRIVATE KEY"
vol -f <image> yarascan.YaraScan --yara-rules "password"
```

## Container-Aware Analysis

When analyzing hosts running Docker/Kubernetes:

```bash
# Look for container runtime processes
vol -f <image> linux.pslist | grep -E "containerd|dockerd|runc"

# Check network namespaces (containers use separate namespaces)
vol -f <image> linux.ip.Addr  # NetNS column shows namespace IDs

# Containers often have PID 1 as the entrypoint process
vol -f <image> linux.pstree  # Look for process trees rooted in container runtimes
```

## Linux Triage Sequence

```bash
# 1. Identify the system
vol -f <image> banners.Banners
vol -f <image> linux.boottime

# 2. Process analysis
vol -f <image> linux.pstree > triage/pstree.txt
vol -f <image> linux.psaux > triage/psaux.txt

# 3. Network
vol -f <image> linux.sockstat > triage/sockstat.txt
vol -f <image> linux.ip.Addr > triage/ipaddr.txt

# 4. Kernel integrity
vol -f <image> linux.lsmod > triage/lsmod.txt
vol -f <image> linux.hidden_modules > triage/hidden_modules.txt
vol -f <image> linux.ebpf > triage/ebpf.txt

# 5. Malware
vol -f <image> linux.malfind > triage/malfind.txt

# 6. Files and credentials
vol -f <image> linux.bash > triage/bash_history.txt
vol -f <image> linux.lsof > triage/lsof.txt
```
