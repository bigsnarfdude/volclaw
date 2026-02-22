---
name: memory-forensics
description: "Use this skill for any task involving volatile memory analysis, RAM dump investigation, or memory forensics using Volatility 3. Triggers include: analyzing .raw, .vmem, .dmp, .mem memory images; hunting for malware, rootkits, or process injection in memory; extracting credentials, network connections, or registry artifacts from RAM; performing incident response triage on memory dumps; using volshell for interactive memory exploration. Also triggers for writing Volatility 3 plugins, automating memory analysis workflows, or generating forensic reports from memory evidence."
---

# Memory Forensics with Volatility 3 — Claude Code Skill

## Overview

This skill enables Claude Code to assist with memory forensics investigations using the Volatility 3 framework. It covers triage, malware hunting, credential extraction, network forensics, rootkit detection, timeline analysis, and Linux-specific analysis.

## Prerequisites

Before running any commands, verify the environment:

```bash
# Check Volatility 3 is installed
python3 -m volatility3 --help 2>/dev/null || vol --help 2>/dev/null || echo "Volatility 3 not found"

# If not installed:
pip install volatility3
# OR clone from source:
# git clone https://github.com/volatilityfoundation/volatility3.git
# cd volatility3 && pip install -e .
```

## Command Format

All Volatility 3 commands follow this pattern:

```bash
vol -f <MEMORY_IMAGE> <plugin_name> [options]
# OR
python3 vol.py -f <MEMORY_IMAGE> <plugin_name> [options]
```

Common global options:
- `-f <path>` / `--single-location <path>` — Path to memory image
- `-o <dir>` / `--output-dir <dir>` — Output directory for dumped files
- `-r <format>` — Output renderer (pretty, csv, json, jsonl)
- `-s <path>` — Symbol table path override
- `-v` / `-vv` — Verbose / very verbose output

## Investigation Workflow

Follow this order for systematic analysis:

### Phase 1: Identify the Image
```bash
vol -f <image> windows.info        # Windows
vol -f <image> linux.pslist        # Linux (also identifies kernel)
vol -f <image> banners.Banners     # Generic OS detection
```

### Phase 2: Process Triage
```bash
vol -f <image> windows.pslist      # Active process list
vol -f <image> windows.pstree      # Process tree (parent-child)
vol -f <image> windows.psscan      # Scan for hidden/terminated processes
vol -f <image> windows.cmdline     # Command-line arguments per process
vol -f <image> windows.dlllist     # Loaded DLLs per process
```

### Phase 3: Network Analysis
```bash
vol -f <image> windows.netscan     # TCP/UDP connections and listeners
vol -f <image> windows.netstat     # Active network connections
```

### Phase 4: Malware Detection
```bash
vol -f <image> windows.malfind     # Detect injected code (RWX pages)
vol -f <image> windows.hollowprocesses  # Detect process hollowing
vol -f <image> windows.ldrmodules  # Detect unlinked DLLs
vol -f <image> yarascan.YaraScan --yara-file <rules.yar>  # YARA scanning
```

### Phase 5: Persistence & Artifacts
```bash
vol -f <image> windows.registry.hivelist   # List registry hives
vol -f <image> windows.registry.printkey   # Read registry keys
vol -f <image> windows.svcscan             # Windows services
vol -f <image> windows.filescan            # Scan for file objects
vol -f <image> windows.dumpfiles --pid <PID>  # Dump process files
```

### Phase 6: Credentials
```bash
vol -f <image> windows.hashdump    # Extract NTLM hashes
vol -f <image> windows.lsadump     # LSA secrets
vol -f <image> windows.cachedump   # Cached domain credentials
```

## Sub-Skills

For deeper analysis in specific areas, see the specialized skills:

| Skill | Path | Use When |
|-------|------|----------|
| Memory Triage | `skills/memory-triage/SKILL.md` | First-pass rapid analysis |
| Malware Hunting | `skills/malware-hunting/SKILL.md` | Investigating code injection, rootkits |
| Credential Extraction | `skills/credential-extraction/SKILL.md` | Recovering passwords and hashes |
| Network Forensics | `skills/network-forensics/SKILL.md` | Analyzing C2, lateral movement |
| Rootkit Detection | `skills/rootkit-detection/SKILL.md` | Kernel-level evasion analysis |
| Timeline Analysis | `skills/timeline-analysis/SKILL.md` | Reconstructing event sequences |
| Linux Forensics | `skills/linux-forensics/SKILL.md` | Linux-specific memory analysis |

## Volshell Interactive Analysis

For ad-hoc exploration, use Volshell:

```bash
volshell -f <image> -w   # Windows mode
volshell -f <image> -l   # Linux mode
volshell -f <image> -m   # macOS mode
```

Key Volshell commands:
- `help()` — List available functions
- `display_bytes(offset, count)` / `db(offset)` — Hex dump
- `display_type(type_name, offset)` / `dt(type, offset)` — Display kernel structure
- `display_symbols(filter)` / `ds(filter)` — Search symbol tables
- `display_plugin_output(PluginClass)` — Run a plugin interactively
- `disassemble(offset, count)` / `dis(offset)` — Disassemble at address
- `change_layer(name)` / `cl(name)` — Switch memory layer
- `change_task(pid)` / `ct(pid)` — Switch process context (Linux)
- `get_process(pid)` — Get process object by PID

## Output Best Practices

1. **Always save raw output**: `vol -f image.raw windows.pslist -r csv > pslist.csv`
2. **Use JSON for programmatic analysis**: `vol -f image.raw windows.pslist -r json > pslist.json`
3. **Dump suspicious files to a directory**: `vol -f image.raw -o ./evidence/ windows.dumpfiles --pid 1234`
4. **Document every command run**: Keep a log of commands and timestamps
5. **Hash all evidence files**: `sha256sum image.raw > image.raw.sha256`

## Key Concepts

- **Layers**: Abstraction over memory address spaces (physical, virtual, swap)
- **Symbol Tables**: OS-specific structure definitions; Volatility 3 auto-detects for Windows
- **Plugins**: Modular analysis routines; namespaced as `windows.*`, `linux.*`, `mac.*`
- **No profiles needed**: Unlike Volatility 2, version 3 uses symbol tables instead of profiles
