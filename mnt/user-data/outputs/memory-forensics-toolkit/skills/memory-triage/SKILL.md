---
name: memory-triage
description: "Rapid first-pass triage of a memory image. Use when you need to quickly assess a memory dump for signs of compromise, establish the OS version, enumerate processes, and flag obvious anomalies before deeper analysis."
---

# Memory Triage Skill

## Purpose

Perform a fast, structured first-pass analysis of a memory image to determine: what OS is running, what processes are active, whether anything is obviously suspicious, and what warrants deeper investigation.

## Triage Sequence

Run these commands in order. Stop and investigate further if any step reveals anomalies.

### Step 1: Image Identification

```bash
# Determine OS and architecture
vol -f <image> windows.info
# OR for Linux:
vol -f <image> banners.Banners
```

**What to look for**: OS version, build number, architecture (x64/x86), number of processors.

### Step 2: Process Enumeration

```bash
# List all processes with metadata
vol -f <image> windows.pslist -r csv > triage/pslist.csv

# Tree view to see parent-child relationships
vol -f <image> windows.pstree > triage/pstree.txt

# Scan for hidden/exited processes not in active list
vol -f <image> windows.psscan -r csv > triage/psscan.csv
```

**Anomaly indicators**:
- Processes with no parent (orphans) — may indicate injection or rootkit
- `svchost.exe` not parented by `services.exe`
- `csrss.exe`, `lsass.exe`, `smss.exe` with wrong parent or duplicate instances
- Processes with suspicious names (typosquatting: `scvhost.exe`, `lsas.exe`)
- Processes with unexpected PIDs (e.g., `System` should be PID 4)
- Processes in psscan but NOT in pslist (hidden processes)

### Step 3: Command Lines

```bash
vol -f <image> windows.cmdline > triage/cmdline.txt
```

**Anomaly indicators**:
- PowerShell with `-enc` or `-encodedcommand` flags
- `cmd.exe` spawned by unusual parents (Word, Excel, browser)
- Paths pointing to `%TEMP%`, `%APPDATA%`, or `C:\Users\Public`
- LOLBins: `certutil`, `mshta`, `regsvr32`, `rundll32` with URLs

### Step 4: Network Connections

```bash
vol -f <image> windows.netscan -r csv > triage/netscan.csv
```

**Anomaly indicators**:
- Connections to known-bad IPs (check VirusTotal, AbuseIPDB)
- Unexpected outbound connections on ports 443, 4444, 8080, 8443
- Processes that shouldn't have network activity (notepad, calc)
- LISTENING ports that don't match known services

### Step 5: Quick Malware Scan

```bash
vol -f <image> windows.malfind -r csv > triage/malfind.csv
```

**Anomaly indicators**:
- Memory regions marked RWX (Read-Write-Execute)
- MZ headers (PE files) found injected in process memory
- Shellcode patterns at the start of executable regions

### Step 6: Loaded Modules

```bash
vol -f <image> windows.dlllist > triage/dlllist.txt
vol -f <image> windows.ldrmodules > triage/ldrmodules.txt
```

**Anomaly indicators in ldrmodules**:
- Entries where InLoad, InInit, or InMem are `False` — may indicate unlinked/hidden DLLs
- If ALL three columns are False, strong indicator of rootkit activity

## Triage Output Template

After running the above, summarize findings:

```
## Memory Triage Summary

**Image**: <filename>
**OS**: <detected OS and version>
**Acquisition Time**: <if available>
**Analysis Date**: <today>

### Process Summary
- Total processes (pslist): <count>
- Hidden processes (in psscan, not pslist): <count>
- Suspicious processes: <list with PIDs>

### Network Summary
- Active connections: <count>
- Suspicious connections: <list with dest IPs>
- Listening ports: <unusual ports>

### Malware Indicators
- Malfind hits: <count>
- Suspicious DLLs: <list>

### Recommended Next Steps
1. <specific follow-up analysis>
2. <processes to investigate deeper>
3. <IOCs to check externally>
```

## Automation

```bash
#!/bin/bash
# Quick triage script
IMAGE="$1"
OUT="triage_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

echo "[*] Running triage on: $IMAGE"
vol -f "$IMAGE" windows.info > "$OUT/info.txt" 2>&1
vol -f "$IMAGE" windows.pslist -r csv > "$OUT/pslist.csv" 2>&1
vol -f "$IMAGE" windows.pstree > "$OUT/pstree.txt" 2>&1
vol -f "$IMAGE" windows.psscan -r csv > "$OUT/psscan.csv" 2>&1
vol -f "$IMAGE" windows.cmdline > "$OUT/cmdline.txt" 2>&1
vol -f "$IMAGE" windows.netscan -r csv > "$OUT/netscan.csv" 2>&1
vol -f "$IMAGE" windows.malfind -r csv > "$OUT/malfind.csv" 2>&1
vol -f "$IMAGE" windows.ldrmodules > "$OUT/ldrmodules.txt" 2>&1

echo "[+] Triage complete. Results in: $OUT/"
```
