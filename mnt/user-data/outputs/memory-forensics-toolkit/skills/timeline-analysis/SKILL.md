---
name: timeline-analysis
description: "Reconstruct a chronological timeline of events from memory artifacts including process creation times, network connection timestamps, registry modification times, and file access times. Use for incident reconstruction and root cause analysis."
---

# Timeline Analysis from Memory — Skill

## Purpose

Build a unified chronological timeline from memory artifacts to reconstruct the sequence of events during an incident. Memory provides timestamps that may not survive on disk (process creation, network connections, handle creation).

## Timestamp Sources in Memory

| Source | Plugin | Timestamp Field |
|--------|--------|----------------|
| Process creation | `windows.pslist` | CreateTime |
| Process exit | `windows.pslist` | ExitTime |
| Network connections | `windows.netscan` | Created |
| MFT entries | `windows.mftscan.MFTScan` | Creation, Modified, Access |
| Registry keys | `windows.registry.printkey` | LastWriteTime |
| Services | `windows.svcscan` | (from binary analysis) |
| Shimcache | `windows.shimcachemem` | LastModified |
| Amcache | `windows.amcache` | Timestamps in registry |

## Building the Timeline

### Step 1: Extract All Timestamped Data

```bash
# Process timestamps
vol -f <image> windows.pslist -r csv > timeline/processes.csv

# Network timestamps
vol -f <image> windows.netscan -r csv > timeline/network.csv

# MFT (file system metadata in memory)
vol -f <image> windows.mftscan.MFTScan -r csv > timeline/mft.csv

# Shimcache (program execution evidence)
vol -f <image> windows.shimcachemem -r csv > timeline/shimcache.csv

# Amcache (program execution with hashes)
vol -f <image> windows.amcache -r csv > timeline/amcache.csv
```

### Step 2: Normalize and Merge

All timestamps should be converted to UTC and merged into a single sorted timeline:

```python
#!/usr/bin/env python3
"""Merge Volatility 3 CSV outputs into a unified timeline."""
import csv
import sys
from datetime import datetime

events = []

def add_events(filename, time_col, desc_template):
    """Read a CSV and extract timestamped events."""
    try:
        with open(filename) as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = row.get(time_col, "").strip()
                if ts and ts != "N/A":
                    desc = desc_template.format(**row)
                    events.append((ts, desc))
    except FileNotFoundError:
        print(f"[!] Skipping {filename} (not found)", file=sys.stderr)

# Add process events
add_events("timeline/processes.csv", "CreateTime",
           "PROCESS_CREATE PID={PID} {ImageFileName}")
add_events("timeline/processes.csv", "ExitTime",
           "PROCESS_EXIT PID={PID} {ImageFileName}")

# Add network events
add_events("timeline/network.csv", "Created",
           "NET_{State} {Proto} {LocalAddr}:{LocalPort} -> {ForeignAddr}:{ForeignPort} PID={PID} {Owner}")

# Sort and output
events.sort(key=lambda x: x[0])
for ts, desc in events:
    print(f"{ts}\t{desc}")
```

### Step 3: Identify Key Moments

Look for these critical timeline events:
1. **Initial access** — First suspicious process creation or network connection
2. **Execution** — When malware was first run
3. **Persistence** — Service installations, registry modifications
4. **Lateral movement** — Internal network connections (SMB, WMI, RDP)
5. **Collection** — File access patterns, archiving tools
6. **Exfiltration** — Outbound data transfers
7. **Impact** — Ransomware execution, data destruction

### Step 4: Document the Timeline

```markdown
## Incident Timeline

| Time (UTC) | Event | Source | Details |
|-----------|-------|--------|---------|
| 2025-01-15 09:23:11 | Initial Access | netscan | Inbound connection on port 443 from 1.2.3.4 |
| 2025-01-15 09:23:15 | Process Created | pslist | powershell.exe (PID 4532) spawned by winword.exe |
| 2025-01-15 09:23:18 | C2 Connection | netscan | powershell.exe -> 5.6.7.8:8443 ESTABLISHED |
| ... | ... | ... | ... |
```

## Tips

- Process `CreateTime` in pslist is the most reliable timestamp for "when did this run"
- Network connection `Created` timestamps show when connections were established
- Compare process creation order with parent-child tree to validate the attack chain
- MFT timestamps can reveal file drops even if the files were later deleted
- Shimcache entries indicate program execution (useful for persistence mechanisms)
