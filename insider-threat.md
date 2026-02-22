# Insider Threat Investigation — Memory Analysis Playbook

## Overview

Memory forensics can reveal insider threat activity that disk forensics may miss: running applications, active file transfers, clipboard contents, browser sessions, and encrypted communications that exist only in RAM.

---

## Key Investigation Areas

### 1. User Activity Reconstruction

```bash
# What programs was the user running?
vol -f <image> windows.pslist -r csv > insider/pslist.csv
vol -f <image> windows.pstree > insider/pstree.txt
vol -f <image> windows.cmdline > insider/cmdline.txt

# Console commands (cmd.exe history)
vol -f <image> windows.cmdscan > insider/cmdscan.txt
vol -f <image> windows.consoles > insider/consoles.txt
```

### 2. File Access & Transfer

```bash
# Files open at time of capture
vol -f <image> windows.filescan -r csv > insider/filescan.csv

# Filter for sensitive locations and file types
grep -iE "confidential|secret|salary|hr|finance|\.xlsx|\.pdf|\.pst" insider/filescan.csv

# Check for USB/removable media artifacts
vol -f <image> windows.registry.printkey --key "SYSTEM\CurrentControlSet\Enum\USB"

# Look for file archiving / staging
vol -f <image> windows.cmdline | grep -iE "7z|rar|zip|copy|xcopy|robocopy"
```

### 3. Network Exfiltration

```bash
vol -f <image> windows.netscan -r csv > insider/netscan.csv

# Cloud storage services
grep -iE "dropbox|onedrive|gdrive|box\.com|mega\." insider/netscan.csv

# Email exfiltration
grep -iE ":25\b|:587\b|:465\b|smtp" insider/netscan.csv

# Webmail / personal email
vol -f <image> windows.cmdline | grep -iE "gmail|yahoo|outlook\.com|proton"

# FTP/SFTP transfers
grep -iE ":21\b|:22\b|:990\b|sftp|ftp" insider/netscan.csv
```

### 4. Application-Specific Analysis

```bash
# Check for data-handling applications
vol -f <image> windows.dlllist | grep -iE "outlook|teams|slack|chrome|firefox|edge"

# Browser history may be in process memory
vol -f <image> -o ./insider/dumps/ windows.dumpfiles --pid <BROWSER_PID>

# Dump specific application memory for string analysis
vol -f <image> -o ./insider/dumps/ windows.memmap --dump --pid <PID>
strings insider/dumps/*.dmp | grep -iE "http|ftp|upload|send|attach"
```

### 5. Privilege Escalation Check

```bash
# Did the user access credentials?
vol -f <image> windows.cmdline | grep -iE "runas|net user|whoami.*priv"

# Check for tools that shouldn't be present
vol -f <image> windows.filescan | grep -iE "psexec|mimikatz|procdump|sysinternals"

# SID analysis — what groups is the user in?
vol -f <image> windows.getsids
```

## Evidence Documentation

For insider threat cases, meticulous evidence documentation is essential as findings may be used in HR proceedings or legal action.

- Hash every artifact extracted
- Log every command with timestamp
- Maintain chain of custody for the memory image
- Document the specific user account under investigation
- Note whether the activity falls within or outside normal job duties
