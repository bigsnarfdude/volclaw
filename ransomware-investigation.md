# Ransomware Investigation — Memory Analysis Playbook

## Overview

Memory analysis during a ransomware incident can recover encryption keys, identify the ransomware variant, determine the scope of encryption, find the initial access vector, and discover lateral movement paths — all critical for response and potential decryption.

---

## Priority Actions

### 1. Identify the Ransomware Process

```bash
# Look for processes that shouldn't be running or have suspicious names
vol -f <image> windows.pstree > ransom/pstree.txt

# Check command lines for ransomware indicators
vol -f <image> windows.cmdline > ransom/cmdline.txt
# Look for: encryption commands, vssadmin delete, bcdedit, wmic shadowcopy

# Common ransomware parent chains:
# explorer.exe → suspicious.exe (user-executed)
# winword.exe/excel.exe → cmd.exe → powershell.exe (macro-based)
# svchost.exe → cmd.exe → ransomware.exe (service-based)
```

### 2. Look for Encryption Key Material

```bash
# Dump the ransomware process memory — keys may still be in memory!
vol -f <image> -o ./ransom/dumps/ windows.memmap --dump --pid <RANSOM_PID>

# Search for crypto constants in memory
vol -f <image> yarascan.YaraScan --yara-rules "{ 63 7C 77 7B F2 6B 6F }" # AES S-box
vol -f <image> yarascan.YaraScan --yara-rules "{ 01 00 01 }" --pid <PID>  # RSA exponent

# Scan for known ransomware signatures
vol -f <image> yarascan.YaraScan --yara-file ransomware_rules.yar
```

### 3. Determine Initial Access

```bash
# Check for malicious documents, email attachments
vol -f <image> windows.filescan | grep -iE "\.doc|\.xls|\.pdf|\.hta|\.js|\.vbs"

# Look for download artifacts
vol -f <image> windows.cmdline | grep -iE "certutil|bitsadmin|powershell.*download"

# Check for RDP sessions (common initial access for ransomware)
vol -f <image> windows.netscan | grep -E "3389|3390"

# Check for exploitation
vol -f <image> windows.cmdline | grep -iE "exploit|psexec|wmic"
```

### 4. Map Lateral Movement

```bash
# Internal SMB connections
vol -f <image> windows.netscan | grep ":445"

# WMI lateral movement
vol -f <image> windows.netscan | grep ":135"

# PsExec evidence
vol -f <image> windows.svcscan | grep -i psexe

# RDP lateral movement
vol -f <image> windows.netscan | grep ":3389"
```

### 5. Assess Data Exfiltration

```bash
# Large outbound transfers (check for exfil before encryption)
vol -f <image> windows.netscan -r csv > ransom/netscan.csv
# Analyze: Look for connections to cloud storage, FTP, uncommon ports

# Check for archiving tools
vol -f <image> windows.cmdline | grep -iE "7z|rar|zip|tar|winrar"
vol -f <image> windows.filescan | grep -iE "\.7z|\.rar|\.zip"
```

### 6. Recovery Artifacts

```bash
# Volume Shadow Copy deletion evidence
vol -f <image> windows.cmdline | grep -iE "vssadmin|wmic.*shadowcopy|bcdedit"

# Check for backup destruction
vol -f <image> windows.cmdline | grep -iE "delete.*backup|wbadmin"

# Ransom note in memory
vol -f <image> yarascan.YaraScan --yara-rules "decrypt" 
vol -f <image> yarascan.YaraScan --yara-rules "bitcoin"
vol -f <image> yarascan.YaraScan --yara-rules ".onion"
```

## Key Artifacts for Ransomware Identification

| Artifact | How to Find |
|----------|------------|
| Ransom note filename | `filescan` for .txt/.html with "README", "DECRYPT", "RESTORE" |
| Encrypted file extension | `filescan` for unusual extensions (.encrypted, .locked, etc.) |
| Bitcoin address | YARA scan for BTC address pattern |
| Tor onion address | YARA scan for `.onion` |
| Ransomware binary | `dumpfiles` on the suspicious PID |
| Encryption keys | Memory dump of ransomware process |

## Reporting Checklist

- [ ] Ransomware variant identified
- [ ] Initial access vector determined
- [ ] Lateral movement scope mapped
- [ ] Data exfiltration assessed
- [ ] Encryption key recovery attempted
- [ ] IOCs extracted (hashes, IPs, BTC addresses, domains)
- [ ] Timeline of encryption activity documented
- [ ] Affected systems list compiled
