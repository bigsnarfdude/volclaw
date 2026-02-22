---
name: credential-extraction
description: "Extract credentials, password hashes, authentication tokens, and secrets from memory dumps. Use during incident response to assess credential exposure, determine lateral movement risk, or recover evidence of credential theft."
---

# Credential Extraction from Memory — Skill

## Purpose

Extract authentication material from memory images to assess the scope of credential compromise. This is critical for determining lateral movement capability and planning password resets during incident response.

## Windows Credential Extraction

### SAM Database Hashes (Local Accounts)

```bash
vol -f <image> windows.hashdump
```

**Output**: `Username:RID:LMHash:NTHash`

These are the local account NTLM hashes stored in the SAM registry hive. They can be cracked offline or used in pass-the-hash attacks.

### LSA Secrets

```bash
vol -f <image> windows.lsadump
```

**Contains**: Service account passwords, auto-logon credentials, VPN passwords, DPAPI secrets, machine account passwords.

### Cached Domain Credentials

```bash
vol -f <image> windows.cachedump
```

**Contains**: Domain credentials cached locally for offline logon (DCC2 hashes). These are salted and slower to crack than NTLM but still valuable.

### Registry-Based Recovery

```bash
# List all loaded registry hives
vol -f <image> windows.registry.hivelist

# Dump specific hives for offline analysis
vol -f <image> -o ./hives/ windows.dumpfiles

# Read specific registry keys
vol -f <image> windows.registry.printkey --key "SAM\Domains\Account\Users"
vol -f <image> windows.registry.printkey --key "SECURITY"
```

### LSASS Process Analysis

LSASS (Local Security Authority Subsystem Service) holds credentials in memory. Attackers commonly dump this process.

```bash
# Find LSASS PID
vol -f <image> windows.pslist | grep -i lsass

# Dump LSASS memory for offline analysis with mimikatz/pypykatz
vol -f <image> -o ./dumps/ windows.memmap --dump --pid <LSASS_PID>

# Alternative: dump the LSASS process files
vol -f <image> -o ./dumps/ windows.dumpfiles --pid <LSASS_PID>
```

**Offline analysis with pypykatz**:
```bash
pip install pypykatz
pypykatz lsa minidump lsass_dump.dmp
```

## What Credentials Reveal

| Credential Type | Lateral Movement Risk | Recommended Action |
|----------------|----------------------|-------------------|
| NTLM Hashes | High (pass-the-hash) | Reset passwords immediately |
| Kerberos Tickets | High (pass-the-ticket) | Purge tickets, reset KRBTGT 2x |
| Cached Domain Creds | Medium (offline cracking) | Reset after assessment |
| LSA Secrets | High (service accounts) | Rotate service account passwords |
| Cleartext Passwords | Critical | Immediate reset, check reuse |

## Evidence of Credential Theft

Look for these indicators that an attacker has already stolen credentials:

```bash
# Check if LSASS was accessed by unusual processes
vol -f <image> windows.handles --pid <LSASS_PID> | grep -i "process"

# Look for credential dumping tools in memory
vol -f <image> yarascan.YaraScan --yara-rules "mimikatz"
vol -f <image> windows.filescan | grep -iE "mimikatz|procdump|comsvcs|sekurlsa"

# Check for suspicious DLLs loaded into LSASS
vol -f <image> windows.dlllist --pid <LSASS_PID>

# Look for procdump or comsvcs.dll abuse
vol -f <image> windows.cmdline | grep -iE "procdump|comsvcs|MiniDump"
```

## Reporting

When reporting credential findings:
1. **Never include cleartext passwords in reports** — note their existence and recommend reset
2. Document which accounts were exposed
3. Note the credential type and lateral movement risk
4. Recommend specific remediation (password resets, KRBTGT rotation)
5. Check for credential reuse across accounts
