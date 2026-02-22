---
name: network-forensics
description: "Analyze network artifacts in memory dumps including active connections, listening ports, DNS cache, and socket objects. Use to identify C2 communications, data exfiltration, lateral movement, and attacker infrastructure."
---

# Network Forensics from Memory — Skill

## Purpose

Extract and analyze network artifacts from memory to map attacker communications, identify command-and-control infrastructure, detect lateral movement, and find evidence of data exfiltration.

## Core Plugins

### Windows Network Analysis

```bash
# Comprehensive network scan — connections, listeners, sockets
vol -f <image> windows.netscan -r csv > network/netscan.csv

# Active network connections (netstat-style)
vol -f <image> windows.netstat
```

**netscan output columns**: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created

### Linux Network Analysis

```bash
# Network connections
vol -f <image> linux.sockstat

# IP address and interface information
vol -f <image> linux.ip.Addr
vol -f <image> linux.ip.Link

# Netfilter / iptables rules
vol -f <image> linux.netfilter
```

## Analysis Workflow

### Step 1: Map All Connections

```bash
vol -f <image> windows.netscan -r csv > net.csv
```

Categorize connections:
- **ESTABLISHED** — Active bidirectional connections (highest priority)
- **LISTENING** — Servers waiting for connections (check for backdoors)
- **CLOSE_WAIT / TIME_WAIT** — Recently closed (historical evidence)
- **SYN_SENT** — Outgoing attempts (may indicate failed C2)

### Step 2: Identify Suspicious Connections

**Red flags**:
- Outbound to unusual ports (4444, 5555, 8443, 1337, etc.)
- Connections from processes that shouldn't network (notepad, calc, etc.)
- Multiple connections to the same foreign IP from different processes
- Connections to IPs in unusual geolocations
- High-numbered ephemeral source ports with low-numbered destinations
- Connections from `svchost.exe` to non-Microsoft IPs

### Step 3: Correlate with Processes

```bash
# Get the full process context for suspicious PIDs found in netscan
vol -f <image> windows.cmdline --pid <PID>
vol -f <image> windows.dlllist --pid <PID>
vol -f <image> windows.pstree --pid <PID>
```

### Step 4: External Enrichment

For each suspicious IP/domain, check:
- VirusTotal (`https://www.virustotal.com/gui/ip-address/<IP>`)
- AbuseIPDB (`https://www.abuseipdb.com/check/<IP>`)
- Shodan (`https://www.shodan.io/host/<IP>`)
- Whois for registration details
- Passive DNS for domain history

## Common C2 Patterns

| Pattern | Indicators |
|---------|-----------|
| HTTP/HTTPS Beaconing | Regular interval connections to same IP on 80/443 |
| DNS Tunneling | High volume of DNS queries to unusual domains |
| Reverse Shell | Single ESTABLISHED connection from victim to attacker on high port |
| Cobalt Strike | Connections on 50050, malleable C2 profiles on 80/443 |
| Lateral Movement | SMB (445), WMI (135), WinRM (5985/5986), RDP (3389) to internal IPs |

## IOC Extraction

```bash
# Extract unique foreign IPs
vol -f <image> windows.netscan -r csv | awk -F',' '{print $5}' | sort -u > iocs/ips.txt

# Extract connections with process context
vol -f <image> windows.netscan -r csv | grep ESTABLISHED > iocs/active_connections.csv
```
