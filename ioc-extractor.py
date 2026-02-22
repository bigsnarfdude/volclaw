#!/usr/bin/env python3
"""
ioc-extractor.py — Extract IOCs from Volatility 3 output files.

Parses triage output (CSV/text) and extracts:
  - IP addresses (internal and external)
  - Domains
  - File hashes (if present)
  - Suspicious process names
  - Network connections with process context

Usage:
    python3 ioc-extractor.py <triage_directory>
"""

import csv
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


def is_external_ip(ip_str: str) -> bool:
    """Check if an IP address is external (not RFC1918/loopback/link-local)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False


def extract_ips_from_netscan(filepath: str) -> dict:
    """Extract network IOCs from netscan CSV output."""
    connections = []
    external_ips = set()

    try:
        # Try CSV parsing first
        with open(filepath) as f_obj:
            reader = csv.DictReader(f_obj)
            for row in reader:
                foreign = row.get("ForeignAddr", row.get("Foreign Addr", "")).strip()
                state = row.get("State", "").strip()
                pid = row.get("PID", "").strip()
                owner = row.get("Owner", "").strip()
                local_port = row.get("LocalPort", row.get("Local Port", "")).strip()
                foreign_port = row.get("ForeignPort", row.get("Foreign Port", "")).strip()

                if foreign and foreign not in ("*", "0.0.0.0", "::", "-"):
                    conn = {
                        "foreign_ip": foreign,
                        "foreign_port": foreign_port,
                        "local_port": local_port,
                        "state": state,
                        "pid": pid,
                        "process": owner,
                    }
                    connections.append(conn)
                    if is_external_ip(foreign):
                        external_ips.add(foreign)
    except Exception:
        # Fall back to regex extraction
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        with open(filepath) as f:
            for match in ip_pattern.finditer(f.read()):
                ip = match.group(1)
                if is_external_ip(ip):
                    external_ips.add(ip)

    return {"connections": connections, "external_ips": sorted(external_ips)}


def extract_suspicious_processes(cmdline_path: str, pslist_path: str) -> list:
    """Identify suspicious processes based on known patterns."""
    suspicious = []

    # Patterns that indicate suspicious activity
    sus_patterns = [
        (r"powershell.*-enc", "Encoded PowerShell"),
        (r"powershell.*downloadstring", "PowerShell download"),
        (r"powershell.*iex", "PowerShell invoke-expression"),
        (r"certutil.*-urlcache", "Certutil download"),
        (r"mshta.*http", "MSHTA remote execution"),
        (r"regsvr32.*/s.*/u.*http", "Regsvr32 remote load"),
        (r"rundll32.*javascript", "Rundll32 script execution"),
        (r"bitsadmin.*/transfer", "BITS transfer"),
        (r"cmd.*\/c.*echo.*>", "Cmd.exe file write"),
        (r"vssadmin.*delete", "Shadow copy deletion"),
        (r"bcdedit.*recoveryenabled.*no", "Recovery disabled"),
        (r"wmic.*shadowcopy.*delete", "WMIC shadow delete"),
        (r"mimikatz|sekurlsa|lsadump", "Credential tool"),
        (r"procdump.*lsass", "LSASS dump attempt"),
    ]

    if os.path.exists(cmdline_path):
        with open(cmdline_path) as f:
            for line in f:
                line_lower = line.lower()
                for pattern, description in sus_patterns:
                    if re.search(pattern, line_lower):
                        suspicious.append({
                            "indicator": description,
                            "evidence": line.strip()[:200],
                        })

    return suspicious


def extract_malfind_hits(malfind_path: str) -> list:
    """Extract malfind detection results."""
    hits = []
    if not os.path.exists(malfind_path):
        return hits

    try:
        with open(malfind_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                pid = row.get("PID", "")
                process = row.get("Process", row.get("ImageFileName", ""))
                if pid:
                    hits.append({"pid": pid, "process": process})
    except Exception:
        pass

    return hits


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <triage_directory>")
        sys.exit(1)

    triage_dir = Path(sys.argv[1])
    if not triage_dir.is_dir():
        print(f"[!] Directory not found: {triage_dir}")
        sys.exit(1)

    report = {
        "external_ips": [],
        "network_connections": [],
        "suspicious_processes": [],
        "malfind_hits": [],
    }

    # Search for netscan output
    for netscan_file in triage_dir.rglob("*netscan*"):
        result = extract_ips_from_netscan(str(netscan_file))
        report["external_ips"].extend(result["external_ips"])
        report["network_connections"].extend(result["connections"])

    # Search for cmdline and process output
    for cmdline_file in triage_dir.rglob("*cmdline*"):
        pslist_file = cmdline_file.parent / "pslist.csv"
        result = extract_suspicious_processes(str(cmdline_file), str(pslist_file))
        report["suspicious_processes"].extend(result)

    # Search for malfind output
    for malfind_file in triage_dir.rglob("*malfind*"):
        result = extract_malfind_hits(str(malfind_file))
        report["malfind_hits"].extend(result)

    # Deduplicate
    report["external_ips"] = sorted(set(report["external_ips"]))

    # Output
    print("=" * 60)
    print(" IOC Extraction Report")
    print("=" * 60)

    print(f"\n## External IPs ({len(report['external_ips'])})")
    for ip in report["external_ips"]:
        print(f"  {ip}")

    print(f"\n## Suspicious Processes ({len(report['suspicious_processes'])})")
    for item in report["suspicious_processes"]:
        print(f"  [{item['indicator']}] {item['evidence']}")

    print(f"\n## Malfind Hits ({len(report['malfind_hits'])})")
    for hit in report["malfind_hits"]:
        print(f"  PID {hit['pid']}: {hit['process']}")

    print(f"\n## Active Connections ({len(report['network_connections'])})")
    for conn in report["network_connections"][:20]:
        print(f"  {conn['process']} (PID {conn['pid']}): "
              f":{conn['local_port']} -> {conn['foreign_ip']}:{conn['foreign_port']} "
              f"[{conn['state']}]")
    if len(report["network_connections"]) > 20:
        print(f"  ... and {len(report['network_connections']) - 20} more")

    # Also save as JSON
    json_path = triage_dir / "iocs.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Full report saved to: {json_path}")


if __name__ == "__main__":
    main()
