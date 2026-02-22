#!/usr/bin/env python3
"""
timeline-builder.py — Build a unified timeline from Volatility 3 CSV outputs.

Merges timestamped events from multiple plugin outputs into a single
chronologically sorted timeline.

Usage:
    python3 timeline-builder.py <triage_directory> [--output timeline.csv]
"""

import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def parse_timestamp(ts_str: str) -> str | None:
    """Attempt to parse a timestamp string into ISO format."""
    if not ts_str or ts_str.strip() in ("N/A", "-", "", "0", "None"):
        return None

    ts_str = ts_str.strip()

    formats = [
        "%Y-%m-%d %H:%M:%S.%f %Z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S %Z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]

    # Strip timezone suffix for parsing
    ts_clean = re.sub(r"\s*(UTC|Z)$", "", ts_str)

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_clean, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            continue

    return None


def extract_events_from_csv(filepath: str, time_columns: list,
                             event_type: str, desc_columns: list) -> list:
    """Extract timestamped events from a CSV file."""
    events = []
    try:
        with open(filepath) as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return events
            for row in reader:
                for time_col in time_columns:
                    if time_col in row:
                        ts = parse_timestamp(row[time_col])
                        if ts:
                            desc_parts = []
                            for col in desc_columns:
                                val = row.get(col, "")
                                if val and val not in ("N/A", "-", ""):
                                    desc_parts.append(f"{col}={val}")
                            events.append({
                                "timestamp": ts,
                                "event_type": f"{event_type}:{time_col}",
                                "source_file": os.path.basename(filepath),
                                "description": " | ".join(desc_parts),
                            })
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)

    return events


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <triage_directory> [--output timeline.csv]")
        sys.exit(1)

    triage_dir = Path(sys.argv[1])
    output_file = "timeline.csv"

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]

    all_events = []

    # Define what to extract from each file type
    extractors = {
        "pslist": {
            "time_columns": ["CreateTime", "ExitTime"],
            "event_type": "PROCESS",
            "desc_columns": ["PID", "PPID", "ImageFileName"],
        },
        "psscan": {
            "time_columns": ["CreateTime", "ExitTime"],
            "event_type": "PROCESS_SCAN",
            "desc_columns": ["PID", "PPID", "ImageFileName"],
        },
        "netscan": {
            "time_columns": ["Created"],
            "event_type": "NETWORK",
            "desc_columns": ["Proto", "LocalAddr", "LocalPort",
                            "ForeignAddr", "ForeignPort", "State", "PID", "Owner"],
        },
        "filescan": {
            "time_columns": [],  # filescan doesn't have timestamps by default
            "event_type": "FILE",
            "desc_columns": ["Name"],
        },
        "shimcache": {
            "time_columns": ["LastModified"],
            "event_type": "SHIMCACHE",
            "desc_columns": ["Path", "Order"],
        },
        "amcache": {
            "time_columns": ["LastModified", "Created"],
            "event_type": "AMCACHE",
            "desc_columns": ["Path", "SHA1"],
        },
    }

    print(f"[*] Scanning {triage_dir} for Volatility 3 output files...")

    for csv_file in triage_dir.rglob("*.csv"):
        filename = csv_file.stem.lower()

        for extractor_key, config in extractors.items():
            if extractor_key in filename:
                events = extract_events_from_csv(
                    str(csv_file),
                    config["time_columns"],
                    config["event_type"],
                    config["desc_columns"],
                )
                all_events.extend(events)
                if events:
                    print(f"    {csv_file.name}: {len(events)} events")
                break

    # Also scan text files for timestamps (best-effort)
    for txt_file in triage_dir.rglob("*.txt"):
        filename = txt_file.stem.lower()
        if "pslist" in filename or "psscan" in filename:
            # Try to extract from text format
            try:
                with open(txt_file) as f:
                    for line in f:
                        # Look for timestamp patterns in free-form text
                        ts_match = re.search(
                            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line
                        )
                        if ts_match:
                            ts = parse_timestamp(ts_match.group(1))
                            if ts:
                                all_events.append({
                                    "timestamp": ts,
                                    "event_type": f"TEXT:{filename}",
                                    "source_file": txt_file.name,
                                    "description": line.strip()[:200],
                                })
            except Exception:
                pass

    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])

    # Output
    print(f"\n[+] Total events: {len(all_events)}")

    if all_events:
        output_path = triage_dir / output_file
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["timestamp", "event_type", "source_file", "description"]
            )
            writer.writeheader()
            writer.writerows(all_events)

        print(f"[+] Timeline saved to: {output_path}")

        # Print summary
        print("\n=== Timeline Summary ===")
        if all_events:
            print(f"  Earliest event: {all_events[0]['timestamp']}")
            print(f"  Latest event:   {all_events[-1]['timestamp']}")

            from collections import Counter
            type_counts = Counter(e["event_type"].split(":")[0] for e in all_events)
            for event_type, count in type_counts.most_common():
                print(f"  {event_type}: {count} events")
    else:
        print("[!] No timestamped events found. Ensure triage was run with -r csv")


if __name__ == "__main__":
    main()
