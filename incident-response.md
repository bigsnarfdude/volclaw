# Incident Response Memory Analysis Playbook

## Overview

This playbook provides a structured workflow for analyzing a memory dump during an active incident. It is designed to be followed sequentially, with decision points that guide deeper analysis based on findings.

---

## Phase 1: Evidence Handling (5 min)

Before analysis begins:

```bash
# 1. Record the hash of the memory image (chain of custody)
sha256sum <image> | tee evidence_hash.txt

# 2. Create working directory
mkdir -p ir_$(date +%Y%m%d)/{triage,processes,network,malware,creds,timeline,dumps}
export WORKDIR="ir_$(date +%Y%m%d)"
export IMAGE="<path-to-image>"

# 3. Note the start time of analysis
echo "Analysis started: $(date -u)" > "$WORKDIR/analysis_log.txt"
```

---

## Phase 2: System Identification (5 min)

```bash
vol -f "$IMAGE" windows.info > "$WORKDIR/triage/sysinfo.txt" 2>&1
# OR for Linux:
vol -f "$IMAGE" banners.Banners > "$WORKDIR/triage/sysinfo.txt" 2>&1
```

Record: OS version, architecture, hostname, acquisition timestamp.

---

## Phase 3: Process Triage (15 min)

```bash
vol -f "$IMAGE" windows.pslist -r csv > "$WORKDIR/triage/pslist.csv"
vol -f "$IMAGE" windows.pstree > "$WORKDIR/triage/pstree.txt"
vol -f "$IMAGE" windows.psscan -r csv > "$WORKDIR/triage/psscan.csv"
vol -f "$IMAGE" windows.cmdline > "$WORKDIR/triage/cmdline.txt"
```

### Decision Point: Process Anomalies?

Check for:
- [ ] Processes in psscan not in pslist (hidden)
- [ ] Unexpected parent-child relationships
- [ ] Suspicious command-line arguments
- [ ] Known-bad process names

**If anomalies found** → Note PIDs, continue to Phase 4 with focus on those PIDs.
**If clean** → Continue to Phase 4 for network analysis.

---

## Phase 4: Network Analysis (10 min)

```bash
vol -f "$IMAGE" windows.netscan -r csv > "$WORKDIR/network/netscan.csv"
```

### Decision Point: Suspicious Network Activity?

Check for:
- [ ] Connections to external IPs from unexpected processes
- [ ] Listening ports that shouldn't exist
- [ ] Connections to known threat intel indicators

**If C2 found** → Extract IPs, correlate with process PIDs, escalate to threat intel team.
**If lateral movement detected** → Document source/dest IPs and ports, check other endpoints.

---

## Phase 5: Malware Analysis (20 min)

```bash
vol -f "$IMAGE" windows.malfind -r csv > "$WORKDIR/malware/malfind.csv"
vol -f "$IMAGE" windows.hollowprocesses > "$WORKDIR/malware/hollowprocesses.txt"
vol -f "$IMAGE" windows.ldrmodules > "$WORKDIR/malware/ldrmodules.txt"
vol -f "$IMAGE" windows.suspicious_threads > "$WORKDIR/malware/suspicious_threads.txt"
```

For each suspicious PID:
```bash
PID=<suspicious_pid>
vol -f "$IMAGE" -o "$WORKDIR/dumps/" windows.dumpfiles --pid $PID
vol -f "$IMAGE" windows.dlllist --pid $PID > "$WORKDIR/processes/dlllist_${PID}.txt"
vol -f "$IMAGE" windows.handles --pid $PID > "$WORKDIR/processes/handles_${PID}.txt"
```

### Decision Point: Malware Confirmed?

- [ ] Injected code found by malfind
- [ ] Hollowed processes detected
- [ ] Unlinked DLLs in ldrmodules
- [ ] Suspicious thread start addresses

**If confirmed** → Dump artifacts, hash them, submit to sandbox/VT, continue.
**If uncertain** → Run YARA scans with known rules, analyze dumped files statically.

---

## Phase 6: Credential Assessment (10 min)

```bash
vol -f "$IMAGE" windows.hashdump > "$WORKDIR/creds/hashdump.txt"
vol -f "$IMAGE" windows.lsadump > "$WORKDIR/creds/lsadump.txt"
vol -f "$IMAGE" windows.cachedump > "$WORKDIR/creds/cachedump.txt"
```

Check for credential theft evidence:
```bash
vol -f "$IMAGE" windows.cmdline | grep -iE "mimikatz|procdump|sekurlsa|comsvcs" \
    > "$WORKDIR/creds/theft_indicators.txt"
```

### Decision Point: Credentials Compromised?

**If credential theft tools found** → Recommend immediate password resets for affected accounts.
**If hashes extracted** → Assess scope, recommend Tier-1/Tier-2 resets.

---

## Phase 7: Persistence Check (10 min)

```bash
vol -f "$IMAGE" windows.svcscan > "$WORKDIR/triage/services.txt"
vol -f "$IMAGE" windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run" \
    > "$WORKDIR/triage/autorun.txt"
vol -f "$IMAGE" windows.shimcachemem -r csv > "$WORKDIR/timeline/shimcache.csv"
vol -f "$IMAGE" windows.amcache -r csv > "$WORKDIR/timeline/amcache.csv"
```

---

## Phase 8: Timeline Reconstruction (15 min)

```bash
# Build timeline from all timestamp sources
# See skills/timeline-analysis/SKILL.md for the merge script
```

Key questions the timeline should answer:
1. When did the initial compromise occur?
2. What was the attack sequence?
3. How long did the attacker have access?
4. What systems were accessed?
5. Was data exfiltrated?

---

## Phase 9: Reporting

Use `templates/findings-report.md` to structure the final report. Key sections:

1. **Executive Summary** — 3-sentence overview for leadership
2. **Timeline** — Chronological event reconstruction
3. **IOCs** — All extracted indicators (IPs, hashes, filenames, mutexes)
4. **Impact Assessment** — What was accessed/stolen/encrypted
5. **Recommendations** — Immediate actions and long-term improvements

---

## Appendix: Quick Command Reference

| Task | Command |
|------|---------|
| System info | `vol -f IMG windows.info` |
| Process list | `vol -f IMG windows.pslist` |
| Process tree | `vol -f IMG windows.pstree` |
| Hidden procs | `vol -f IMG windows.psscan` |
| Cmd lines | `vol -f IMG windows.cmdline` |
| Network | `vol -f IMG windows.netscan` |
| Injected code | `vol -f IMG windows.malfind` |
| DLL list | `vol -f IMG windows.dlllist --pid N` |
| Hidden DLLs | `vol -f IMG windows.ldrmodules` |
| Dump files | `vol -f IMG -o dir/ windows.dumpfiles --pid N` |
| Hashes | `vol -f IMG windows.hashdump` |
| Registry | `vol -f IMG windows.registry.printkey --key KEY` |
| YARA | `vol -f IMG yarascan.YaraScan --yara-file rules.yar` |
| Services | `vol -f IMG windows.svcscan` |
| File scan | `vol -f IMG windows.filescan` |
