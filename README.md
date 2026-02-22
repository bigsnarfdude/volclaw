# Memory Forensics Investigation Toolkit

A comprehensive collection of **Claude Code skills**, investigation playbooks, and automation scripts for **memory forensics analysis** using [Volatility 3](https://github.com/volatilityfoundation/volatility3).

Designed to be used by DFIR analysts, SOC teams, and anyone performing memory analysis — either manually or with AI-assisted workflows via Claude Code.

---

## Repository Structure

```
memory-forensics-toolkit/
├── README.md                          # You are here
├── SKILL.md                           # Claude Code skill definition (root)
├── skills/
│   ├── memory-triage/SKILL.md         # Rapid triage skill
│   ├── malware-hunting/SKILL.md       # Malware detection skill
│   ├── credential-extraction/SKILL.md # Credential recovery skill
│   ├── network-forensics/SKILL.md     # Network artifact analysis
│   ├── rootkit-detection/SKILL.md     # Rootkit & evasion detection
│   ├── timeline-analysis/SKILL.md     # Timeline reconstruction
│   └── linux-forensics/SKILL.md       # Linux-specific analysis
├── playbooks/
│   ├── incident-response.md           # Full IR memory playbook
│   ├── ransomware-investigation.md    # Ransomware-specific workflow
│   └── insider-threat.md              # Insider threat investigation
├── scripts/
│   ├── vol3-triage.sh                 # Automated triage script
│   ├── ioc-extractor.py              # Extract IOCs from vol3 output
│   └── timeline-builder.py           # Build unified timeline
├── templates/
│   ├── findings-report.md            # Investigation report template
│   └── evidence-log.md               # Chain of custody / evidence log
└── docs/
    ├── volatility3-quickref.md        # Volatility 3 quick reference
    ├── volshell-guide.md              # Volshell interactive analysis
    └── setup.md                       # Environment setup guide
```

## Quick Start

### 1. Install Volatility 3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m venv venv && . venv/bin/activate
pip install -e ".[dev]"
```

### 2. Download Symbol Tables

```bash
# Windows (auto-downloads from Microsoft symbol server on first use)
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -P volatility3/symbols/
# Mac
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip -P volatility3/symbols/
# Linux — must be generated per-kernel with dwarf2json
```

### 3. Using as Claude Code Skills

Copy the `skills/` directory into your Claude Code project's skill path, or reference them directly:

```bash
# In your Claude Code project
cp -r memory-forensics-toolkit/skills/ /path/to/your/project/.claude/skills/
```

Each skill folder contains a `SKILL.md` that Claude Code reads to understand how to perform that category of analysis.

## Supported Platforms

| Platform | Process Analysis | Network | Registry | Malware Detection | Credentials |
|----------|-----------------|---------|----------|-------------------|-------------|
| Windows  | ✅               | ✅       | ✅        | ✅                 | ✅           |
| Linux    | ✅               | ✅       | N/A      | ✅                 | Partial     |
| macOS    | ✅               | ✅       | N/A      | ✅                 | Partial     |

## License

MIT — Use freely for defensive security operations.
