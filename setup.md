# Environment Setup Guide

## Volatility 3 Installation

### Option 1: pip (Recommended)

```bash
pip install volatility3
```

### Option 2: From Source (Latest Development)

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m venv venv
source venv/bin/activate    # Linux/Mac
# venv\Scripts\activate     # Windows
pip install -e ".[dev]"
```

### Requirements

- Python 3.8+
- Recommended extras: `pycryptodome` (credential plugins), `yara-python` (YARA scanning), `capstone` (disassembly)

```bash
pip install pycryptodome yara-python capstone
```

## Symbol Tables

### Windows

Windows symbols are auto-downloaded from Microsoft's symbol server on first use. You can also pre-download them:

```bash
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d volatility3/symbols/
```

### Linux

Linux symbol tables must match the exact kernel version. Check the pre-built repo first:

```
https://github.com/volatilityfoundation/volatility3-symbols
```

If your kernel isn't available, generate manually with `dwarf2json`:

```bash
# Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build

# Generate from kernel debug symbols
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > symbol.json
xz symbol.json
cp symbol.json.xz /path/to/volatility3/symbols/
```

### macOS

```bash
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
unzip mac.zip -d volatility3/symbols/
```

## Memory Acquisition Tools

Volatility only **analyzes** memory — you need a separate tool to **acquire** it.

| Tool | Platform | Notes |
|------|----------|-------|
| WinPmem | Windows | Open source, raw format |
| FTK Imager | Windows | Free, multiple formats |
| Magnet RAM Capture | Windows | Free |
| DumpIt | Windows | One-click acquisition |
| AVML | Linux | Microsoft's open-source tool |
| LiME | Linux | Kernel module, raw/padded |
| osxpmem | macOS | Part of Rekall project |

## Companion Tools

| Tool | Purpose | Install |
|------|---------|---------|
| pypykatz | Offline mimikatz (LSASS analysis) | `pip install pypykatz` |
| YARA | Pattern matching rules | `pip install yara-python` |
| strings | Extract printable strings | Built into Linux; `strings` on Windows via SysInternals |
| VirusTotal CLI | IOC reputation checking | `pip install vt-cli` |

## Verification

```bash
# Verify installation
vol --help

# List available plugins
vol --help | grep windows
vol --help | grep linux

# Test with a sample image (if available)
vol -f sample.raw windows.info
```
