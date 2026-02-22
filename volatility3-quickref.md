# Volatility 3 — Quick Reference

## Installation

```bash
pip install volatility3
# OR from source:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -e ".[dev]"
```

## Basic Syntax

```bash
vol -f <image> <plugin> [options]
```

## Global Options

| Option | Description |
|--------|-------------|
| `-f <path>` | Path to memory image |
| `-o <dir>` | Output directory for dumped files |
| `-r <fmt>` | Renderer: `pretty`, `csv`, `json`, `jsonl` |
| `-s <path>` | Symbol table directory override |
| `-v` / `-vv` | Verbose / very verbose |
| `--help` | Show help (add after plugin name for plugin-specific help) |

## Windows Plugins

### Process & Thread Analysis

| Plugin | Description |
|--------|-------------|
| `windows.pslist` | List running processes (linked list walk) |
| `windows.pstree` | Process tree with parent-child |
| `windows.psscan` | Pool scan for EPROCESS (finds hidden) |
| `windows.psxview` | Cross-view process detection |
| `windows.cmdline` | Process command-line arguments |
| `windows.dlllist` | Loaded DLLs per process |
| `windows.handles` | Open handles per process |
| `windows.threads` | Thread listing |
| `windows.suspended_threads` | Suspended threads |
| `windows.suspicious_threads` | Threads with suspicious properties |
| `windows.orphan_kernel_threads` | Kernel threads without module |
| `windows.getsids` | Process SIDs |

### Memory & Code Analysis

| Plugin | Description |
|--------|-------------|
| `windows.malfind` | Detect injected/suspicious memory regions |
| `windows.hollowprocesses` | Detect process hollowing |
| `windows.ldrmodules` | Hidden DLL detection (3-way comparison) |
| `windows.vadinfo` | VAD tree information |
| `windows.memmap` | Process memory map (use `--dump`) |
| `windows.dumpfiles` | Dump files from process (use `--pid`) |
| `windows.pedump` | Dump PE from memory |
| `windows.processghosting` | Detect process ghosting |
| `windows.direct_system_calls` | Direct syscall detection |
| `windows.indirect_system_calls` | Indirect syscall detection |

### Network

| Plugin | Description |
|--------|-------------|
| `windows.netscan` | Scan for network connections & sockets |
| `windows.netstat` | Active network connections |

### Registry

| Plugin | Description |
|--------|-------------|
| `windows.registry.hivelist` | List loaded registry hives |
| `windows.registry.hivescan` | Scan for registry hives |
| `windows.registry.printkey` | Read registry key (use `--key`) |
| `windows.registry.getcellroutine` | Registry cell callback routines |

### Services & Drivers

| Plugin | Description |
|--------|-------------|
| `windows.svcscan` | Scan for Windows services |
| `windows.svclist` | Service list |
| `windows.svcdiff` | Compare service list vs scan |
| `windows.driverscan` | Scan for loaded drivers |
| `windows.driverirp` | Driver IRP hook detection |
| `windows.modules` | Loaded kernel modules |
| `windows.modscan` | Scan for modules (finds unlinked) |
| `windows.unloadedmodules` | Previously loaded modules |

### Credentials

| Plugin | Description |
|--------|-------------|
| `windows.hashdump` | Extract SAM hashes |
| `windows.lsadump` | LSA secrets |
| `windows.cachedump` | Cached domain credentials |

### File System & Persistence

| Plugin | Description |
|--------|-------------|
| `windows.filescan` | Scan for file objects |
| `windows.mftscan.MFTScan` | MFT entries in memory |
| `windows.mftscan.ADS` | Alternate data streams |
| `windows.shimcachemem` | Application compatibility cache |
| `windows.amcache` | Amcache execution artifacts |
| `windows.cmdscan` | Command history buffers |
| `windows.consoles` | Console output buffers |

### System & Kernel

| Plugin | Description |
|--------|-------------|
| `windows.info` | System information |
| `windows.bigpools` | Big pool allocations |
| `windows.callbacks` | Kernel callback routines |
| `windows.ssdt` | SSDT entries |
| `windows.debugregisters` | Hardware debug registers |
| `windows.timers` | Kernel timers |
| `windows.crashinfo` | Crash dump info |
| `windows.kpcrs` | Kernel processor control regions |

### GUI

| Plugin | Description |
|--------|-------------|
| `windows.deskscan` | Desktop objects |
| `windows.desktops` | Desktop details |
| `windows.windows` | Window objects |
| `windows.windowstations` | Window stations |

### Scanning

| Plugin | Description |
|--------|-------------|
| `yarascan.YaraScan` | YARA rule scanning |
| `windows.vadregexscan` | Regex scan over VADs |

## Linux Plugins

| Plugin | Description |
|--------|-------------|
| `linux.pslist` | Process list |
| `linux.pstree` | Process tree |
| `linux.psscan` | Process scan |
| `linux.psaux` | Process with command lines |
| `linux.envars` | Environment variables |
| `linux.bash` | Bash history |
| `linux.lsmod` | Loaded kernel modules |
| `linux.hidden_modules` | Hidden module detection |
| `linux.modxview` | Module cross-view |
| `linux.module_extract` | Extract kernel module |
| `linux.sockstat` | Socket statistics |
| `linux.ip.Addr` | IP addresses |
| `linux.ip.Link` | Network links |
| `linux.netfilter` | Netfilter rules |
| `linux.malfind` | Injected code detection |
| `linux.elfs` | ELF analysis |
| `linux.proc.Maps` | Process memory maps |
| `linux.library_list` | Shared libraries |
| `linux.lsof` | Open files |
| `linux.mountinfo` | Mount points |
| `linux.pagecache` | Page cache files |
| `linux.ebpf` | eBPF programs |
| `linux.kthreads` | Kernel threads |
| `linux.kallsyms` | Kernel symbols |
| `linux.boottime` | Boot timestamp |
| `linux.dmesg` | Kernel messages |
| `linux.pidhashtable` | PID hash table comparison |
| `linux.ptrace` | Ptrace relationships |
| `linux.pscallstack` | Process call stacks |
| `linux.tracing.ftrace` | Ftrace hooks |
| `linux.tracing.tracepoints` | Tracepoint hooks |
| `linux.tracing.perf_events` | Perf event hooks |
| `linux.vmcoreinfo` | VMcore information |
| `linux.vmaregexscan` | VMA regex scanner |

## macOS Plugins

| Plugin | Description |
|--------|-------------|
| `mac.pslist` | Process list |
| `mac.pstree` | Process tree |
| `mac.ifconfig` | Network interfaces |
| `mac.dmesg` | Kernel messages |
| `mac.regexscan` | Regex scanner |

## Generic / Cross-Platform

| Plugin | Description |
|--------|-------------|
| `banners.Banners` | OS identification |
| `yarascan.YaraScan` | YARA rule scanning |
| `layerwriter.LayerWriter` | Write out a memory layer |
| `isfinfo.IsfInfo` | Symbol table information |
