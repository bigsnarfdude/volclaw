#!/bin/bash
# vol3-triage.sh — Automated Volatility 3 Memory Triage
# Usage: ./vol3-triage.sh <memory_image> [os_type]
# os_type: windows (default), linux, mac

set -euo pipefail

IMAGE="${1:?Usage: $0 <memory_image> [windows|linux|mac]}"
OS_TYPE="${2:-windows}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="triage_${TIMESTAMP}"
VOL="vol"

# Check if vol is available, fall back to python3 vol.py
if ! command -v vol &>/dev/null; then
    if [ -f "vol.py" ]; then
        VOL="python3 vol.py"
    elif [ -f "volatility3/vol.py" ]; then
        VOL="python3 volatility3/vol.py"
    else
        echo "[!] Volatility 3 not found. Install with: pip install volatility3"
        exit 1
    fi
fi

echo "============================================"
echo " Volatility 3 Automated Triage"
echo " Image:    $IMAGE"
echo " OS Type:  $OS_TYPE"
echo " Output:   $OUTDIR/"
echo " Started:  $(date -u)"
echo "============================================"

mkdir -p "$OUTDIR"/{triage,processes,network,malware,creds,timeline,dumps}

# Log all commands
exec > >(tee -a "$OUTDIR/triage.log") 2>&1

# Hash the image
echo "[*] Hashing memory image..."
if command -v sha256sum &>/dev/null; then
    sha256sum "$IMAGE" > "$OUTDIR/image_hash.sha256"
else
    shasum -a 256 "$IMAGE" > "$OUTDIR/image_hash.sha256"
fi

run_plugin() {
    local plugin="$1"
    local output="$2"
    local extra="${3:-}"
    echo "[*] Running: $plugin"
    if $VOL -f "$IMAGE" $plugin $extra > "$output" 2>&1; then
        echo "    -> $output"
    else
        echo "    [!] Failed or no output: $plugin"
    fi
}

if [ "$OS_TYPE" = "windows" ]; then
    # === WINDOWS TRIAGE ===
    echo ""
    echo "=== Phase 1: System Identification ==="
    run_plugin "windows.info" "$OUTDIR/triage/sysinfo.txt"

    echo ""
    echo "=== Phase 2: Process Analysis ==="
    run_plugin "windows.pslist" "$OUTDIR/processes/pslist.csv" "-r csv"
    run_plugin "windows.pstree" "$OUTDIR/processes/pstree.txt"
    run_plugin "windows.psscan" "$OUTDIR/processes/psscan.csv" "-r csv"
    run_plugin "windows.cmdline" "$OUTDIR/processes/cmdline.txt"
    run_plugin "windows.dlllist" "$OUTDIR/processes/dlllist.txt"

    echo ""
    echo "=== Phase 3: Network Analysis ==="
    run_plugin "windows.netscan" "$OUTDIR/network/netscan.csv" "-r csv"

    echo ""
    echo "=== Phase 4: Malware Detection ==="
    run_plugin "windows.malfind" "$OUTDIR/malware/malfind.csv" "-r csv"
    run_plugin "windows.ldrmodules" "$OUTDIR/malware/ldrmodules.txt"

    echo ""
    echo "=== Phase 5: Credential Artifacts ==="
    run_plugin "windows.hashdump" "$OUTDIR/creds/hashdump.txt"
    run_plugin "windows.lsadump" "$OUTDIR/creds/lsadump.txt"

    echo ""
    echo "=== Phase 6: Persistence & Services ==="
    run_plugin "windows.svcscan" "$OUTDIR/triage/services.txt"

    echo ""
    echo "=== Phase 7: File System Artifacts ==="
    run_plugin "windows.filescan" "$OUTDIR/triage/filescan.csv" "-r csv"

elif [ "$OS_TYPE" = "linux" ]; then
    # === LINUX TRIAGE ===
    echo ""
    echo "=== Phase 1: System Identification ==="
    run_plugin "banners.Banners" "$OUTDIR/triage/banners.txt"
    run_plugin "linux.boottime" "$OUTDIR/triage/boottime.txt"

    echo ""
    echo "=== Phase 2: Process Analysis ==="
    run_plugin "linux.pslist" "$OUTDIR/processes/pslist.csv" "-r csv"
    run_plugin "linux.pstree" "$OUTDIR/processes/pstree.txt"
    run_plugin "linux.psaux" "$OUTDIR/processes/psaux.txt"

    echo ""
    echo "=== Phase 3: Network Analysis ==="
    run_plugin "linux.sockstat" "$OUTDIR/network/sockstat.txt"
    run_plugin "linux.ip.Addr" "$OUTDIR/network/ipaddr.txt"

    echo ""
    echo "=== Phase 4: Kernel Module Analysis ==="
    run_plugin "linux.lsmod" "$OUTDIR/triage/lsmod.txt"
    run_plugin "linux.hidden_modules" "$OUTDIR/malware/hidden_modules.txt"

    echo ""
    echo "=== Phase 5: Malware Detection ==="
    run_plugin "linux.malfind" "$OUTDIR/malware/malfind.txt"
    run_plugin "linux.ebpf" "$OUTDIR/malware/ebpf.txt"

    echo ""
    echo "=== Phase 6: User Activity ==="
    run_plugin "linux.bash" "$OUTDIR/triage/bash_history.txt"
    run_plugin "linux.lsof" "$OUTDIR/triage/lsof.txt"

elif [ "$OS_TYPE" = "mac" ]; then
    # === MACOS TRIAGE ===
    echo ""
    echo "=== Phase 1: System Identification ==="
    run_plugin "banners.Banners" "$OUTDIR/triage/banners.txt"

    echo ""
    echo "=== Phase 2: Process Analysis ==="
    run_plugin "mac.pslist" "$OUTDIR/processes/pslist.txt"
    run_plugin "mac.pstree" "$OUTDIR/processes/pstree.txt"

    echo ""
    echo "=== Phase 3: Network Analysis ==="
    run_plugin "mac.ifconfig" "$OUTDIR/network/ifconfig.txt"
fi

echo ""
echo "============================================"
echo " Triage complete!"
echo " Results: $OUTDIR/"
echo " Finished: $(date -u)"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Review $OUTDIR/triage.log for errors"
echo "  2. Check $OUTDIR/malware/ for detections"
echo "  3. Analyze $OUTDIR/network/ for suspicious connections"
echo "  4. Review $OUTDIR/processes/ for anomalies"
