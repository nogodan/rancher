#!/usr/bin/env bash

set -uo pipefail

INPUT="${1:-}"
if [ -z "$INPUT" ]; then
    echo "Usage: $0 <supportconfig.txz | extracted_dir>"
    exit 1
fi

if [ ! -e "$INPUT" ]; then
    echo "ERROR: path not found: $INPUT"
    exit 1
fi

WORKDIR=$(mktemp -d /tmp/suse_rca.XXXXXX)
BUNDLE_BASENAME=$(basename "$INPUT")
BUNDLE_BASENAME="${BUNDLE_BASENAME%.txz}"
BUNDLE_BASENAME="${BUNDLE_BASENAME%.tar.bz2}"
BUNDLE_BASENAME="${BUNDLE_BASENAME%.tar.gz}"
REPORT="$(pwd)/${BUNDLE_BASENAME}_rca_report.txt"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

log() { echo -e "$1" | tee -a "$REPORT"; }
sep() { log "================================================================================"; }
section_header() { log "\n$1"; log "--------------------------------------------------------------------------------"; }

if [ -d "$INPUT" ]; then
    SCDIR="$INPUT"
else
    echo "Extracting $INPUT ..."
    case "$INPUT" in
        *.txz|*.tar.xz)   tar xJf "$INPUT" -C "$WORKDIR" ;;
        *.tbz|*.tar.bz2)  tar xjf "$INPUT" -C "$WORKDIR" ;;
        *.tgz|*.tar.gz)   tar xzf "$INPUT" -C "$WORKDIR" ;;
        *.tar)            tar xf "$INPUT" -C "$WORKDIR" ;;
        *)
            echo "ERROR: unrecognized archive format: $INPUT"
            exit 1
            ;;
    esac
    SCDIR=$(find "$WORKDIR" -maxdepth 1 -mindepth 1 -type d | head -n1)
    if [ -z "$SCDIR" ]; then
        echo "ERROR: could not locate extracted supportconfig directory"
        exit 1
    fi
fi

> "$REPORT"
sep
log "SUSE KERNEL PANIC / REBOOT RCA REPORT"
log ""
log "Bundle    : $BUNDLE_BASENAME"
log "Analyzed  : $(date '+%Y-%m-%d %H:%M:%S %Z')"
sep

findfile() {
    local f
    for f in "$@"; do
        if [ -f "$SCDIR/$f" ]; then
            echo "$SCDIR/$f"
            return 0
        fi
    done
    return 1
}

# Variable evaluations after findfile & SCDIR are safely established
MESSAGES=$(findfile messages.txt boot.txt var-log-messages.txt syslog.txt 2>/dev/null || echo "")
BOOT=$(findfile boot.txt 2>/dev/null || echo "")
BASICENV=$(findfile basic-environment.txt 2>/dev/null || echo "")
KERNEL=$(findfile kernel.txt 2>/dev/null || echo "")
MEMINFO=$(findfile memory.txt mem.txt 2>/dev/null || echo "")
KDUMP=$(findfile kdump.txt 2>/dev/null || echo "")
CRASHF=$(findfile crash.txt 2>/dev/null || echo "")
IPMI=$(findfile ipmitool-sel.txt ipmi.txt 2>/dev/null || echo "")
RPM=$(findfile rpm.txt 2>/dev/null || echo "")
HW=$(findfile hardware.txt 2>/dev/null || echo "")
FS=$(findfile fs-diskio.txt partitions.txt 2>/dev/null || echo "")
PARTITIONS=$(findfile fs-diskio.txt partitions.txt 2>/dev/null || echo "")
MODPROBE=$(findfile modprobe.txt udev.txt 2>/dev/null || echo "")
NETSTAT=$(findfile network.txt 2>/dev/null || echo "")
HAVE_SAR_BIN=0
command -v sar >/dev/null 2>&1 && HAVE_SAR_BIN=1

ALL_LOGS=""
for f in "$MESSAGES" "$BOOT"; do
    [ -n "${f:-}" ] && [ -f "$f" ] && ALL_LOGS="$ALL_LOGS $f"
done
if [ -z "$ALL_LOGS" ]; then
    ALL_LOGS=$(find "$SCDIR" -maxdepth 1 \( -iname "*messages*" -o -iname "boot.txt" \) 2>/dev/null | tr '\n' ' ')
fi

section_header "Server Information"

if [ -n "${BASICENV:-}" ] && [ -f "$BASICENV" ]; then
    grep -E "^Linux " "$BASICENV" 2>/dev/null | head -1 | while read -r line; do
        log "Hostname/Kernel : $line"
    done
fi

if [ -n "${RPM:-}" ] && [ -f "$RPM" ]; then
    KVER=$(grep -m1 -E "^kernel-default|^kernel-azure" "$RPM" 2>/dev/null || echo "")
    [ -n "$KVER" ] && log "Kernel Version  : $KVER"

    PRODUCT=$(grep -m1 "SUSE Linux Enterprise\|openSUSE" "$RPM" 2>/dev/null || echo "")
    [ -n "$PRODUCT" ] && log "Product         : $PRODUCT"

    SPACK=$(grep -m1 "SP[0-9]" "$RPM" 2>/dev/null || echo "")
    [ -n "$SPACK" ] && log "Service Pack    : $SPACK"
fi

if [ -n "${HW:-}" ] && [ -f "$HW" ]; then
    HYPERVISOR=$(grep -im1 "^[[:space:]]*Manufacturer:" "$HW" 2>/dev/null || echo "")
    [ -n "$HYPERVISOR" ] && log "$HYPERVISOR"
fi

if [ -n "${BASICENV:-}" ] && [ -f "$BASICENV" ]; then
    UPTIME=$(grep -i "uptime" "$BASICENV" 2>/dev/null | head -1 || echo "")
    [ -n "$UPTIME" ] && log "System Uptime   : $UPTIME"
fi

section_header "Last 3 Reboot Dates and Times"

HAVE_REBOOTS=0
if [ -n "${BOOT:-}" ] && [ -f "$BOOT" ]; then
    COUNT=0
    while IFS= read -r time; do
        [ -z "$time" ] && continue
        COUNT=$((COUNT + 1))
        log "  $COUNT. $time"
        HAVE_REBOOTS=1
    done < <(grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' "$BOOT" 2>/dev/null | uniq | head -n 3)
fi

if [ "$HAVE_REBOOTS" -eq 0 ]; then
    log "(No reboot timestamps found in logs)"
fi

section_header "Platform and Virtualization"

VIRT_TYPE="unknown"
if [ -n "${HW:-}" ] && [ -f "$HW" ]; then
    RAW_MANUF=$(grep -im1 "^[[:space:]]*Manufacturer:" "$HW" 2>/dev/null || echo "")
    RAW_PROD=$(grep -im1 "^[[:space:]]*Product Name:" "$HW" 2>/dev/null || echo "")

    VAL_MANUF=$(echo "$RAW_MANUF" | cut -d':' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    VAL_PROD=$(echo "$RAW_PROD" | cut -d':' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    [ -n "$VAL_MANUF" ] && log "$(printf "%-16s: %s" "Manufacturer" "$VAL_MANUF")"
    [ -n "$VAL_PROD" ] && log "$(printf "%-16s: %s" "Product Name" "$VAL_PROD")"

    COMBINED="${VAL_MANUF} ${VAL_PROD}"
    case "$COMBINED" in
        *VMware*)                    VIRT_TYPE="VMware (ESXi)" ;;
        *"Microsoft Corporation"*)   VIRT_TYPE="Microsoft Hyper-V / Azure" ;;
        *QEMU*|*KVM*)                VIRT_TYPE="KVM/QEMU" ;;
        *Xen*)                       VIRT_TYPE="Xen" ;;
        *"innotek GmbH"*|*VirtualBox*) VIRT_TYPE="Oracle VirtualBox" ;;
        *"Google"*)                  VIRT_TYPE="Google Compute Engine (GCP)" ;;
        *"Amazon EC2"*)              VIRT_TYPE="Amazon EC2 (AWS)" ;;
        *Bochs*)                     VIRT_TYPE="Bochs/QEMU emulation" ;;
        " ")                         VIRT_TYPE="Unknown (no strings found)" ;;
        *)                           VIRT_TYPE="Bare Metal" ;;
    esac
fi
log "$(printf "%-16s: %s" "Platform" "$VIRT_TYPE")"

if [[ "$VIRT_TYPE" != Bare\ Metal* ]] && [[ "$VIRT_TYPE" != Unknown* ]]; then
    log "[NOTE] VM detected: Hardware MCE/PCIe signatures unlikely. Check hypervisor logs instead."
fi

# ---------------------------------------------------------------------------
# Section 2: CPU / Memory / Disk Inventory
# ---------------------------------------------------------------------------

log "\n[2] CPU / Memory / Disk Inventory"

if [ -n "${HW:-}" ] && [ -f "$HW" ]; then
    log "  CPU:"
    grep -im1 -E "^[[:space:]]*Model name:" "$HW" 2>/dev/null | while read -r line; do log "    $line"; done
    grep -im1 -E "^CPU\(s\):" "$HW" 2>/dev/null | while read -r line; do log "    $line"; done
    grep -im1 -E "^Thread\(s\) per core:|^Core\(s\) per socket:|^Socket\(s\):" "$HW" 2>/dev/null | while read -r line; do log "    $line"; done
fi

if [ -n "${MEMINFO:-}" ] && [ -f "$MEMINFO" ]; then
    log "  Memory:"
    awk -F: '
    /^[Mm]emTotal/  { printf "    MemTotal:       %.2f GB\n", $2/1024/1024 }
    /^[Ss]wapTotal/ { printf "    SwapTotal:      %.2f GB\n", $2/1024/1024 }
    ' "$MEMINFO" 2>/dev/null
fi

if [ -n "${PARTITIONS:-}" ] && [ -f "$PARTITIONS" ]; then
    log "  Disk layout:"
    grep -iE "^Disk /dev|^NAME|disk[[:space:]]|^/dev/" "$PARTITIONS" 2>/dev/null | head -15 | while read -r line; do log "    $line"; done
elif [ -n "${HW:-}" ] && [ -f "$HW" ]; then
    grep -iE "^Disk /dev" "$HW" 2>/dev/null | head -10 | while read -r line; do log "    $line"; done
fi

# ---------------------------------------------------------------------------
# Section 3: Performance Metrics (sar) - Optimized Data Streaming
# ---------------------------------------------------------------------------

section_header "Performance Metrics (sar)"

UNIFIED_SAR_TEXT="$WORKDIR/unified_sar_metrics.txt"
touch "$UNIFIED_SAR_TEXT"

# Searches recursively underneath the entire extracted bundle structure
ALL_SAR_FILES=$(find "$SCDIR" -type f \( -name "sar*" -o -name "sa[0-9]*" \) 2>/dev/null || echo "")

if [ -n "$ALL_SAR_FILES" ]; then
    while read -r f; do
        [ -z "$f" ] && continue
        
        # Determine specific decompression profile
        DECOMPRESS_CMD="cat"
        if [[ "$f" == *.xz ]]; then
            DECOMPRESS_CMD="xzcat"
        elif [[ "$f" == *.gz ]]; then
            DECOMPRESS_CMD="zcat"
        elif [[ "$f" == *.bz2 ]]; then
            DECOMPRESS_CMD="bzcat"
        fi
        
        # Output uncompressed stream to temporary verification profile
        $DECOMPRESS_CMD "$f" > "$WORKDIR/current_sar_check" 2>/dev/null || continue
        [ ! -s "$WORKDIR/current_sar_check" ] && continue
        
        # Process dynamically depending on binary format vs text logs
        if [ "$HAVE_SAR_BIN" -eq 1 ] && sar -f "$WORKDIR/current_sar_check" >/dev/null 2>&1; then
            # OPTIMIZATION: Extract ONLY Overall CPU, Memory, and Disk to avoid core-dump bloat on large nodes
            sar -u -r -d -f "$WORKDIR/current_sar_check" >> "$UNIFIED_SAR_TEXT" 2>/dev/null
        else
            # Ensure it is standard ASCII text data (prevents corrupted binary logs)
            if grep -qI '.' "$WORKDIR/current_sar_check" 2>/dev/null; then
                cat "$WORKDIR/current_sar_check" >> "$UNIFIED_SAR_TEXT"
            fi
        fi
    done <<< "$ALL_SAR_FILES"
fi

SAR_ANY_DATA=0
if [ -s "$UNIFIED_SAR_TEXT" ]; then
    SAR_ANY_DATA=1
    log "Source: Performance metrics profile aggregation"

    # STREAMING OPTIMIZATION: Pipe large files directly through awk to prevent Bash memory exhaustion

    CPU_FLAGS=$(awk '/%iowait/ { grab=1 } grab && NF==0 { grab=0 } grab && $3=="all" { iowait=$7+0; idle=$9+0; if (idle < 10) print "[HIGH] CPU near-saturation (%idle="idle"%)"; else if (iowait > 30) print "[HIGH] High I/O wait (%iowait="iowait"%)" }' "$UNIFIED_SAR_TEXT" | sort -u)
    [ -n "$CPU_FLAGS" ] && { log "CPU Bottlenecks:"; echo "$CPU_FLAGS" | while read -r line; do log "  $line"; done; } || log "CPU: OK"

    MEM_FLAGS=$(awk '/%memused/ { grab=1 } grab && NF==0 { grab=0 } grab && !/%memused|Average/ && NF>=5 { memused=$5+0; if (memused > 90) print "[HIGH] High memory (%memused="memused"%)" }' "$UNIFIED_SAR_TEXT" | sort -u)
    [ -n "$MEM_FLAGS" ] && { log "Memory Pressure:"; echo "$MEM_FLAGS" | while read -r line; do log "  $line"; done; } || log "Memory: OK"

    DISK_FLAGS=$(awk '/%util/ { grab=1 } grab && NF==0 { grab=0 } grab && !/%util|Average/ && NF>=9 { await=$9+0; util=$NF+0; if (await > 50) print "[HIGH] High disk await ("await"ms)"; else if (util > 90) print "[HIGH] Disk saturation (%util="util"%)" }' "$UNIFIED_SAR_TEXT" | sort -u)
    [ -n "$DISK_FLAGS" ] && { log "Disk I/O:"; echo "$DISK_FLAGS" | while read -r line; do log "  $line"; done; } || log "Disk I/O: OK"

fi

#if [ -n "$ALL_SAR_FILES" ]; then
#    log "\nProcessed Performance Metric Source Files:"
#    echo "$ALL_SAR_FILES" | while read -r f; do [ -f "$f" ] && log "  - $(basename "$f")"; done
#fi

if [ "$SAR_ANY_DATA" -eq 0 ]; then
    log "No parsed sar metric profiles found (use 'supportconfig -p' to capture data)"
fi

# ---------------------------------------------------------------------------
# Section 4+: Signatures and Analysis Profiles
# ---------------------------------------------------------------------------

section_header "Kernel Panic / Oops / Fault Signatures"

declare -A PATTERNS_FATAL=(
    ["Kernel panic - not syncing"]="Kernel halted itself - check lines following for subsystem"
    ["Internal error: Oops"]="ARM/ARM64 style oops"
    ["general protection fault"]="Memory/pointer corruption in kernel code"
    ["NULL pointer dereference"]="Null pointer deref in kernel/driver"
    ["BUG: unable to handle kernel paging request"]="Bad memory access in kernel space"
    ["double fault"]="Stack corruption or cascading fault"
    ["Call Trace:"]="Stack backtrace present"
)

FOUND_FATAL=0
for pat in "${!PATTERNS_FATAL[@]}"; do
    if [ -n "$ALL_LOGS" ]; then
        MATCH=$(grep -inE "$pat" $ALL_LOGS 2>/dev/null | head -2 || echo "")
        if [ -n "$MATCH" ]; then
            FOUND_FATAL=1
            log "[HIGH] $pat"
            log "       -> ${PATTERNS_FATAL[$pat]}"
            echo "$MATCH" | while read -r line; do log "       | ${line#*:}"; done
        fi
    fi
done
[ "$FOUND_FATAL" -eq 0 ] && log "No direct panic/oops strings found (check Hardware Errors and Reboot Gap sections)"

section_header "Hardware Error Signatures"

declare -A PATTERNS_HW=(
    ["Machine Check Exception|mce:|Hardware Error"]="CPU machine check - hardware fault (CPU/cache/memory/PCIe)"
    ["nvme[0-9]+.*resetting controller due to AER"]="NVMe reset due to PCIe AER - hardware-level link/device error"
    ["nvme[0-9]+.*(timeout|I/O error|reset controller)"]="NVMe timeout/reset - check firmware, link, and PCIe health"
    ["EXT4-fs.*aborted journal"]="ext4 journal abort - usually downstream of storage controller error"
    ["mpt3sas.*(fault|error)"]="LSI/Broadcom SAS controller fault"
    ["megaraid_sas.*(fault|error)"]="MegaRAID controller fault"
    ["XFS.*corruption"]="XFS filesystem corruption"
    ["ata[0-9]+.*(exception|hard resetting)"]="SATA/AHCI link reset - disk/cabling issue"
    ["scsi.*Result: hostbyte"]="SCSI command abort - storage path issue"
    ["PCIe Bus Error|AER:"]="PCIe Advanced Error Reporting - device/link fault"
    ["thermal.*critical|Critical temperature reached"]="Thermal event - CPU/board overheating"
    ["hv_storvsc.*error|hv_netvsc.*error"]="Hyper-V synthetic driver error"
)

FOUND_HW=0
for pat in "${!PATTERNS_HW[@]}"; do
    if [ -n "$ALL_LOGS" ]; then
        MATCH=$(grep -inE "$pat" $ALL_LOGS 2>/dev/null | head -2 || echo "")
        if [ -n "$MATCH" ]; then
            FOUND_HW=1
            log "[CRITICAL] $pat"
            log "            -> ${PATTERNS_HW[$pat]}"
            echo "$MATCH" | while read -r line; do log "            | ${line#*:}"; done
        fi
    fi
done
[ "$FOUND_HW" -eq 0 ] && log "No hardware-error signatures in OS logs (check IPMI/SEL for bare-metal)"

section_header "Soft Lockup / Hung Task / Watchdog"

declare -A PATTERNS_LOCKUP=(
    ["BUG: soft lockup"]="CPU stuck in kernel >20s without yielding"
    ["INFO: task .* blocked for more than"]="Hung task detector - stuck in D-state (I/O wait)"
    ["RCU stall|rcu_sched"]="RCU stall - CPU not checking in to kernel RCU system"
    ["Watchdog detected hard LOCKUP"]="Watchdog escalated soft lockup to hard lockup"
)

FOUND_LOCK=0
for pat in "${!PATTERNS_LOCKUP[@]}"; do
    if [ -n "$ALL_LOGS" ]; then
        MATCH=$(grep -inE "$pat" $ALL_LOGS 2>/dev/null | head -2 || echo "")
        if [ -n "$MATCH" ]; then
            FOUND_LOCK=1
            log "[HIGH] $pat"
            log "       -> ${PATTERNS_LOCKUP[$pat]}"
            echo "$MATCH" | while read -r line; do log "       | ${line#*:}"; done
        fi
    fi
done
[ "$FOUND_LOCK" -eq 0 ] && log "No soft-lockup/hung-task signatures found"

section_header "Out-of-Memory / Memory Pressure"

if [ -n "$ALL_LOGS" ]; then
    OOM_MATCH=$(grep -inE "Out of memory|oom-kill|oom_reaper" $ALL_LOGS 2>/dev/null | head -5 || echo "")
    if [ -n "$OOM_MATCH" ]; then
        log "[HIGH] OOM killer activity detected:"
        echo "$OOM_MATCH" | while read -r line; do log "       | ${line#*:}"; done
    else
        log "No OOM killer activity"
    fi
fi

section_header "Reboot Gap Analysis"

if [ -n "${MESSAGES:-}" ] && [ -f "$MESSAGES" ]; then
    log "Last log lines before suspected reboot:"
    tail -5 "$MESSAGES" 2>/dev/null | while read -r line; do log "$line"; done
fi
if [ -n "${BOOT:-}" ] && [ -f "$BOOT" ]; then
    log "First log lines after reboot (boot.txt):"
    head -5 "$BOOT" 2>/dev/null | while read -r line; do log "$line"; done
fi
log "Check timestamps: a gap with NO panic string suggests external reset (power/watchdog/hypervisor)"

section_header "IPMI / BMC System Event Log (Bare Metal Only)"

if [ -n "${IPMI:-}" ] && [ -f "$IPMI" ]; then
    SEL_HITS=$(grep -inE "Power|Watchdog|Critical|Processor|Memory|Temperature|Voltage" "$IPMI" 2>/dev/null | tail -10 || echo "")
    if [ -n "$SEL_HITS" ]; then
        log "[CRITICAL] SEL events found - correlate timestamps against Reboot Gap:"
        echo "$SEL_HITS" | while read -r line; do log "            | ${line#*:}"; done
    else
        log "No significant SEL events"
    fi
else
    if [[ "$VIRT_TYPE" == Bare\ Metal* ]]; then
        log "Bare metal host but no IPMI data in bundle - check BMC directly"
    else
        log "VM host - skip IPMI (expected)"
    fi
fi

section_header "kdump / Kernel Crash Dump Status"

if [ -n "${KDUMP:-}" ] && [ -f "$KDUMP" ]; then
    if grep -qiE "enabled|active" "$KDUMP" 2>/dev/null; then
        log "kdump enabled"
        if grep -qiE "vmcore" "$KDUMP" 2>/dev/null; then
            log "vmcore reference found - use: crash <vmlinux-debuginfo> <vmcore>"
        fi
    else
        log "[WARNING] kdump not enabled - RECOMMENDATION: enable for next occurrence"
        log "systemctl enable --now kdump"
    fi
else
    log "[WARNING] kdump status unknown - verify: systemctl status kdump"
fi

section_header "Known Driver / Subsystem Bugs"

declare -A PATTERNS_KNOWN=(
    ["calico|felix.*timeout"]="Calico/CNI timeout with storage controller errors -> RKE2 PV-helper issue"
    ["selinux.*reload"]="SELinux policy reload - can spike CPU/IO during reload window"
    ["vmxnet3.*(timeout|reset)"]="VMware vmxnet3 NIC driver timeout"
    ["e1000e.*(Tx Unit Hang|Reset adapter)"]="Intel e1000e NIC hang - sustained load issue"
    ["zfs.*panic|zfs.*assert"]="ZFS module panic - check module/kernel ABI compatibility"
    ["audit.*denied.*suppressed"]="Audit subsystem overload - starves CPU"
    ["journald.*Failed|journald.*Suppressed"]="journald overload - lost diagnostic data"
)

FOUND_KNOWN=0
for pat in "${!PATTERNS_KNOWN[@]}"; do
    if [ -n "$ALL_LOGS" ]; then
        MATCH=$(grep -inE "$pat" $ALL_LOGS 2>/dev/null | head -2 || echo "")
        if [ -n "$MATCH" ]; then
            FOUND_KNOWN=1
            log "[MED] $pat"
            log "      -> ${PATTERNS_KNOWN[$pat]}"
            echo "$MATCH" | while read -r line; do log "      | ${line#*:}"; done
        fi
    fi
done
[ "$FOUND_KNOWN" -eq 0 ] && log "No known driver/subsystem signatures matched"

section_header "Summary & RCA Recommendation"

log ""
log "Fatal Panic/Oops Found        : $([ $FOUND_FATAL -eq 1 ] && echo "YES" || echo "NO")"
log "Hardware Errors Found         : $([ $FOUND_HW -eq 1 ] && echo "YES [CRITICAL]" || echo "NO")"
log "Soft Lockup/Hung Task Found   : $([ $FOUND_LOCK -eq 1 ] && echo "YES" || echo "NO")"
log "Known Driver Signatures       : $([ $FOUND_KNOWN -eq 1 ] && echo "YES" || echo "NO")"
log ""
log "RCA Priority Order:"
log ""
log "1. If Hardware Errors fired (Section 5 or IPMI Section 9)"
log "   -> Escalate to vendor/hardware replacement. Pull the failing device model/firmware."
log ""
log "2. If Panic/Oops has a Call Trace (Section 4)"
log "   -> Extract exact kernel NVR from rpm.txt, check SUSE Bugzilla/changelog before"
log "      assuming a novel bug. Cross-check with performance trends from Section 3 sar data"
log "      to identify if a resource exhaustion triggered the fault."
log ""
log "3. If Soft Lockup without Panic (Section 6)"
log "   -> Identify which function/CPU was stuck in the Call Trace. Correlate against"
log "      sar CPU/IO/memory spikes immediately preceding the gap."
log ""
log "4. If nothing triggered anywhere"
log "   -> Likely externally-driven hard reset (power/watchdog/BMC). Rely on IPMI SEL"
log "      (bare metal) or hypervisor/cloud platform host-health logs (VM)."
log ""
log "5. Regardless of cause"
log "   -> Verify kdump is enabled (Section 10) so the *next* occurrence yields a vmcore"
log "      for definitive crash-utility analysis."
log ""

sep
log "Report saved to: $REPORT"
sep