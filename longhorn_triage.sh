#!/usr/bin/env bash
# ============================================================
#  longhorn-triage.sh — SUSE Longhorn Node Triage Script
#  Quick root-cause diagnosis for Longhorn storage nodes
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Config ───────────────────────────────────────────────────
DISK_WARN=80
DISK_CRIT=90
INODE_WARN=80
INODE_CRIT=90
LONGHORN_DATA_PATH="${LONGHORN_DATA_PATH:-/var/lib/longhorn}"

ISSUES=()
WARNINGS=()

# ── RKE2 Environment Bootstrap ───────────────────────────────
export CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml
PATH="/var/lib/rancher/rke2/bin:$PATH"

# ── Helpers ──────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}${BOLD}  $1${NC}"
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

ok()   { echo -e "  ${GREEN}✔${NC}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; WARNINGS+=("$1"); }
fail() { echo -e "  ${RED}✖${NC}  $1"; ISSUES+=("$1"); }
info() { echo -e "  ${DIM}ℹ${NC}  $1"; }

check_cmd() { command -v "$1" &>/dev/null; }

# ── 0. Pre-flight ─────────────────────────────────────────────
banner "0 / Pre-flight"

info "Hostname  : $(hostname)"
info "Uptime    : $(uptime -p 2>/dev/null || uptime)"
info "Time      : $(date)"
if [[ -f /etc/os-release ]]; then
  info "OS        : $(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
fi
info "Kernel    : $(uname -r)"

if check_cmd kubectl; then
  ok "kubectl found"
else
  warn "kubectl not found — some checks will be skipped"
fi

# ── 1. Longhorn Prerequisites — Required Packages & Services ──
banner "1 / Longhorn Prerequisites"

# iscsid — required for iSCSI volume attachment
# On SLES/SLE Micro the iSCSI stack has three units:
#   iscsi.service   — scans/logs in to targets (active exited = healthy)
#   iscsid.service  — daemon (inactive at idle = normal, socket-activated)
#   iscsid.socket   — triggers iscsid on demand (should be active/listening)
# A false-positive occurs when only iscsid.service is checked and it shows inactive.
if check_cmd systemctl; then
  ISCSI_SVC=$(systemctl is-active iscsi.service   2>/dev/null || echo "unknown")
  ISCSID_SVC=$(systemctl is-active iscsid.service 2>/dev/null || echo "unknown")
  ISCSID_SOCK=$(systemctl is-active iscsid.socket 2>/dev/null || echo "unknown")

  if [[ "$ISCSI_SVC" == "active" || "$ISCSID_SVC" == "active" ]]; then
    ok "iSCSI stack: active (iscsi=${ISCSI_SVC} iscsid=${ISCSID_SVC} socket=${ISCSID_SOCK})"
  elif [[ "$ISCSID_SOCK" == "active" ]]; then
    ok "iSCSI stack: iscsid.socket active/listening — iscsid starts on-demand (SLES/SLE Micro)"
  elif [[ "$ISCSI_SVC" == "failed" || "$ISCSID_SVC" == "failed" ]]; then
    fail "iSCSI service FAILED — run: systemctl status iscsi.service iscsid.service"
  elif systemctl cat iscsid.service &>/dev/null 2>&1 && check_cmd iscsiadm; then
    ok "iSCSI stack: inactive at idle (socket-activated on SLES/SLE Micro — normal when no volumes attached)"
  else
    fail "iSCSI stack not found — install open-iscsi (SLES: zypper in open-iscsi)"
  fi
else
  warn "systemctl not available — skipping iscsid check"
fi
# iscsiadm binary
if check_cmd iscsiadm; then
  ok "iscsiadm binary found"
  info "  Version: $(iscsiadm --version 2>/dev/null | head -1 || echo 'unknown')"
else
  fail "iscsiadm not found — install open-iscsi"
fi

# iscsi_tcp kernel module — SLES needs kernel-default (not kernel-default-base)
if lsmod 2>/dev/null | grep -q iscsi_tcp; then
  ok "iscsi_tcp kernel module loaded"
else
  # Try to load it
  if modprobe iscsi_tcp &>/dev/null 2>&1; then
    ok "iscsi_tcp kernel module loaded (modprobe succeeded)"
  else
    fail "iscsi_tcp kernel module not found — on SLES, ensure kernel-default is installed (not kernel-default-base)"
    info "  Run: zypper in kernel-default && reboot"
  fi
fi

# dm_crypt — required for volume encryption feature
if lsmod 2>/dev/null | grep -q dm_crypt; then
  ok "dm_crypt kernel module loaded"
else
  info "dm_crypt kernel module not loaded (only required for encrypted volumes)"
fi

# nfs-client — required for RWX volumes and NFS backup targets
if check_cmd mount.nfs4 || check_cmd showmount; then
  ok "NFS client utilities found"
elif rpm -q nfs-client &>/dev/null 2>&1 || rpm -q nfs-utils &>/dev/null 2>&1; then
  ok "NFS client package installed"
else
  warn "NFS client not found — required for RWX volumes and NFS backup targets"
  info "  Run: zypper in nfs-client"
fi

# Mount propagation — required for CSI
MOUNT_PROP=$(findmnt -o PROPAGATION / 2>/dev/null | tail -1 || echo "")
if echo "$MOUNT_PROP" | grep -q "shared"; then
  ok "Mount propagation: shared (required for CSI)"
else
  warn "Mount propagation may not be set to 'shared' — Longhorn CSI requires it"
  info "  Detected: '${MOUNT_PROP:-unknown}'"
fi

# Required CLI tools
for tool in bash curl findmnt grep awk blkid lsblk; do
  if check_cmd "$tool"; then
    ok "${tool}: found"
  else
    fail "${tool}: not found — required by Longhorn"
  fi
done

# multipathd — known to conflict with Longhorn
if check_cmd systemctl && systemctl cat multipathd.service &>/dev/null 2>&1; then
  STATE=$(systemctl is-active multipathd 2>/dev/null || echo "unknown")
  if [[ "$STATE" == "active" ]]; then
    warn "multipathd: active — can conflict with Longhorn volumes"
    info "  See: https://longhorn.io/kb/troubleshooting-volume-with-multipath/"
    info "  Add Longhorn devices to /etc/multipath.conf blacklist"
  else
    ok "multipathd: not active (no conflict)"
  fi
fi

# ── 2. Longhorn Data Disk & Filesystem ───────────────────────
banner "2 / Longhorn Data Disk & Filesystem"

info "Longhorn data path: ${LONGHORN_DATA_PATH}"

if [[ -d "${LONGHORN_DATA_PATH}" ]]; then
  ok "Longhorn data directory exists: ${LONGHORN_DATA_PATH}"

  # Disk usage on the Longhorn data path
  USAGE=$(df -hP "${LONGHORN_DATA_PATH}" 2>/dev/null | tail -1)
  USE_PCT=$(echo "$USAGE" | awk '{print $5}' | tr -d '%')
  AVAIL=$(echo "$USAGE" | awk '{print $4}')
  MOUNT=$(echo "$USAGE" | awk '{print $6}')
  FS_TYPE=$(findmnt -n -o FSTYPE "${LONGHORN_DATA_PATH}" 2>/dev/null || echo "unknown")

  info "Filesystem: ${FS_TYPE}  |  Mount: ${MOUNT}  |  Available: ${AVAIL}"

  if (( USE_PCT >= DISK_CRIT )); then
    fail "Longhorn disk CRITICAL ${USE_PCT}% used — ${MOUNT}"
  elif (( USE_PCT >= DISK_WARN )); then
    warn "Longhorn disk WARNING ${USE_PCT}% used — ${MOUNT}"
  else
    ok "Longhorn disk OK ${USE_PCT}% used — ${MOUNT}"
  fi

  # Filesystem type check — Longhorn supports ext4 and xfs
  if echo "$FS_TYPE" | grep -qE "ext4|xfs"; then
    ok "Filesystem type ${FS_TYPE} supported by Longhorn"
  elif [[ "$FS_TYPE" != "unknown" ]]; then
    warn "Filesystem type ${FS_TYPE} — Longhorn recommends ext4 or xfs"
  fi

  # File extents feature (required by Longhorn) — ext4/xfs both support it
  if echo "$FS_TYPE" | grep -qE "ext4|xfs"; then
    ok "File extents feature supported on ${FS_TYPE}"
  fi
else
  warn "Longhorn data directory not found: ${LONGHORN_DATA_PATH}"
  info "  Longhorn will create it on first use, or set LONGHORN_DATA_PATH to override"
fi

# All block devices — show what's available
echo ""
info "Block devices on this node:"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null \
  | while IFS= read -r line; do info "  ${line}"; done || true

# Disk I/O latency on Longhorn data path (fio if available)
echo ""
info "Disk I/O latency check on ${LONGHORN_DATA_PATH}:"
if check_cmd fio && [[ -d "${LONGHORN_DATA_PATH}" ]]; then
  info "Running fio fsync latency test (3s)..."
  FIO_OUT=$(fio --rw=write --ioengine=sync --fdatasync=1 \
    --directory="${LONGHORN_DATA_PATH}" --size=22m --bs=4k \
    --name=lh-fsync-test --runtime=3 --time_based \
    --output-format=terse 2>/dev/null || true)
  FSYNC_99=$(echo "$FIO_OUT" | awk -F';' '{print $49}' | head -1)
  if [[ -n "$FSYNC_99" && "$FSYNC_99" =~ ^[0-9]+$ ]]; then
    FSYNC_MS=$(( FSYNC_99 / 1000000 ))
    if (( FSYNC_MS > 10 )); then
      warn "Disk fsync p99 ${FSYNC_MS}ms — may impact Longhorn replica performance (recommended <10ms)"
    else
      ok "Disk fsync p99 ${FSYNC_MS}ms (OK)"
    fi
  fi
  rm -f "${LONGHORN_DATA_PATH}"/lh-fsync-test.* 2>/dev/null || true
else
  info "fio not available — skipping latency test"
fi

# ── 3. Longhorn Pods & CRDs ───────────────────────────────────
banner "3 / Longhorn Pods & CRDs"

# Auto-import kubeconfig
LONGHORN_KUBECONFIG=""
for kc in "/etc/rancher/rke2/rke2.yaml" "/etc/rancher/k3s/k3s.yaml" "${KUBECONFIG:-}"; do
  [[ -z "$kc" || ! -f "$kc" ]] && continue
  if KUBECONFIG="$kc" kubectl cluster-info &>/dev/null 2>&1; then
    export KUBECONFIG="$kc"
    LONGHORN_KUBECONFIG="$kc"
    break
  fi
done

if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  # Longhorn namespace
  LH_NS=$(kubectl get ns 2>/dev/null | grep -oE 'longhorn-system|longhorn' | head -1 || true)
  if [[ -n "$LH_NS" ]]; then
    ok "Longhorn namespace found: ${LH_NS}"
  else
    warn "Longhorn namespace not found — is Longhorn installed?"
    LH_NS="longhorn-system"
  fi

  echo ""
  info "Longhorn pods (non-healthy only):"
  UNHEALTHY=$(kubectl get pods -n "${LH_NS}" --no-headers 2>/dev/null \
    | grep -Ev "Running|Completed" || true)
  if [[ -z "$UNHEALTHY" ]]; then
    ok "All Longhorn pods healthy in ${LH_NS}"
  else
    echo "$UNHEALTHY" | while IFS= read -r line; do
      echo -e "  ${RED}✖${NC}  ${line}"
    done
    ISSUES+=("Unhealthy Longhorn pods detected")
  fi

  echo ""
  info "Longhorn node status:"
  kubectl get nodes.longhorn.io -n "${LH_NS}" 2>/dev/null \
    | while IFS= read -r line; do
      if echo "$line" | grep -q "False\|NotReady\|Error"; then
        echo -e "  ${RED}✖${NC}  ${line}"
      else
        echo -e "  ${GREEN}✔${NC}  ${line}"
      fi
    done || info "  longhorn.io nodes CRD not available yet"

  echo ""
  info "Longhorn volumes (Degraded/Faulted only):"
  DEGRADED=$(kubectl get volumes.longhorn.io -n "${LH_NS}" --no-headers 2>/dev/null \
    | grep -Ei "degraded\|faulted\|error" || true)
  if [[ -z "$DEGRADED" ]]; then
    ok "No degraded or faulted Longhorn volumes"
  else
    echo "$DEGRADED" | while IFS= read -r line; do
      echo -e "  ${RED}✖${NC}  ${line}"
    done
    ISSUES+=("Degraded/Faulted Longhorn volumes detected")
  fi

  echo ""
  info "Longhorn replicas (Failed only):"
  FAILED_REPLICAS=$(kubectl get replicas.longhorn.io -n "${LH_NS}" --no-headers 2>/dev/null \
    | grep -i "error\|failed" || true)
  if [[ -z "$FAILED_REPLICAS" ]]; then
    ok "No failed Longhorn replicas"
  else
    echo "$FAILED_REPLICAS" | while IFS= read -r line; do
      echo -e "  ${RED}✖${NC}  ${line}"
    done
    ISSUES+=("Failed Longhorn replicas detected")
  fi

else
  warn "kubectl not connected — skipping Longhorn CRD checks"
fi

# ── 4. iSCSI Targets & Sessions ──────────────────────────────
banner "4 / iSCSI Targets & Sessions"

if check_cmd iscsiadm; then
  SESSION_OUT=$(iscsiadm -m session 2>/dev/null || echo "")
  if [[ -z "$SESSION_OUT" ]]; then
    info "No active iSCSI sessions (normal if no volumes currently attached)"
  else
    SESSION_COUNT=$(echo "$SESSION_OUT" | grep -c "tcp\|iscsi" || true)
    ok "Active iSCSI sessions: ${SESSION_COUNT}"
    echo "$SESSION_OUT" | while IFS= read -r line; do info "  ${line}"; done
  fi

  # Check iSCSI initiator name
  if [[ -f /etc/iscsi/initiatorname.iscsi ]]; then
    INITIATOR=$(grep -v '^#' /etc/iscsi/initiatorname.iscsi 2>/dev/null | grep InitiatorName | head -1 || echo "")
    if [[ -n "$INITIATOR" ]]; then
      ok "iSCSI initiator name configured: ${INITIATOR}"
    else
      warn "iSCSI initiator name not set in /etc/iscsi/initiatorname.iscsi"
    fi
  else
    warn "/etc/iscsi/initiatorname.iscsi not found — run: iscsi-iname > /etc/iscsi/initiatorname.iscsi"
  fi
else
  warn "iscsiadm not available — skipping iSCSI session check"
fi

# ── 5. Longhorn Network Ports ─────────────────────────────────
banner "5 / Longhorn Network Ports"

tcp_check() {
  local host="$1" port="$2"
  if check_cmd nc; then
    nc -z -w 3 "$host" "$port" &>/dev/null 2>&1
  else
    (echo >/dev/tcp/"$host"/"$port") &>/dev/null 2>&1
  fi
}

# Longhorn manager listens on 9500 (inter-node replica traffic)
# Longhorn instance manager: 8500-8599 range
info "Local Longhorn ports:"
for port in 9500 9501 9502 9503; do
  if check_cmd ss; then
    if ss -tlnp 2>/dev/null | grep -q ":${port}\b"; then
      ok "Port ${port} listening (Longhorn engine/replica)"
    else
      info "Port ${port} not listening (normal if no volumes attached to this node)"
    fi
  fi
done

# Check inter-node connectivity to other Longhorn nodes (port 9500)
# Uses kubectl to discover peer node IPs
if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  echo ""
  info "Inter-node Longhorn port 9500 reachability:"
  NODE_IPS=$(kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' \
    2>/dev/null || true)
  MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
  for ip in $NODE_IPS; do
    [[ "$ip" == "$MY_IP" ]] && continue
    if tcp_check "$ip" 9500; then
      ok "TCP ${ip}:9500 reachable (Longhorn replica traffic)"
    else
      warn "TCP ${ip}:9500 unreachable — inter-node replica traffic may be blocked"
    fi
  done
fi

# ── 6. Filesystem & Disk Usage ───────────────────────────────
banner "6 / Filesystem & Disk Usage"

while IFS= read -r line; do
  [[ "$line" =~ ^Filesystem ]] && continue
  USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
  MOUNT=$(echo "$line" | awk '{print $6}')
  FS=$(echo "$line" | awk '{print $1}')
  [[ -z "$USE" || -z "$MOUNT" ]] && continue
  if (( USE >= DISK_CRIT )); then
    fail "Disk CRITICAL ${USE}% used — ${MOUNT} (${FS})"
  elif (( USE >= DISK_WARN )); then
    warn "Disk WARNING ${USE}% used — ${MOUNT} (${FS})"
  else
    ok   "Disk OK ${USE}% used — ${MOUNT}"
  fi
done < <(df -hP 2>/dev/null | grep -v tmpfs | grep -v devtmpfs)

echo ""
info "inode usage:"
while IFS= read -r line; do
  [[ "$line" =~ ^Filesystem ]] && continue
  USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
  MOUNT=$(echo "$line" | awk '{print $6}')
  [[ -z "$USE" || "$USE" == "-" ]] && continue
  if (( USE >= INODE_CRIT )); then
    fail "inode CRITICAL ${USE}% used — ${MOUNT}"
  elif (( USE >= INODE_WARN )); then
    warn "inode WARNING ${USE}% used — ${MOUNT}"
  else
    ok   "inode OK ${USE}% used — ${MOUNT}"
  fi
done < <(df -iP 2>/dev/null | grep -v tmpfs | grep -v devtmpfs)

# ── 7. System Resources ───────────────────────────────────────
banner "7 / System Resources (CPU / Memory)"

LOAD1=$(awk '{print $1}' /proc/loadavg)
CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
LOAD_RATIO=$(echo "$LOAD1 $CORES" | awk '{printf "%.1f", $1/$2 * 100}')
info "Load average (1m): ${LOAD1}  |  CPU cores: ${CORES}  |  Load ratio: ${LOAD_RATIO}%"
if (( $(echo "$LOAD_RATIO > 200" | bc -l 2>/dev/null || echo 0) )); then
  fail "CPU overloaded — Load ${LOAD1} on ${CORES} cores (${LOAD_RATIO}%)"
elif (( $(echo "$LOAD_RATIO > 100" | bc -l 2>/dev/null || echo 0) )); then
  warn "CPU load high — Load ${LOAD1} on ${CORES} cores"
else
  ok "CPU load OK (${LOAD_RATIO}%)"
fi

MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_AVAIL=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
MEM_USED_PCT=$(( (MEM_TOTAL - MEM_AVAIL) * 100 / MEM_TOTAL ))
MEM_TOTAL_GB=$(echo "$MEM_TOTAL" | awk '{printf "%.1f", $1/1024/1024}')
MEM_AVAIL_GB=$(echo "$MEM_AVAIL" | awk '{printf "%.1f", $1/1024/1024}')
info "Memory: ${MEM_USED_PCT}% used  |  Total ${MEM_TOTAL_GB}GB  |  Available ${MEM_AVAIL_GB}GB"
if (( MEM_USED_PCT >= 95 )); then
  fail "Memory CRITICAL — ${MEM_USED_PCT}% used (available: ${MEM_AVAIL_GB}GB)"
elif (( MEM_USED_PCT >= 85 )); then
  warn "Memory WARNING — ${MEM_USED_PCT}% used"
else
  ok "Memory OK — ${MEM_USED_PCT}% used"
fi

# Longhorn recommended minimum: 4 vCPU, 8GB RAM
if (( CORES < 4 )); then
  warn "CPU cores: ${CORES} — Longhorn recommends minimum 4 vCPUs for storage nodes"
fi
MEM_GB_INT=$(echo "$MEM_TOTAL_GB" | awk '{printf "%d", $1}')
if (( MEM_GB_INT < 8 )); then
  warn "Memory: ${MEM_TOTAL_GB}GB — Longhorn recommends minimum 8GB RAM for storage nodes"
fi

# ── 8. OOM Events ────────────────────────────────────────────
banner "8 / Recent System Events (OOM)"

if check_cmd journalctl; then
  OOM=$(journalctl -k --since "1 hour ago" 2>/dev/null \
    | grep -i "oom\|out of memory\|killed process" | tail -5 || true)
  if [[ -n "$OOM" ]]; then
    fail "OOM Killer triggered (last 1 hour):"
    echo "$OOM" | while IFS= read -r line; do
      echo -e "    ${RED}${line}${NC}"
    done
  else
    ok "No OOM events in the last 1 hour"
  fi
else
  OOM=$(dmesg 2>/dev/null | grep -i "oom\|out of memory\|killed process" | tail -5 || true)
  if [[ -n "$OOM" ]]; then
    fail "OOM Killer triggered (dmesg):"
    echo "$OOM" | while IFS= read -r line; do echo -e "    ${RED}${line}${NC}"; done
  else
    ok "No OOM events found (dmesg)"
  fi
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Triage Summary  [Longhorn node: $(hostname)]${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if (( ${#ISSUES[@]} == 0 && ${#WARNINGS[@]} == 0 )); then
  echo -e "\n  ${GREEN}${BOLD}✔  All checks passed — no obvious issues found${NC}\n"
else
  if (( ${#ISSUES[@]} > 0 )); then
    echo -e "\n  ${RED}${BOLD}✖  Critical issues (${#ISSUES[@]}):${NC}"
    for i in "${!ISSUES[@]}"; do
      echo -e "  ${RED}  $((i+1)). ${ISSUES[$i]}${NC}"
    done
  fi
  if (( ${#WARNINGS[@]} > 0 )); then
    echo -e "\n  ${YELLOW}${BOLD}⚠  Warnings (${#WARNINGS[@]}):${NC}"
    for i in "${!WARNINGS[@]}"; do
      echo -e "  ${YELLOW}  $((i+1)). ${WARNINGS[$i]}${NC}"
    done
  fi
fi

# ── Threshold Reference ───────────────────────────────────────
trow3()  { printf "  │ %-34s │ %-12s │ %-12s │\n" "$1" "$2" "$3"; }
trow2()  { printf "  │ %-34s │ %-28s │\n" "$1" "$2"; }

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Normal Threshold Reference${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}FILESYSTEM${NC}"
echo    "  ┌────────────────────────────────────┬──────────────┬──────────────┐"
echo    "  │ Metric                             │ Warning      │ Critical     │"
echo    "  ├────────────────────────────────────┼──────────────┼──────────────┤"
trow3   "Disk usage"    ">= ${DISK_WARN}%"   ">= ${DISK_CRIT}%"
trow3   "inode usage"   ">= ${INODE_WARN}%"  ">= ${INODE_CRIT}%"
echo    "  └────────────────────────────────────┴──────────────┴──────────────┘"
echo ""
echo -e "  ${CYAN}${BOLD}LONGHORN PREREQUISITES${NC}"
echo    "  ┌────────────────────────────────────┬──────────────────────────────┐"
echo    "  │ Requirement                        │ Expected state               │"
echo    "  ├────────────────────────────────────┼──────────────────────────────┤"
trow2   "iscsid service"                  "active"
trow2   "iscsiadm binary"                 "present"
trow2   "iscsi_tcp kernel module"         "loaded"
trow2   "NFS client"                      "installed (for RWX / backups)"
trow2   "Mount propagation"               "shared"
trow2   "multipathd"                      "inactive (conflicts with Longhorn)"
trow2   "Filesystem type"                 "ext4 or xfs"
echo    "  └────────────────────────────────────┴──────────────────────────────┘"
echo ""
echo -e "  ${CYAN}${BOLD}SYSTEM RESOURCES${NC}"
echo    "  ┌────────────────────────────────────┬──────────────┬──────────────┐"
echo    "  │ Metric                             │ Warning      │ Critical     │"
echo    "  ├────────────────────────────────────┼──────────────┼──────────────┤"
trow3   "CPU load ratio"    "> 100%"  "> 200%"
trow3   "Memory usage"      ">= 85%"  ">= 95%"
trow3   "Disk fsync p99"    "> 10ms"  "N/A"
echo    "  └────────────────────────────────────┴──────────────┴──────────────┘"
echo ""
echo -e "  ${CYAN}${BOLD}LONGHORN MINIMUM HW (storage nodes)${NC}"
echo    "  ┌────────────────────────────────────┬──────────────────────────────┐"
echo    "  │ Resource                           │ Minimum                      │"
echo    "  ├────────────────────────────────────┼──────────────────────────────┤"
trow2   "CPU"               "4 vCPUs"
trow2   "Memory"            "8 GB RAM"
trow2   "Longhorn disk"     "/var/lib/longhorn (ext4/xfs)"
trow2   "Inter-node port"   "9500/TCP open between nodes"
echo    "  └────────────────────────────────────┴──────────────────────────────┘"

echo -e "\n  ${DIM}Completed at: $(date)${NC}"
echo ""