#!/usr/bin/env bash
# ============================================================
#  rancher-bundle-triage.sh
#  Analyses a Rancher v2.x log bundle produced by:
#    curl -Ls rnch.io/rancher2_logs | sudo bash
#    (rancherlabs/support-tools rancher2_logs_collector.sh)
#
#  Input : the .tar.gz bundle
#  Usage : ./rancher-bundle-triage.sh <hostname-YYYY-MM-DD_HH_MM_SS.tar.gz>
#
#  Output: plain-text mono report — no colour codes
# ============================================================

set -euo pipefail

# ── No colours — plain mono output ───────────────────────────
ISSUES=(); WARNINGS=()

# Per-bug result tracking (DETECTED / CLEAR / SKIP)
BUG_R1="SKIP"; BUG_R2="SKIP"; BUG_R3="SKIP"; BUG_R4="SKIP"
BUG_R5="SKIP"; BUG_R6="SKIP"; BUG_R7="SKIP"
BUG_K1="SKIP"; BUG_K2="SKIP"; BUG_K3="SKIP"
BUG_K4="SKIP"; BUG_K5="SKIP"; BUG_K6="SKIP"

# ── Helpers ───────────────────────────────────────────────────
banner()  {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}
ok()      { echo "  [OK]   $1"; }
warn()    { echo "  [WARN] $1"; WARNINGS+=("$1"); }
fail()    { echo "  [FAIL] $1"; ISSUES+=("$1"); }
info()    { echo "  [INFO] $1"; }
section() { echo ""; echo "  --- $1"; }
sgrep()   { grep "$@" 2>/dev/null || true; }
check_cmd() { command -v "$1" &>/dev/null; }

# Safe integer comparison - ensures value is numeric
safe_int() {
  local val="$1"
  echo "$val" | tr -d '[:space:]' | grep -oE '^[0-9]+$' || echo "0"
}

# ── Arg check ─────────────────────────────────────────────────
[[ $# -lt 1 ]] && { echo "Usage: $0 <rancher-bundle.tar.gz>"; exit 1; }
BUNDLE="$1"
[[ ! -f "$BUNDLE" ]] && { echo "ERROR: Not found: ${BUNDLE}"; exit 1; }
check_cmd tar || { echo "ERROR: tar required."; exit 1; }

# ── Extract ───────────────────────────────────────────────────
BUNDLE_NAME=$(basename "$BUNDLE" .tar.gz)
WORK_DIR=$(mktemp -d "/tmp/rancher-triage-XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

echo ""
echo "Rancher Log Bundle Triage"
echo "Bundle : ${BUNDLE}"
echo ""

info "Extracting..."
tar -xzf "$BUNDLE" -C "$WORK_DIR" 2>/dev/null || {
  echo "ERROR: Extract failed — not a valid tar.gz?"; exit 1; }

# Locate bundle root (collector extracts to <hostname-timestamp>/)
ROOT=$(find "$WORK_DIR" -maxdepth 2 -name "systeminfo" -type d 2>/dev/null \
  | head -1 | xargs dirname 2>/dev/null || echo "$WORK_DIR")
info "Bundle root: ${ROOT}"

# Paths matching collector output layout
SYSINFO="${ROOT}/systeminfo"
NETWORKING="${ROOT}/networking"

# Detect distro subdirectory: rke2/ k3s/ rke/ kubeadm/
DISTRO_DIR=""; DISTRO="unknown"
for d in rke2 k3s rke kubeadm; do
  if [[ -d "${ROOT}/${d}" ]]; then
    DISTRO_DIR="${ROOT}/${d}"; DISTRO="$d"; break
  fi
done
KUBECTL_DIR="${DISTRO_DIR}/kubectl"
LOGS_DIR="${DISTRO_DIR}/logs"
PODS_DIR="${DISTRO_DIR}/podlogs"

# ── 0. Versions & Environment ─────────────────────────────────
banner "0 / Bundle Overview — Versions & Environment"

info "K8s distro : ${DISTRO}"

VERSION_FILE="${ROOT}/versions"
if [[ -f "$VERSION_FILE" ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] && info "  ${line}"
  done < "$VERSION_FILE"
fi

RANCHER_VERSION=""
if [[ -d "${PODS_DIR:-/dev/null}" ]]; then
  RANCHER_VERSION=$(find "$PODS_DIR" -name "*.log" -exec grep -l "Rancher version" {} \; 2>/dev/null \
    | head -1 | xargs grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[^ "]*' 2>/dev/null \
    | sort -V | tail -1 || true)
fi
if [[ -z "$RANCHER_VERSION" && -d "${DISTRO_DIR:-/dev/null}" ]]; then
  RANCHER_VERSION=$(find "$DISTRO_DIR" -name "*.log" -exec grep -l "rancher/rancher:" {} \; 2>/dev/null \
    | head -1 | xargs grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[^ "]*' 2>/dev/null \
    | sort -V | tail -1 || true)
fi
info "Rancher version : ${RANCHER_VERSION:-unknown}"

if [[ -f "${SYSINFO}/osrelease" ]]; then
  OS_NAME=$(sgrep "PRETTY_NAME" "${SYSINFO}/osrelease" | cut -d'"' -f2 | head -1 || true)
  info "OS              : ${OS_NAME:-unknown}"
fi
[[ -f "${SYSINFO}/uname" ]] && info "Kernel          : $(cat "${SYSINFO}/uname")"

# CNI detection
CNI="unknown"
if [[ -f "${NETWORKING}/ethtool" ]]; then
  if sgrep -q "flannel" "${NETWORKING}/ethtool" 2>/dev/null; then
    CNI="flannel"
  elif sgrep -q "vxlan.calico" "${NETWORKING}/ethtool" 2>/dev/null; then
    CNI="calico"
  elif sgrep -q "cilium" "${NETWORKING}/ethtool" 2>/dev/null; then
    CNI="cilium"
  fi
fi
if [[ "$CNI" == "unknown" && -d "${NETWORKING}/cni" ]]; then
  CNI_CONF=$(find "${NETWORKING}/cni" -name "*.conf" -o -name "*.conflist" 2>/dev/null | head -1 || true)
  if [[ -n "$CNI_CONF" && -f "$CNI_CONF" ]]; then
    CNI=$(sgrep '"type"' "$CNI_CONF" | grep -oE '"[a-zA-Z_-]+"' | tr -d '"' | head -1 || echo "unknown")
  fi
fi
info "CNI             : ${CNI}"

# CSI detection
CSI="unknown"
if [[ -f "${KUBECTL_DIR}/pods" ]]; then
  if sgrep -q "longhorn" "${KUBECTL_DIR}/pods" 2>/dev/null; then
    CSI="Longhorn"
  fi
  if sgrep -q "csi-nfs" "${KUBECTL_DIR}/pods" 2>/dev/null; then
    CSI="${CSI}/NFS"
  fi
  if sgrep -q "rook-ceph" "${KUBECTL_DIR}/pods" 2>/dev/null; then
    CSI="${CSI}/Ceph"
  fi
fi
info "CSI             : ${CSI}"

if [[ -f "${SYSINFO}/systemd-detect-virt" ]]; then
  info "Virt type       : $(cat "${SYSINFO}/systemd-detect-virt" 2>/dev/null)"
fi

# ── 1. Node Overview ──────────────────────────────────────────
banner "1 / Node Overview"

if [[ -f "${KUBECTL_DIR}/nodes" ]]; then
  section "Node list:"
  while IFS= read -r line; do
    case "$line" in
      *NotReady*)
        echo "  [FAIL] ${line}"
        ISSUES+=("NotReady node: $(echo "$line" | awk '{print $1}')")
        ;;
      *Ready*)
        echo "  [OK]   ${line}"
        ;;
      *)
        echo "  [INFO] ${line}"
        ;;
    esac
  done < "${KUBECTL_DIR}/nodes"
else
  warn "kubectl/nodes not found in bundle"
fi

if [[ -f "${KUBECTL_DIR}/nodesdescribe" ]]; then
  for pressure in "MemoryPressure:True" "DiskPressure:True" "PIDPressure:True"; do
    KEY="${pressure%%:*}"
    COUNT=$(sgrep -c "${KEY}.*True" "${KUBECTL_DIR}/nodesdescribe" 2>/dev/null || echo "0")
    COUNT=$(safe_int "$COUNT")
    if (( COUNT > 0 )); then
      fail "${COUNT} node(s) with ${KEY}"
    else
      ok "No ${KEY}"
    fi
  done
fi

# ── 2. Certificate Expiry ─────────────────────────────────────
banner "2 / Certificate Expiry"

CERT_FILE="${KUBECTL_DIR}/certificate-check"
if [[ -f "$CERT_FILE" ]]; then
  section "Certificate check output:"
  while IFS= read -r line; do
    # Use case statement to avoid grep in if-condition with pipefail
    case "$line" in
      *[Ee][Xx][Pp][Ii][Rr]*|*[Ii][Nn][Vv][Aa][Ll][Ii][Dd]*|*FAILED*|*[Ee][Rr][Rr][Oo][Rr]*)
        fail "  CERT: ${line}"
        ;;
      *[Ww][Aa][Rr][Nn]*|*"30 day"*|*"60 day"*)
        warn "  CERT: ${line}"
        ;;
      *[Oo][Kk]*|*[Vv][Aa][Ll][Ii][Dd]*|*[Ss][Uu][Cc][Cc][Ee][Ss][Ss]*)
        ok   "  ${line}"
        ;;
      *)
        info "  ${line}"
        ;;
    esac
  done < "$CERT_FILE"
fi

# Certificate error patterns — require specific error-context strings
CERT_ERR_PAT='certificate has expired|certificate.*expir|x509: certificate|x509.*certificate.*expir|tls: .*certificate|certificate signed by unknown authority|certificate verify failed'
CERT_ERRORS=0
declare -a CERT_SAMPLE_LINES=()

while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  while IFS= read -r line; do
    # Skip info-level kubelet/controller log lines (prefix: I<MMDD> or I<YYYY>)
    [[ "$line" =~ ^I[0-9] ]] && continue
    
    # Check for certificate error patterns using bash matching
    match_found=false
    if [[ "$line" =~ [Cc]ertificate[[:space:]].*[Ee]xpir ]] || \
       [[ "$line" =~ [Xx]509:[[:space:]]*[Cc]ertificate ]] || \
       [[ "$line" =~ [Tt][Ll][Ss]:[[:space:]].*[Cc]ertificate ]] || \
       [[ "$line" =~ [Cc]ertificate[[:space:]]*signed[[:space:]]*by[[:space:]]*unknown ]] || \
       [[ "$line" =~ [Cc]ertificate[[:space:]]*verify[[:space:]]*failed ]]; then
      match_found=true
    fi
    
    if [[ "$match_found" == true ]]; then
      CERT_ERRORS=$(( CERT_ERRORS + 1 ))
      if (( ${#CERT_SAMPLE_LINES[@]} < 10 )); then
        CERT_SAMPLE_LINES+=("  [$(basename "$f")] ${line}")
      fi
    fi
  done < <(sgrep -iE "$CERT_ERR_PAT" "$f" 2>/dev/null || true)
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null | head -100)

if (( CERT_ERRORS > 0 )); then
  fail "Certificate errors in logs: ${CERT_ERRORS} occurrence(s)"
  ISSUES+=("Certificate errors found in logs")
  section "Matching lines (up to 10, full line):"
  for sample in "${CERT_SAMPLE_LINES[@]}"; do
    echo "    ${sample}"
  done
else
  ok "No certificate expiry errors in logs"
fi

# ── 3. Disk & Filesystem ──────────────────────────────────────
banner "3 / Disk & Filesystem"

if [[ -f "${SYSINFO}/dfh" ]]; then
  section "Disk usage:"
  while IFS= read -r line; do
    [[ "$line" =~ ^Filesystem ]] && continue
    USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
    MOUNT=$(echo "$line" | awk '{print $6}')
    [[ -z "$USE" || -z "$MOUNT" ]] && continue
    [[ ! "$USE" =~ ^[0-9]+$ ]] && info "Disk skipped (stale/error): ${MOUNT} (reported: ${USE})" && continue
    if (( USE >= 90 )); then
      fail "Disk CRITICAL ${USE}% used — ${MOUNT}"
    elif (( USE >= 80 )); then
      warn "Disk WARNING ${USE}% used — ${MOUNT}"
    else
      ok   "Disk OK ${USE}% used — ${MOUNT}"
    fi
  done < <(sgrep -v tmpfs "${SYSINFO}/dfh" | sgrep -v devtmpfs)
fi

if [[ -f "${SYSINFO}/dfi" ]]; then
  section "inode usage:"
  while IFS= read -r line; do
    [[ "$line" =~ ^Filesystem ]] && continue
    USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
    MOUNT=$(echo "$line" | awk '{print $6}')
    [[ -z "$USE" || "$USE" == "-" ]] && continue
    [[ -z "$MOUNT" ]] && continue
    [[ ! "$USE" =~ ^[0-9]+$ ]] && info "inode skipped (stale/error): ${MOUNT} (reported: ${USE})" && continue
    if (( USE >= 90 )); then
      fail "inode CRITICAL ${USE}% — ${MOUNT}"
    elif (( USE >= 80 )); then
      warn "inode WARNING ${USE}% — ${MOUNT}"
    fi
  done < <(sgrep -v tmpfs "${SYSINFO}/dfi" | sgrep -v devtmpfs)
fi

if [[ -f "${SYSINFO}/dmesg" ]]; then
  IO_ERRS=$(sgrep -ci "I/O error\|blk_update_request\|SCSI error\|EXT4-fs error\|XFS.*error" \
    "${SYSINFO}/dmesg" || echo "0")
  IO_ERRS=$(safe_int "$IO_ERRS")
  if (( IO_ERRS > 0 )); then
    fail "Disk I/O errors in dmesg: ${IO_ERRS}"
    ISSUES+=("Disk I/O errors in dmesg")
  else
    ok "No disk I/O errors in dmesg"
  fi

  OOM_DMESG=$(sgrep -ci "oom_kill\|Out of memory\|Killed process" "${SYSINFO}/dmesg" || echo "0")
  OOM_DMESG=$(safe_int "$OOM_DMESG")
  if (( OOM_DMESG > 0 )); then
    fail "OOM events in dmesg: ${OOM_DMESG}"
  else
    ok "No OOM events in dmesg"
  fi
fi

if [[ -f "${SYSINFO}/iostathx" ]]; then
  HIGH_AWAIT=$(awk 'NR>3 && $10+0 > 20 {print $1, "await=" $10 "ms"}' \
    "${SYSINFO}/iostathx" 2>/dev/null | head -5 || true)
  if [[ -n "$HIGH_AWAIT" ]]; then
    warn "High disk await (>20ms):"
    echo "$HIGH_AWAIT" | while IFS= read -r line; do info "  ${line}"; done
  else
    ok "Disk await times within normal range"
  fi
fi

ETCD_SLOW=0
while IFS= read -r f; do
  C=$(sgrep -c "slow fdatasync\|apply entries took too long\|slow linearizable" "$f" 2>/dev/null || echo "0")
  ETCD_SLOW=$(( ETCD_SLOW + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -path "*etcd*" -name "*.log" 2>/dev/null)
if (( ETCD_SLOW > 0 )); then
  fail "etcd slow disk/apply warnings: ${ETCD_SLOW}"
  ISSUES+=("etcd slow disk warnings")
else
  ok "No etcd slow disk warnings"
fi

# ── 4. CPU & Memory — ENHANCED DEEP ANALYSIS ─────────────────
banner "4 / CPU & Memory — Deep Analysis"

# ──────────────────────────────────────────────────────────────
# 4A. MEMORY ANALYSIS
# ──────────────────────────────────────────────────────────────
section "4A. Memory Analysis"

if [[ -f "${SYSINFO}/freeh" ]]; then
  section "Memory snapshot:"
  while IFS= read -r line; do
    info "  ${line}"
  done < "${SYSINFO}/freeh"
  
  MEM_LINE=$(sgrep "^Mem:" "${SYSINFO}/freeh" || true)
  if [[ -n "$MEM_LINE" ]]; then
    TOTAL=$(echo "$MEM_LINE" | awk '{print $2}' | sed 's/Gi//g')
    AVAIL=$(echo "$MEM_LINE" | awk '{print $7}' | sed 's/Gi//g')
    
    if [[ "$TOTAL" =~ ^[0-9.]+$ && "$AVAIL" =~ ^[0-9.]+$ ]]; then
      USED_PCT=$(echo "$TOTAL $AVAIL" | awk '{printf "%d", ($1-$2)/$1*100}')
      
      info "Memory utilization: ${USED_PCT}% used"
      
      if (( USED_PCT >= 95 )); then
        fail "Memory CRITICAL: ${USED_PCT}% used — system at risk of OOM"
        ISSUES+=("Memory critical: ${USED_PCT}% used")
      elif (( USED_PCT >= 85 )); then
        warn "Memory WARNING: ${USED_PCT}% used — approaching critical threshold"
      elif (( USED_PCT >= 75 )); then
        warn "Memory ELEVATED: ${USED_PCT}% used — monitor closely"
      else
        ok "Memory OK: ${USED_PCT}% used"
      fi
      
      AVAIL_MB=$(echo "$AVAIL" | awk '{printf "%.0f", $1 * 1024}' 2>/dev/null || echo "0")
      if (( AVAIL_MB < 256 )); then
        fail "Available memory critically low: ${AVAIL_MB}MB — OOM kills imminent"
        ISSUES+=("Available memory <256MB")
      elif (( AVAIL_MB < 512 )); then
        warn "Available memory low: ${AVAIL_MB}MB — risk of OOM kills"
      fi
    fi
  fi
  
  SWAP_LINE=$(sgrep "^Swap:" "${SYSINFO}/freeh" || true)
  if [[ -n "$SWAP_LINE" ]]; then
    SWAP_TOTAL=$(echo "$SWAP_LINE" | awk '{print $2}' | sed 's/Gi//g')
    SWAP_USED=$(echo "$SWAP_LINE" | awk '{print $3}' | sed 's/Gi//g')
    
    if [[ "$SWAP_TOTAL" =~ ^[0-9.]+$ && "$SWAP_TOTAL" != "0" ]]; then
      SWAP_PCT=$(echo "$SWAP_TOTAL $SWAP_USED" | awk '{printf "%d", $2/$1*100}')
      SWAP_USED_MB=$(echo "$SWAP_USED" | awk '{printf "%.0f", $1 * 1024}' 2>/dev/null || echo "0")
      
      section "Swap analysis:"
      info "Swap usage: ${SWAP_PCT}% (${SWAP_USED_MB}MB used)"
      
      if (( SWAP_PCT >= 50 )); then
        fail "Swap heavily used (${SWAP_PCT}%) — indicates memory pressure"
        ISSUES+=("Heavy swap usage: ${SWAP_PCT}%")
      elif (( SWAP_PCT >= 20 )); then
        warn "Swap usage elevated (${SWAP_PCT}%) — memory pressure likely"
      elif (( SWAP_PCT > 0 )); then
        info "Minor swap usage — may be normal for some workloads"
      else
        ok "No swap usage"
      fi
      
      warn "Swap is enabled — Kubernetes recommends disabling swap"
    else
      ok "Swap disabled (recommended for Kubernetes)"
    fi
  fi
else
  warn "free -h output not found in bundle"
fi

# Check /proc/meminfo if available
if [[ -f "${SYSINFO}/meminfo" ]]; then
  section "Detailed memory breakdown:"
  
  SLAB_TOTAL=$(awk '/^Slab:/ {print $2}' "${SYSINFO}/meminfo" 2>/dev/null || echo "0")
  SLAB_UNRECLAIMABLE=$(awk '/^SUnreclaim:/ {print $2}' "${SYSINFO}/meminfo" 2>/dev/null || echo "0")
  
  if [[ "$SLAB_TOTAL" =~ ^[0-9]+$ && "$SLAB_TOTAL" -gt 0 ]]; then
    SLAB_MB=$(( SLAB_TOTAL / 1024 ))
    SLAB_UNRECLAIM_MB=$(( SLAB_UNRECLAIMABLE / 1024 ))
    info "Slab cache: ${SLAB_MB}MB total, ${SLAB_UNRECLAIM_MB}MB unreclaimable"
    
    if (( SLAB_UNRECLAIM_MB > 1024 )); then
      warn "High unreclaimable slab memory: ${SLAB_UNRECLAIM_MB}MB — possible kernel memory leak"
    fi
  fi
  
  HUGEPAGES_TOTAL=$(awk '/^HugePages_Total:/ {print $2}' "${SYSINFO}/meminfo" 2>/dev/null || echo "0")
  HUGEPAGES_FREE=$(awk '/^HugePages_Free:/ {print $2}' "${SYSINFO}/meminfo" 2>/dev/null || echo "0")
  if [[ "$HUGEPAGES_TOTAL" =~ ^[0-9]+$ && "$HUGEPAGES_TOTAL" -gt 0 ]]; then
    HUGEPAGES_USED=$(( HUGEPAGES_TOTAL - HUGEPAGES_FREE ))
    HUGEPAGES_PCT=$(( HUGEPAGES_USED * 100 / HUGEPAGES_TOTAL ))
    info "HugePages: ${HUGEPAGES_USED}/${HUGEPAGES_TOTAL} used (${HUGEPAGES_PCT}%)"
    if (( HUGEPAGES_PCT >= 90 )); then
      warn "HugePages nearly exhausted — may affect VM workloads"
    fi
  fi
fi

# ──────────────────────────────────────────────────────────────
# 4B. CPU ANALYSIS
# ──────────────────────────────────────────────────────────────
section "4B. CPU Analysis"

CPU_COUNT=1
if [[ -f "${SYSINFO}/cpuinfo" ]]; then
  CPU_COUNT=$(grep -c "^processor" "${SYSINFO}/cpuinfo" 2>/dev/null || echo "1")
fi

if [[ -f "${SYSINFO}/uptime" ]]; then
  UPTIME_CONTENT=$(cat "${SYSINFO}/uptime")
  info "Uptime: ${UPTIME_CONTENT}"
  
  LOADS=$(echo "$UPTIME_CONTENT" | awk -F'load average:' '{print $2}' | tr -d ' ' || echo "")
  LOAD1=$(echo "$LOADS" | cut -d',' -f1 || echo "0")
  LOAD5=$(echo "$LOADS" | cut -d',' -f2 | tr -d ' ' || echo "0")
  LOAD15=$(echo "$LOADS" | cut -d',' -f3 | tr -d ' ' || echo "0")
  
  if [[ "$LOAD1" =~ ^[0-9.]+$ ]]; then
    LOAD_PCT=$(echo "$LOAD1 $CPU_COUNT" | awk '{printf "%.0f", ($1/$2)*100}')
    
    section "Load average analysis:"
    info "CPU cores: ${CPU_COUNT}"
    info "Load averages: 1min=${LOAD1}  5min=${LOAD5}  15min=${LOAD15}"
    info "1-min load per CPU: ${LOAD_PCT}%"
    
    if [[ "$LOAD1" =~ ^[0-9.]+$ && "$LOAD15" =~ ^[0-9.]+$ ]]; then
      LOAD_TREND=$(echo "$LOAD1 $LOAD15" | awk '{if ($1 > $2 * 1.5) print "INCREASING"; else if ($1 < $2 * 0.7) print "DECREASING"; else print "STABLE"}')
      info "Load trend: ${LOAD_TREND}"
      if [[ "$LOAD_TREND" == "INCREASING" && "$LOAD_PCT" -gt 70 ]]; then
        warn "Load increasing and high — possible CPU congestion building"
      fi
    fi
    
    if (( LOAD_PCT >= 200 )); then
      fail "CPU CRITICAL: Load ${LOAD_PCT}% of capacity — severe CPU congestion"
      ISSUES+=("CPU critical: load ${LOAD_PCT}% of capacity")
    elif (( LOAD_PCT >= 100 )); then
      fail "CPU OVERLOADED: Load ${LOAD_PCT}% of capacity — processes waiting"
      ISSUES+=("CPU overloaded: load ${LOAD_PCT}% of capacity")
    elif (( LOAD_PCT >= 80 )); then
      warn "CPU HIGH: Load ${LOAD_PCT}% of capacity — approaching saturation"
    elif (( LOAD_PCT >= 60 )); then
      info "CPU MODERATE: Load ${LOAD_PCT}% of capacity — monitor during peak"
    else
      ok "CPU OK: Load ${LOAD_PCT}% of capacity"
    fi
  fi
fi

if [[ -f "${SYSINFO}/top" ]]; then
  section "Top process analysis (from top output):"
  
  CPU_HEADER=$(head -3 "${SYSINFO}/top" 2>/dev/null | tail -1 || true)
  info "CPU summary line: ${CPU_HEADER}"
  
  if [[ -n "$CPU_HEADER" ]]; then
    CPU_USER=$(echo "$CPU_HEADER" | grep -oE '[0-9]+\.[0-9]+ us' | grep -oE '[0-9]+\.[0-9]+' || echo "0")
    CPU_SYS=$(echo "$CPU_HEADER" | grep -oE '[0-9]+\.[0-9]+ sy' | grep -oE '[0-9]+\.[0-9]+' || echo "0")
    CPU_IOWAIT=$(echo "$CPU_HEADER" | grep -oE '[0-9]+\.[0-9]+ wa' | grep -oE '[0-9]+\.[0-9]+' || echo "0")
    CPU_STEAL=$(echo "$CPU_HEADER" | grep -oE '[0-9]+\.[0-9]+ st' | grep -oE '[0-9]+\.[0-9]+' || echo "0")
    
    section "CPU time breakdown:"
    info "  User:   ${CPU_USER}%"
    info "  System: ${CPU_SYS}%"
    info "  IOWait: ${CPU_IOWAIT}%"
    info "  Steal:  ${CPU_STEAL}%"
    
    STEAL_INT=$(echo "$CPU_STEAL" | awk '{printf "%.0f", $1}' 2>/dev/null || echo "0")
    if (( STEAL_INT >= 10 )); then
      fail "CPU steal time CRITICAL (${CPU_STEAL}%) — VM starved by hypervisor"
      ISSUES+=("High CPU steal: ${CPU_STEAL}%")
    elif (( STEAL_INT >= 5 )); then
      warn "CPU steal time elevated (${CPU_STEAL}%) — noisy neighbor"
    elif (( STEAL_INT > 0 )); then
      info "Minor CPU steal — normal for shared cloud instances"
    fi
    
    IOWAIT_INT=$(echo "$CPU_IOWAIT" | awk '{printf "%.0f", $1}' 2>/dev/null || echo "0")
    if (( IOWAIT_INT >= 20 )); then
      fail "CPU IOWait CRITICAL (${CPU_IOWAIT}%) — severe I/O bottleneck"
      ISSUES+=("High IOWait: ${CPU_IOWAIT}%")
    elif (( IOWAIT_INT >= 10 )); then
      warn "CPU IOWait elevated (${CPU_IOWAIT}%) — I/O bottleneck likely"
    elif (( IOWAIT_INT >= 5 )); then
      info "CPU IOWait moderate (${CPU_IOWAIT}%) — monitor disk"
    fi
  fi
  
  section "Top CPU-consuming processes:"
  HIGH_CPU_PROCS=$(tail -n +8 "${SYSINFO}/top" 2>/dev/null | awk '$9+0 > 10 {print $9"%", $12, $13, $14}' | sort -t'%' -k1 -rn | head -10 || true)
  if [[ -n "$HIGH_CPU_PROCS" ]]; then
    echo "$HIGH_CPU_PROCS" | while IFS= read -r line; do
      CPU_PCT=$(echo "$line" | awk '{print $1}' | tr -d '%')
      if [[ "$CPU_PCT" =~ ^[0-9]+$ ]] && (( CPU_PCT > 50 )); then
        warn "  CPU ${line}"
      else
        info "  CPU ${line}"
      fi
    done
  else
    ok "No processes with >10% CPU"
  fi
fi

# ──────────────────────────────────────────────────────────────
# 4C. DISK I/O ANALYSIS
# ──────────────────────────────────────────────────────────────
section "4C. Disk I/O Analysis"

if [[ -f "${SYSINFO}/iostathx" ]]; then
  section "iostat extended analysis:"
  
  awk 'NR>3 && NF>=14 {
    device=$1
    await=$10
    util=$NF
    avgqu=$8
    r_await=$11
    w_await=$12
    
    printf "  %s: await=%.1fms r_await=%.1fms w_await=%.1fms avgqu=%.2f util=%.1f%%\n", device, await, r_await, w_await, avgqu, util
    
    if (await+0 > 50) printf "    >> CRITICAL: await %.1fms exceeds 50ms\n", await
    else if (await+0 > 20) printf "    >> WARNING: await %.1fms exceeds 20ms\n", await
    
    if (util+0 > 90) printf "    >> CRITICAL: utilization %.1f%% — saturated\n", util
    else if (util+0 > 70) printf "    >> WARNING: utilization %.1f%%\n", util
  }' "${SYSINFO}/iostathx" 2>/dev/null || true
  
  HIGH_AWAIT_DEVICES=$(awk 'NR>3 && $10+0 > 20 {print $1, "await=" $10 "ms, util=" $NF "%"}' \
    "${SYSINFO}/iostathx" 2>/dev/null || true)
  
  if [[ -n "$HIGH_AWAIT_DEVICES" ]]; then
    warn "Devices with high await (>20ms):"
    echo "$HIGH_AWAIT_DEVICES" | while IFS= read -r line; do
      info "  ${line}"
    done
  else
    ok "All devices have healthy await times"
  fi
fi

# ──────────────────────────────────────────────────────────────
# 4D. CONGESTION SUMMARY
# ──────────────────────────────────────────────────────────────
section "4D. Congestion Summary"

CPU_CONGESTION="NONE"
MEM_CONGESTION="NONE"
IO_CONGESTION="NONE"

if [[ -n "${LOAD1:-}" && "$LOAD1" =~ ^[0-9.]+$ ]]; then
  LOAD_PCT=$(echo "$LOAD1 $CPU_COUNT" | awk '{printf "%.0f", ($1/$2)*100}')
  if (( LOAD_PCT >= 100 )); then
    CPU_CONGESTION="CRITICAL"
  elif (( LOAD_PCT >= 80 )); then
    CPU_CONGESTION="HIGH"
  elif (( LOAD_PCT >= 60 )); then
    CPU_CONGESTION="MODERATE"
  fi
fi

if [[ -n "${CPU_STEAL:-}" && "$CPU_STEAL" =~ ^[0-9.]+$ ]]; then
  STEAL_INT=$(echo "$CPU_STEAL" | awk '{printf "%.0f", $1}')
  if (( STEAL_INT >= 10 )) && [[ "$CPU_CONGESTION" != "CRITICAL" ]]; then
    CPU_CONGESTION="CRITICAL (steal)"
  elif (( STEAL_INT >= 5 )) && [[ "$CPU_CONGESTION" == "NONE" ]]; then
    CPU_CONGESTION="MODERATE (steal)"
  fi
fi

if [[ -n "${USED_PCT:-}" ]]; then
  if (( USED_PCT >= 95 )); then
    MEM_CONGESTION="CRITICAL"
  elif (( USED_PCT >= 85 )); then
    MEM_CONGESTION="HIGH"
  elif (( USED_PCT >= 75 )); then
    MEM_CONGESTION="MODERATE"
  fi
fi

if [[ -f "${SYSINFO}/iostathx" ]]; then
  MAX_AWAIT=$(awk 'NR>3 {if($10+0 > max) max=$10} END {printf "%.0f", max+0}' "${SYSINFO}/iostathx" 2>/dev/null || echo "0")
  MAX_UTIL=$(awk 'NR>3 {if($NF+0 > max) max=$NF} END {printf "%.0f", max+0}' "${SYSINFO}/iostathx" 2>/dev/null || echo "0")
  
  if (( MAX_AWAIT >= 50 || MAX_UTIL >= 90 )); then
    IO_CONGESTION="CRITICAL"
  elif (( MAX_AWAIT >= 20 || MAX_UTIL >= 70 )); then
    IO_CONGESTION="HIGH"
  elif (( MAX_AWAIT >= 10 || MAX_UTIL >= 50 )); then
    IO_CONGESTION="MODERATE"
  fi
fi

if [[ -n "${CPU_IOWAIT:-}" && "$CPU_IOWAIT" =~ ^[0-9.]+$ ]]; then
  IOWAIT_INT=$(echo "$CPU_IOWAIT" | awk '{printf "%.0f", $1}')
  if (( IOWAIT_INT >= 20 )) && [[ "$IO_CONGESTION" != "CRITICAL" ]]; then
    IO_CONGESTION="CRITICAL (iowait)"
  elif (( IOWAIT_INT >= 10 )) && [[ "$IO_CONGESTION" == "NONE" ]]; then
    IO_CONGESTION="MODERATE (iowait)"
  fi
fi

echo ""
info "CPU Congestion : ${CPU_CONGESTION}"
info "Memory Congestion: ${MEM_CONGESTION}"
info "I/O Congestion  : ${IO_CONGESTION}"

if [[ "$CPU_CONGESTION" == "CRITICAL" || "$CPU_CONGESTION" == "HIGH" ]]; then
  warn "CPU CONGESTION DETECTED:"
  if [[ "$CPU_CONGESTION" == *"steal"* ]]; then
    info "  - HIGH STEAL: Consider dedicated hosts or larger instance"
  else
    info "  - Scale horizontally or right-size workloads"
  fi
fi

if [[ "$MEM_CONGESTION" == "CRITICAL" || "$MEM_CONGESTION" == "HIGH" ]]; then
  warn "MEMORY CONGESTION DETECTED:"
  info "  - Add more nodes or upgrade node memory"
fi

if [[ "$IO_CONGESTION" == "CRITICAL" || "$IO_CONGESTION" == "HIGH" ]]; then
  warn "DISK I/O CONGESTION DETECTED:"
  info "  - For etcd: ensure fast SSD storage"
  info "  - Consider higher IOPS storage class"
fi

if [[ "$CPU_CONGESTION" == "NONE" && "$MEM_CONGESTION" == "NONE" && "$IO_CONGESTION" == "NONE" ]]; then
  ok "No resource congestion detected"
fi

# File descriptor check
if [[ -f "${SYSINFO}/file-nr" ]]; then
  section "File descriptor usage:"
  FD_USED=$(awk '{print $1}' "${SYSINFO}/file-nr" 2>/dev/null || echo "0")
  FD_MAX=$(awk '{print $3}'  "${SYSINFO}/file-nr" 2>/dev/null || echo "1")
  if [[ "$FD_MAX" =~ ^[0-9]+$ && "$FD_USED" =~ ^[0-9]+$ && "$FD_MAX" -gt 0 ]]; then
    FD_PCT=$(( FD_USED * 100 / FD_MAX ))
    if (( FD_PCT >= 90 )); then
      fail "File descriptors CRITICAL: ${FD_PCT}% used (${FD_USED}/${FD_MAX})"
      ISSUES+=("File descriptors critical: ${FD_PCT}%")
    elif (( FD_PCT >= 80 )); then
      warn "File descriptors WARNING: ${FD_PCT}% used (${FD_USED}/${FD_MAX})"
    else
      ok "File descriptors ${FD_PCT}% used (${FD_USED}/${FD_MAX})"
    fi
  fi
fi

# ── 5. Networking ─────────────────────────────────────────────
banner "5 / Networking"

if [[ -f "${NETWORKING}/iptablessave" ]]; then
  IPT_RULES=$(wc -l < "${NETWORKING}/iptablessave" 2>/dev/null || echo "0")
  IPT_RULES=$(safe_int "$IPT_RULES")
  info "iptables rules: ${IPT_RULES} lines"
  if (( IPT_RULES > 10000 )); then
    warn "iptables rule count very high (${IPT_RULES})"
  fi
  KUBE_DROPS=$(sgrep -c "KUBE.*REJECT\|DROP.*6443\|DROP.*2379\|DROP.*10250" \
    "${NETWORKING}/iptablessave" 2>/dev/null || echo "0")
  KUBE_DROPS=$(safe_int "$KUBE_DROPS")
  if (( KUBE_DROPS > 0 )); then
    fail "iptables DROP rules on Kubernetes ports: ${KUBE_DROPS}"
  else
    ok "No DROP rules on critical Kubernetes ports"
  fi
fi

if [[ -f "${SYSINFO}/dmesg" ]]; then
  CONNTRACK_FULL=$(sgrep -ci "nf_conntrack: table full\|nf_conntrack: falling behind\|conntrack: dropping" \
    "${SYSINFO}/dmesg" 2>/dev/null || echo "0")
  CONNTRACK_FULL=$(safe_int "$CONNTRACK_FULL")
  if (( CONNTRACK_FULL > 0 )); then
    fail "conntrack table full: ${CONNTRACK_FULL} events"
    ISSUES+=("conntrack table full")
  else
    ok "No conntrack table overflow"
  fi
fi

if [[ -f "${SYSINFO}/etcresolvconf" ]]; then
  section "resolv.conf:"
  while IFS= read -r line; do
    info "  ${line}"
  done < "${SYSINFO}/etcresolvconf"
  NAMESERVER_COUNT=$(sgrep -c "^nameserver" "${SYSINFO}/etcresolvconf" 2>/dev/null || echo "0")
  NAMESERVER_COUNT=$(safe_int "$NAMESERVER_COUNT")
  if (( NAMESERVER_COUNT == 0 )); then
    fail "No nameservers in /etc/resolv.conf"
  fi
fi

CNI_ERRORS=0
for ns in kube-system cattle-system; do
  while IFS= read -r f; do
    [[ ! -f "$f" ]] && continue
    C=$(sgrep -ci "level=error\|level=fatal\|FATA\|panic:" "$f" 2>/dev/null || echo "0")
    CNI_ERRORS=$(( CNI_ERRORS + C ))
  done < <(find "${PODS_DIR:-/dev/null}" -path "*${ns}*" -name "*.log" 2>/dev/null \
    | sgrep -Ei "canal|flannel|calico|cilium|multus" 2>/dev/null || true)
done
if (( CNI_ERRORS > 0 )); then
  warn "CNI component log errors: ${CNI_ERRORS} lines"
else
  ok "No CNI component errors"
fi

# ── 6. etcd Health ────────────────────────────────────────────
banner "6 / etcd Health"

ETCD_PATTERN_LIST=(
  "apply_too_long|FAIL|apply request took too long|apply entries took too long"
  "heartbeat_failed|FAIL|failed to send out heartbeat on time|failed to send out heartbeat"
  "leader_changed|FAIL|etcdserver: leader changed|lost leader|became leader"
  "context_deadline|FAIL|context deadline exceeded"
  "slow_fdatasync|FAIL|slow fdatasync"
  "alarm_nospace|FAIL|etcd server is running low on space|mvcc: database space exceeded"
  "raft_error|FAIL|raft: failed to|raft error"
  "leader_lost|WARN|lost leader|elected leader"
  "snapshot_failed|WARN|failed to save snapshot|snapshot.*failed"
  "compaction_failed|WARN|failed to defrag|compaction.*failed"
  "disconnect|WARN|lost the TCP streaming connection|rafthttp: failed to dial"
)

ETCD_LOG_FOUND=false
ETCD_FILES=()
while IFS= read -r f; do
  ETCD_LOG_FOUND=true
  ETCD_FILES+=("$f")
done < <(find "${DISTRO_DIR:-$ROOT}" -path "*etcd*" -name "*.log" 2>/dev/null | sort)

if [[ "$ETCD_LOG_FOUND" == false ]]; then
  info "No etcd log files found in bundle"
else
  info "etcd log files found: ${#ETCD_FILES[@]}"
  for f in "${ETCD_FILES[@]}"; do
    info "  $(basename "$f")"
  done

  for entry in "${ETCD_PATTERN_LIST[@]}"; do
    key="${entry%%|*}"
    rest="${entry#*|}"
    sev="${rest%%|*}"
    pats="${rest#*|}"
    grep_pat=$(echo "$pats" | sed 's/|/\\|/g')

    TOTAL_C=0
    for f in "${ETCD_FILES[@]}"; do
      C=$(sgrep -ci "$grep_pat" "$f" 2>/dev/null || echo "0")
      TOTAL_C=$(( TOTAL_C + C ))
    done

    if (( TOTAL_C > 0 )); then
      if [[ "$sev" == "FAIL" ]]; then
        fail "etcd [${key}]: ${TOTAL_C} occurrence(s)"
        ISSUES+=("etcd ${key} (${TOTAL_C} hits)")
      else
        warn "etcd [${key}]: ${TOTAL_C} occurrence(s)"
      fi

      section "  Last 3 occurrences of [${key}]:"
      for f in "${ETCD_FILES[@]}"; do
        sgrep -i "$grep_pat" "$f" 2>/dev/null | tail -3
      done | tail -3 | while IFS= read -r line; do
        echo "    ${line}"
        TOOK=$(echo "$line" | grep -oE '"took":"[^"]*"' | head -1 || true)
        EXPECTED=$(echo "$line" | grep -oE '"expected-duration":"[^"]*"' | head -1 || true)
        REQUEST=$(echo "$line" | grep -oE '"request":"[^"]*"' | head -1 || true)
        if [[ -n "$TOOK" ]]; then
          echo "      >> duration  : ${TOOK}"
          echo "      >> threshold : ${EXPECTED}"
          [[ -n "$REQUEST" ]] && echo "      >> request   : ${REQUEST}"
        fi
      done
      echo ""
    else
      ok "etcd [${key}]: no occurrences found"
    fi
  done

  section "apply_too_long duration analysis:"
  ALL_TOOK=""
  for f in "${ETCD_FILES[@]}"; do
    Took=$(sgrep -i "apply request took too long\|apply entries took too long" "$f" 2>/dev/null \
      | grep -oE '"took":"[^"]*"' 2>/dev/null || true)
    [[ -n "$Took" ]] && ALL_TOOK="${ALL_TOOK}${Took}"$'\n'
  done
  
  if [[ -n "$ALL_TOOK" ]]; then
    WORST=$(echo "$ALL_TOOK" | sort -t'"' -k4 -V | tail -1 || true)
    TOTAL_APPLY=$(echo "$ALL_TOOK" | grep -cE '"took":' 2>/dev/null || echo "0")
    TOTAL_APPLY=$(safe_int "$TOTAL_APPLY")
    info "Total apply_too_long events    : ${TOTAL_APPLY}"
    info "Worst recorded duration        : ${WORST}"
    SEVERE=$(echo "$ALL_TOOK" | grep -cE '"took":"[0-9]+\.[0-9]+s"' 2>/dev/null || echo "0")
    SEVERE=$(safe_int "$SEVERE")
    if (( SEVERE > 0 )); then
      fail "apply_too_long events >= 1s    : ${SEVERE} (severe)"
      ISSUES+=("etcd apply_too_long: ${SEVERE} events exceeded 1 second")
    else
      ok "No apply_too_long events >= 1 second"
    fi
  fi
fi

# ── 7. Rancher Server & Webhook ───────────────────────────────
banner "7 / Rancher Server & Webhook"

RANCHER_LOG_ERRS=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -ci 'level=error\|level=fatal\|panic:\|"level":"error"' "$f" 2>/dev/null || echo "0")
  RANCHER_LOG_ERRS=$(( RANCHER_LOG_ERRS + C ))
  if (( C > 0 )); then
    warn "Rancher errors in $(basename "$(dirname "$f")")/$(basename "$f"): ${C}"
    sgrep -i 'level=error\|level=fatal\|panic:' "$f" 2>/dev/null | tail -3 | \
      while IFS= read -r line; do echo "    ${line:0:160}"; done
  fi
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-system*rancher*" -name "*.log" 2>/dev/null | sort)
if (( RANCHER_LOG_ERRS == 0 )); then
  ok "No Rancher server errors found"
fi

WEBHOOK_DEAD=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -ci "rancher-webhook.*context deadline exceeded\|failed to call webhook.*rancher\|webhook.*timeout" \
    "$f" 2>/dev/null || echo "0")
  WEBHOOK_DEAD=$(( WEBHOOK_DEAD + C ))
done < <(find "${PODS_DIR:-/dev/null}" \( -path "*cattle-system*" -o -path "*rancher*" \) -name "*.log" 2>/dev/null)
if (( WEBHOOK_DEAD > 0 )); then
  fail "rancher-webhook timeout/deadline: ${WEBHOOK_DEAD} occurrence(s)"
  ISSUES+=("rancher-webhook unresponsive")
else
  ok "No rancher-webhook timeout errors"
fi

if [[ -f "${KUBECTL_DIR}/validatingwebhookconfigurations" ]]; then
  WEBHOOK_RULES=$(sgrep -A5 "name: rancher.cattle.io" \
    "${KUBECTL_DIR}/validatingwebhookconfigurations" 2>/dev/null | \
    sgrep -c "rules:\|webhooks:" 2>/dev/null || echo "0")
  WEBHOOK_RULES=$(safe_int "$WEBHOOK_RULES")
  if (( WEBHOOK_RULES == 0 )); then
    fail "rancher.cattle.io ValidatingWebhookConfiguration has 0 rules (CVE-2023-22651 indicator)"
    ISSUES+=("Webhook misconfiguration: 0 rules")
  else
    ok "rancher.cattle.io webhook rules present"
  fi
fi

# ── 8. cattle-cluster-agent & Fleet ───────────────────────────
banner "8 / cattle-cluster-agent & Fleet"

AGENT_PAT='level=error|tunnel disconnect|cluster agent disconnected|failed to connect|websocket.*closed|connection.*refused'
AGENT_ERRORS=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -ciE "$AGENT_PAT" "$f" 2>/dev/null || echo "0")
  AGENT_ERRORS=$(( AGENT_ERRORS + C ))
  if (( C > 0 )); then
    fail "cattle-cluster-agent errors in $(basename "$(dirname "$f")"): ${C}"
    sgrep -iE "$AGENT_PAT" "$f" 2>/dev/null | tail -3 | \
      while IFS= read -r line; do echo "    ${line:0:160}"; done
  fi
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-cluster-agent*" -name "*.log" 2>/dev/null | sort)
if (( AGENT_ERRORS == 0 )); then
  ok "No cattle-cluster-agent connectivity errors"
fi

STRICT_CA=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -ci "Strict CA verification.*error\|unable to read CA file\|no such file.*serverca" \
    "$f" 2>/dev/null || echo "0")
  STRICT_CA=$(( STRICT_CA + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle*" -name "*.log" 2>/dev/null)
if (( STRICT_CA > 0 )); then
  fail "Strict CA error: ${STRICT_CA} hit(s) — check agent-tls-mode setting"
  ISSUES+=("Strict CA verification error")
else
  ok "No strict CA verification errors"
fi

FLEET_ERRORS=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -ci 'level=error|"level":"error"|reconciler error' "$f" 2>/dev/null || echo "0")
  FLEET_ERRORS=$(( FLEET_ERRORS + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*fleet*" -name "*.log" 2>/dev/null)
if (( FLEET_ERRORS > 0 )); then
  warn "Fleet log errors: ${FLEET_ERRORS} lines"
else
  ok "No Fleet log errors"
fi

# ── 9. Pod Health ─────────────────────────────────────────────
banner "9 / Pod Health (All Namespaces)"

if [[ -f "${KUBECTL_DIR}/pods" ]]; then
  TOTAL_PODS=$(sgrep -v "^NAMESPACE\|^$" "${KUBECTL_DIR}/pods" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  TOTAL_PODS=$(safe_int "$TOTAL_PODS")
  RUNNING=$(sgrep -c "Running" "${KUBECTL_DIR}/pods" 2>/dev/null | tr -d ' ' || echo "0")
  RUNNING=$(safe_int "$RUNNING")
  PENDING=$(sgrep -c "Pending" "${KUBECTL_DIR}/pods" 2>/dev/null | tr -d ' ' || echo "0")
  PENDING=$(safe_int "$PENDING")
  FAILED=$(sgrep -cE "Failed|OOMKilled|CrashLoopBackOff" "${KUBECTL_DIR}/pods" 2>/dev/null | tr -d ' ' || echo "0")
  FAILED=$(safe_int "$FAILED")
  COMPLETED=$(sgrep -c "Completed" "${KUBECTL_DIR}/pods" 2>/dev/null | tr -d ' ' || echo "0")
  COMPLETED=$(safe_int "$COMPLETED")

  printf "  [INFO] Pods: total=%s  running=%s  pending=%s  failed/crash=%s  completed=%s\n" \
    "${TOTAL_PODS}" "${RUNNING}" "${PENDING}" "${FAILED}" "${COMPLETED}"

  if (( PENDING > 0 )); then
    fail "Pending pods: ${PENDING}"
    sgrep "Pending" "${KUBECTL_DIR}/pods" 2>/dev/null | while IFS= read -r line; do echo "    ${line}"; done
    ISSUES+=("${PENDING} Pending pod(s)")
  else
    ok "No Pending pods"
  fi

  if (( FAILED > 0 )); then
    fail "Failed/CrashLoop pods: ${FAILED}"
    sgrep -E "Failed|OOMKilled|CrashLoopBackOff" "${KUBECTL_DIR}/pods" 2>/dev/null | \
      while IFS= read -r line; do echo "    ${line}"; done
    ISSUES+=("${FAILED} Failed/CrashLoop pod(s)")
  else
    ok "No Failed/CrashLoop pods"
  fi
else
  warn "kubectl/pods not found in bundle"
fi

for ns in kube-system cattle-system cattle-fleet-system; do
  CRASH_COUNT=0
  while IFS= read -r f; do
    [[ ! -f "$f" ]] && continue
    C=$(sgrep -ci "panic:\|fatal error\|OOMKilled\|CrashLoopBackOff" "$f" 2>/dev/null || echo "0")
    CRASH_COUNT=$(( CRASH_COUNT + C ))
  done < <(find "${PODS_DIR:-/dev/null}" -path "*${ns}*" -name "*.log" 2>/dev/null)
  if (( CRASH_COUNT > 0 )); then
    warn "${ns}: ${CRASH_COUNT} panic/OOM/crash lines"
  fi
done

# ══════════════════════════════════════════════════════════════
# Bug detection
# ══════════════════════════════════════════════════════════════

# ── 10. Known Rancher Bug Signatures ─────────────────────────
banner "10 / Known Rancher Bug Signatures"

section "BUG-R1: Tunnel disconnect — cluster-agent instability:"
TUNNEL_DISC=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "tunnel disconnect\|watch.*ended.*tunnel disconnect" "$f" 2>/dev/null || echo "0")
  TUNNEL_DISC=$(( TUNNEL_DISC + C ))
done < <(find "${PODS_DIR:-/dev/null}" -name "*.log" 2>/dev/null)
if (( TUNNEL_DISC > 5 )); then
  fail "BUG-R1: tunnel disconnect events: ${TUNNEL_DISC}"
  ISSUES+=("BUG-R1: Repeated tunnel disconnects")
  BUG_R1="DETECTED"
else
  ok "BUG-R1: No significant tunnel disconnect events (count=${TUNNEL_DISC})"
  BUG_R1="CLEAR"
fi

section "BUG-R2: CVE-2023-22651 — webhook 0 rules after upgrade (v2.7.2 only):"
if [[ "$RANCHER_VERSION" == *"v2.7.2"* ]]; then
  warn "BUG-R2: Running v2.7.2 — verify webhook rule count"
  info "  Run: kubectl get validatingwebhookconfigurations rancher.cattle.io"
  BUG_R2="WARN"
else
  ok "BUG-R2: Not v2.7.2 — not applicable"
  BUG_R2="N/A"
fi

section "BUG-R3: Dirty helm2 release data — cluster-agent panic:"
HELM2_PANIC=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "slice bounds out of range\|panic.*helm\|runtime error.*slice" "$f" 2>/dev/null || echo "0")
  HELM2_PANIC=$(( HELM2_PANIC + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-cluster-agent*" -name "*.log" 2>/dev/null)
if (( HELM2_PANIC > 0 )); then
  fail "BUG-R3: cluster-agent helm2 panic: ${HELM2_PANIC}"
  ISSUES+=("BUG-R3: cluster-agent panic — dirty helm2 data")
  BUG_R3="DETECTED"
else
  ok "BUG-R3: No helm2 dirty data panic"
  BUG_R3="CLEAR"
fi

section "BUG-R4: rancher-webhook context deadline — resource operations blocked:"
WEBHOOK_CDX=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "failed calling webhook.*rancher.cattle.io\|webhook.*context deadline exceeded\|Post.*rancher-webhook.*deadline" \
    "$f" 2>/dev/null || echo "0")
  WEBHOOK_CDX=$(( WEBHOOK_CDX + C ))
done < <(find "${PODS_DIR:-/dev/null}" -name "*.log" 2>/dev/null)
if (( WEBHOOK_CDX > 0 )); then
  fail "BUG-R4: webhook deadline exceeded: ${WEBHOOK_CDX}"
  ISSUES+=("BUG-R4: rancher-webhook blocking API operations")
  BUG_R4="DETECTED"
  find "${PODS_DIR:-/dev/null}" -name "*.log" 2>/dev/null | \
    xargs sgrep -i "failed calling webhook.*rancher.cattle.io" 2>/dev/null | tail -3 | \
    while IFS= read -r line; do echo "    ${line:0:160}"; done
else
  ok "BUG-R4: No webhook context deadline errors"
  BUG_R4="CLEAR"
fi

section "BUG-R5: agent-tls-mode strict CA provisioning error:"
if (( STRICT_CA > 0 )); then
  fail "BUG-R5: Strict CA verification failure — ${STRICT_CA} occurrence(s)"
  BUG_R5="DETECTED"
else
  ok "BUG-R5: No strict CA errors"
  BUG_R5="CLEAR"
fi

section "BUG-R6: Fleet gitjob OOMKilled:"
FLEET_OOM=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "OOMKilled\|signal: killed\|exit code 137" "$f" 2>/dev/null || echo "0")
  FLEET_OOM=$(( FLEET_OOM + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*fleet*gitjob*" -name "*.log" 2>/dev/null)
if (( FLEET_OOM > 0 )); then
  warn "BUG-R6: Fleet gitjob OOMKilled: ${FLEET_OOM}"
  BUG_R6="DETECTED"
else
  ok "BUG-R6: No Fleet gitjob OOM events"
  BUG_R6="CLEAR"
fi

section "BUG-R7: CAPI provisioning cluster stuck:"
PROV_STUCK=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "provisioning.*timeout\|cluster.*stuck\|Machine.*not found\|failed to get kubeconfig" \
    "$f" 2>/dev/null || echo "0")
  PROV_STUCK=$(( PROV_STUCK + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-provisioning-capi*" -name "*.log" 2>/dev/null)
if (( PROV_STUCK > 0 )); then
  warn "BUG-R7: Provisioning issues: ${PROV_STUCK} occurrence(s)"
  BUG_R7="DETECTED"
else
  ok "BUG-R7: No CAPI provisioning issues"
  BUG_K7="CLEAR"
fi

# ── 11. Known RKE2/k3s Bug Signatures ────────────────────────
banner "11 / Known RKE2 / k3s Bug Signatures"

section "BUG-K1: Flannel/Canal MASQUERADE missing — pod egress broken:"
if [[ -f "${NETWORKING}/iptablessave" ]]; then
  FLANNEL_MASQ=$(sgrep -c "FLANNEL-POSTRTG\|flannel.*MASQUERADE\|MASQUERADE.*flannel" \
    "${NETWORKING}/iptablessave" 2>/dev/null || echo "0")
  FLANNEL_MASQ=$(safe_int "$FLANNEL_MASQ")
  if (( FLANNEL_MASQ == 0 )); then
    warn "BUG-K1: No Flannel MASQUERADE rules found"
    BUG_K1="DETECTED"
  else
    ok "BUG-K1: Flannel MASQUERADE rules present"
    BUG_K1="CLEAR"
  fi
else
  info "BUG-K1: iptablessave not available — skipped"
  BUG_K1="SKIP"
fi

section "BUG-K2: etcd snapshot restore failure:"
SNAPSHOT_ERR=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "restore.*failed\|snapshot.*corrupt\|etcd.*restore.*error" "$f" 2>/dev/null || echo "0")
  SNAPSHOT_ERR=$(( SNAPSHOT_ERR + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( SNAPSHOT_ERR > 0 )); then
  fail "BUG-K2: etcd snapshot restore errors: ${SNAPSHOT_ERR}"
  ISSUES+=("BUG-K2: etcd snapshot restore failure")
  BUG_K2="DETECTED"
else
  ok "BUG-K2: No snapshot restore errors"
  BUG_K2="CLEAR"
fi

section "BUG-K3: kube-proxy conntrack drops:"
CONNTRACK_DROP=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "Failed to delete stale service\|failed to sync.*conntrack\|dropping packet" \
    "$f" 2>/dev/null || echo "0")
  CONNTRACK_DROP=$(( CONNTRACK_DROP + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -path "*kube-proxy*" -name "*.log" 2>/dev/null)
if (( CONNTRACK_DROP > 0 )); then
  warn "BUG-K3: kube-proxy conntrack issues: ${CONNTRACK_DROP}"
  BUG_K3="DETECTED"
else
  ok "BUG-K3: No kube-proxy conntrack issues"
  BUG_K3="CLEAR"
fi

section "BUG-K4: kubelet eviction loops — disk pressure:"
EVICTION=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "eviction manager.*threshold\|DiskPressure\|imagefs.*available.*threshold" \
    "$f" 2>/dev/null || echo "0")
  EVICTION=$(( EVICTION + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( EVICTION > 5 )); then
  warn "BUG-K4: kubelet eviction events: ${EVICTION}"
  BUG_K4="DETECTED"
else
  ok "BUG-K4: No excessive kubelet eviction events"
  BUG_K4="CLEAR"
fi

section "BUG-K5: Image pull failures — registry unreachable:"
PULL_FAIL=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "Failed to pull image\|ErrImagePull\|ImagePullBackOff\|failed to get image" \
    "$f" 2>/dev/null || echo "0")
  PULL_FAIL=$(( PULL_FAIL + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( PULL_FAIL > 0 )); then
  warn "BUG-K5: Image pull failures: ${PULL_FAIL}"
  BUG_K5="DETECTED"
else
  ok "BUG-K5: No image pull failures"
  BUG_K5="CLEAR"
fi

section "BUG-K6: Bootstrap token expired — new nodes cannot join:"
CSR_ERR=0
while IFS= read -r f; do
  [[ ! -f "$f" ]] && continue
  C=$(sgrep -c "bootstrap.*token.*expired\|certificate.*bootstrap.*failed\|failed to bootstrap" \
    "$f" 2>/dev/null || echo "0")
  CSR_ERR=$(( CSR_ERR + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( CSR_ERR > 0 )); then
  fail "BUG-K6: Bootstrap token/CSR errors: ${CSR_ERR}"
  ISSUES+=("BUG-K6: Bootstrap token expired")
  BUG_K6="DETECTED"
else
  ok "BUG-K6: No bootstrap token expiry errors"
  BUG_K6="CLEAR"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "  Triage Summary  [${BUNDLE_NAME}]"
echo "════════════════════════════════════════════════════════════════════════════════"

if (( ${#ISSUES[@]} == 0 && ${#WARNINGS[@]} == 0 )); then
  echo ""
  echo "  RESULT: All checks passed — no critical issues or warnings found"
  echo ""
else
  if (( ${#ISSUES[@]} > 0 )); then
    echo ""
    echo "  CRITICAL ISSUES (${#ISSUES[@]}):"
    for i in "${!ISSUES[@]}"; do
      echo "    $((i+1)). ${ISSUES[$i]}"
    done
  fi
  if (( ${#WARNINGS[@]} > 0 )); then
    echo ""
    echo "  WARNINGS (${#WARNINGS[@]}):"
    for i in "${!WARNINGS[@]}"; do
      echo "    $((i+1)). ${WARNINGS[$i]}"
    done
  fi
fi

# ── Bug detection status table ────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "  Bug Detection Status"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
_bug_status() {
  local result="$1"
  case "$result" in
    DETECTED) echo "[DETECTED]" ;;
    CLEAR)    echo "[CLEAR]   " ;;
    WARN)     echo "[WARN]    " ;;
    N/A)      echo "[N/A]     " ;;
    *)        echo "[SKIP]    " ;;
  esac
}
brow() { printf "  | %-6s | %s | %-42s | %-16s |\n" "$1" "$(_bug_status "$2")" "$3" "$4"; }
echo "  +--------+------------+--------------------------------------------+------------------+"
echo "  | ID     | Status     | Description                                | Affects          |"
echo "  +--------+------------+--------------------------------------------+------------------+"
brow "BUG-R1" "$BUG_R1" "Tunnel disconnect — cluster-agent"           "all versions"
brow "BUG-R2" "$BUG_R2" "CVE-2023-22651 webhook 0 rules"              "v2.7.2 upgrade"
brow "BUG-R3" "$BUG_R3" "Helm2 dirty data — cluster-agent panic"      "< v2.6.x"
brow "BUG-R4" "$BUG_R4" "rancher-webhook deadline — API blocked"       "all versions"
brow "BUG-R5" "$BUG_R5" "agent-tls-mode strict CA failure"            "v2.8+"
brow "BUG-R6" "$BUG_R6" "Fleet gitjob OOMKilled"                      "all versions"
brow "BUG-R7" "${BUG_R7:-SKIP}" "CAPI provisioning cluster stuck"             "v2.6+"
echo "  +--------+------------+--------------------------------------------+------------------+"
brow "BUG-K1" "$BUG_K1" "Flannel MASQUERADE missing — pod egress"     "RKE2/k3s"
brow "BUG-K2" "$BUG_K2" "etcd snapshot restore failure"               "RKE2/k3s"
brow "BUG-K3" "$BUG_K3" "kube-proxy conntrack drops"                  "all distros"
brow "BUG-K4" "$BUG_K4" "kubelet eviction loop — disk pressure"       "all distros"
brow "BUG-K5" "$BUG_K5" "Image pull failures — registry unreachable"  "all distros"
brow "BUG-K6" "$BUG_K6" "Bootstrap token expired — node join"         "RKE2/k3s"
echo "  +--------+------------+--------------------------------------------+------------------+"
echo ""
echo "  Status key: [DETECTED] = signature found in logs"
echo "              [CLEAR]    = no matching signature found"
echo "              [WARN]     = possible match or version risk"
echo "              [N/A]      = not applicable to this version/distro"
echo "              [SKIP]     = required file not present in bundle"
echo ""
echo "  Completed at: $(date)"
echo ""