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
  while IFS= read -r line; do [[ -n "$line" ]] && info "  ${line}"; done < "$VERSION_FILE"
fi

RANCHER_VERSION=$(sgrep -r "Rancher version" "${PODS_DIR:-/dev/null}" 2>/dev/null \
  | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[^ "]*' | sort -V | tail -1 || true)
[[ -z "$RANCHER_VERSION" ]] && RANCHER_VERSION=$(sgrep -r "rancher/rancher:" \
  "${DISTRO_DIR:-/dev/null}" 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[^ "]*' \
  | sort -V | tail -1 || true)
info "Rancher version : ${RANCHER_VERSION:-unknown}"

if [[ -f "${SYSINFO}/osrelease" ]]; then
  OS_NAME=$(sgrep "PRETTY_NAME" "${SYSINFO}/osrelease" | cut -d'"' -f2 | head -1 || true)
  info "OS              : ${OS_NAME:-unknown}"
fi
[[ -f "${SYSINFO}/uname" ]] && info "Kernel          : $(cat "${SYSINFO}/uname")"

# CNI detection
CNI="unknown"
if [[ -f "${NETWORKING}/ethtool" ]]; then
  grep -q "flannel"      "${NETWORKING}/ethtool" && CNI="flannel"
  grep -q "vxlan.calico" "${NETWORKING}/ethtool" && CNI="calico"
  grep -q "cilium"       "${NETWORKING}/ethtool" && CNI="cilium"
fi
if [[ "$CNI" == "unknown" && -d "${NETWORKING}/cni" ]]; then
  CNI_CONF=$(find "${NETWORKING}/cni" -name "*.conf" -o -name "*.conflist" 2>/dev/null | head -1 || true)
  [[ -n "$CNI_CONF" ]] && CNI=$(sgrep '"type"' "$CNI_CONF" | grep -oE '"[a-zA-Z_-]+"' \
    | tr -d '"' | head -1 || echo "unknown")
fi
info "CNI             : ${CNI}"

# CSI detection
CSI="unknown"
if [[ -f "${KUBECTL_DIR}/pods" ]]; then
  grep -q "longhorn"   "${KUBECTL_DIR}/pods" && CSI="Longhorn"
  grep -q "csi-nfs"    "${KUBECTL_DIR}/pods" && CSI="${CSI}/NFS"
  grep -q "rook-ceph"  "${KUBECTL_DIR}/pods" && CSI="${CSI}/Ceph"
fi
info "CSI             : ${CSI}"

[[ -f "${SYSINFO}/systemd-detect-virt" ]] && \
  info "Virt type       : $(cat "${SYSINFO}/systemd-detect-virt" 2>/dev/null)"

# ── 1. Node Overview ──────────────────────────────────────────
banner "1 / Node Overview"

if [[ -f "${KUBECTL_DIR}/nodes" ]]; then
  section "Node list:"
  while IFS= read -r line; do
    if echo "$line" | grep -q "NotReady"; then
      echo "  [FAIL] ${line}"
      ISSUES+=("NotReady node: $(echo "$line" | awk '{print $1}')")
    elif echo "$line" | grep -q "Ready"; then
      echo "  [OK]   ${line}"
    else
      echo "  [INFO] ${line}"
    fi
  done < "${KUBECTL_DIR}/nodes"
else
  warn "kubectl/nodes not found in bundle"
fi

if [[ -f "${KUBECTL_DIR}/nodesdescribe" ]]; then
  for pressure in "MemoryPressure:True" "DiskPressure:True" "PIDPressure:True"; do
    KEY="${pressure%%:*}"; VAL="${pressure##*:}"
    COUNT=$(sgrep -c "${KEY}.*${VAL}" "${KUBECTL_DIR}/nodesdescribe" || true)
    (( COUNT > 0 )) && fail "${COUNT} node(s) with ${KEY}" || ok "No ${KEY}"
  done
fi

# ── 2. Certificate Expiry ─────────────────────────────────────
banner "2 / Certificate Expiry"

CERT_FILE="${KUBECTL_DIR}/certificate-check"
if [[ -f "$CERT_FILE" ]]; then
  section "Certificate check output:"
  while IFS= read -r line; do
    if echo "$line" | grep -qiE "expir|invalid|FAILED|error"; then
      fail "  CERT: ${line}"
    elif echo "$line" | grep -qiE "warn|30 day|60 day"; then
      warn "  CERT: ${line}"
    elif echo "$line" | grep -qiE "ok|valid|success"; then
      ok   "  ${line}"
    else
      info "  ${line}"
    fi
  done < "$CERT_FILE"
fi

CERT_ERR_PAT='certificate.*expir\|x509.*expir\|tls.*expir\|certif.*invalid\|certificate has expired\|certificate signed by unknown\|x509: certificate'
CERT_ERRORS=0
while IFS= read -r f; do
  C=$(sgrep -ci "$CERT_ERR_PAT" "$f" || true)
  CERT_ERRORS=$(( CERT_ERRORS + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null | head -100)
if (( CERT_ERRORS > 0 )); then
  fail "Certificate errors in logs: ${CERT_ERRORS} occurrence(s)"
  ISSUES+=("Certificate errors found in logs")
  while IFS= read -r f; do
    sgrep -i "$CERT_ERR_PAT" "$f" | tail -2 | \
      while IFS= read -r line; do echo "    ${line:0:160}"; done
  done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null | head -100)
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
    # Verify USE is a valid integer to prevent crash under set -u if df reports a Stale file handle error ("handle")
    [[ ! "$USE" =~ ^[0-9]+$ ]] && continue
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
    [[ -z "$USE" || "$USE" == "-" || -z "$MOUNT" ]] && continue
    # Verify USE is a valid integer to prevent crash under set -u if df reports a Stale file handle error ("handle")
    [[ ! "$USE" =~ ^[0-9]+$ ]] && continue
    if (( USE >= 90 )); then
      fail "inode CRITICAL ${USE}% — ${MOUNT}"
    elif (( USE >= 80 )); then
      warn "inode WARNING ${USE}% — ${MOUNT}"
    fi
  done < <(sgrep -v tmpfs "${SYSINFO}/dfi" | sgrep -v devtmpfs)
fi

if [[ -f "${SYSINFO}/dmesg" ]]; then
  IO_ERRS=$(sgrep -ci "I/O error\|blk_update_request\|SCSI error\|EXT4-fs error\|XFS.*error" \
    "${SYSINFO}/dmesg" || true)
  (( IO_ERRS > 0 )) && fail "Disk I/O errors in dmesg: ${IO_ERRS}" && \
    ISSUES+=("Disk I/O errors in dmesg") || ok "No disk I/O errors in dmesg"

  OOM_DMESG=$(sgrep -ci "oom_kill\|Out of memory\|Killed process" "${SYSINFO}/dmesg" || true)
  (( OOM_DMESG > 0 )) && fail "OOM events in dmesg: ${OOM_DMESG}" || ok "No OOM events in dmesg"
fi

if [[ -f "${SYSINFO}/iostathx" ]]; then
  HIGH_AWAIT=$(awk 'NR>3 && $10+0 > 20 {print $1, "await=" $10 "ms"}' \
    "${SYSINFO}/iostathx" 2>/dev/null | head -5 || true)
  [[ -n "$HIGH_AWAIT" ]] && warn "High disk await (>20ms):" && \
    echo "$HIGH_AWAIT" | while IFS= read -r line; do info "  ${line}"; done || \
    ok "Disk await times within normal range"
fi

ETCD_SLOW=0
while IFS= read -r f; do
  C=$(sgrep -c "slow fdatasync\|apply entries took too long\|slow linearizable" "$f" 2>/dev/null || true)
  ETCD_SLOW=$(( ETCD_SLOW + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -path "*etcd*" -name "*.log" 2>/dev/null)
(( ETCD_SLOW > 0 )) && fail "etcd slow disk/apply warnings: ${ETCD_SLOW}" && \
  ISSUES+=("etcd slow disk warnings") || ok "No etcd slow disk warnings"

# ── 4. CPU & Memory ───────────────────────────────────────────
banner "4 / CPU & Memory"

if [[ -f "${SYSINFO}/freeh" ]]; then
  section "Memory:"
  cat "${SYSINFO}/freeh" | while IFS= read -r line; do info "  ${line}"; done
  MEM_LINE=$(sgrep "^Mem:" "${SYSINFO}/freeh" || true)
  if [[ -n "$MEM_LINE" ]]; then
    TOTAL=$(echo "$MEM_LINE" | awk '{print $2}' | tr -d 'Gi')
    AVAIL=$(echo "$MEM_LINE" | awk '{print $7}' | tr -d 'Gi')
    if [[ "$TOTAL" =~ ^[0-9.]+$ && "$AVAIL" =~ ^[0-9.]+$ ]]; then
      USED_PCT=$(echo "$TOTAL $AVAIL" | awk '{printf "%d", ($1-$2)/$1*100}')
      (( USED_PCT >= 95 )) && fail "Memory CRITICAL: ${USED_PCT}% used" || \
      (( USED_PCT >= 85 )) && warn "Memory high: ${USED_PCT}% used" || \
        ok "Memory OK: ${USED_PCT}% used"
    fi
  fi
fi

[[ -f "${SYSINFO}/uptime" ]] && info "$(cat "${SYSINFO}/uptime")"

for logfile in "${ROOT}/varlog/syslog" "${ROOT}/varlog/messages"; do
  [[ ! -f "$logfile" ]] && continue
  OOM_SYS=$(sgrep -ci "oom-killer\|Out of memory" "$logfile" || true)
  (( OOM_SYS > 0 )) && fail "OOM killer in $(basename "$logfile"): ${OOM_SYS}" && \
    ISSUES+=("OOM killer events in system log")
done

if [[ -f "${SYSINFO}/top" ]]; then
  section "High CPU processes (>50%):"
  HIGH_CPU=$(tail -n +8 "${SYSINFO}/top" 2>/dev/null | awk '$9+0 > 50 {print}' | head -5 || true)
  if [[ -n "$HIGH_CPU" ]]; then
    echo "$HIGH_CPU" | while IFS= read -r line; do warn "  CPU >50%: ${line:0:120}"; done
  else
    ok "No processes with >50% CPU"
  fi
fi

if [[ -f "${SYSINFO}/file-nr" ]]; then
  FD_USED=$(awk '{print $1}' "${SYSINFO}/file-nr" 2>/dev/null || echo 0)
  FD_MAX=$(awk '{print $3}'  "${SYSINFO}/file-nr" 2>/dev/null || echo 1)
  if [[ "$FD_MAX" =~ ^[0-9]+$ && "$FD_USED" =~ ^[0-9]+$ && "$FD_MAX" -gt 0 ]]; then
    FD_PCT=$(( FD_USED * 100 / FD_MAX ))
    (( FD_PCT >= 80 )) && warn "File descriptors ${FD_PCT}% used (${FD_USED}/${FD_MAX})" || \
      ok "File descriptors ${FD_PCT}% used (${FD_USED}/${FD_MAX})"
  fi
fi

# ── 5. Networking ─────────────────────────────────────────────
banner "5 / Networking"

if [[ -f "${NETWORKING}/iptablessave" ]]; then
  IPT_RULES=$(wc -l < "${NETWORKING}/iptablessave" || true)
  info "iptables rules: ${IPT_RULES} lines"
  (( IPT_RULES > 10000 )) && warn "iptables rule count very high (${IPT_RULES})"
  KUBE_DROPS=$(sgrep -c "KUBE.*REJECT\|DROP.*6443\|DROP.*2379\|DROP.*10250" \
    "${NETWORKING}/iptablessave" || true)
  (( KUBE_DROPS > 0 )) && \
    fail "iptables DROP rules on Kubernetes ports: ${KUBE_DROPS}" || \
    ok "No DROP rules on critical Kubernetes ports"
fi

if [[ -f "${SYSINFO}/dmesg" ]]; then
  CONNTRACK_FULL=$(sgrep -ci "nf_conntrack: table full\|nf_conntrack: falling behind\|conntrack: dropping" \
    "${SYSINFO}/dmesg" || true)
  (( CONNTRACK_FULL > 0 )) && fail "conntrack table full: ${CONNTRACK_FULL} events" && \
    ISSUES+=("conntrack table full") || ok "No conntrack table overflow"
fi

if [[ -f "${SYSINFO}/etcresolvconf" ]]; then
  section "resolv.conf:"
  cat "${SYSINFO}/etcresolvconf" | while IFS= read -r line; do info "  ${line}"; done
  NAMESERVER_COUNT=$(sgrep -c "^nameserver" "${SYSINFO}/etcresolvconf" || true)
  (( NAMESERVER_COUNT == 0 )) && fail "No nameservers in /etc/resolv.conf"
fi

if [[ -f "${SYSINFO}/networkmanager-configs" ]]; then
  NM_MANAGED=$(sgrep -ci "managed=true\|unmanaged=false" \
    "${SYSINFO}/networkmanager-configs" || true)
  (( NM_MANAGED > 0 )) && warn "NetworkManager may be managing k8s interfaces"
fi

CNI_ERRORS=0
for ns in kube-system cattle-system; do
  while IFS= read -r f; do
    C=$(sgrep -ci "level=error\|level=fatal\|FATA\|panic:" "$f" || true)
    CNI_ERRORS=$(( CNI_ERRORS + C ))
  done < <(find "${PODS_DIR:-/dev/null}" -path "*${ns}*" -name "*.log" 2>/dev/null \
    | sgrep -Ei "canal|flannel|calico|cilium|multus" 2>/dev/null || true)
done
(( CNI_ERRORS > 0 )) && warn "CNI component log errors: ${CNI_ERRORS} lines" || \
  ok "No CNI component errors"

# ── 6. etcd Health ────────────────────────────────────────────
banner "6 / etcd Health"

# Portable key|pattern pairs — no associative arrays
ETCD_PATTERN_LIST=(
  "slow_fdatasync|slow fdatasync"
  "heartbeat_failed|failed to send out heartbeat"
  "apply_too_long|apply entries took too long"
  "leader_lost|lost leader\|elected leader"
  "raft_error|raft: failed to\|raft error"
  "snapshot_failed|failed to save snapshot\|snapshot.*failed"
  "compaction_failed|failed to defrag\|compaction.*failed"
  "alarm_nospace|etcd server is running low on space\|mvcc: database space exceeded"
)

ETCD_LOG_FOUND=false
while IFS= read -r f; do
  ETCD_LOG_FOUND=true
  for entry in "${ETCD_PATTERN_LIST[@]}"; do
    key="${entry%%|*}"; pat="${entry#*|}"
    C=$(sgrep -ci "$pat" "$f" || true)
    if (( C > 0 )); then
      case "$key" in
        slow_fdatasync|alarm_nospace|raft_error|heartbeat_failed|apply_too_long)
          fail "etcd [${key}]: ${C} occurrence(s) in $(basename "$f")"
          ISSUES+=("etcd ${key}") ;;
        *)
          warn "etcd [${key}]: ${C} occurrence(s) in $(basename "$f")" ;;
      esac
      sgrep -i "$pat" "$f" | tail -2 | \
        while IFS= read -r line; do echo "    ${line:0:160}"; done
    fi
  done
done < <(find "${DISTRO_DIR:-$ROOT}" -path "*etcd*" -name "*.log" 2>/dev/null | sort)
[[ "$ETCD_LOG_FOUND" == false ]] && info "No etcd log files found in bundle"

# ── 7. Rancher Server & Webhook ───────────────────────────────
banner "7 / Rancher Server & Webhook"

RANCHER_LOG_ERRS=0
while IFS= read -r f; do
  C=$(sgrep -ci 'level=error\|level=fatal\|panic:\|"level":"error"' "$f" || true)
  RANCHER_LOG_ERRS=$(( RANCHER_LOG_ERRS + C ))
  if (( C > 0 )); then
    warn "Rancher errors in $(basename "$(dirname "$f")")/$(basename "$f"): ${C}"
    sgrep -i 'level=error\|level=fatal\|panic:' "$f" | tail -3 | \
      while IFS= read -r line; do echo "    ${line:0:160}"; done
  fi
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-system*rancher*" \
  -name "*.log" 2>/dev/null | sort)
(( RANCHER_LOG_ERRS == 0 )) && ok "No Rancher server errors found"

WEBHOOK_DEAD=0
while IFS= read -r f; do
  C=$(sgrep -ci "rancher-webhook.*context deadline exceeded\|failed to call webhook.*rancher\|webhook.*timeout" \
    "$f" || true)
  WEBHOOK_DEAD=$(( WEBHOOK_DEAD + C ))
done < <(find "${PODS_DIR:-/dev/null}" \
  \( -path "*cattle-system*" -o -path "*rancher*" \) -name "*.log" 2>/dev/null)
(( WEBHOOK_DEAD > 0 )) && \
  fail "rancher-webhook timeout/deadline: ${WEBHOOK_DEAD} occurrence(s)" && \
  ISSUES+=("rancher-webhook unresponsive") || ok "No rancher-webhook timeout errors"

if [[ -f "${KUBECTL_DIR}/validatingwebhookconfigurations" ]]; then
  WEBHOOK_RULES=$(sgrep -A5 "name: rancher.cattle.io" \
    "${KUBECTL_DIR}/validatingwebhookconfigurations" | \
    sgrep -c "rules:\|webhooks:" || true)
  (( WEBHOOK_RULES == 0 )) && \
    fail "rancher.cattle.io ValidatingWebhookConfiguration has 0 rules (CVE-2023-22651 indicator)" && \
    ISSUES+=("Webhook misconfiguration: 0 rules") || \
    ok "rancher.cattle.io webhook rules present"
fi

# ── 8. cattle-cluster-agent & Fleet ───────────────────────────
banner "8 / cattle-cluster-agent & Fleet"

AGENT_PAT='level=error\|tunnel disconnect\|cluster agent disconnected\|failed to connect\|websocket.*closed\|connection.*refused'
AGENT_ERRORS=0
while IFS= read -r f; do
  C=$(sgrep -ci "$AGENT_PAT" "$f" || true)
  AGENT_ERRORS=$(( AGENT_ERRORS + C ))
  if (( C > 0 )); then
    fail "cattle-cluster-agent errors in $(basename "$(dirname "$f")"): ${C}"
    sgrep -i "$AGENT_PAT" "$f" | tail -3 | \
      while IFS= read -r line; do echo "    ${line:0:160}"; done
  fi
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-cluster-agent*" \
  -name "*.log" 2>/dev/null | sort)
(( AGENT_ERRORS == 0 )) && ok "No cattle-cluster-agent connectivity errors"

STRICT_CA=0
while IFS= read -r f; do
  C=$(sgrep -ci "Strict CA verification.*error\|unable to read CA file\|no such file.*serverca" \
    "$f" || true)
  STRICT_CA=$(( STRICT_CA + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle*" -name "*.log" 2>/dev/null)
(( STRICT_CA > 0 )) && \
  fail "Strict CA error: ${STRICT_CA} hit(s) — check agent-tls-mode setting" && \
  ISSUES+=("Strict CA verification error") || ok "No strict CA verification errors"

FLEET_ERRORS=0
while IFS= read -r f; do
  C=$(sgrep -ci 'level=error\|"level":"error"\|reconciler error' "$f" || true)
  FLEET_ERRORS=$(( FLEET_ERRORS + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*fleet*" -name "*.log" 2>/dev/null)
(( FLEET_ERRORS > 0 )) && warn "Fleet log errors: ${FLEET_ERRORS} lines" || \
  ok "No Fleet log errors"

# ── 9. Pod Health ─────────────────────────────────────────────
banner "9 / Pod Health (All Namespaces)"

if [[ -f "${KUBECTL_DIR}/pods" ]]; then
  TOTAL_PODS=$(sgrep -v "^NAMESPACE\|^$" "${KUBECTL_DIR}/pods" | wc -l || true)
  RUNNING=$(sgrep  -c "Running"                              "${KUBECTL_DIR}/pods" || true)
  PENDING=$(sgrep  -c "Pending"                              "${KUBECTL_DIR}/pods" || true)
  FAILED=$(sgrep   -c "Failed\|OOMKilled\|CrashLoopBackOff"  "${KUBECTL_DIR}/pods" || true)
  COMPLETED=$(sgrep -c "Completed"                           "${KUBECTL_DIR}/pods" || true)

  info "Pods: total=${TOTAL_PODS}  running=${RUNNING}  pending=${PENDING}  failed/crash=${FAILED}  completed=${COMPLETED}"

  if (( PENDING > 0 )); then
    fail "Pending pods: ${PENDING}"
    sgrep "Pending" "${KUBECTL_DIR}/pods" | while IFS= read -r line; do echo "    ${line}"; done
    ISSUES+=("${PENDING} Pending pod(s)")
  else
    ok "No Pending pods"
  fi

  if (( FAILED > 0 )); then
    fail "Failed/CrashLoop pods: ${FAILED}"
    sgrep "Failed\|OOMKilled\|CrashLoopBackOff" "${KUBECTL_DIR}/pods" | \
      while IFS= read -r line; do echo "    ${line}"; done
    ISSUES+=("${FAILED} Failed/CrashLoop pod(s)")
  else
    ok "No Failed/CrashLoop pods"
  fi
fi

for ns in kube-system cattle-system cattle-fleet-system; do
  CRASH_COUNT=0
  while IFS= read -r f; do
    C=$(sgrep -ci "panic:\|fatal error\|OOMKilled\|CrashLoopBackOff" "$f" || true)
    CRASH_COUNT=$(( CRASH_COUNT + C ))
  done < <(find "${PODS_DIR:-/dev/null}" -path "*${ns}*" -name "*.log" 2>/dev/null)
  (( CRASH_COUNT > 0 )) && warn "${ns}: ${CRASH_COUNT} panic/OOM/crash lines" || true
done

# ══════════════════════════════════════════════════════════════
# Bug detection — each sets its BUG_Xn variable for the table
# ══════════════════════════════════════════════════════════════

# ── 10. Known Rancher Bug Signatures ─────────────────────────
banner "10 / Known Rancher Bug Signatures"

section "BUG-R1: Tunnel disconnect — cluster-agent instability:"
TUNNEL_DISC=0
while IFS= read -r f; do
  C=$(sgrep -c "tunnel disconnect\|watch.*ended.*tunnel disconnect" "$f" 2>/dev/null || true)
  TUNNEL_DISC=$(( TUNNEL_DISC + C ))
done < <(find "${PODS_DIR:-/dev/null}" -name "*.log" 2>/dev/null)
if (( TUNNEL_DISC > 5 )); then
  fail "BUG-R1: tunnel disconnect events: ${TUNNEL_DISC}"
  ISSUES+=("BUG-R1: Repeated tunnel disconnects"); BUG_R1="DETECTED"
else
  ok "BUG-R1: No significant tunnel disconnect events (count=${TUNNEL_DISC})"; BUG_R1="CLEAR"
fi

section "BUG-R2: CVE-2023-22651 — webhook 0 rules after upgrade (v2.7.2 only):"
if echo "${RANCHER_VERSION}" | grep -q "v2\.7\.2"; then
  warn "BUG-R2: Running v2.7.2 — verify webhook rule count"
  info "  Run: kubectl get validatingwebhookconfigurations rancher.cattle.io"
  BUG_R2="WARN"
else
  ok "BUG-R2: Not v2.7.2 — not applicable"; BUG_R2="N/A"
fi

section "BUG-R3: Dirty helm2 release data — cluster-agent panic:"
HELM2_PANIC=0
while IFS= read -r f; do
  C=$(sgrep -c "slice bounds out of range\|panic.*helm\|runtime error.*slice" "$f" 2>/dev/null || true)
  HELM2_PANIC=$(( HELM2_PANIC + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-cluster-agent*" -name "*.log" 2>/dev/null)
if (( HELM2_PANIC > 0 )); then
  fail "BUG-R3: cluster-agent helm2 panic: ${HELM2_PANIC}"; BUG_R3="DETECTED"
  ISSUES+=("BUG-R3: cluster-agent panic — dirty helm2 data")
else
  ok "BUG-R3: No helm2 dirty data panic"; BUG_R3="CLEAR"
fi

section "BUG-R4: rancher-webhook context deadline — resource operations blocked:"
WEBHOOK_CDX=0
while IFS= read -r f; do
  C=$(sgrep -c "failed calling webhook.*rancher.cattle.io\|webhook.*context deadline exceeded\|Post.*rancher-webhook.*deadline" \
    "$f" 2>/dev/null || true)
  WEBHOOK_CDX=$(( WEBHOOK_CDX + C ))
done < <(find "${PODS_DIR:-/dev/null}" -name "*.log" 2>/dev/null)
if (( WEBHOOK_CDX > 0 )); then
  fail "BUG-R4: webhook deadline exceeded: ${WEBHOOK_CDX}"; BUG_R4="DETECTED"
  ISSUES+=("BUG-R4: rancher-webhook blocking API operations")
  find "${PODS_DIR:-/dev/null}" -name "*.log" 2>/dev/null | \
    xargs sgrep -i "failed calling webhook.*rancher.cattle.io" 2>/dev/null | tail -3 | \
    while IFS= read -r line; do echo "    ${line:0:160}"; done
else
  ok "BUG-R4: No webhook context deadline errors"; BUG_R4="CLEAR"
fi

section "BUG-R5: agent-tls-mode strict CA provisioning error:"
if (( STRICT_CA > 0 )); then
  fail "BUG-R5: Strict CA verification failure — ${STRICT_CA} occurrence(s)"; BUG_R5="DETECTED"
else
  ok "BUG-R5: No strict CA errors"; BUG_R5="CLEAR"
fi

section "BUG-R6: Fleet gitjob OOMKilled:"
FLEET_OOM=0
while IFS= read -r f; do
  C=$(sgrep -c "OOMKilled\|signal: killed\|exit code 137" "$f" 2>/dev/null || true)
  FLEET_OOM=$(( FLEET_OOM + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*fleet*gitjob*" -name "*.log" 2>/dev/null)
if (( FLEET_OOM > 0 )); then
  warn "BUG-R6: Fleet gitjob OOMKilled: ${FLEET_OOM}"; BUG_R6="DETECTED"
else
  ok "BUG-R6: No Fleet gitjob OOM events"; BUG_R6="CLEAR"
fi

section "BUG-R7: CAPI provisioning cluster stuck:"
PROV_STUCK=0
while IFS= read -r f; do
  C=$(sgrep -c "provisioning.*timeout\|cluster.*stuck\|Machine.*not found\|failed to get kubeconfig" \
    "$f" 2>/dev/null || true)
  PROV_STUCK=$(( PROV_STUCK + C ))
done < <(find "${PODS_DIR:-/dev/null}" -path "*cattle-provisioning-capi*" -name "*.log" 2>/dev/null)
if (( PROV_STUCK > 0 )); then
  warn "BUG-R7: Provisioning issues: ${PROV_STUCK} occurrence(s)"; BUG_R7="DETECTED"
else
  ok "BUG-R7: No CAPI provisioning issues"; BUG_R7="CLEAR"
fi

# ── 11. Known RKE2/k3s Bug Signatures ────────────────────────
banner "11 / Known RKE2 / k3s Bug Signatures"

section "BUG-K1: Flannel/Canal MASQUERADE missing — pod egress broken:"
if [[ -f "${NETWORKING}/iptablessave" ]]; then
  FLANNEL_MASQ=$(sgrep -c "FLANNEL-POSTRTG\|flannel.*MASQUERADE\|MASQUERADE.*flannel" \
    "${NETWORKING}/iptablessave" || true)
  if (( FLANNEL_MASQ == 0 )); then
    warn "BUG-K1: No Flannel MASQUERADE rules found"; BUG_K1="DETECTED"
  else
    ok "BUG-K1: Flannel MASQUERADE rules present"; BUG_K1="CLEAR"
  fi
else
  info "BUG-K1: iptablessave not available — skipped"; BUG_K1="SKIP"
fi

section "BUG-K2: etcd snapshot restore failure:"
SNAPSHOT_ERR=0
while IFS= read -r f; do
  C=$(sgrep -c "restore.*failed\|snapshot.*corrupt\|etcd.*restore.*error" "$f" 2>/dev/null || true)
  SNAPSHOT_ERR=$(( SNAPSHOT_ERR + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( SNAPSHOT_ERR > 0 )); then
  fail "BUG-K2: etcd snapshot restore errors: ${SNAPSHOT_ERR}"; BUG_K2="DETECTED"
  ISSUES+=("BUG-K2: etcd snapshot restore failure")
else
  ok "BUG-K2: No snapshot restore errors"; BUG_K2="CLEAR"
fi

section "BUG-K3: kube-proxy conntrack drops:"
CONNTRACK_DROP=0
while IFS= read -r f; do
  C=$(sgrep -c "Failed to delete stale service\|failed to sync.*conntrack\|dropping packet" \
    "$f" 2>/dev/null || true)
  CONNTRACK_DROP=$(( CONNTRACK_DROP + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -path "*kube-proxy*" -name "*.log" 2>/dev/null)
if (( CONNTRACK_DROP > 0 )); then
  warn "BUG-K3: kube-proxy conntrack issues: ${CONNTRACK_DROP}"; BUG_K3="DETECTED"
else
  ok "BUG-K3: No kube-proxy conntrack issues"; BUG_K3="CLEAR"
fi

section "BUG-K4: kubelet eviction loops — disk pressure:"
EVICTION=0
while IFS= read -r f; do
  C=$(sgrep -c "eviction manager.*threshold\|DiskPressure\|imagefs.*available.*threshold" \
    "$f" 2>/dev/null || true)
  EVICTION=$(( EVICTION + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( EVICTION > 5 )); then
  warn "BUG-K4: kubelet eviction events: ${EVICTION}"; BUG_K4="DETECTED"
else
  ok "BUG-K4: No excessive kubelet eviction events"; BUG_K4="CLEAR"
fi

section "BUG-K5: Image pull failures — registry unreachable:"
PULL_FAIL=0
while IFS= read -r f; do
  C=$(sgrep -c "Failed to pull image\|ErrImagePull\|ImagePullBackOff\|failed to get image" \
    "$f" 2>/dev/null || true)
  PULL_FAIL=$(( PULL_FAIL + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( PULL_FAIL > 0 )); then
  warn "BUG-K5: Image pull failures: ${PULL_FAIL}"; BUG_K5="DETECTED"
else
  ok "BUG-K5: No image pull failures"; BUG_K5="CLEAR"
fi

section "BUG-K6: Bootstrap token expired — new nodes cannot join:"
CSR_ERR=0
while IFS= read -r f; do
  C=$(sgrep -c "bootstrap.*token.*expired\|certificate.*bootstrap.*failed\|failed to bootstrap" \
    "$f" 2>/dev/null || true)
  CSR_ERR=$(( CSR_ERR + C ))
done < <(find "${DISTRO_DIR:-$ROOT}" -name "*.log" 2>/dev/null)
if (( CSR_ERR > 0 )); then
  fail "BUG-K6: Bootstrap token/CSR errors: ${CSR_ERR}"; BUG_K6="DETECTED"
  ISSUES+=("BUG-K6: Bootstrap token expired")
else
  ok "BUG-K6: No bootstrap token expiry errors"; BUG_K6="CLEAR"
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
brow "BUG-R7" "$BUG_R7" "CAPI provisioning cluster stuck"             "v2.6+"
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
