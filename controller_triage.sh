#!/usr/bin/env bash
# ============================================================
#  k8s-triage.sh — Kubernetes Emergency Triage Script
#  Quick root-cause diagnosis: ports, connectivity, etcd disk I/O, filesystem
# ============================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────
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
ETCD_LATENCY_WARN_MS=100   # etcd fio benchmark threshold (ms)
FS_FULL_WARN=85

ISSUES=()
WARNINGS=()

# ── RKE2 Environment Bootstrap ───────────────────────────────
# Prepend RKE2 bin dir so crictl/etcdctl/kubectl are available
export CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml
PATH="/var/lib/rancher/rke2/bin:$PATH"

ETCD_CERT=/var/lib/rancher/rke2/server/tls/etcd/server-client.crt
ETCD_KEY=/var/lib/rancher/rke2/server/tls/etcd/server-client.key
ETCD_CACERT=/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt

# Discover the running etcd container and build the full endpoints list
RKE2_ETCD_READY=false
if command -v crictl &>/dev/null && [[ -f "$ETCD_CERT" && -f "$ETCD_KEY" && -f "$ETCD_CACERT" ]]; then
  etcdcontainer=$(crictl ps --label io.kubernetes.container.name=etcd --quiet 2>/dev/null | head -1 || true)
  if [[ -n "$etcdcontainer" ]]; then
    ETCDCTL_ENDPOINTS=$(crictl exec "${etcdcontainer}" \
      etcdctl --cert "${ETCD_CERT}" --key "${ETCD_KEY}" --cacert "${ETCD_CACERT}" \
      member list 2>/dev/null \
      | cut -d, -f5 | sed -e 's/ //g' | paste -sd ',' || true)
    if [[ -n "$ETCDCTL_ENDPOINTS" ]]; then
      export ETCDCTL_ENDPOINTS
      export ETCDCTL_CACERT="$ETCD_CACERT"
      export ETCDCTL_CERT="$ETCD_CERT"
      export ETCDCTL_KEY="$ETCD_KEY"
      export ETCDCTL_API=3
      RKE2_ETCD_READY=true
    fi
  fi
fi

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

DISTRO="unknown"
if check_cmd kubectl; then
  ok "kubectl found"
else
  warn "kubectl not found — some checks will be skipped"
fi

if [[ -f /etc/os-release ]]; then
  DISTRO=$(. /etc/os-release && echo "${ID:-unknown}")
  info "OS:       $(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
fi

info "Hostname: $(hostname)"
info "Uptime:   $(uptime -p 2>/dev/null || uptime)"
info "Time:     $(date)"

# ── 1. Filesystem / Disk Usage ───────────────────────────────
banner "1 / Filesystem & Disk Usage"

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

# ── 2. etcd Disk I/O Latency ─────────────────────────────────
banner "2 / etcd Disk I/O Latency"

ETCD_DATA_DIR=""
for d in /var/lib/etcd /var/lib/rancher/rke2/server/db/etcd \
          /var/lib/k0s/etcd /var/lib/microshift/data/etcd; do
  if [[ -d "$d" ]]; then
    ETCD_DATA_DIR="$d"
    break
  fi
done

if [[ -z "$ETCD_DATA_DIR" ]]; then
  ETCD_DATA_DIR=$(ps aux 2>/dev/null \
    | grep -oP '(?<=--data-dir=)\S+' | head -1 || true)
fi

if [[ -z "$ETCD_DATA_DIR" ]]; then
  warn "Could not locate etcd data directory — skipping disk I/O check"
else
  info "etcd data dir: ${ETCD_DATA_DIR}"

  if check_cmd fio; then
    info "Measuring fsync latency with fio (3s)..."
    FIO_OUTPUT=$(fio --rw=write --ioengine=sync --fdatasync=1 \
      --directory="${ETCD_DATA_DIR}" --size=22m --bs=2300 \
      --name=etcd-fsync-test --runtime=3 --time_based \
      --output-format=terse 2>/dev/null || true)
    # terse format: field 49 = fsync 99th percentile (ns)
    FSYNC_99=$(echo "$FIO_OUTPUT" | awk -F';' '{print $49}' | head -1)
    if [[ -n "$FSYNC_99" && "$FSYNC_99" =~ ^[0-9]+$ ]]; then
      FSYNC_MS=$(( FSYNC_99 / 1000000 ))
      if (( FSYNC_MS > 10 )); then
        fail "etcd fsync p99 ${FSYNC_MS}ms — exceeds 10ms recommended threshold (slow disk or I/O contention)"
      else
        ok "etcd fsync p99 ${FSYNC_MS}ms (recommended <10ms)"
      fi
    else
      warn "Could not parse fio output — manual check required"
    fi
    rm -f "${ETCD_DATA_DIR}"/etcd-fsync-test.* 2>/dev/null || true
  else
    # fallback to dd
    info "fio not found — using dd for write speed estimate..."
    TMPF="${ETCD_DATA_DIR}/.triage_dd_$$"
    DD_RESULT=$(dd if=/dev/zero of="$TMPF" bs=4k count=1024 \
      conv=fdatasync 2>&1 | tail -1 || true)
    rm -f "$TMPF" 2>/dev/null || true
    info "dd result: ${DD_RESULT}"
    SPEED=$(echo "$DD_RESULT" | grep -oP '[\d.]+ [MG]B/s' | head -1 || true)
    if [[ -n "$SPEED" ]]; then
      info "Disk write speed: ${SPEED}"
      SPEED_NUM=$(echo "$SPEED" | grep -oP '[\d.]+' | head -1)
      UNIT=$(echo "$SPEED" | grep -oP '[MG]B/s' | head -1)
      if [[ "$UNIT" == "MB/s" ]]; then
        if (( $(echo "$SPEED_NUM < 50" | bc -l 2>/dev/null || echo 0) )); then
          warn "Disk write speed low: ${SPEED} (etcd recommends 50MB/s+)"
        else
          ok "Disk write speed: ${SPEED}"
        fi
      fi
    fi
  fi

  WAL_COUNT=$(find "${ETCD_DATA_DIR}" -name "*.wal" 2>/dev/null | wc -l)
  info "etcd WAL file count: ${WAL_COUNT}"
fi

# ── 3. Required Kubernetes Port Checks ───────────────────────
banner "3 / Required Port Listening Check"

declare -A K8S_PORTS=(
  ["2379"]="etcd client"
  ["2380"]="etcd peer"
  ["6443"]="kube-apiserver"
  ["10250"]="kubelet"
  ["10251"]="kube-scheduler (deprecated)"
  ["10252"]="kube-controller-manager (deprecated)"
  ["10255"]="kubelet read-only"
  ["10257"]="kube-controller-manager"
  ["10259"]="kube-scheduler"
)

declare -A RKE2_PORTS=(
  ["9345"]="RKE2 supervisor"
  ["8472"]="Flannel VXLAN (UDP)"
  ["51820"]="WireGuard IPv4"
  ["51821"]="WireGuard IPv6"
)

check_port_listening() {
  local port="$1"
  if check_cmd ss; then
    ss -tlnp 2>/dev/null | grep -q ":${port}\b"
  elif check_cmd netstat; then
    netstat -tlnp 2>/dev/null | grep -q ":${port}\b"
  else
    printf '%04X' "$port" | grep -qi "$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '{print $2}' | cut -d: -f2)"
  fi
}

for port in "${!K8S_PORTS[@]}"; do
  svc="${K8S_PORTS[$port]}"
  if check_port_listening "$port"; then
    ok "Port ${port} listening — ${svc}"
  else
    case "$port" in
      2379|2380|6443|10250)
        fail "Port ${port} NOT listening — ${svc}" ;;
      *)
        info "Port ${port} not in use — ${svc}" ;;
    esac
  fi
done

echo ""
info "RKE2/k3s ports:"
for port in "${!RKE2_PORTS[@]}"; do
  svc="${RKE2_PORTS[$port]}"
  if check_port_listening "$port"; then
    ok "Port ${port} listening — ${svc}"
  else
    info "Port ${port} not in use — ${svc}"
  fi
done

# ── 4. Network Connectivity ───────────────────────────────────
banner "4 / Network Connectivity"

APISERVER_URL="https://127.0.0.1:6443"

# RKE2 apiserver TLS certs for authenticated health check
RKE2_API_CACERT="/var/lib/rancher/rke2/server/tls/server-ca.crt"
RKE2_API_CLIENT_CERT="/var/lib/rancher/rke2/server/tls/client-admin.crt"
RKE2_API_CLIENT_KEY="/var/lib/rancher/rke2/server/tls/client-admin.key"

if check_cmd curl; then
  # First: try unauthenticated to confirm apiserver is reachable at all
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 "${APISERVER_URL}/healthz" 2>/dev/null || echo "ERR")

  case "$HTTP_CODE" in
    200)
      ok "kube-apiserver /healthz: HTTP 200 OK"
      ;;
    401|403)
      # Apiserver is up but needs auth — try again with RKE2 client certs
      if [[ -f "$RKE2_API_CACERT" && -f "$RKE2_API_CLIENT_CERT" && -f "$RKE2_API_CLIENT_KEY" ]]; then
        AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
          --cacert  "$RKE2_API_CACERT" \
          --cert    "$RKE2_API_CLIENT_CERT" \
          --key     "$RKE2_API_CLIENT_KEY" \
          --max-time 5 "${APISERVER_URL}/healthz" 2>/dev/null || echo "ERR")
        if [[ "$AUTH_CODE" == "200" ]]; then
          ok "kube-apiserver /healthz: HTTP 200 OK (authenticated)"
        else
          warn "kube-apiserver /healthz: HTTP ${AUTH_CODE} with client cert (expected 200)"
        fi
      elif check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
        # Fallback: use kubectl which already has a valid kubeconfig
        LIVEZ=$(kubectl get --raw /healthz 2>/dev/null || echo "ERR")
        if [[ "$LIVEZ" == "ok" ]]; then
          ok "kube-apiserver /healthz: OK (via kubectl)"
        else
          warn "kube-apiserver /healthz returned: ${LIVEZ}"
        fi
      else
        warn "kube-apiserver reachable but returned HTTP ${HTTP_CODE} — no client certs available for authenticated check"
      fi
      ;;
    ERR|000)
      fail "kube-apiserver /healthz unreachable — no response (is apiserver running?)"
      ;;
    *)
      fail "kube-apiserver /healthz unexpected response: HTTP ${HTTP_CODE}"
      ;;
  esac
else
  warn "curl not found — skipping apiserver connectivity test"
fi

ETCD_HEALTH_URL="https://127.0.0.1:2379/health"
ETCD_CERT_DIRS=(
  "/etc/kubernetes/pki/etcd"
  "/var/lib/rancher/rke2/server/tls/etcd"
  "/etc/etcd"
)
ETCD_CERT_DIR=""
for d in "${ETCD_CERT_DIRS[@]}"; do
  if [[ -d "$d" ]]; then ETCD_CERT_DIR="$d"; break; fi
done

ETCD_CHECKED=false

# Method 1: crictl exec into etcd container (RKE2 primary path)
if [[ "$RKE2_ETCD_READY" == true ]]; then
  info "etcd container: ${etcdcontainer}"
  info "etcd endpoints: ${ETCDCTL_ENDPOINTS}"

  # helper: run etcdctl inside the etcd container
  _etcdctl() {
    crictl exec "${etcdcontainer}" \
      etcdctl --cert "${ETCD_CERT}" --key "${ETCD_KEY}" --cacert "${ETCD_CACERT}" \
      --endpoints "${ETCDCTL_ENDPOINTS}" "$@"
  }

  # ── endpoint health ──────────────────────────────────────
  echo ""
  info "[ etcd endpoint health ]"
  HEALTH_OUT=$(_etcdctl endpoint health --write-out=table 2>&1 || true)
  if echo "$HEALTH_OUT" | grep -q "false"; then
    fail "One or more etcd endpoints unhealthy"
  else
    ok "All etcd endpoints healthy"
  fi
  echo "$HEALTH_OUT" | while IFS= read -r line; do info "  ${line}"; done

  # ── endpoint status ──────────────────────────────────────
  echo ""
  info "[ etcd endpoint status ]"
  _etcdctl endpoint status --write-out=table 2>/dev/null \
    | while IFS= read -r line; do info "  ${line}"; done || true

  # ── member list ──────────────────────────────────────────
  echo ""
  info "[ etcd member list ]"
  _etcdctl member list --write-out=table 2>/dev/null \
    | while IFS= read -r line; do info "  ${line}"; done || true

  # ── alarm list ───────────────────────────────────────────
  echo ""
  info "[ etcd alarm list ]"
  ALARM_OUT=$(_etcdctl alarm list 2>/dev/null || true)
  if [[ -z "$ALARM_OUT" ]]; then
    ok "No etcd alarms"
  else
    fail "etcd alarms active:"
    echo "$ALARM_OUT" | while IFS= read -r line; do
      echo -e "    ${RED}${line}${NC}"
    done
  fi

  # ── check perf ───────────────────────────────────────────
  echo ""
  info "[ etcd check perf ] (this may take ~30s)"
  PERF_OUT=$(_etcdctl check perf 2>&1 || true)
  if echo "$PERF_OUT" | grep -qi "fail\|FAIL"; then
    fail "etcd performance check FAILED"
    echo "$PERF_OUT" | while IFS= read -r line; do
      echo -e "    ${RED}${line}${NC}"
    done
  else
    ok "etcd performance check passed"
    echo "$PERF_OUT" | while IFS= read -r line; do info "  ${line}"; done
  fi

  ETCD_CHECKED=true
fi

# Method 2: curl with TLS certs (kubeadm / vanilla k8s fallback)
if [[ "$ETCD_CHECKED" == false ]] && check_cmd curl && \
    [[ -n "$ETCD_CERT_DIR" && \
       -f "${ETCD_CERT_DIR}/ca.crt" && \
       -f "${ETCD_CERT_DIR}/healthcheck-client.crt" && \
       -f "${ETCD_CERT_DIR}/healthcheck-client.key" ]]; then
  info "etcd health check via curl+TLS (${ETCD_CERT_DIR})"
  ETCD_RESP=$(curl -sk \
    --cacert "${ETCD_CERT_DIR}/ca.crt" \
    --cert   "${ETCD_CERT_DIR}/healthcheck-client.crt" \
    --key    "${ETCD_CERT_DIR}/healthcheck-client.key" \
    --max-time 5 "${ETCD_HEALTH_URL}" 2>/dev/null || echo "ERR")
  if echo "$ETCD_RESP" | grep -q '"health":"true"'; then
    ok "etcd health check passed (curl+TLS)"
  else
    fail "etcd health check FAILED (curl+TLS): ${ETCD_RESP}"
  fi
  ETCD_CHECKED=true
fi

# Method 3: kubectl get --raw /healthz (last resort via apiserver)
if [[ "$ETCD_CHECKED" == false ]] && check_cmd kubectl && \
    kubectl cluster-info &>/dev/null 2>&1; then
  info "etcd health check via kubectl get --raw /healthz"
  RAW=$(kubectl get --raw /healthz 2>/dev/null || echo "ERR")
  if [[ "$RAW" == "ok" ]]; then
    ok "apiserver /healthz OK (etcd reachable via apiserver)"
  else
    warn "apiserver /healthz returned: ${RAW} (etcd state unknown)"
  fi
  ETCD_CHECKED=true
fi

if [[ "$ETCD_CHECKED" == false ]]; then
  warn "etcd health check skipped — etcd container not found, no certs, no kubectl"
  info "  Expected cert path: /var/lib/rancher/rke2/server/tls/etcd/"
  info "  Run: crictl ps --label io.kubernetes.container.name=etcd"
fi

info "DNS resolution check..."
if check_cmd nslookup; then
  if nslookup kubernetes.default.svc.cluster.local &>/dev/null; then
    ok "In-cluster DNS (CoreDNS) responding"
  else
    warn "In-cluster DNS not responding — check CoreDNS pods"
  fi
  if nslookup google.com 8.8.8.8 &>/dev/null; then
    ok "External DNS resolution OK"
  else
    warn "External DNS resolution failed"
  fi
elif check_cmd dig; then
  if dig +short +timeout=3 kubernetes.default.svc.cluster.local &>/dev/null; then
    ok "In-cluster DNS (CoreDNS) responding"
  else
    warn "In-cluster DNS not responding"
  fi
fi

if check_cmd curl; then
  if curl -s --max-time 5 https://registry-1.docker.io/v2/ &>/dev/null; then
    ok "Docker Hub reachable"
  else
    warn "Docker Hub unreachable — image pulls may fail"
  fi
fi

# ── 5. System Resources ───────────────────────────────────────
banner "5 / System Resources (CPU / Memory)"

LOAD1=$(cat /proc/loadavg | awk '{print $1}')
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

SWAP_TOTAL=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
SWAP_FREE=$(grep SwapFree /proc/meminfo | awk '{print $2}')
if (( SWAP_TOTAL > 0 )); then
  SWAP_USED=$(( SWAP_TOTAL - SWAP_FREE ))
  SWAP_PCT=$(( SWAP_USED * 100 / SWAP_TOTAL ))
  if (( SWAP_PCT > 20 )); then
    warn "Swap in use — ${SWAP_PCT}% (swap is not recommended for Kubernetes)"
  else
    ok "Swap usage low — ${SWAP_PCT}%"
  fi
else
  ok "Swap disabled (recommended)"
fi

# ── 6. Service Status ─────────────────────────────────────────
banner "6 / Service Status"

SERVICES=(kubelet containerd docker crio rke2-server rke2-agent k3s k3s-agent)
if check_cmd systemctl; then
  for svc in "${SERVICES[@]}"; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null \
        && systemctl list-unit-files "${svc}.service" | grep -q "$svc"; then
      STATE=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
      case "$STATE" in
        active)   ok   "${svc}: ${STATE}" ;;
        inactive) info "${svc}: ${STATE} (installed but not running)" ;;
        failed)   fail "${svc}: FAILED — run: systemctl status ${svc}" ;;
        *)        warn "${svc}: ${STATE}" ;;
      esac
    fi
  done
else
  warn "systemctl not found — skipping service status checks"
fi

# ── 6.5 kubeconfig: auto-import RKE2 / k3s if needed ─────────
RKE2_KUBECONFIG="/etc/rancher/rke2/rke2.yaml"
K3S_KUBECONFIG="/etc/rancher/k3s/k3s.yaml"

_try_kubeconfig() {
  local cfg="$1" label="$2"
  if [[ -f "$cfg" ]]; then
    if kubectl --kubeconfig="$cfg" cluster-info &>/dev/null 2>&1; then
      export KUBECONFIG="$cfg"
      ok "kubeconfig loaded from ${cfg} (${label})"
      return 0
    else
      warn "Found ${cfg} but cluster unreachable with it"
      return 1
    fi
  fi
  return 1
}

if ! kubectl cluster-info &>/dev/null 2>&1; then
  info "No active kubeconfig — trying well-known paths..."
  if ! _try_kubeconfig "$RKE2_KUBECONFIG" "RKE2"; then
    if ! _try_kubeconfig "$K3S_KUBECONFIG" "k3s"; then
      warn "No usable kubeconfig found — kubectl checks will be skipped"
    fi
  fi
else
  info "kubeconfig already active: ${KUBECONFIG:-default (~/.kube/config)}"
fi

# ── 7. kubectl Cluster State ──────────────────────────────────
banner "7 / kubectl Cluster State"

if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then

  echo ""
  info "Node status:"
  kubectl get nodes -o wide 2>/dev/null | while IFS= read -r line; do
    if echo "$line" | grep -q "NotReady\|Unknown"; then
      echo -e "  ${RED}✖${NC}  ${line}"
      ISSUES+=("NotReady node detected: ${line}")
    elif echo "$line" | grep -q "Ready"; then
      echo -e "  ${GREEN}✔${NC}  ${line}"
    else
      echo -e "  ${DIM}ℹ${NC}  ${line}"
    fi
  done

  echo ""
  info "kube-system pods (non-healthy only):"
  UNHEALTHY=$(kubectl get pods -n kube-system \
    --no-headers 2>/dev/null \
    | grep -Ev "Running|Completed" || true)
  if [[ -z "$UNHEALTHY" ]]; then
    ok "All kube-system pods healthy"
  else
    while IFS= read -r line; do
      echo -e "  ${RED}✖${NC}  ${line}"
      ISSUES+=("Unhealthy pod (kube-system): ${line}")
    done <<< "$UNHEALTHY"
  fi

  if kubectl get componentstatuses &>/dev/null 2>&1; then
    echo ""
    info "Component statuses:"
    kubectl get componentstatuses --no-headers 2>/dev/null | while IFS= read -r line; do
      if echo "$line" | grep -q "Unhealthy"; then
        echo -e "  ${RED}✖${NC}  ${line}"
      else
        echo -e "  ${GREEN}✔${NC}  ${line}"
      fi
    done
  fi

  PVC_PENDING=$(kubectl get pvc --all-namespaces --no-headers 2>/dev/null \
    | grep "Pending" || true)
  if [[ -n "$PVC_PENDING" ]]; then
    warn "Pending PVCs detected:"
    echo "$PVC_PENDING" | while IFS= read -r line; do
      echo -e "    ${YELLOW}⚠${NC}  ${line}"
    done
  fi

else
  warn "kubectl unreachable or not connected to a cluster — skipping kubectl checks"
fi

# ── 8. Recent Kernel OOM / System Events ─────────────────────
banner "8 / Recent System Events (OOM, Errors)"

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
    echo "$OOM" | while IFS= read -r line; do
      echo -e "    ${RED}${line}${NC}"
    done
  else
    ok "No OOM events found (dmesg)"
  fi
fi

# ── 9. Kernel Parameters (Kubernetes requirements) ───────────
banner "9 / Kernel Parameters"

check_sysctl() {
  local key="$1" expected="$2" label="$3"
  local val
  val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
  if [[ "$val" == "$expected" ]]; then
    ok "${label}: ${val}"
  else
    warn "${label}: ${val} (expected: ${expected})"
  fi
}

check_sysctl net.ipv4.ip_forward                 "1" "IP forwarding"
check_sysctl net.bridge.bridge-nf-call-iptables  "1" "Bridge iptables (IPv4)"
check_sysctl net.bridge.bridge-nf-call-ip6tables "1" "Bridge iptables (IPv6)"
check_sysctl vm.swappiness                        "0" "Swappiness"

if lsmod 2>/dev/null | grep -q br_netfilter; then
  ok "br_netfilter module loaded"
else
  warn "br_netfilter module missing — run: modprobe br_netfilter"
fi

if lsmod 2>/dev/null | grep -q overlay; then
  ok "overlay module loaded"
else
  warn "overlay module missing"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Triage Summary${NC}"
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
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Normal Threshold Reference${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}FILESYSTEM${NC}"
echo -e "  ${DIM}┌─────────────────────────────────┬──────────────┬──────────────┐${NC}"
echo -e "  ${DIM}│ Metric                          │ Warning      │ Critical     │${NC}"
echo -e "  ${DIM}├─────────────────────────────────┼──────────────┼──────────────┤${NC}"
printf  "  [2m│[0m %-31s [2m│[0m %-12s [2m│[0m %-12s [2m│[0m
"         "Disk usage"    ">= ${DISK_WARN}%"   ">= ${DISK_CRIT}%"
printf  "  [2m│[0m %-31s [2m│[0m %-12s [2m│[0m %-12s [2m│[0m
"         "inode usage"   ">= ${INODE_WARN}%"  ">= ${INODE_CRIT}%"
echo -e "  ${DIM}└─────────────────────────────────┴──────────────┴──────────────┘${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}ETCD DISK I/O${NC}"
echo -e "  ${DIM}┌─────────────────────────────────┬──────────────────────────────┐${NC}"
echo -e "  ${DIM}│ Metric                          │ Threshold                    │${NC}"
echo -e "  ${DIM}├─────────────────────────────────┼──────────────────────────────┤${NC}"
printf  "  [2m│[0m %-31s [2m│[0m %-28s [2m│[0m
"         "fsync latency p99 (fio)"   "< 10ms  (fail > 10ms)"
printf  "  [2m│[0m %-31s [2m│[0m %-28s [2m│[0m
"         "Write speed (dd fallback)" ">= 50 MB/s"
echo -e "  ${DIM}└─────────────────────────────────┴──────────────────────────────┘${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}SYSTEM RESOURCES${NC}"
echo -e "  ${DIM}┌─────────────────────────────────┬──────────────┬──────────────┐${NC}"
echo -e "  ${DIM}│ Metric                          │ Warning      │ Critical     │${NC}"
echo -e "  ${DIM}├─────────────────────────────────┼──────────────┼──────────────┤${NC}"
printf  "  [2m│[0m %-31s [2m│[0m %-12s [2m│[0m %-12s [2m│[0m
"         "CPU load ratio"    "> 100%"  "> 200%"
printf  "  [2m│[0m %-31s [2m│[0m %-12s [2m│[0m %-12s [2m│[0m
"         "Memory usage"     ">= 85%"  ">= 95%"
printf  "  [2m│[0m %-31s [2m│[0m %-12s [2m│[0m %-12s [2m│[0m
"         "Swap usage"       "> 20%"   "N/A (off=best)"
echo -e "  ${DIM}└─────────────────────────────────┴──────────────┴──────────────┘${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}KERNEL PARAMETERS (required = OK)${NC}"
echo -e "  ${DIM}┌─────────────────────────────────────────────┬───────────────┐${NC}"
echo -e "  ${DIM}│ Parameter                                   │ Required      │${NC}"
echo -e "  ${DIM}├─────────────────────────────────────────────┼───────────────┤${NC}"
printf  "  [2m│[0m %-43s [2m│[0m %-13s [2m│[0m
" "net.ipv4.ip_forward"                   "1"
printf  "  [2m│[0m %-43s [2m│[0m %-13s [2m│[0m
" "net.bridge.bridge-nf-call-iptables"    "1"
printf  "  [2m│[0m %-43s [2m│[0m %-13s [2m│[0m
" "net.bridge.bridge-nf-call-ip6tables"   "1"
printf  "  [2m│[0m %-43s [2m│[0m %-13s [2m│[0m
" "vm.swappiness"                         "0"
printf  "  [2m│[0m %-43s [2m│[0m %-13s [2m│[0m
" "br_netfilter module"                   "loaded"
printf  "  [2m│[0m %-43s [2m│[0m %-13s [2m│[0m
" "overlay module"                        "loaded"
echo -e "  ${DIM}└─────────────────────────────────────────────┴───────────────┘${NC}"

echo -e "\n  ${DIM}Completed at: $(date)${NC}"
echo ""
