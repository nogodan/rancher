#!/usr/bin/env bash
# ============================================================
#  k8s-worker-triage.sh — Kubernetes Worker Node Triage
#  Checks worker node health and connectivity to a controller
#  Usage: sudo ./k8s-worker-triage.sh <CONTROLLER_IP>
# ============================================================

set -euo pipefail

# ── Argument check ───────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <CONTROLLER_IP>"
  echo "  Example: $0 10.0.0.10"
  exit 1
fi

CONTROLLER_IP="$1"

# Basic IP format sanity check
if ! [[ "$CONTROLLER_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "ERROR: '$CONTROLLER_IP' does not look like a valid IPv4 address."
  exit 1
fi

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
CONN_TIMEOUT=5     # TCP connection timeout (seconds)

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

# TCP port reachability test (no data sent, just SYN)
# Uses /dev/tcp if nc/curl not available
tcp_check() {
  local host="$1" port="$2"
  if check_cmd nc; then
    nc -z -w "${CONN_TIMEOUT}" "$host" "$port" &>/dev/null 2>&1
  elif check_cmd curl; then
    curl -sk --connect-timeout "${CONN_TIMEOUT}" \
      "https://${host}:${port}" -o /dev/null &>/dev/null 2>&1 || \
    curl -sk --connect-timeout "${CONN_TIMEOUT}" \
      "http://${host}:${port}" -o /dev/null &>/dev/null 2>&1
  else
    # bash /dev/tcp fallback
    (echo >/dev/tcp/"$host"/"$port") &>/dev/null 2>&1
  fi
}

check_port() {
  local host="$1" port="$2" label="$3" required="${4:-true}"
  if tcp_check "$host" "$port"; then
    ok "TCP ${host}:${port} reachable — ${label}"
  else
    if [[ "$required" == "true" ]]; then
      fail "TCP ${host}:${port} UNREACHABLE — ${label}"
    else
      warn "TCP ${host}:${port} unreachable — ${label} (optional)"
    fi
  fi
}

# ── 0. Pre-flight ─────────────────────────────────────────────
banner "0 / Pre-flight"

info "Worker hostname : $(hostname)"
info "Controller IP   : ${CONTROLLER_IP}"
info "Uptime          : $(uptime -p 2>/dev/null || uptime)"
info "Time            : $(date)"
if [[ -f /etc/os-release ]]; then
  info "OS              : $(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
fi

MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
info "Worker IP       : ${MY_IP}"

# ── 1. Basic Reachability ─────────────────────────────────────
banner "1 / Basic Reachability to Controller (${CONTROLLER_IP})"

# ICMP ping
if check_cmd ping; then
  if ping -c 3 -W 2 "${CONTROLLER_IP}" &>/dev/null 2>&1; then
    RTT=$(ping -c 3 -W 2 "${CONTROLLER_IP}" 2>/dev/null \
      | grep 'avg' | awk -F'/' '{print $5}' || echo "?")
    ok "ICMP ping to ${CONTROLLER_IP} OK (avg RTT: ${RTT}ms)"
  else
    fail "ICMP ping to ${CONTROLLER_IP} FAILED — host unreachable or ICMP blocked"
  fi
else
  warn "ping not available — skipping ICMP check"
fi

# Traceroute (informational — shows path to controller)
if check_cmd traceroute; then
  info "Traceroute to ${CONTROLLER_IP} (max 10 hops):"
  traceroute -m 10 -w 2 "${CONTROLLER_IP}" 2>/dev/null \
    | while IFS= read -r line; do info "  ${line}"; done || true
elif check_cmd tracepath; then
  info "Tracepath to ${CONTROLLER_IP}:"
  tracepath -m 10 "${CONTROLLER_IP}" 2>/dev/null \
    | head -12 \
    | while IFS= read -r line; do info "  ${line}"; done || true
fi

# ── 2. RKE2 Control Plane Ports (worker → controller) ────────
banner "2 / RKE2 Control Plane Ports  (worker → ${CONTROLLER_IP})"

echo ""
echo -e "  ${BOLD}Required ports:${NC}"

# RKE2 supervisor / registration
check_port "${CONTROLLER_IP}" 9345  "RKE2 supervisor (agent registration)"
# Kubernetes API server
check_port "${CONTROLLER_IP}" 6443  "kube-apiserver"
# etcd (only needed if this worker can become a server — optional)
check_port "${CONTROLLER_IP}" 2379  "etcd client"   "false"
check_port "${CONTROLLER_IP}" 2380  "etcd peer"     "false"

echo ""
echo -e "  ${BOLD}CNI / overlay network ports:${NC}"

# Flannel VXLAN (UDP) — tested via TCP knock; UDP needs different approach
if check_cmd nc; then
  if nc -zu -w "${CONN_TIMEOUT}" "${CONTROLLER_IP}" 8472 &>/dev/null 2>&1; then
    ok "UDP ${CONTROLLER_IP}:8472 reachable — Flannel VXLAN"
  else
    warn "UDP ${CONTROLLER_IP}:8472 unreachable — Flannel VXLAN (UDP test may be inaccurate without response)"
  fi
else
  info "nc not available — skipping UDP 8472 Flannel VXLAN test"
fi

# Canal/Calico BGP
check_port "${CONTROLLER_IP}" 179   "BGP (Canal/Calico)"      "false"
# Calico Typha
check_port "${CONTROLLER_IP}" 5473  "Calico Typha"            "false"
# WireGuard
check_port "${CONTROLLER_IP}" 51820 "WireGuard IPv4"          "false"
check_port "${CONTROLLER_IP}" 51821 "WireGuard IPv6"          "false"

echo ""
echo -e "  ${BOLD}Kubelet / metrics ports (controller → worker, reverse check):${NC}"
info "Note: the following checks confirm THIS worker's ports are listening"
info "      (controller needs to reach these on the worker)"

check_local_port() {
  local port="$1" label="$2" required="${3:-true}"
  if check_cmd ss; then
    if ss -tlnp 2>/dev/null | grep -q ":${port}\b"; then
      ok "Port ${port} listening locally — ${label}"
    else
      if [[ "$required" == "true" ]]; then
        fail "Port ${port} NOT listening locally — ${label}"
      else
        info "Port ${port} not listening — ${label} (not in use)"
      fi
    fi
  elif check_cmd netstat; then
    if netstat -tlnp 2>/dev/null | grep -q ":${port}\b"; then
      ok "Port ${port} listening locally — ${label}"
    else
      if [[ "$required" == "true" ]]; then
        fail "Port ${port} NOT listening locally — ${label}"
      else
        info "Port ${port} not listening — ${label} (not in use)"
      fi
    fi
  else
    warn "ss/netstat not available — skipping local port ${port} check"
  fi
}

check_local_port 10250 "kubelet API (controller polls this)"
check_local_port 10256 "kube-proxy healthz"                   "false"
check_local_port 9345  "RKE2 supervisor (if dual-role node)"  "false"

# ── 3. kube-apiserver Authenticated Health Check ─────────────
banner "3 / kube-apiserver Health Check  (${CONTROLLER_IP}:6443)"

RKE2_AGENT_KUBECONFIG="/var/lib/rancher/rke2/agent/kubelet.kubeconfig"
RKE2_SERVER_KUBECONFIG="/etc/rancher/rke2/rke2.yaml"

APISERVER_URL="https://${CONTROLLER_IP}:6443"

# Try unauthenticated first to confirm TCP+TLS works
if check_cmd curl; then
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time "${CONN_TIMEOUT}" "${APISERVER_URL}/healthz" 2>/dev/null || echo "ERR")

  case "$HTTP_CODE" in
    200)
      ok "kube-apiserver /healthz: HTTP 200 OK"
      ;;
    401|403)
      # Apiserver up but needs auth — try with available kubeconfigs
      AUTHED=false
      for kc in "$RKE2_SERVER_KUBECONFIG" "$RKE2_AGENT_KUBECONFIG" "${KUBECONFIG:-}"; do
        [[ -z "$kc" || ! -f "$kc" ]] && continue
        AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
          --max-time "${CONN_TIMEOUT}" \
          --cacert  <(kubectl --kubeconfig="$kc" config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null | base64 -d 2>/dev/null || echo "") \
          "${APISERVER_URL}/healthz" 2>/dev/null || echo "ERR")
        if [[ "$AUTH_CODE" == "200" ]]; then
          ok "kube-apiserver /healthz: HTTP 200 OK (via kubeconfig: $kc)"
          AUTHED=true
          break
        fi
      done
      if [[ "$AUTHED" == false ]]; then
        # kubectl fallback
        if check_cmd kubectl; then
          for kc in "$RKE2_SERVER_KUBECONFIG" "$RKE2_AGENT_KUBECONFIG"; do
            [[ ! -f "$kc" ]] && continue
            if KUBECONFIG="$kc" kubectl get --raw /healthz \
                --server="${APISERVER_URL}" &>/dev/null 2>&1; then
              ok "kube-apiserver /healthz OK (kubectl, kubeconfig: $kc)"
              AUTHED=true
              break
            fi
          done
        fi
      fi
      if [[ "$AUTHED" == false ]]; then
        warn "kube-apiserver reachable but auth required — HTTP ${HTTP_CODE} (no valid client cert found)"
      fi
      ;;
    ERR|000)
      fail "kube-apiserver ${APISERVER_URL}/healthz — no response (TCP open but TLS/app failed?)"
      ;;
    *)
      fail "kube-apiserver /healthz unexpected: HTTP ${HTTP_CODE}"
      ;;
  esac
else
  warn "curl not available — skipping apiserver health check"
fi

# ── 4. RKE2 Agent Registration Check ─────────────────────────
banner "4 / RKE2 Agent Registration  (${CONTROLLER_IP}:9345)"

if check_cmd curl; then
  REG_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time "${CONN_TIMEOUT}" \
    "https://${CONTROLLER_IP}:9345/cacerts" 2>/dev/null || echo "ERR")
  case "$REG_CODE" in
    200)
      ok "RKE2 supervisor /cacerts: HTTP 200 — agent can register"
      # Fetch and display the CA cert subject for verification
      CA_SUBJ=$(curl -sk --max-time "${CONN_TIMEOUT}" \
        "https://${CONTROLLER_IP}:9345/cacerts" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null || echo "")
      [[ -n "$CA_SUBJ" ]] && info "CA cert: ${CA_SUBJ}"
      ;;
    ERR|000)
      fail "RKE2 supervisor ${CONTROLLER_IP}:9345 — no response"
      ;;
    *)
      warn "RKE2 supervisor /cacerts returned HTTP ${REG_CODE}"
      ;;
  esac
fi

# ── 5. DNS Resolution ─────────────────────────────────────────
banner "5 / DNS Resolution"

# Discover the cluster DNS service IP from multiple sources.
# Never rely on the host's /etc/resolv.conf — on worker nodes it points
# to the host resolver, not CoreDNS, causing false-positive failures.
CLUSTER_DNS_IP=""

# Source 1: kubelet config (most reliable — what kubelet was told to use)
KUBELET_CFG="/var/lib/rancher/rke2/agent/etc/kubelet.env"
if [[ -z "$CLUSTER_DNS_IP" && -f "$KUBELET_CFG" ]]; then
  CLUSTER_DNS_IP=$(grep -oP '(?<=--cluster-dns=)\S+' "$KUBELET_CFG" 2>/dev/null | head -1 || true)
fi

# Source 2: running kubelet process args
if [[ -z "$CLUSTER_DNS_IP" ]]; then
  CLUSTER_DNS_IP=$(cat /proc/$(pgrep -x kubelet 2>/dev/null | head -1)/cmdline \
    2>/dev/null | tr '\0' '\n' | grep -oP '(?<=--cluster-dns=)\S+' | head -1 || true)
fi

# Source 3: kubectl — look up the kube-dns service ClusterIP
if [[ -z "$CLUSTER_DNS_IP" ]] && check_cmd kubectl; then
  for kc in "/etc/rancher/rke2/rke2.yaml" "/var/lib/rancher/rke2/agent/kubelet.kubeconfig" "${KUBECONFIG:-}"; do
    [[ -z "$kc" || ! -f "$kc" ]] && continue
    CLUSTER_DNS_IP=$(KUBECONFIG="$kc" kubectl get svc kube-dns -n kube-system \
      -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
    [[ -n "$CLUSTER_DNS_IP" ]] && break
  done
fi

# Source 4: RKE2 default (10.43.0.10 for standard 10.43.0.0/16 service CIDR)
if [[ -z "$CLUSTER_DNS_IP" ]]; then
  CLUSTER_DNS_IP="10.43.0.10"
  info "Could not detect cluster DNS IP — using RKE2 default: ${CLUSTER_DNS_IP}"
fi

info "Cluster DNS IP: ${CLUSTER_DNS_IP}"

# Test CoreDNS port reachability first (TCP 53)
if tcp_check "${CLUSTER_DNS_IP}" 53; then
  ok "CoreDNS TCP port 53 reachable at ${CLUSTER_DNS_IP}"
else
  fail "CoreDNS TCP port 53 UNREACHABLE at ${CLUSTER_DNS_IP} — CoreDNS pod may be down or network broken"
fi

# Query CoreDNS directly by pointing nslookup/dig at the cluster DNS IP
# This bypasses host /etc/resolv.conf entirely
DNS_TOOL=""
check_cmd nslookup && DNS_TOOL="nslookup"
check_cmd dig      && DNS_TOOL="dig"

if [[ -n "$DNS_TOOL" ]]; then
  if [[ "$DNS_TOOL" == "dig" ]]; then
    RESULT=$(dig +short +timeout=3 @"${CLUSTER_DNS_IP}" kubernetes.default.svc.cluster.local 2>/dev/null || true)
  else
    RESULT=$(nslookup kubernetes.default.svc.cluster.local "${CLUSTER_DNS_IP}" 2>/dev/null || true)
  fi

  if [[ -n "$RESULT" ]]; then
    ok "In-cluster DNS: kubernetes.default.svc.cluster.local resolves via CoreDNS (${CLUSTER_DNS_IP})"
    [[ "$DNS_TOOL" == "dig" ]] && info "  → ${RESULT}"
  else
    warn "In-cluster DNS: kubernetes.default.svc.cluster.local did not resolve via ${CLUSTER_DNS_IP}"
  fi

  # Reverse DNS for controller IP (informational)
  CTRL_HOSTNAME=$(nslookup "${CONTROLLER_IP}" 2>/dev/null \
    | grep -i 'name\|Name' | awk '{print $NF}' | head -1 || echo "")
  if [[ -n "$CTRL_HOSTNAME" ]]; then
    info "Controller ${CONTROLLER_IP} reverse DNS: ${CTRL_HOSTNAME}"
  else
    info "Controller ${CONTROLLER_IP}: no reverse DNS entry"
  fi
else
  info "nslookup/dig not available — testing CoreDNS via TCP port only"
fi

# External DNS (uses host resolver — intentionally separate from cluster DNS check)
if check_cmd nslookup; then
  if nslookup google.com 8.8.8.8 &>/dev/null 2>&1; then
    ok "External DNS (google.com via 8.8.8.8) resolves"
  else
    warn "External DNS resolution failed"
  fi
fi

# ── 6. Worker Node Local Services ────────────────────────────
banner "6 / Worker Node Local Services"

if check_cmd systemctl; then
  # RKE2 services — the only ones that must be active on an RKE2 worker
  # rke2-agent is expected on pure workers; rke2-server on control-plane nodes
  RKE2_ACTIVE=false
  for svc in rke2-agent rke2-server; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 \
        && systemctl list-unit-files "${svc}.service" | grep -q "$svc"; then
      STATE=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
      case "$STATE" in
        active)
          ok "${svc}: active"
          RKE2_ACTIVE=true
          ;;
        failed)
          fail "${svc}: FAILED — run: systemctl status ${svc}"
          ;;
        inactive)
          info "${svc}: inactive"
          ;;
        *)
          warn "${svc}: ${STATE}"
          ;;
      esac
    fi
  done

  # kubelet — may be managed by RKE2 directly (not a standalone systemd unit)
  if systemctl list-unit-files "kubelet.service" &>/dev/null 2>&1 \
      && systemctl list-unit-files "kubelet.service" | grep -q "kubelet"; then
    STATE=$(systemctl is-active kubelet 2>/dev/null || echo "unknown")
    case "$STATE" in
      active)   ok   "kubelet: active (standalone systemd unit)" ;;
      inactive) info "kubelet: inactive — expected on RKE2 (kubelet is embedded in rke2-agent)" ;;
      failed)   fail "kubelet: FAILED — run: systemctl status kubelet" ;;
      *)        warn "kubelet: ${STATE}" ;;
    esac
  fi

  # containerd is an internal component of rke2-agent/k3s —
  # it is not a separate systemd service on RKE2/k3s nodes. No check needed.

  # docker — only check on non-RKE2/k3s nodes where it may be the CRI.
  if [[ "$RKE2_ACTIVE" == false ]] && systemctl cat docker.service &>/dev/null 2>&1; then
    STATE=$(systemctl is-active docker 2>/dev/null || echo "unknown")
    case "$STATE" in
      active)  ok   "docker: active" ;;
      failed)  fail "docker: FAILED — run: systemctl status docker" ;;
      *)       warn "docker: ${STATE}" ;;
    esac
  fi
else
  warn "systemctl not available — skipping service status checks"
fi

# kubelet last restart time
if check_cmd systemctl; then
  KUBELET_SINCE=$(systemctl show kubelet --property=ActiveEnterTimestamp \
    2>/dev/null | cut -d= -f2 || echo "")
  [[ -n "$KUBELET_SINCE" ]] && info "kubelet active since: ${KUBELET_SINCE}"
fi

# ── 7. Filesystem & Disk ──────────────────────────────────────
banner "7 / Filesystem & Disk Usage"

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

# ── 8. System Resources ───────────────────────────────────────
banner "8 / System Resources (CPU / Memory)"

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

# ── 9. Kernel Parameters ─────────────────────────────────────
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

# ── 10. OOM / Recent Kernel Events ───────────────────────────
banner "10 / Recent System Events (OOM)"

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

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Triage Summary  [worker: $(hostname)  →  controller: ${CONTROLLER_IP}]${NC}"
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
echo -e "  ${CYAN}${BOLD}REQUIRED PORTS (worker → controller: ${CONTROLLER_IP})${NC}"
echo -e "  ${DIM}┌──────────┬────────────────────────────────────┬──────────┐${NC}"
echo -e "  ${DIM}│ Port     │ Purpose                            │ Required │${NC}"
echo -e "  ${DIM}├──────────┼────────────────────────────────────┼──────────┤${NC}"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "9345/TCP"  "RKE2 supervisor (agent registration)" "YES"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "6443/TCP"  "kube-apiserver"                       "YES"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "8472/UDP"  "Flannel VXLAN (overlay network)"      "YES"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "51820/UDP" "WireGuard IPv4 (if enabled)"          "optional"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "179/TCP"   "BGP (Canal/Calico, if enabled)"       "optional"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "5473/TCP"  "Calico Typha (if enabled)"            "optional"
echo -e "  ${DIM}└──────────┴────────────────────────────────────┴──────────┘${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}REQUIRED PORTS (controller → this worker: ${MY_IP})${NC}"
echo -e "  ${DIM}┌──────────┬────────────────────────────────────┬──────────┐${NC}"
echo -e "  ${DIM}│ Port     │ Purpose                            │ Required │${NC}"
echo -e "  ${DIM}├──────────┼────────────────────────────────────┼──────────┤${NC}"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "10250/TCP" "kubelet API"                          "YES"
printf  "  \033[2m│\033[0m %-8s \033[2m│\033[0m %-34s \033[2m│\033[0m %-8s \033[2m│\033[0m\n" "10256/TCP" "kube-proxy healthz"                   "optional"
echo -e "  ${DIM}└──────────┴────────────────────────────────────┴──────────┘${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}FILESYSTEM & RESOURCES${NC}"
echo -e "  ${DIM}┌─────────────────────────────────┬──────────────┬──────────────┐${NC}"
echo -e "  ${DIM}│ Metric                          │ Warning      │ Critical     │${NC}"
echo -e "  ${DIM}├─────────────────────────────────┼──────────────┼──────────────┤${NC}"
printf  "  \033[2m│\033[0m %-31s \033[2m│\033[0m %-12s \033[2m│\033[0m %-12s \033[2m│\033[0m\n" "Disk usage"    ">= ${DISK_WARN}%"  ">= ${DISK_CRIT}%"
printf  "  \033[2m│\033[0m %-31s \033[2m│\033[0m %-12s \033[2m│\033[0m %-12s \033[2m│\033[0m\n" "inode usage"   ">= ${INODE_WARN}%" ">= ${INODE_CRIT}%"
printf  "  \033[2m│\033[0m %-31s \033[2m│\033[0m %-12s \033[2m│\033[0m %-12s \033[2m│\033[0m\n" "CPU load ratio"  "> 100%"  "> 200%"
printf  "  \033[2m│\033[0m %-31s \033[2m│\033[0m %-12s \033[2m│\033[0m %-12s \033[2m│\033[0m\n" "Memory usage"    ">= 85%"  ">= 95%"
printf  "  \033[2m│\033[0m %-31s \033[2m│\033[0m %-12s \033[2m│\033[0m %-12s \033[2m│\033[0m\n" "Swap usage"      "> 20%"   "N/A (off=best)"
echo -e "  ${DIM}└─────────────────────────────────┴──────────────┴──────────────┘${NC}"

echo -e "\n  ${DIM}Completed at: $(date)${NC}"
echo ""