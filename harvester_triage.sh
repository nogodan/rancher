#!/usr/bin/env bash
# ============================================================
#  harvester-triage.sh — SUSE Harvester HCI Node Triage Script
#  Quick root-cause diagnosis for Harvester bare-metal HCI nodes
#  Source: https://docs.harvesterhci.io/v1.8/install/requirements
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

ISSUES=()
WARNINGS=()

# ── RKE2 / Harvester Environment Bootstrap ───────────────────
# Harvester runs on RKE2 internally; prepend its bin dir
export CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml
PATH="/var/lib/rancher/rke2/bin:$PATH"

# etcd certs for Harvester management nodes
ETCD_CERT=/var/lib/rancher/rke2/server/tls/etcd/server-client.crt
ETCD_KEY=/var/lib/rancher/rke2/server/tls/etcd/server-client.key
ETCD_CACERT=/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt

RKE2_ETCD_READY=false
if command -v crictl &>/dev/null && [[ -f "$ETCD_CERT" && -f "$ETCD_KEY" && -f "$ETCD_CACERT" ]]; then
  etcdcontainer=$(crictl ps --label io.kubernetes.container.name=etcd --quiet 2>/dev/null | head -1 || true)
  if [[ -n "$etcdcontainer" ]]; then
    ETCDCTL_ENDPOINTS=$(crictl exec "${etcdcontainer}" \
      etcdctl --cert "${ETCD_CERT}" --key "${ETCD_KEY}" --cacert "${ETCD_CACERT}" \
      member list 2>/dev/null \
      | cut -d, -f5 | sed -e 's/ //g' | paste -sd ',' || true)
    if [[ -n "$ETCDCTL_ENDPOINTS" ]]; then
      export ETCDCTL_ENDPOINTS ETCDCTL_CACERT="$ETCD_CACERT"
      export ETCDCTL_CERT="$ETCD_CERT" ETCDCTL_KEY="$ETCD_KEY" ETCDCTL_API=3
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

tcp_check() {
  local host="$1" port="$2"
  if check_cmd nc; then
    nc -z -w 3 "$host" "$port" &>/dev/null 2>&1
  else
    (echo >/dev/tcp/"$host"/"$port") &>/dev/null 2>&1
  fi
}

check_local_port() {
  local port="$1" label="$2" required="${3:-true}"
  if check_cmd ss; then
    if ss -tlnp 2>/dev/null | grep -q ":${port}\b"; then
      ok "Port ${port} listening — ${label}"
      return
    fi
  elif check_cmd netstat; then
    if netstat -tlnp 2>/dev/null | grep -q ":${port}\b"; then
      ok "Port ${port} listening — ${label}"
      return
    fi
  fi
  if [[ "$required" == "true" ]]; then
    fail "Port ${port} NOT listening — ${label}"
  else
    info "Port ${port} not listening — ${label} (optional/node-role dependent)"
  fi
}

# ── 0. Pre-flight ─────────────────────────────────────────────
banner "0 / Pre-flight"

info "Hostname   : $(hostname)"
info "Uptime     : $(uptime -p 2>/dev/null || uptime)"
info "Time       : $(date)"
if [[ -f /etc/os-release ]]; then
  info "OS         : $(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
fi
info "Kernel     : $(uname -r)"

# Detect node role (management vs compute)
NODE_ROLE="compute"
if [[ -f /var/lib/rancher/rke2/server/tls/server-ca.crt ]]; then
  NODE_ROLE="management"
fi
info "Node role  : ${NODE_ROLE} ($(
  [[ "$NODE_ROLE" == "management" ]] && echo "has RKE2 server TLS — etcd checks enabled" \
    || echo "no RKE2 server TLS — etcd checks skipped"
))"

# Detect product UUID (must be unique per node for Harvester)
PRODUCT_UUID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo "unavailable")
info "Product UUID: ${PRODUCT_UUID}"
if [[ "$PRODUCT_UUID" == "unavailable" || -z "$PRODUCT_UUID" ]]; then
  warn "product_uuid not readable — Harvester requires unique UUID per node for live migration"
fi

# Check hardware-assisted virtualisation (required for KubeVirt/VMs)
if grep -qE 'vmx|svm' /proc/cpuinfo 2>/dev/null; then
  ok "Hardware virtualisation (vmx/svm) detected in CPU flags"
else
  fail "Hardware virtualisation NOT detected — KubeVirt/VM workloads will not work"
fi

if check_cmd kubectl; then
  ok "kubectl found"
else
  warn "kubectl not found — some checks will be skipped"
fi

# ── 1. Harvester / RKE2 Services ─────────────────────────────
banner "1 / Harvester & RKE2 Services"

if check_cmd systemctl; then
  RKE2_ACTIVE=false
  for svc in rke2-server rke2-agent; do
    if systemctl cat "${svc}.service" &>/dev/null 2>&1; then
      STATE=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
      case "$STATE" in
        active)
          ok   "${svc}: active"
          RKE2_ACTIVE=true
          ;;
        failed) fail "${svc}: FAILED — run: systemctl status ${svc}" ;;
        inactive) info "${svc}: inactive" ;;
        *)        warn "${svc}: ${STATE}" ;;
      esac
    fi
  done
  [[ "$RKE2_ACTIVE" == false ]] && fail "Neither rke2-server nor rke2-agent is active"

  # containerd is internal to RKE2 — no separate unit
  info "containerd: managed internally by RKE2 (no separate systemd unit)"

  # Harvester-specific: KubeVirt requires libvirtd / virt-handler
  for svc in kubevirt-handler virt-handler; do
    if systemctl cat "${svc}.service" &>/dev/null 2>&1; then
      STATE=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
      case "$STATE" in
        active)   ok   "${svc}: active" ;;
        failed)   fail "${svc}: FAILED — run: systemctl status ${svc}" ;;
        *)        info "${svc}: ${STATE}" ;;
      esac
    fi
  done

  # iscsid — required by embedded Longhorn
  # Harvester runs on SLE Micro: iscsi.service shows "active exited" (normal),
  # iscsid.service is "inactive" at idle (socket-activated), iscsid.socket is "active".
  # Checking only iscsid.service is-active produces a false-positive inactive warning.
  if check_cmd systemctl; then
    ISCSI_SVC=$(systemctl is-active iscsi.service   2>/dev/null || echo "unknown")
    ISCSID_SVC=$(systemctl is-active iscsid.service 2>/dev/null || echo "unknown")
    ISCSID_SOCK=$(systemctl is-active iscsid.socket 2>/dev/null || echo "unknown")

    if [[ "$ISCSI_SVC" == "active" || "$ISCSID_SVC" == "active" ]]; then
      ok "iSCSI stack: active (iscsi=${ISCSI_SVC} iscsid=${ISCSID_SVC} socket=${ISCSID_SOCK})"
    elif [[ "$ISCSID_SOCK" == "active" ]]; then
      ok "iSCSI stack: iscsid.socket active — iscsid starts on-demand (SLE Micro)"
    elif [[ "$ISCSI_SVC" == "failed" || "$ISCSID_SVC" == "failed" ]]; then
      fail "iSCSI service FAILED — run: systemctl status iscsi.service iscsid.service"
    elif systemctl cat iscsid.service &>/dev/null 2>&1 && check_cmd iscsiadm; then
      ok "iSCSI stack: inactive at idle (socket-activated on SLE Micro — normal when no volumes attached)"
    else
      fail "iSCSI stack not found — required for Harvester embedded Longhorn storage"
    fi
  else
    warn "systemctl not available — skipping iscsid check"
  fi
else
  warn "systemctl not available — skipping service checks"
fi

# ── 2. etcd Health (management nodes only) ───────────────────
banner "2 / etcd Health"

if [[ "$NODE_ROLE" == "management" ]]; then
  if [[ "$RKE2_ETCD_READY" == true ]]; then
    _etcdctl() {
      crictl exec "${etcdcontainer}" \
        etcdctl --cert "${ETCD_CERT}" --key "${ETCD_KEY}" --cacert "${ETCD_CACERT}" \
        --endpoints "${ETCDCTL_ENDPOINTS}" "$@"
    }

    info "etcd container : ${etcdcontainer}"
    info "etcd endpoints : ${ETCDCTL_ENDPOINTS}"

    echo ""
    info "[ etcd endpoint health ]"
    HEALTH_OUT=$(_etcdctl endpoint health --write-out=table 2>&1 || true)
    if echo "$HEALTH_OUT" | grep -q "false"; then
      fail "One or more etcd endpoints unhealthy"
    else
      ok "All etcd endpoints healthy"
    fi
    echo "$HEALTH_OUT" | while IFS= read -r line; do info "  ${line}"; done

    echo ""
    info "[ etcd endpoint status ]"
    _etcdctl endpoint status --write-out=table 2>/dev/null \
      | while IFS= read -r line; do info "  ${line}"; done || true

    echo ""
    info "[ etcd member list ]"
    _etcdctl member list --write-out=table 2>/dev/null \
      | while IFS= read -r line; do info "  ${line}"; done || true

    echo ""
    info "[ etcd alarm list ]"
    ALARM_OUT=$(_etcdctl alarm list 2>/dev/null || true)
    if [[ -z "$ALARM_OUT" ]]; then
      ok "No etcd alarms"
    else
      fail "etcd alarms active: ${ALARM_OUT}"
    fi

    echo ""
    info "[ etcd check perf ] (this may take ~30s)"
    PERF_OUT=$(_etcdctl check perf 2>&1 || true)
    if echo "$PERF_OUT" | grep -qi "fail\|FAIL"; then
      fail "etcd performance check FAILED"
      echo "$PERF_OUT" | while IFS= read -r line; do echo -e "    ${RED}${line}${NC}"; done
    else
      ok "etcd performance check passed"
      echo "$PERF_OUT" | while IFS= read -r line; do info "  ${line}"; done
    fi
  else
    warn "etcd container or certs not found — skipping etcd checks"
    info "  Expected certs: /var/lib/rancher/rke2/server/tls/etcd/"
  fi
else
  info "Compute node — etcd checks skipped (management nodes only)"
fi

# ── 3. Required Ports — Local Listening ──────────────────────
banner "3 / Required Ports — Local Listening"

echo ""
echo -e "  ${BOLD}Management & compute nodes:${NC}"
check_local_port 10250 "kubelet"
check_local_port 10256 "kube-proxy healthz"          "false"
check_local_port 10010 "containerd (Harvester)"

echo ""
echo -e "  ${BOLD}Management nodes only:${NC}"
if [[ "$NODE_ROLE" == "management" ]]; then
  check_local_port 2379  "etcd client"
  check_local_port 2380  "etcd peer"
  check_local_port 2381  "etcd metrics"
  check_local_port 2382  "etcd client HTTP"           "false"
  check_local_port 6443  "kube-apiserver"
  check_local_port 9345  "RKE2 supervisor"
  check_local_port 10252 "kube-controller-manager healthz" "false"
  check_local_port 10257 "kube-controller-manager secure"
  check_local_port 10251 "kube-scheduler healthz"     "false"
  check_local_port 10259 "kube-scheduler secure"
  check_local_port 10258 "cloud-controller-manager"   "false"
else
  info "Skipping management-only port checks (compute node)"
fi

echo ""
echo -e "  ${BOLD}Harvester-specific services:${NC}"
check_local_port 8181  "Harvester nginx ingress (HTTP)"  "false"
check_local_port 8443  "Harvester nginx ingress (HTTPS)" "false"
check_local_port 30000 "Harvester VIP NodePort range start" "false"

echo ""
echo -e "  ${BOLD}VM networking / KubeVirt:${NC}"
check_local_port 4789  "VXLAN (VM overlay, UDP — shown as TCP here)" "false"
check_local_port 8472  "Flannel VXLAN"                  "false"

# ── 4. Inter-node Connectivity ────────────────────────────────
banner "4 / Inter-node Connectivity"

# Auto-load kubeconfig
for kc in "/etc/rancher/rke2/rke2.yaml" "${KUBECONFIG:-}"; do
  [[ -z "$kc" || ! -f "$kc" ]] && continue
  if KUBECONFIG="$kc" kubectl cluster-info &>/dev/null 2>&1; then
    export KUBECONFIG="$kc"
    break
  fi
done

if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  NODE_IPS=$(kubectl get nodes \
    -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' \
    2>/dev/null || true)
  MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")

  for peer_ip in $NODE_IPS; do
    [[ "$peer_ip" == "$MY_IP" ]] && continue
    echo ""
    info "Peer node: ${peer_ip}"

    # Critical: RKE2 supervisor + apiserver
    tcp_check "$peer_ip" 9345  && ok "TCP ${peer_ip}:9345 reachable — RKE2 supervisor" \
      || fail "TCP ${peer_ip}:9345 UNREACHABLE — RKE2 supervisor"
    tcp_check "$peer_ip" 6443  && ok "TCP ${peer_ip}:6443 reachable — kube-apiserver" \
      || fail "TCP ${peer_ip}:6443 UNREACHABLE — kube-apiserver"

    # Kubelet (management polls workers)
    tcp_check "$peer_ip" 10250 && ok "TCP ${peer_ip}:10250 reachable — kubelet" \
      || warn "TCP ${peer_ip}:10250 unreachable — kubelet"

    # Longhorn replica traffic
    tcp_check "$peer_ip" 9500  && ok "TCP ${peer_ip}:9500 reachable — Longhorn replica" \
      || warn "TCP ${peer_ip}:9500 unreachable — Longhorn inter-node replica traffic"

    # etcd (management → management)
    if [[ "$NODE_ROLE" == "management" ]]; then
      tcp_check "$peer_ip" 2379 && ok "TCP ${peer_ip}:2379 reachable — etcd client" \
        || fail "TCP ${peer_ip}:2379 UNREACHABLE — etcd client"
      tcp_check "$peer_ip" 2380 && ok "TCP ${peer_ip}:2380 reachable — etcd peer" \
        || fail "TCP ${peer_ip}:2380 UNREACHABLE — etcd peer"
    fi
  done
else
  warn "kubectl not connected — skipping inter-node connectivity checks"
fi

# ── 5. kube-apiserver Health ──────────────────────────────────
banner "5 / kube-apiserver Health"

APISERVER_URL="https://127.0.0.1:6443"
RKE2_API_CACERT="/var/lib/rancher/rke2/server/tls/server-ca.crt"
RKE2_API_CLIENT_CERT="/var/lib/rancher/rke2/server/tls/client-admin.crt"
RKE2_API_CLIENT_KEY="/var/lib/rancher/rke2/server/tls/client-admin.key"

if check_cmd curl; then
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 "${APISERVER_URL}/healthz" 2>/dev/null || echo "ERR")
  case "$HTTP_CODE" in
    200)
      ok "kube-apiserver /healthz: HTTP 200 OK"
      ;;
    401|403)
      if [[ -f "$RKE2_API_CACERT" && -f "$RKE2_API_CLIENT_CERT" && -f "$RKE2_API_CLIENT_KEY" ]]; then
        AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
          --cacert  "$RKE2_API_CACERT" \
          --cert    "$RKE2_API_CLIENT_CERT" \
          --key     "$RKE2_API_CLIENT_KEY" \
          --max-time 5 "${APISERVER_URL}/healthz" 2>/dev/null || echo "ERR")
        if [[ "$AUTH_CODE" == "200" ]]; then
          ok "kube-apiserver /healthz: HTTP 200 OK (authenticated)"
        else
          warn "kube-apiserver /healthz: HTTP ${AUTH_CODE} with client cert"
        fi
      elif check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
        LIVEZ=$(kubectl get --raw /healthz 2>/dev/null || echo "ERR")
        [[ "$LIVEZ" == "ok" ]] && ok "kube-apiserver /healthz OK (via kubectl)" \
          || warn "kube-apiserver /healthz returned: ${LIVEZ}"
      else
        warn "kube-apiserver reachable but returned HTTP ${HTTP_CODE} — no client cert available"
      fi
      ;;
    ERR|000)
      if [[ "$NODE_ROLE" == "compute" ]]; then
        info "kube-apiserver not on this compute node (expected)"
      else
        fail "kube-apiserver not responding on management node"
      fi
      ;;
    *)
      fail "kube-apiserver /healthz unexpected: HTTP ${HTTP_CODE}"
      ;;
  esac
else
  warn "curl not available — skipping apiserver health check"
fi

# ── 6. DNS Resolution ─────────────────────────────────────────
banner "6 / DNS Resolution"

CLUSTER_DNS_IP=""
for f in /var/lib/rancher/rke2/agent/etc/kubelet.env; do
  [[ -f "$f" ]] && CLUSTER_DNS_IP=$(grep -oP '(?<=--cluster-dns=)\S+' "$f" 2>/dev/null | head -1 || true)
  [[ -n "$CLUSTER_DNS_IP" ]] && break
done
if [[ -z "$CLUSTER_DNS_IP" ]]; then
  KUBELET_PID=$(pgrep -x kubelet 2>/dev/null | head -1 || true)
  [[ -n "$KUBELET_PID" ]] && \
    CLUSTER_DNS_IP=$(tr '\0' '\n' < /proc/"$KUBELET_PID"/cmdline 2>/dev/null \
      | grep -oP '(?<=--cluster-dns=)\S+' | head -1 || true)
fi
if [[ -z "$CLUSTER_DNS_IP" ]] && check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  CLUSTER_DNS_IP=$(kubectl get svc kube-dns -n kube-system \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
fi
[[ -z "$CLUSTER_DNS_IP" ]] && CLUSTER_DNS_IP="10.53.0.10"
info "Cluster DNS IP: ${CLUSTER_DNS_IP}"

if check_cmd nc; then
  nc -z -w 3 "${CLUSTER_DNS_IP}" 53 &>/dev/null 2>&1 \
    && ok "CoreDNS TCP:53 reachable at ${CLUSTER_DNS_IP}" \
    || fail "CoreDNS TCP:53 UNREACHABLE at ${CLUSTER_DNS_IP}"
fi
if check_cmd nslookup; then
  nslookup kubernetes.default.svc.cluster.local "${CLUSTER_DNS_IP}" &>/dev/null 2>&1 \
    && ok "In-cluster DNS: kubernetes.default.svc.cluster.local resolves via ${CLUSTER_DNS_IP}" \
    || warn "In-cluster DNS: query to ${CLUSTER_DNS_IP} failed — check CoreDNS pods"
  nslookup google.com 8.8.8.8 &>/dev/null 2>&1 \
    && ok "External DNS resolution OK" \
    || warn "External DNS resolution failed"
elif check_cmd dig; then
  dig +short +timeout=3 @"${CLUSTER_DNS_IP}" kubernetes.default.svc.cluster.local &>/dev/null 2>&1 \
    && ok "In-cluster DNS resolves via ${CLUSTER_DNS_IP}" \
    || warn "In-cluster DNS: query to ${CLUSTER_DNS_IP} failed"
fi

# ── 7. Harvester Pods & VMs ───────────────────────────────────
banner "7 / Harvester Pods & VM Health"

if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  echo ""
  info "Node status:"
  kubectl get nodes -o wide 2>/dev/null | while IFS= read -r line; do
    if echo "$line" | grep -qE "NotReady|Unknown"; then
      echo -e "  ${RED}✖${NC}  ${line}"
    elif echo "$line" | grep -q "Ready"; then
      echo -e "  ${GREEN}✔${NC}  ${line}"
    else
      echo -e "  ${DIM}ℹ${NC}  ${line}"
    fi
  done

  echo ""
  info "harvester-system pods (non-healthy only):"
  UNHEALTHY=$(kubectl get pods -n harvester-system --no-headers 2>/dev/null \
    | grep -Ev "Running|Completed" || true)
  if [[ -z "$UNHEALTHY" ]]; then
    ok "All harvester-system pods healthy"
  else
    echo "$UNHEALTHY" | while IFS= read -r line; do
      echo -e "  ${RED}✖${NC}  ${line}"
    done
    ISSUES+=("Unhealthy pods in harvester-system")
  fi

  echo ""
  info "kubevirt/cattle-system pods (non-healthy only):"
  for ns in kubevirt cattle-system; do
    UNHEALTHY=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null \
      | grep -Ev "Running|Completed" || true)
    if [[ -n "$UNHEALTHY" ]]; then
      echo "$UNHEALTHY" | while IFS= read -r line; do
        echo -e "  ${RED}✖${NC}  [${ns}] ${line}"
      done
      ISSUES+=("Unhealthy pods in ${ns}")
    else
      ok "All ${ns} pods healthy"
    fi
  done

  echo ""
  info "Longhorn volumes in harvester-system (Degraded/Faulted):"
  LH_NS=$(kubectl get ns 2>/dev/null | grep -oE 'longhorn-system|longhorn' | head -1 || true)
  if [[ -n "$LH_NS" ]]; then
    DEGRADED=$(kubectl get volumes.longhorn.io -n "${LH_NS}" --no-headers 2>/dev/null \
      | grep -Ei "degraded|faulted|error" || true)
    if [[ -z "$DEGRADED" ]]; then
      ok "No degraded or faulted Longhorn volumes"
    else
      echo "$DEGRADED" | while IFS= read -r line; do
        echo -e "  ${RED}✖${NC}  ${line}"
      done
      ISSUES+=("Degraded/Faulted Longhorn volumes detected")
    fi
  else
    info "Longhorn namespace not found — skipping volume check"
  fi

  echo ""
  info "Virtual machines:"
  VM_OUT=$(kubectl get vmi --all-namespaces --no-headers 2>/dev/null || true)
  if [[ -z "$VM_OUT" ]]; then
    info "No running VMs (VMIs) found"
  else
    TOTAL=$(echo "$VM_OUT" | wc -l)
    FAILING=$(echo "$VM_OUT" | grep -cv "Running" || true)
    ok "VM instances total: ${TOTAL}"
    if (( FAILING > 0 )); then
      warn "${FAILING} VM instance(s) not in Running state:"
      echo "$VM_OUT" | grep -v "Running" | while IFS= read -r line; do
        echo -e "  ${YELLOW}⚠${NC}  ${line}"
      done
    fi
  fi
else
  warn "kubectl not connected — skipping Harvester pod and VM checks"
fi

# ── 8. KubeVirt & Hardware Virtualisation ────────────────────
banner "8 / KubeVirt & Hardware Virtualisation"

# Nested virt check (must NOT be nested for production)
if grep -qE 'vmx|svm' /proc/cpuinfo 2>/dev/null; then
  VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
  if [[ "$VIRT_TYPE" == "none" ]]; then
    ok "Bare-metal node — hardware virtualisation enabled (vmx/svm)"
  else
    warn "Running inside VM (${VIRT_TYPE}) — nested virtualisation is NOT supported by Harvester"
  fi
else
  fail "vmx/svm CPU flag not found — hardware-assisted virtualisation disabled or unavailable"
fi

# KVM device
if [[ -e /dev/kvm ]]; then
  ok "/dev/kvm device exists"
else
  fail "/dev/kvm not found — KubeVirt cannot run VMs without KVM"
fi

# KubeVirt CRD check
if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  KV_STATUS=$(kubectl get kubevirt -n kubevirt --no-headers 2>/dev/null | head -1 || true)
  if [[ -n "$KV_STATUS" ]]; then
    if echo "$KV_STATUS" | grep -qi "deployed"; then
      ok "KubeVirt: $(echo "$KV_STATUS" | awk '{print $1, $2}')"
    else
      warn "KubeVirt status: ${KV_STATUS}"
    fi
  else
    info "KubeVirt CRD not found or not yet deployed"
  fi
fi

# ── 9. Harvester Networking ───────────────────────────────────
banner "9 / Harvester Networking"

# Management bond interface (mgmt-bo)
if ip link show mgmt-bo &>/dev/null 2>&1; then
  ok "mgmt-bo bond interface exists"
  BOND_STATE=$(ip link show mgmt-bo 2>/dev/null | grep -oP '(?<=state )\w+' | head -1 || echo "unknown")
  info "  mgmt-bo state: ${BOND_STATE}"
  if [[ "$BOND_STATE" != "UP" ]]; then
    fail "mgmt-bo interface is ${BOND_STATE} — management network may be down"
  fi
else
  info "mgmt-bo not found (may use different NIC naming or single-NIC setup)"
fi

# Management bridge (mgmt-br)
if ip link show mgmt-br &>/dev/null 2>&1; then
  ok "mgmt-br bridge interface exists"
else
  info "mgmt-br bridge not found"
fi

# Network interfaces overview
echo ""
info "Network interfaces:"
ip -brief address 2>/dev/null | while IFS= read -r line; do
  info "  ${line}"
done || true

# VLAN check — switches need trunk ports configured
echo ""
if check_cmd bridge; then
  VLAN_OUT=$(bridge vlan show 2>/dev/null | head -20 || true)
  if [[ -n "$VLAN_OUT" ]]; then
    info "VLAN config (first 20 lines):"
    echo "$VLAN_OUT" | while IFS= read -r line; do info "  ${line}"; done
  fi
fi

# Unique product_uuid check across cluster (if kubectl available)
if check_cmd kubectl && kubectl cluster-info &>/dev/null 2>&1; then
  echo ""
  info "Checking node product_uuid uniqueness:"
  UUIDS=$(kubectl get nodes \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.nodeInfo.systemUUID}{"\n"}{end}' \
    2>/dev/null || true)
  if [[ -n "$UUIDS" ]]; then
    UNIQUE=$(echo "$UUIDS" | awk '{print $2}' | sort -u | wc -l)
    TOTAL_NODES=$(echo "$UUIDS" | wc -l)
    if (( UNIQUE == TOTAL_NODES )); then
      ok "All ${TOTAL_NODES} nodes have unique product_uuid"
    else
      fail "Duplicate product_uuid detected — live migration will fail"
      echo "$UUIDS" | while IFS= read -r line; do info "  ${line}"; done
    fi
  fi
fi

# ── 10. Filesystem & Disk ─────────────────────────────────────
banner "10 / Filesystem & Disk Usage"

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

# ── 11. System Resources ──────────────────────────────────────
banner "11 / System Resources (CPU / Memory)"

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

if (( CORES < 8 )); then
  warn "CPU cores: ${CORES} — Harvester requires minimum 8 cores (16 for production)"
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

MEM_GB_INT=$(echo "$MEM_TOTAL_GB" | awk '{printf "%d", $1}')
if (( MEM_GB_INT < 32 )); then
  warn "Memory ${MEM_TOTAL_GB}GB — Harvester requires minimum 32GB (64GB for production)"
fi

SWAP_TOTAL=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
SWAP_FREE=$(grep SwapFree /proc/meminfo | awk '{print $2}')
if (( SWAP_TOTAL > 0 )); then
  SWAP_PCT=$(( (SWAP_TOTAL - SWAP_FREE) * 100 / SWAP_TOTAL ))
  if (( SWAP_PCT > 20 )); then
    warn "Swap in use — ${SWAP_PCT}%"
  else
    ok "Swap usage low — ${SWAP_PCT}%"
  fi
else
  ok "Swap disabled (recommended)"
fi

# ── 12. OOM Events ───────────────────────────────────────────
banner "12 / Recent System Events (OOM)"

if check_cmd journalctl; then
  OOM=$(journalctl -k --since "1 hour ago" 2>/dev/null \
    | grep -i "oom\|out of memory\|killed process" | tail -5 || true)
  if [[ -n "$OOM" ]]; then
    fail "OOM Killer triggered (last 1 hour):"
    echo "$OOM" | while IFS= read -r line; do echo -e "    ${RED}${line}${NC}"; done
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
echo -e "${BOLD}  Triage Summary  [Harvester ${NODE_ROLE} node: $(hostname)]${NC}"
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
echo -e "  ${CYAN}${BOLD}HARVESTER MINIMUM HARDWARE${NC}"
echo    "  ┌────────────────────────────────────┬──────────────────────────────┐"
echo    "  │ Resource                           │ Min (Dev)  / Min (Prod)      │"
echo    "  ├────────────────────────────────────┼──────────────────────────────┤"
trow2   "CPU (hardware virt required)"   "8 cores    / 16 cores"
trow2   "Memory"                         "32 GB      / 64 GB"
trow2   "Disk capacity"                  "250 GB     / 500 GB (1 TB+ rec)"
trow2   "Disk IOPS (SSD/NVMe)"          "5,000+ random IOPS per disk"
trow2   "NIC speed"                      "1 Gbps     / 10 Gbps"
trow2   "NICs (mgmt network)"            "1 req, 2 rec / 2 rec (bonded)"
echo    "  └────────────────────────────────────┴──────────────────────────────┘"
echo ""
echo -e "  ${CYAN}${BOLD}REQUIRED PORTS (management nodes)${NC}"
echo    "  ┌────────────┬──────────────────────────────────────┬──────────┐"
echo    "  │ Port       │ Purpose                              │ Required │"
echo    "  ├────────────┼──────────────────────────────────────┼──────────┤"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "2379/TCP"  "etcd client"                          "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "2380/TCP"  "etcd peer"                            "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "2381/TCP"  "etcd metrics"                         "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "6443/TCP"  "kube-apiserver"                       "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "9345/TCP"  "RKE2 supervisor"                      "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "10257/TCP" "kube-controller-manager"              "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "10259/TCP" "kube-scheduler"                       "YES"
echo    "  ├────────────┼──────────────────────────────────────┼──────────┤"
echo    "  │            │ All nodes                            │          │"
echo    "  ├────────────┼──────────────────────────────────────┼──────────┤"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "10010/TCP" "containerd (Harvester)"               "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "10250/TCP" "kubelet"                              "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "8472/UDP"  "Flannel VXLAN"                        "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "4789/UDP"  "VXLAN (VM overlay)"                   "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "9500/TCP"  "Longhorn replica"                     "YES"
printf  "  │ %-10s │ %-36s │ %-8s │\n" "443/TCP"   "Rancher integration (if used)"        "optional"
echo    "  └────────────┴──────────────────────────────────────┴──────────┘"
echo ""
echo -e "  ${CYAN}${BOLD}FILESYSTEM & RESOURCES${NC}"
echo    "  ┌────────────────────────────────────┬──────────────┬──────────────┐"
echo    "  │ Metric                             │ Warning      │ Critical     │"
echo    "  ├────────────────────────────────────┼──────────────┼──────────────┤"
trow3   "Disk usage"     ">= ${DISK_WARN}%"   ">= ${DISK_CRIT}%"
trow3   "inode usage"    ">= ${INODE_WARN}%"  ">= ${INODE_CRIT}%"
trow3   "CPU load ratio" "> 100%"              "> 200%"
trow3   "Memory usage"   ">= 85%"             ">= 95%"
echo    "  └────────────────────────────────────┴──────────────┴──────────────┘"

echo -e "\n  ${DIM}Completed at: $(date)${NC}"
echo ""