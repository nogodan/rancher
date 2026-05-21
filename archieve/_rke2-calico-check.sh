#!/bin/bash

# --- CONFIGURATION ---
# Use the first argument as the Server IP
SERVER_IP=$1
EXPECTED_MTU=1450 
RKE2_SOCK="unix:///run/k3s/containerd/containerd.sock"

# Check if IP argument is provided
if [ -z "$SERVER_IP" ]; then
  echo "Usage: sudo $0 <SERVER_IP>"
  echo "Example: sudo $0 192.168.1.50"
  exit 1
fi

echo "=== 1. SERVICE STATUS CHECK ==="
if systemctl is-active --quiet rke2-server || systemctl is-active --quiet rke2-agent; then
  echo "[OK] RKE2 service is running."
else
  echo "[FAIL] RKE2 service is NOT running. Check 'systemctl status rke2-server/agent'."
fi

echo -e "\n=== 2. CALICO & RKE2 PORT AVAILABILITY (Target: $SERVER_IP) ==="
# TCP: 179 (BGP), 5473 (Typha), 9099 (Health), 6443 (API), 9345 (Supervisor), 10250 (Kubelet)
# UDP: 4789 (VXLAN)
for port in 179 4789 5473 9099 6443 9345 10250; do
  PROTO="TCP"; [[ "$port" == "4789" ]] && PROTO="UDP"
  
  if [[ "$PROTO" == "UDP" ]]; then
    # Timeout 2s, zero-I/O mode
    nc -z -u -w 2 $SERVER_IP $port > /dev/null 2>&1
  else
    nc -zv -w 2 $SERVER_IP $port > /dev/null 2>&1
  fi

  if [[ $? -eq 0 ]]; then
    echo "[OK] Port $port ($PROTO) is reachable."
  else
    echo "[FAIL] Port $port ($PROTO) is BLOCKED or service is down."
  fi
done

echo -e "\n=== 3. MTU MISMATCH & PATH FRAGMENTATION CHECK ==="
PAYLOAD_SIZE=$((EXPECTED_MTU - 28))
if ping -c 2 -M do -s $PAYLOAD_SIZE $SERVER_IP > /dev/null 2>&1; then
  echo "[OK] Path supports MTU $EXPECTED_MTU without fragmentation."
else
  echo "[WARN] MTU Issue! Packets larger than $PAYLOAD_SIZE bytes are being dropped."
  echo "      Verify firewall/cloud network MTU settings."
fi

echo -e "\n=== 4. CALICO CNI & INTERFACE CHECK ==="
CNI_IFACE=$(ip link show | grep -oE "vxlan.calico|tunl0" | head -1)
if [[ -n "$CNI_IFACE" ]]; then
  CNI_MTU=$(ip link show $CNI_IFACE | grep -oP 'mtu \K\d+')
  echo "[OK] Calico interface ($CNI_IFACE) found. MTU: $CNI_MTU"
else
  echo "[FAIL] No Calico interfaces (vxlan/tunl0) found. Pod network may not be initialized."
fi

echo -e "\n=== 5. CONTAINER LOGS (CALICO-NODE) ==="
# Use explicit RKE2 socket to avoid CRI connection errors
CALICO_POD_ID=$(sudo /var/lib/rancher/rke2/bin/crictl --runtime-endpoint $RKE2_SOCK ps --name calico-node -q | head -1)

if [[ -n "$CALICO_POD_ID" ]]; then
  echo "Checking last 5 errors in calico-node pod ($CALICO_POD_ID):"
  sudo /var/lib/rancher/rke2/bin/crictl --runtime-endpoint $RKE2_SOCK logs "$CALICO_POD_ID" 2>&1 | grep -iE "error|fail|fatal|refused" | tail -n 5
else
  echo "[FAIL] calico-node container not found via crictl. Checking journal logs..."
  sudo journalctl -u rke2-server --no-pager -n 10 | grep -i "calico"
fi
