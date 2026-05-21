#!/bin/bash
# This script uses kubectl to auto-discover your cluster's topology and validates the essential port requirements for RKE2 and Rancher communication.
# run this script on one of controller nodes
# Updated KUBECONFIG location
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml

# Check if KUBECONFIG exists
if [ ! -f "$KUBECONFIG" ]; then
    printf "[ERROR] KUBECONFIG not found at %s\n" "$KUBECONFIG"
    exit 1
fi

# Function to provide port details (Replaces declare -A for compatibility)
get_port_info() {
    case "$1" in
        6443) echo "Kubernetes API Server - Required for all nodes and kubectl" ;;
        9345) echo "RKE2 Supervisor API - Essential for node registration and join" ;;
        2379) echo "etcd Client Port - Required for database access on controllers" ;;
        2380) echo "etcd Peer Port - Required for high-availability controller sync" ;;
        10250) echo "Kubelet API - Required for metrics-server and log retrieval" ;;
        8472) echo "VXLAN (UDP) - Required for Flannel/Cilium pod-to-pod networking" ;;
        443) echo "Rancher HTTPS - Required for downstream cluster-agent heartbeats" ;;
        *) echo "Kubernetes internal communication port" ;;
    esac
}

# Auto-discover Node IPs
CONTROLLER_IPS=$(kubectl get nodes -l node-role.kubernetes.io/control-plane=true -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
WORKER_IPS=$(kubectl get nodes -l 'node-role.kubernetes.io/control-plane!=true' -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
RANCHER_URL=$(kubectl get ingress -n cattle-system rancher -o jsonpath='{.spec.rules.host}' 2>/dev/null)

check_port() {
    local ip=$1
    local port=$2
    local protocol=$3
    local status=1

    if [[ "$protocol" == "udp" ]]; then
        nc -z -u -v -w 2 "$ip" "$port" &>/dev/null
        status=$?
    else
        # Try curl first (handles RKE2 SSL ports)
        curl --insecure --silent --max-time 2 "https://$ip:$port" &>/dev/null
        status=$?

        # Fallback to raw TCP socket (standard bash)
        if [ $status -ne 0 ]; then
            timeout 2 bash -c "</dev/tcp/$ip/$port" &>/dev/null
            status=$?
        fi
    fi

    if [ $status -eq 0 ]; then
        printf "  [\033[32mPASS\033[0m] %s:%s (%s)\n" "$ip" "$port" "$protocol"
    else
        printf "  [\033[31mFAIL\033[0m] %s:%s (%s)\n" "$ip" "$port" "$protocol"
        printf "         \033[90m↳ Purpose: %s\033[0m\n" "$(get_port_info "$port")"
    fi
}

echo "--- 1. RKE2 Controller Mesh Check ---"
for target in $CONTROLLER_IPS; do
    echo "Node: $target"
    for port in 6443 9345 2379 2380 10250; do check_port "$target" "$port" "tcp"; done
    check_port "$target" 8472 "udp"
done

echo -e "\n--- 2. Worker Connectivity Check ---"
for target in $WORKER_IPS; do
    echo "Node: $target"
    check_port "$target" 10250 "tcp"
    check_port "$target" 8472 "udp"
done

echo -e "\n--- 3. Rancher Downstream Check ---"
if [ -n "$RANCHER_URL" ]; then
    echo "Targeting Rancher: $RANCHER_URL"
    check_port "$RANCHER_URL" 443 "tcp"
else
    echo "Rancher URL not detected via Ingress."
fi