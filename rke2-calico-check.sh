#!/bin/bash

# Usage: ./rke2-calico-check.sh <TARGET_IP> <NODE_TYPE: server|agent>

TARGET_IP=$1
NODE_TYPE=$2

if [[ -z "$TARGET_IP" || -z "$NODE_TYPE" ]]; then
    echo "Usage: $0 <TARGET_IP> <server|agent>"
    echo "Example (Worker to Server): $0 10.0.0.10 server"
    exit 1
fi

# Core RKE2 Ports
SERVER_PORTS=(
    "6443 TCP Kubernetes-API"
    "9345 TCP RKE2-Supervisor"
    "2379 TCP etcd-Client"
    "2380 TCP etcd-Peer"
)
AGENT_PORTS=(
    "10250 TCP Kubelet-API"
)

# Calico Specific Ports
CALICO_PORTS=(
    "179 TCP Calico-BGP"
    "5473 TCP Calico-Typha"
    "9099 TCP Calico-Health"
    "4789 UDP Calico-VXLAN"
)

check_tcp() {
    local ip=$1 port=$2 desc=$3
    if timeout 2 bash -c "</dev/tcp/$ip/$port" 2>/dev/null; then
        echo -e "\e[32m[PASS]\e[0m $port/TCP ($desc)"
    else
        echo -e "\e[31m[FAIL]\e[0m $port/TCP ($desc) - Blocked or Service Down"
    fi
}

check_udp() {
    local ip=$1 port=$2 desc=$3
    # nc -z -u is a basic "reachability" test (checks for ICMP 'port unreachable' errors)
    if nc -z -u -w2 "$ip" "$port" 2>/dev/null; then
        echo -e "\e[33m[CHECK]\e[0m $port/UDP ($desc) - Probe sent (verify with 'tcpdump -i any port $port')"
    else
        echo -e "\e[31m[FAIL]\e[0m $port/UDP ($desc) - Likely Blocked"
    fi
}

echo "--- RKE2 Calico Connectivity Check: $TARGET_IP ($NODE_TYPE) ---"

# 1. Check Core RKE2 role ports
if [[ "$NODE_TYPE" == "server" ]]; then
    for item in "${SERVER_PORTS[@]}"; do
        read -r port proto desc <<< "$item"
        check_tcp "$TARGET_IP" "$port" "$desc"
    done
else
    for item in "${AGENT_PORTS[@]}"; do
        read -r port proto desc <<< "$item"
        check_tcp "$TARGET_IP" "$port" "$desc"
    done
fi

# 2. Check Calico CNI ports (required on all nodes)
echo "--- Calico CNI Stack ---"
for item in "${CALICO_PORTS[@]}"; do
    read -r port proto desc <<< "$item"
    if [[ "$proto" == "UDP" ]]; then
        check_udp "$TARGET_IP" "$port" "$desc"
    else
        check_tcp "$TARGET_IP" "$port" "$desc"
    fi
done
