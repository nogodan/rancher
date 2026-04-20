#!/bin/bash

# ==============================================================================
# SCRIPT: etcd_check.sh
# DESCRIPTION: Diagnoses RKE2 ETCD cluster health, performance, and logs.
# USAGE: ./etcd_check.sh (All output is directed to stdout)
# NOTE: To capture output to file as discussed, run:
#       ./etcd_check.sh 2>&1 | tee etcd_report.txt
# ==============================================================================

# --- Environment Setup ---
# Set the config file for crictl to interact with RKE2 runtime
export CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml

# Update PATH to include RKE2 binaries so we don't have to use full paths every time
PATH="$PATH:/var/lib/rancher/rke2/bin"

# --- Helper Functions ---
# Prints 3 empty lines and a header to make the log readable
section_header() {
    printf "\n\n\n"
    echo "======================================================================"
    echo ">>> $1"
    echo "======================================================================"
}

# --- Variable Initialization ---
# Identify the active ETCD container ID
etcdcontainer=$(crictl ps --label io.kubernetes.container.name=etcd --quiet)

# Define paths to ETCD certificates required for authentication
ETCD_CERT=/var/lib/rancher/rke2/server/tls/etcd/server-client.crt
ETCD_KEY=/var/lib/rancher/rke2/server/tls/etcd/server-client.key
ETCD_CACERT=/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt

# Validate if container was found before proceeding
if [ -z "$etcdcontainer" ]; then
    echo "ERROR: ETCD container not found! Is RKE2 running?"
    exit 1
fi

# Define the base command for etcdctl to avoid repetition
# This executes etcdctl INSIDE the container using the local certificates
ETCDCTL_CMD="crictl exec ${etcdcontainer} etcdctl --cert ${ETCD_CERT} --key ${ETCD_KEY} --cacert ${ETCD_CACERT}"

# Dynamically build the list of all cluster endpoints by parsing 'member list'
# This ensures commands check the health of the WHOLE cluster, not just the local node
ETCDCTL_ENDPOINTS=$($ETCDCTL_CMD member list | cut -d, -f5 | sed -e 's/ //g' | paste -sd ',')

# --- Execution ---

section_header "Checking ETCD container runtime status"
# Shows status, image, and uptime of the etcd container
crictl ps --name etcd

section_header "Collecting last 200 lines of ETCD logs"
# Removed '-f' (follow) because it would cause the script to hang forever
crictl logs --tail 200 "$etcdcontainer"

section_header "ETCD Performance Check (Disk/Network Latency)"
# Runs a 60-second simulated workload to check if disk IO is sufficient
$ETCDCTL_CMD --endpoints="$ETCDCTL_ENDPOINTS" check perf

section_header "Cluster Member List"
# Lists all members in the ETCD quorum and their status
$ETCDCTL_CMD --endpoints="$ETCDCTL_ENDPOINTS" --write-out table member list

section_header "Endpoint Status (Database Size & Raft Index)"
# Displays DB size and drift between nodes. Useful for finding out-of-sync nodes.
$ETCDCTL_CMD --endpoints="$ETCDCTL_ENDPOINTS" endpoint status --write-out=table

section_header "Endpoint Health"
# Simple check to see if endpoints are responding to heartbeats
$ETCDCTL_CMD --endpoints="$ETCDCTL_ENDPOINTS" endpoint health --write-out=table

section_header "Active Alarms"
# Checks for 'NOSPACE' or 'CORRUPT' alarms that stop write operations
$ETCDCTL_CMD --endpoints="$ETCDCTL_ENDPOINTS" alarm list

section_header "Disarming Alarms"
# Attempts to clear alarms. Note: If NOSPACE persists, you must defrag first.
$ETCDCTL_CMD --endpoints="$ETCDCTL_ENDPOINTS" alarm disarm

section_header "Local Metrics (Disk IO Check)"
# Scrapes the Prometheus metrics endpoint for raw disk/request latency data
curl -s --connect-timeout 5 "http://127.0.0.1:2381/metrics" | grep -E "etcd_disk|etcd_server" | head -n 20

echo -e "\n\n--- Diagnostics Complete ---"