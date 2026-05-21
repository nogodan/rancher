# 🩺 SUSE / RKE2 Kubernetes Triage Scripts

A collection of emergency triage shell scripts for quickly diagnosing common issues on **SUSE / RKE2-based Kubernetes** infrastructure. Designed for support engineers and platform teams who need fast root-cause visibility when a customer opens a critical case.

Each script runs in under a minute (except `etcd check perf` which takes ~30s), requires no dependencies beyond standard shell tools, and prints a colour-coded summary of critical issues and warnings at the end.

---

## Scripts

| Script | Target node | Use when |
|---|---|---|
| [`controller_triage.sh`](#-k8s-triagesh--rke2-controller-node) | RKE2 controller / management node | API server unreachable, etcd issues, cluster-wide problems |
| [`worker_triage.sh`](#-k8s-worker-triagesh--rke2-worker-node) | RKE2 worker node | Node NotReady, workloads not scheduling, kubelet issues |
| [`longhorn_triage.sh`](#-longhorn-triagesh--longhorn-storage-node) | Longhorn storage node | PVC stuck Pending, volume degraded, iSCSI errors |
| [`harvester_triage.sh`](#-harvester-triagesh--harvester-hci-node) | Harvester HCI node | VM not starting, Harvester node unhealthy, storage/network issues |

---

## Quick Usage

All scripts must be run as **root** (`sudo`). They are safe to run on live production nodes — they are read-only and make no changes to the system.

### 🖥️ controller_triage.sh — RKE2 Controller Node

Run directly on the **controller / management node**:

```bash
# Download and run
curl -sL https://raw.githubusercontent.com/nogodan/rancher/main/controller_triage.sh | sudo bash

# Or download first, inspect, then run
curl -sLO https://raw.githubusercontent.com/nogodan/rancher/main/controller_triage.sh
chmod +x controller_triage.sh
sudo ./controller_triage.sh
```

**What it checks:**

| Section | Description |
|---|---|
| 0 / Pre-flight | OS, hostname, uptime, kubectl availability |
| 1 / Filesystem & Disk Usage | Disk usage (warn ≥80%, crit ≥90%), inode usage |
| 2 / etcd Disk I/O Latency | `fio` fsync p99 latency (fail >10ms), `dd` fallback |
| 3 / Required Port Listening | etcd 2379/2380, apiserver 6443, kubelet 10250, RKE2 9345 |
| 4 / Network Connectivity | Authenticated apiserver `/healthz`, etcd health via `crictl exec` |
| 4.5 / DNS Resolution | CoreDNS direct query (bypasses host resolver), external DNS |
| 5 / System Resources | CPU load ratio, memory usage, swap status |
| 6 / Service Status | `rke2-server`, `rke2-agent`, `kubelet` — RKE2-aware (no containerd false-positives) |
| 7 / kubectl Cluster State | Node status, unhealthy pods in `kube-system`, Pending PVCs |
| 8 / OOM Events | Kernel OOM killer events in last 1 hour |
| 9 / Kernel Parameters | `ip_forward`, `bridge-nf-call-iptables`, `br_netfilter`, `overlay` modules |

**etcd deep-dive** (runs automatically on management nodes with RKE2 certs):
```
etcdctl endpoint health   --write-out=table
etcdctl endpoint status   --write-out=table
etcdctl member list       --write-out=table
etcdctl alarm list
etcdctl check perf                           (~30s)
```

---

### 👷 worker_triage.sh — RKE2 Worker Node

Requires the **controller IP** as an argument:

```bash
# Download and run
curl -sL https://raw.githubusercontent.com/nogodan/rancher/main/worker_triage.sh \
  | sudo bash -s -- <CONTROLLER_IP>

# Or download first, inspect, then run
curl -sLO https://raw.githubusercontent.com/nogodan/rancher/main/worker_triage.sh
chmod +x worker_triage.sh
sudo ./worker_triage.sh 10.0.0.10
```

**What it checks:**

| Section | Description |
|---|---|
| 0 / Pre-flight | OS, hostname, uptime, worker IP |
| 1 / Basic Reachability | ICMP ping + traceroute to controller |
| 2 / RKE2 Control Plane Ports | TCP reachability from worker → controller: 9345, 6443, 8472/UDP (Flannel), WireGuard, BGP |
| 3 / kube-apiserver Health | Authenticated `/healthz` on controller |
| 4 / RKE2 Agent Registration | `https://<CONTROLLER>:9345/cacerts` reachability and CA cert |
| 5 / DNS Resolution | CoreDNS IP discovery → direct query, external DNS |
| 6 / Worker Node Local Services | `rke2-agent`, `kubelet` — no false-positives for RKE2-managed containerd |
| 7 / Filesystem & Disk Usage | All mounts + inode usage |
| 8 / System Resources | CPU load, memory, swap |
| 9 / Kernel Parameters | Required sysctl and kernel modules |
| 10 / OOM Events | journalctl / dmesg OOM scan |

> **Note:** The script checks ports in **both directions** — outbound from the worker to the controller (TCP 9345, 6443, etc.) and local listening ports that the controller needs to reach on the worker (TCP 10250 kubelet, 10256 kube-proxy).

---

### 💾 longhorn_triage.sh — Longhorn Storage Node

Run on any node in a Longhorn cluster:

```bash
# Download and run
curl -sL https://raw.githubusercontent.com/nogodan/rancher/main/longhorn_triage.sh | sudo bash

# Override the default Longhorn data path if needed
LONGHORN_DATA_PATH=/custom/path \
  curl -sL https://raw.githubusercontent.com/nogodan/rancher/main/longhorn_triage.sh | sudo bash

# Or download first, inspect, then run
curl -sLO https://raw.githubusercontent.com/nogodan/rancher/main/longhorn_triage.sh
chmod +x longhorn_triage.sh
sudo ./longhorn_triage.sh
```

**What it checks:**

| Section | Description |
|---|---|
| 0 / Pre-flight | OS, hostname, kernel version |
| 1 / Longhorn Prerequisites | `iscsid` / `iscsi.service` / `iscsid.socket` (socket-activation aware — no false-positives on SLES/SLE Micro), `iscsiadm`, `iscsi_tcp` module (flags missing `kernel-default` on SLES), NFS client, mount propagation, required CLI tools (`curl findmnt awk blkid lsblk`), `multipathd` conflict detection |
| 2 / Longhorn Data Disk | Usage + inode on `/var/lib/longhorn`, filesystem type (ext4/xfs check), `lsblk` overview, `fio` fsync latency |
| 3 / Longhorn Pods & CRDs | Namespace detection, pod health, `nodes.longhorn.io` status, degraded/faulted volumes, failed replicas |
| 4 / iSCSI Targets & Sessions | Active iSCSI sessions, initiator name in `/etc/iscsi/initiatorname.iscsi` |
| 5 / Longhorn Network Ports | Local port 9500 (engine/replica), inter-node TCP 9500 to all cluster peers |
| 6 / Filesystem & Disk Usage | All mounts + inode |
| 7 / System Resources | CPU/memory with Longhorn minimum hw check (4 vCPU / 8 GB) |
| 8 / OOM Events | journalctl / dmesg OOM scan |

**Common Longhorn issues diagnosed:**
- `iscsid` not running or `iscsi_tcp` module missing → PVC stuck Pending
- `multipathd` active → volume attach/detach failures
- `kernel-default-base` instead of `kernel-default` on SLES → `iscsi_tcp` not loadable
- Disk fsync >10ms → replica rebuild timeouts
- Inter-node TCP 9500 blocked → replica scheduling failures

---

### 🌾 harvester_triage.sh — Harvester HCI Node

Run on any Harvester node (auto-detects management vs compute role):

```bash
# Download and run
curl -sL https://raw.githubusercontent.com/nogodan/rancher/main/harvester_triage.sh | sudo bash

# Or download first, inspect, then run
curl -sLO https://raw.githubusercontent.com/nogodan/rancher/main/harvester_triage.sh
chmod +x harvester_triage.sh
sudo ./harvester_triage.sh
```

**What it checks:**

| Section | Description |
|---|---|
| 0 / Pre-flight | OS, hostname, node role (management / compute), `product_uuid` (unique per node — required for live migration), vmx/svm CPU flag |
| 1 / Harvester & RKE2 Services | `rke2-server`/`rke2-agent`, `iscsid` stack (socket-activation aware), KubeVirt handlers |
| 2 / etcd Health | (management nodes only) Full etcd suite: endpoint health, status, member list, alarm list, `check perf` |
| 3 / Required Ports — Local | Split by role: management (etcd 2379/2380, apiserver 6443, RKE2 9345, scheduler/controller) vs all-nodes (kubelet 10250, containerd 10010, VXLAN 8472/4789) |
| 4 / Inter-node Connectivity | TCP reachability to all peer nodes: 9345, 6443, 10250, 9500 (Longhorn), 2379/2380 (mgmt↔mgmt only) |
| 5 / kube-apiserver Health | Authenticated `/healthz` with RKE2 client certs fallback |
| 6 / DNS Resolution | CoreDNS at Harvester default `10.53.0.10` (auto-detected from kubelet config, kubectl, or default) |
| 7 / Harvester Pods & VM Health | `harvester-system`, `kubevirt`, `cattle-system` pod health, Longhorn volume status, VMI running state |
| 8 / KubeVirt & Hardware Virt | `/dev/kvm` device, bare-metal vs nested detection, KubeVirt CRD status |
| 9 / Harvester Networking | `mgmt-bo` bond, `mgmt-br` bridge, interface overview, VLAN config, duplicate `product_uuid` check across all nodes |
| 10 / Filesystem & Disk Usage | All mounts + inode |
| 11 / System Resources | CPU/memory with Harvester minimum hw check (8 cores dev / 16 prod, 32 GB dev / 64 GB prod) |
| 12 / OOM Events | journalctl / dmesg OOM scan |

**Common Harvester issues diagnosed:**
- Duplicate `product_uuid` → VM live migration failures
- `vmx`/`svm` not present or `/dev/kvm` missing → VMs fail to start
- `mgmt-bo` bond DOWN → management network loss
- Inter-node 9500 blocked → Longhorn replica failures in embedded storage
- `iscsid` not enabled → Longhorn volumes unattachable

---

## Output Format

All scripts use the same colour-coded output:

```
✔  green   — check passed
⚠  yellow  — warning (investigate, may not be critical)
✖  red     — critical issue (likely root cause)
ℹ  dim     — informational
```

Each script ends with two sections:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Triage Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✖  Critical issues (2):
     1. Port 2379 NOT listening — etcd client
     2. etcd endpoint health FAILED

  ⚠  Warnings (1):
     1. Disk WARNING 85% used — /var/lib/longhorn

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Normal Threshold Reference
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Requirements

| Tool | Required by | Notes |
|---|---|---|
| `bash` 4.0+ | all scripts | Standard on all SLES/SLE Micro nodes |
| `systemctl` | all scripts | Service status checks |
| `ss` or `netstat` | all scripts | Port listening checks |
| `curl` | all scripts | HTTP health checks |
| `crictl` | controller, harvester | Auto-added via `/var/lib/rancher/rke2/bin` |
| `etcdctl` | controller, harvester | Auto-added via `/var/lib/rancher/rke2/bin` |
| `kubectl` | all scripts | Optional — kubeconfig auto-imported from RKE2 path |
| `nc` | worker, longhorn, harvester | TCP port checks (fallback to `/dev/tcp`) |
| `fio` | controller, longhorn | Disk latency test (falls back to `dd` if absent) |
| `iscsiadm` | longhorn, harvester | iSCSI session check |
| `nslookup` or `dig` | all scripts | DNS resolution check |

> Scripts degrade gracefully — if a tool is missing, the relevant check is skipped with a warning rather than failing the entire script.

---

## Environment Variables

| Variable | Script | Default | Description |
|---|---|---|---|
| `LONGHORN_DATA_PATH` | `longhorn_triage.sh` | `/var/lib/longhorn` | Override Longhorn data directory |
| `KUBECONFIG` | all scripts | auto-detected | Override kubeconfig path |

---

## False-positive Notes

These are known behaviours that the scripts handle correctly and will **not** produce warnings:

| Behaviour | Why it's normal |
|---|---|
| `containerd` service inactive | RKE2 manages its own containerd binary — no system unit exists |
| `kubelet` service inactive | RKE2 embeds kubelet — no standalone systemd unit on RKE2 nodes |
| `docker` not present | RKE2/k3s/Harvester do not use Docker |
| `iscsid.service` inactive | Socket-activated on SLES/SLE Micro via `iscsid.socket` — idle state is normal |
| `iscsi.service` active (exited) | Successfully scanned targets on boot — exited state is healthy |
| apiserver returning HTTP 401/403 | apiserver is running; 401/403 just means auth required — scripts retry with client certs |
| `rke2-agent` inactive on controller | Controller runs `rke2-server`, not `rke2-agent` — inactive is expected |

---

## Repo Structure

```
.
├── controller_triage.sh            # RKE2 controller / management node
├── worker_triage.sh     # RKE2 worker node (requires CONTROLLER_IP arg)
├── longhorn_triage.sh       # Longhorn storage node
├── harvester_triage.sh      # Harvester HCI node (management + compute)
└── README.md
```

---

## Contributing

Pull requests welcome. When adding new checks, follow the existing conventions:

- Use `ok`, `warn`, `fail`, `info` helper functions — never raw `echo` for check results
- Add items to `ISSUES[]` for critical failures and `WARNINGS[]` for non-critical
- Use `systemctl cat <unit>.service` to verify a unit file actually exists before calling `is-active` (prevents false-positives from stale systemd database entries)
- Test against real RKE2, k3s, SLES, and SLE Micro nodes before submitting

---

## License

Apache 2.0
