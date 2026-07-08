#!/usr/bin/env python3
"""Rancher Log Bundle Triage - Python 3 OOP Implementation.

Analyzes a Rancher v2.x log bundle produced by rancher2_logs_collector.sh.
Bug signatures are loaded from an external 'bug_signatures.txt' file located
next to this script, allowing detection rules to be maintained separately
from the analysis code.
"""

import tarfile
import os
import re
import sys
import tempfile
import shutil
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union


# ─── Data Models ─────────────────────────────────────────────────
@dataclass
class LogIssue:
    """Represents a single finding during analysis."""
    level: str
    message: str


@dataclass
class BugSignature:
    """A single bug signature loaded from bug_signatures.txt."""
    bug_id: str
    description: str
    affects: str
    severity: str            # FAIL | WARN
    scopes: List[str]        # e.g., ["pods_log:*.log"]
    pattern: str             # regex alternation
    threshold: int
    operator: str            # > | ==0 | version
    condition: str           # none | calico_skip | version_2.7.2_only


class TriageResult:
    """Accumulates issues, warnings, and bug detection statuses."""
    def __init__(self):
        self.issues: List[str] = []
        self.warnings: List[str] = []
        self.bug_status: Dict[str, str] = {}  # filled from loaded signatures

    def add_issue(self, msg: str):
        self.issues.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)

    @property
    def has_issues(self) -> bool:
        return bool(self.issues)

    def get_status(self, key: str) -> str:
        return self.bug_status.get(key, "SKIP")

    def set_status(self, key: str, status: str):
        self.bug_status[key] = status


# ─── Signature File Loader ──────────────────────────────────────────
def load_bug_signatures(sig_file: Path) -> List[BugSignature]:
    """Loads bug signatures from a pipe-delimited text file.

    Lines beginning with '#' are treated as comments and skipped.
    Each non-comment line must contain 9 pipe-separated fields:
        ID | Description | Affects | Severity | Scope | Pattern |
        Threshold | Operator | Condition
    """
    sigs: List[BugSignature] = []
    if not sig_file.exists():
        return sigs

    with open(sig_file, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 9:
                continue
            try:
                sig = BugSignature(
                    bug_id=parts[0],
                    description=parts[1],
                    affects=parts[2],
                    severity=parts[3].upper(),
                    scopes=[s.strip() for s in parts[4].split(',') if s.strip()],
                    pattern=parts[5],
                    threshold=int(parts[6]),
                    operator=parts[7].strip(),
                    condition=parts[8].strip(),
                )
                sigs.append(sig)
            except Exception:
                continue
    return sigs


# ─── Utility Functions ──────────────────────────────────────────────
def safe_int(val) -> int:
    if isinstance(val, int):
        return val
    if not val:
        return 0
    match = re.search(r'\d+', str(val))
    return int(match.group()) if match else 0


def strip_ansi(text: str) -> str:
    return text.replace('\033', '')


def read_file(path: Path, strip_esc: bool = False) -> str:
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
        return strip_ansi(content) if strip_esc else content
    except Exception:
        return ""


def sgrep(pattern: str, path: Path, count_only: bool = False) -> Union[str, int]:
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
        if count_only:
            return len(re.findall(pattern, content, re.IGNORECASE))
        matches = [line.strip() for line in content.splitlines()
                   if re.search(pattern, line, re.IGNORECASE)]
        return "\n".join(matches)
    except Exception:
        return "" if not count_only else 0


def print_box(title: str):
    width = 64
    print("")
    print("━" * width)
    print(f"  {title}")
    print("━" * width)


def print_section(title: str):
    print(f"\n  --- {title}")


def fmt(level: str, msg: str) -> str:
    return f"  [{level:<7}] {msg}"


def ok(msg: str) -> str:   return fmt("OK", msg)
def warn(msg: str) -> str: return fmt("WARN", msg)
def fail(msg: str) -> str: return fmt("FAIL", msg)
def info(msg: str) -> str: return fmt("INFO", msg)
def section(title: str):   print_section(title)


# ─── Core Analyzer Class ──────────────────────────────────────────
class BundleAnalyzer:
    """Main orchestrator for extracting and analyzing the Rancher bundle."""

    def __init__(self, bundle_path: str, signatures: List[BugSignature]):
        self.bundle_path = Path(bundle_path)
        self.bundle_name = self.bundle_path.name
        self.work_dir = Path(tempfile.mkdtemp(prefix="rancher-triage-"))
        self.signatures = signatures

        self.root: Optional[Path] = None
        self.sysinfo: Optional[Path] = None
        self.networking: Optional[Path] = None
        self.distro_dir: Optional[Path] = None
        self.distro: str = "unknown"
        self.kubectl_dir: Optional[Path] = None
        self.pods_dir: Optional[Path] = None
        self.etcd_dir: Optional[Path] = None
        self.result = TriageResult()

        # Initialise bug statuses from signatures file
        for sig in self.signatures:
            self.result.set_status(sig.bug_id, "SKIP")

        # Versions
        self.rancher_version: str = ""
        self.k8s_version: str = ""
        self.rke2_version: str = ""

        # CNI/CSI
        self.cni: str = "unknown"
        self.cni_version: str = ""
        self.cni_source: str = ""

        # CPU/Memory
        self.cpu_count: int = 1
        self.load1: float = 0.0
        self.load5: float = 0.0
        self.load15: float = 0.0
        self.cpu_user: str = "0"
        self.cpu_sys: str = "0"
        self.cpu_iowait: str = "0"
        self.cpu_steal: str = "0"
        self.used_pct: int = 0

        # I/O state
        self.max_await: float = 0.0
        self.max_util: float = 0.0

    def add_issue(self, msg: str):
        self.result.add_issue(msg)

    # ────────────────────────────────────────────────────────────────
    def extract(self):
        print(fmt("INFO", "Extracting..."))
        try:
            with tarfile.open(self.bundle_path, 'r:gz') as tar:
                tar.extractall(path=str(self.work_dir))
        except tarfile.TarError:
            print("ERROR: Extract failed — not a valid tar.gz?")
            sys.exit(1)

        sysinfo_dirs = [d for d in self.work_dir.rglob("systeminfo") if d.is_dir()]
        self.root = sysinfo_dirs[0].parent if sysinfo_dirs else self.work_dir

        self.sysinfo = self.root / "systeminfo" if (self.root / "systeminfo").is_dir() else None
        self.networking = self.root / "networking" if (self.root / "networking").is_dir() else None

        for d in ["rke2", "k3s", "rke", "kubeadm"]:
            if (self.root / d).is_dir():
                self.distro_dir = self.root / d
                self.distro = d
                break

        self.kubectl_dir = self.distro_dir / "kubectl" if self.distro_dir else None
        self.pods_dir = self.distro_dir / "podlogs" if self.distro_dir else None

        candidates = [self.root / "etcd", self.distro_dir / "etcd"] if self.distro_dir else [self.root / "etcd"]
        for c in candidates:
            if c and c.is_dir():
                self.etcd_dir = c
                break

        print(fmt("INFO", f"Bundle root: {self.root}"))

    # ────────────────────────────────────────────────────────────────
    #  0. Versions & Environment
    # ────────────────────────────────────────────────────────────────
    def analyze_versions(self):
        print_box("0 / Bundle Overview — Versions & Environment")
        print(fmt("INFO", f"K8s distro : {self.distro}"))

        versions_file = self.root / "versions"
        if not versions_file.exists():
            return

        lines = read_file(versions_file).splitlines()
        i = 0
        in_section = False

        def classify_helm(first_data: str) -> str:
            if re.match(r'rke2-', first_data): return "Helm Releases (kube-system)"
            if re.match(r'(mcc-|rancher-)', first_data): return "Helm Releases (cattle-system / managed)"
            if re.match(r'fleet-', first_data): return "Helm Releases (fleet-agent)"
            return "Helm Releases"

        while i < len(lines):
            line = lines[i]
            if not line:
                i += 1
                continue

            if "NAME IMAGE" in line or (line.startswith("NAME ") and "IMAGE" in line):
                if in_section: print()
                print_section("Pods with Container Images:")
                in_section = True
                print(fmt("INFO", f"  {line}"))
            elif "NAME CHART " in line:
                if in_section: print()
                in_section = True
                next_data = ""
                for j in range(i + 1, min(i + 5, len(lines))):
                    c = lines[j]
                    if c and "NAME CHART" not in c and "NAMESPACE" not in c and "NAME IMAGE" not in c:
                        next_data = c
                        break
                print_section(classify_helm(next_data))
                print(fmt("INFO", f"  {line}"))
            elif "NAMESPACE " in line:
                if in_section: print()
                print_section("Namespaced Resources:")
                in_section = True
                print(fmt("INFO", f"  {line}"))
            else:
                print(fmt("INFO", f"  {line}"))
            i += 1

    def detect_versions(self):
        print_section("Version Detection:")

        pods_file = self.kubectl_dir / "pods" if self.kubectl_dir else None
        if pods_file and pods_file.exists():
            content = read_file(pods_file)
            m = re.search(r'(rancher-agent:|rancher/rancher:)(v[0-9]+\.[0-9]+\.[0-9]+[^ "]*)', content)
            if m: self.rancher_version = m.group(2)

        versions_file = self.root / "versions"
        if not self.rancher_version and versions_file.exists():
            content = read_file(versions_file)
            m = re.search(r'(rancher-agent:|rancher/rancher:)(v[0-9]+\.[0-9]+\.[0-9]+[^ "]*)', content)
            if m: self.rancher_version = m.group(2)

        if self.rancher_version:
            print(fmt("INFO", f"Rancher version : {self.rancher_version}"))
        else:
            print(fmt("WARN", "Rancher version : unable to detect (may be downstream cluster only)"))

        kv_file = self.sysinfo / "kubeversion" if self.sysinfo else None
        if kv_file and kv_file.exists():
            self.k8s_version = read_file(kv_file).strip()
        if not self.k8s_version and pods_file and pods_file.exists():
            m = re.search(r'(v[0-9]+\.[0-9]+\.[0-9]+)', read_file(pods_file))
            if m: self.k8s_version = m.group(1)
        print(fmt("INFO", f"Kubernetes       : {self.k8s_version or 'unable to detect'}"))

        rke2_ver_file = self.sysinfo / "rke2-version" if self.sysinfo else None
        if rke2_ver_file and rke2_ver_file.exists():
            self.rke2_version = read_file(rke2_ver_file).strip()
        if not self.rke2_version and self.sysinfo:
            pkg_file = self.sysinfo / "packages"
            if pkg_file and pkg_file.exists():
                m = re.search(r'(rke2-server|rke2-agent)[\s-]+([0-9]+\.[0-9]+[^\s]*)', read_file(pkg_file))
                if m: self.rke2_version = f"v{m.group(2)}"
        if self.rke2_version:
            print(fmt("INFO", f"RKE2 version    : {self.rke2_version}"))

    def analyze_os(self):
        print_section("Operating System:")
        osrel = self.sysinfo / "osrelease" if self.sysinfo else None
        if osrel and osrel.exists():
            content = read_file(osrel, strip_esc=True)
            m = re.search(r'PRETTY_NAME="([^"]+)"', content)
            if m: print(fmt("INFO", f"Distribution    : {m.group(1)}"))
            m = re.search(r'^ID="?([^"\n]+)"?', content, re.MULTILINE)
            if m: print(fmt("INFO", f"OS ID           : {m.group(1)}"))
            m = re.search(r'^VERSION_ID="?([^"\n]+)"?', content, re.MULTILINE)
            if m: print(fmt("INFO", f"OS Version      : {m.group(1)}"))

        uname_file = self.sysinfo / "uname" if self.sysinfo else None
        if uname_file and uname_file.exists():
            uname = read_file(uname_file)
            kern = re.search(r' (\S+) ', uname)
            arch = re.search(r'(x86_64|aarch64|arm64|s390x)', uname)
            if kern: print(fmt("INFO", f"Kernel          : {kern.group(1)}"))
            if arch:  print(fmt("INFO", f"Architecture    : {arch.group(1)}"))

        virt_file = self.sysinfo / "systemd-detect-virt" if self.sysinfo else None
        if virt_file and virt_file.exists():
            vtype = read_file(virt_file).strip()
            print(fmt("INFO", f"Virtualization  : {vtype}"))
            if vtype == "none":          print("  >> Bare metal detected")
            elif vtype in ("kvm","qemu"): print("  >> KVM/QEMU virtual machine")
            elif vtype == "vmware":       print("  >> VMware virtual machine")

    def analyze_cni_csi(self):
        print_section("CNI (Container Network Interface):")
        versions_file = self.root / "versions"
        if versions_file and versions_file.exists():
            content = read_file(versions_file)
            if re.search(r'rke2-calico ', content):
                self.cni = "Calico"
                m = re.search(r'rke2-calico ([\w\.]+)', content)
                if m: self.cni_version = m.group(1)
                self.cni_source = "helm release (rke2-calico)"
            elif re.search(r'rke2-canal ', content):
                self.cni = "Canal (Flannel+Calico)"
                m = re.search(r'rke2-canal ([\w\.]+)', content)
                if m: self.cni_version = m.group(1)
                self.cni_source = "helm release (rke2-cni)"
            elif re.search(r'rke2-flannel ', content):
                self.cni = "Flannel"
                m = re.search(r'rke2-flannel ([\w\.]+)', content)
                if m: self.cni_version = m.group(1)
                self.cni_source = "helm release (rke2-flannel)"

        if self.cni == "unknown" and self.networking:
            cni_dir = self.networking / "cni"
            if cni_dir and cni_dir.exists():
                conf = next(cni_dir.glob("*.conf"), next(cni_dir.glob("*.conflist"), None))
                if conf:
                    m = re.search(r'"type":\s*"([^"]+)"', read_file(conf))
                    if m:
                        self.cni = m.group(1).capitalize()
                        self.cni_source = "CNI config"

        if self.cni == "unknown" and self.kubectl_dir:
            pods_file = self.kubectl_dir / "pods"
            if pods_file and pods_file.exists():
                content = read_file(pods_file)
                if "calico-node" in content or "calico-typha" in content: self.cni = "Calico"
                elif "kube-flannel" in content or "flannel" in content:   self.cni = "Flannel"
                elif "cilium" in content:                                  self.cni = "Cilium"
                if self.cni != "unknown": self.cni_source = "running pods"

        print(fmt("INFO", f"CNI Plugin      : {self.cni}"))
        if self.cni_version:
            print(fmt("INFO", f"CNI Version     : {self.cni_version}"))
        print(fmt("INFO", f"Detection source: {self.cni_source or 'unknown'}"))

        if versions_file and versions_file.exists():
            if "rke2-multus" in read_file(versions_file):
                m = re.search(r'rke2-multus ([\w\.]+)', read_file(versions_file))
                ver_str = f" ({m.group(1)})" if m else ""
                print(fmt("INFO", f"Multus          : detected{ver_str} — multi-network support"))

        print_section("CSI (Container Storage Interface):")
        csi_drivers = self.kubectl_dir / "csidrivers" if self.kubectl_dir else None
        csi_detected, csi_details = [], []
        if csi_drivers and csi_drivers.exists():
            for line in read_file(csi_drivers).splitlines():
                m = re.search(r'([a-z0-9.-]+\.[a-z0-9.-]+)', line)
                if m:
                    name = m.group(1)
                    if "longhorn" in name:           csi_detected.append("Longhorn"); csi_details.append(f"Longhorn (driver: {name})")
                    elif "nfs.csi.k8s.io" in name:   csi_detected.append("NFS");      csi_details.append(f"NFS CSI (driver: {name})")
                    elif "rbd.csi.ceph.com" in name: csi_detected.append("Ceph RBD"); csi_details.append(f"Ceph RBD (driver: {name})")
                    else:                            csi_detected.append(name);        csi_details.append(name)

        if not csi_detected and self.kubectl_dir:
            pods_file = self.kubectl_dir / "pods"
            if pods_file and pods_file.exists():
                content = read_file(pods_file)
                if "longhorn-csi" in content: csi_detected.append("Longhorn"); csi_details.append("Longhorn (pods)")
                if "csi-nfs" in content:      csi_detected.append("NFS");      csi_details.append("NFS CSI (pods)")
                if "csi-rbd" in content or "csi-cephfs" in content:
                    csi_detected.append("Ceph"); csi_details.append("Ceph CSI (pods)")

        if csi_detected:
            for d in csi_details: print(fmt("INFO", f"CSI Driver      : {d}"))
        else:
            print(fmt("INFO", "CSI Driver      : None detected"))

        sc_file = self.kubectl_dir / "storageclasses" if self.kubectl_dir else None
        if sc_file and sc_file.exists():
            print_section("Storage Classes:")
            sc_count = safe_int(sgrep(r'^NAME:', sc_file, count_only=True))
            if sc_count > 0:
                print(fmt("INFO", f"Found {sc_count} StorageClass(es):"))
                current_name, current_prov = "", ""
                for line in read_file(sc_file).splitlines():
                    n = re.match(r'^NAME:\s+(\S+)', line)
                    p = re.search(r'provisioner:\s+(\S+)', line)
                    if n: current_name = n.group(1)
                    if p: current_prov = p.group(1)
                    if not line.strip() and current_name:
                        print(f"  {current_name:<30} provisioner: {current_prov}")
                        current_name, current_prov = "", ""
                print(ok("Default StorageClass: " + ("None set" if not sgrep(r'is-default-class.*true', sc_file) else "detected")))
            else:
                print(ok("No default StorageClass set"))

    # ────────────────────────────────────────────────────────────────
    # 1-2. Nodes and Certs
    # ────────────────────────────────────────────────────────────────
    def analyze_nodes(self):
        print_box("1 / Node Overview")
        pods_file = self.kubectl_dir / "nodes" if self.kubectl_dir else None
        if pods_file and pods_file.exists():
            print_section("Node list:")
            for line in read_file(pods_file).splitlines():
                if "NotReady" in line:
                    print(fail(line))
                    self.result.add_issue(f"NotReady node: {line.split()[0]}")
                elif "Ready" in line:
                    print(ok(line))
                else:
                    print(fmt("INFO", line))
        else:
            print(warn("kubectl/nodes not found in bundle"))

        desc_file = self.kubectl_dir / "nodesdescribe" if self.kubectl_dir else None
        if desc_file and desc_file.exists():
            print_section("Node conditions:")
            for pressure in ["MemoryPressure:True", "DiskPressure:True", "PIDPressure:True"]:
                key = pressure.split(":")[0]
                count = safe_int(sgrep(rf"{key}.*True", desc_file, count_only=True))
                if count > 0:
                    self.result.add_issue(f"{count} node(s) with {key}")
                    print(fail(f"{count} node(s) with {key}"))
                else:
                    print(ok(f"No {key}"))

    def analyze_certs(self):
        print_box("2 / Certificate Expiry")
        cert_file = self.kubectl_dir / "certificate-check" if self.kubectl_dir else None
        if cert_file and cert_file.exists():
            print_section("Certificate check output:")
            for line in read_file(cert_file).splitlines():
                if re.search(r'expir|invalid|FAILED|error', line, re.IGNORECASE):
                    print(fail(f"  CERT: {line}"))
                elif re.search(r'warn|30 day|60 day', line, re.IGNORECASE):
                    print(warn(f"  CERT: {line}"))
                elif re.search(r'ok|valid|success', line, re.IGNORECASE):
                    print(ok(f"  {line}"))
                else:
                    print(info(f"  {line}"))

        cert_err_pat = (r'certificate has expired|certificate.*expir|x509: certificate|'
                        r'tls: .*certificate|certificate signed by unknown authority|'
                        r'certificate verify failed')
        cert_errors = 0
        cert_samples = []
        for f in list(self.root.rglob("*.log"))[:100]:
            for line in read_file(f).splitlines():
                if re.match(r'^I[0-9]', line): continue
                if re.search(cert_err_pat, line, re.IGNORECASE):
                    cert_errors += 1
                    if len(cert_samples) < 10:
                        cert_samples.append(f"  [{f.name}] {line.strip()}")

        if cert_errors > 0:
            self.result.add_issue(f"Certificate errors found in logs: {cert_errors}")
            print(fail(f"Certificate errors in logs: {cert_errors} occurrence(s)"))
            print_section("Matching lines (up to 10):")
            for s in cert_samples: print(f"    {s}")
        else:
            print(ok("No certificate expiry errors in logs"))

    # ────────────────────────────────────────────────────────────────
    # 3. Disk & etcd slow disk
    # ────────────────────────────────────────────────────────────────
    def analyze_disk(self):
        print_box("3 / Disk & Filesystem")

        dfh = self.sysinfo / "dfh" if self.sysinfo else None
        if dfh and dfh.exists():
            print_section("Disk usage:")
            for line in read_file(dfh).splitlines():
                if line.startswith("Filesystem") or "tmpfs" in line or "devtmpfs" in line:
                    continue
                m_use = re.search(r'(\d+)%\s+\S+', line)
                m_mount = re.search(r'(/\S+)$', line)
                if not m_use or not m_mount: continue
                use = int(m_use.group(1)); mount = m_mount.group(1)
                if "/containerd/" in mount or "/overlay" in mount or "/docker/" in mount: continue
                if use >= 90:   print(fail(f"Disk CRITICAL {use}% used — {mount}"))
                elif use >= 80: print(warn(f"Disk WARNING {use}% used — {mount}"))
                else:           print(ok(f"Disk OK {use}% used — {mount}"))

        dfi = self.sysinfo / "dfi" if self.sysinfo else None
        if dfi and dfi.exists():
            print_section("inode usage:")
            for line in read_file(dfi).splitlines():
                if line.startswith("Filesystem") or "tmpfs" in line or "devtmpfs" in line: continue
                m_use = re.search(r'(\d+)%\s+\S+', line)
                m_mount = re.search(r'(/\S+)$', line)
                if not m_use or not m_mount or m_use.group(1) == "-": continue
                use = int(m_use.group(1)); mount = m_mount.group(1)
                if "/containerd/" in mount or "/overlay" in mount or "/docker/" in mount: continue
                if use >= 90:   print(fail(f"inode CRITICAL {use}% — {mount}"))
                elif use >= 80: print(warn(f"inode WARNING {use}% — {mount}"))

        dmesg = self.sysinfo / "dmesg" if self.sysinfo else None
        if dmesg and dmesg.exists():
            io_errs = safe_int(sgrep(r'I/O error|blk_update_request|SCSI error|EXT4-fs error|XFS.*error', dmesg, count_only=True))
            oom_dmesg = safe_int(sgrep(r'oom_kill|Out of memory|Killed process', dmesg, count_only=True))
            if io_errs > 0:
                self.result.add_issue("Disk I/O errors in dmesg")
                print(fail(f"Disk I/O errors in dmesg: {io_errs}"))
            else:
                print(ok("No disk I/O errors in dmesg"))
            if oom_dmesg > 0: print(fail(f"OOM events in dmesg: {oom_dmesg}"))
            else:             print(ok("No OOM events in dmesg"))

        self._analyze_etcd_slow_disk()

    def _analyze_etcd_slow_disk(self):
        slow_apply_metric = slow_wal_metric = slow_log = 0
        if self.etcd_dir and self.etcd_dir.exists():
            for mfile in self.etcd_dir.glob("etcd-metrics-*.txt"):
                if not mfile.is_file(): continue
                content = read_file(mfile)
                for m in re.finditer(r'^etcd_server_slow_apply_total (\d+)', content, re.MULTILINE):
                    slow_apply_metric += int(m.group(1))
                slow_wal_metric += len(re.findall(r'etcd_disk_wal_fsync_duration_seconds\{quantile="0.99"\}.*?(\d+\.\d+)', content))
                slow_wal_metric += len(re.findall(r'etcd_disk_commit_duration_seconds\{quantile="0.99"\}.*?(\d+\.\d+)', content))
            for f in self.etcd_dir.glob("*.log"):
                if not f.is_file(): continue
                slow_log += safe_int(sgrep(r'slow fdatasync|apply entries took too long|slow linearizable', f, count_only=True))

        total = slow_apply_metric + slow_wal_metric + slow_log
        if total > 0:
            self.result.add_issue(f"etcd slow disk/apply warnings: {total}")
            print(fail(f"etcd slow disk/apply warnings: {total}"))
            print_section("etcd slow disk/apply breakdown:")
            if slow_apply_metric > 0: print(fmt("INFO", f"  slow_apply_total (metrics)       : {slow_apply_metric}"))
            if slow_wal_metric > 0:    print(fmt("INFO", f"  WAL fsync/commit >threshold     : {slow_wal_metric}"))
            if slow_log > 0:           print(fmt("INFO", f"  slow fdatasync/took too long (logs): {slow_log}"))
        else:
            print(ok("No etcd slow disk/apply warnings"))

    # ────────────────────────────────────────────────────────────────
    # 4. CPU, Memory, Disk I/O
    # ────────────────────────────────────────────────────────────────
    def analyze_cpu_mem(self):
        print_box("4 / CPU & Memory — Deep Analysis")
        self._analyze_memory()
        self._analyze_cpu()
        self._analyze_disk_io()
        self._analyze_congestion()
        self._analyze_file_descriptors()

    def _analyze_memory(self):
        print_section("4A. Memory Analysis")
        freeh = self.sysinfo / "freeh" if self.sysinfo else None
        if freeh and freeh.exists():
            print_section("Memory snapshot:")
            for line in read_file(freeh, strip_esc=True).splitlines():
                print(fmt("INFO", f"  {line}"))
            mem_line = re.search(r'^Mem:\s+(\S+)\s+(\S+)\s+(\S+)', read_file(freeh, strip_esc=True), re.MULTILINE)
            if mem_line:
                total_str, avail_str = mem_line.group(1), mem_line.group(3)
                total = float(re.sub(r'[A-Za-z]+', '', total_str))
                avail = float(re.sub(r'[A-Za-z]+', '', avail_str))
                if total > 0:
                    self.used_pct = int((total - avail) / total * 100)
                    print(fmt("INFO", f"Memory utilization: {self.used_pct}% used"))
                    if self.used_pct >= 95: self.result.add_issue(f"Memory critical: {self.used_pct}% used"); print(fail(f"Memory CRITICAL: {self.used_pct}% used"))
                    elif self.used_pct >= 85: print(warn(f"Memory WARNING: {self.used_pct}% used"))
                    elif self.used_pct >= 75: print(warn(f"Memory ELEVATED: {self.used_pct}% used"))
                    else: print(ok(f"Memory OK: {self.used_pct}% used"))

                    avail_mb = int(avail * 1024)
                    if avail_mb < 256:
                        self.result.add_issue(f"Available memory critically low: {avail_mb}MB")
                        print(fail(f"Available memory critically low: {avail_mb}MB"))
                    elif avail_mb < 512:
                        print(warn(f"Available memory low: {avail_mb}MB"))

            swap_line = re.search(r'^Swap:\s+(\S+)\s+(\S+)', read_file(freeh, strip_esc=True), re.MULTILINE)
            if swap_line:
                swap_total = float(re.sub(r'[A-Za-z]+', '', swap_line.group(1)))
                swap_used  = float(re.sub(r'[A-Za-z]+', '', swap_line.group(2)))
                if swap_total > 0:
                    swap_pct = int(swap_used / swap_total * 100)
                    print_section("Swap analysis:")
                    print(fmt("INFO", f"Swap usage: {swap_pct}%"))
                    if swap_pct >= 50:
                        self.result.add_issue(f"Heavy swap usage: {swap_pct}%")
                        print(fail(f"Swap heavily used ({swap_pct}%)"))
                    elif swap_pct >= 20: print(warn(f"Swap usage elevated ({swap_pct}%)"))
                    elif swap_pct > 0:   print(info("Minor swap usage"))
                    else:                 print(ok("No swap usage"))
                    print(warn("Swap is enabled — Kubernetes recommends disabling swap"))
                else:
                    print(ok("Swap disabled (recommended for Kubernetes)"))
        else:
            print(warn("free -h output not found in bundle"))

    def _analyze_cpu(self):
        print_section("4B. CPU Analysis")
        cpuinfo = self.sysinfo / "cpuinfo" if self.sysinfo else None
        if cpuinfo and cpuinfo.exists():
            self.cpu_count = len(re.findall(r'^processor', read_file(cpuinfo), re.MULTILINE))

        uptime_file = self.sysinfo / "uptime" if self.sysinfo else None
        if uptime_file and uptime_file.exists():
            uptime = read_file(uptime_file)
            print(fmt("INFO", f"Uptime: {uptime.strip()}"))
            
            # Fixed regex to capture three separate float groups, ignoring commas
            loads = re.search(r'load average:\s+([\d.]+),\s+([\d.]+),\s+([\d.]+)', uptime)
            if loads:
                self.load1 = float(loads.group(1))
                self.load5 = float(loads.group(2))
                self.load15 = float(loads.group(3))

                if self.load1 > 0 and self.cpu_count > 0:
                    load_pct = int(self.load1 / self.cpu_count * 100)
                    print_section("Load average analysis:")
                    print(fmt("INFO", f"CPU cores: {self.cpu_count}"))
                    print(fmt("INFO", f"Load averages: 1min={self.load1}  5min={self.load5}  15min={self.load15}"))
                    print(fmt("INFO", f"1-min load per CPU: {load_pct}%"))
                    
                    if self.load15 > 0:
                        if self.load1 > self.load15 * 1.5:   trend = "INCREASING"
                        elif self.load1 < self.load15 * 0.7: trend = "DECREASING"
                        else:                                 trend = "STABLE"
                        print(fmt("INFO", f"Load trend: {trend}"))
                        if trend == "INCREASING" and load_pct > 70:
                            print(warn("Load increasing and high — CPU congestion building"))
                            
                    if load_pct >= 200:
                        self.result.add_issue(f"CPU critical: load {load_pct}% of capacity"); print(fail(f"CPU CRITICAL: Load {load_pct}% of capacity"))
                    elif load_pct >= 100:
                        self.result.add_issue(f"CPU overloaded: load {load_pct}% of capacity"); print(fail(f"CPU OVERLOADED: Load {load_pct}% of capacity"))
                    elif load_pct >= 80: print(warn(f"CPU HIGH: Load {load_pct}% of capacity"))
                    elif load_pct >= 60: print(info(f"CPU MODERATE: Load {load_pct}% of capacity"))
                    else:                print(ok(f"CPU OK: Load {load_pct}% of capacity"))

        top_file = self.sysinfo / "top" if self.sysinfo else None
        if top_file and top_file.exists():
            print_section("Top process analysis:")
            header = "\n".join(read_file(top_file).splitlines()[:3])
            print(fmt("INFO", f"CPU summary: {header.strip()}"))
            if header:
                mu = re.search(r'([\d.]+) us', header); self.cpu_user = mu.group(1) if mu else "0"
                ms = re.search(r'([\d.]+) sy', header); self.cpu_sys = ms.group(1) if ms else "0"
                mw = re.search(r'([\d.]+) wa', header); self.cpu_iowait = mw.group(1) if mw else "0"
                mst = re.search(r'([\d.]+) st', header); self.cpu_steal = mst.group(1) if mst else "0"
                print_section("CPU time breakdown:")
                print(f"  User: {self.cpu_user}%  System: {self.cpu_sys}%  IOWait: {self.cpu_iowait}%  Steal: {self.cpu_steal}%")
                steal_int = int(float(self.cpu_steal))
                if steal_int >= 10:
                    self.result.add_issue(f"High CPU steal: {self.cpu_steal}%"); print(fail(f"CPU steal CRITICAL ({self.cpu_steal}%)"))
                elif steal_int >= 5: print(warn(f"CPU steal elevated ({self.cpu_steal}%)"))
                iowait_int = int(float(self.cpu_iowait))
                if iowait_int >= 20:
                    self.result.add_issue(f"High IOWait: {self.cpu_iowait}%"); print(fail(f"CPU IOWait CRITICAL ({self.cpu_iowait}%)"))
                elif iowait_int >= 10: print(warn(f"CPU IOWait elevated ({self.cpu_iowait}%)"))

            print_section("Top CPU-consuming processes:")
            high_cpu = []
            for line in read_file(top_file).splitlines()[7:]:
                m = re.search(r'^\s*(\d+\.\d+)%\s+(\S+)', line)
                if m and float(m.group(1)) > 10.0:
                    high_cpu.append(f"{m.group(1)}% {m.group(2)}")
            if high_cpu:
                for line in high_cpu[:10]: print(fmt("INFO", f"  CPU {line}"))
            else:
                print(ok("No processes with >10% CPU"))

    def _analyze_disk_io(self):
        print_section("4C. Problematic Disk I/O Summary")
        iostat_file = self.sysinfo / "iostathx" if self.sysinfo else None
        if iostat_file and not iostat_file.exists():
            iostat_file = self.sysinfo / "iostat"
        if not iostat_file or not iostat_file.exists():
            print(info("No iostat data in bundle")); return
        if os.path.getsize(iostat_file) == 0:
            print(warn("iostat file is empty")); return

        def safe_float(val: str) -> float:
            try: return float(re.sub(r'[a-zA-Z%]', '', val))
            except (ValueError, TypeError): return 0.0

        headers = []
        problematic_devices = []
        with open(iostat_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if "Device" in line:
                    headers = line.split(); continue
                if not headers: continue
                fields = line.split()
                if len(fields) != len(headers): continue
                row = dict(zip(headers, fields))
                dev = row.get("Device", "Unknown")
                issues = []
                if "%util" in row:
                    util = safe_float(row["%util"])
                    if util > 90:   issues.append(f"util: {util}% (CRITICAL)")
                    elif util > 70: issues.append(f"util: {util}% (WARNING)")
                await_val = safe_float(row.get("await", row.get("w_await", "0")))
                if await_val > 50:   issues.append(f"lat: {await_val}ms (CRITICAL)")
                elif await_val > 20: issues.append(f"lat: {await_val}ms (WARNING)")
                if issues:
                    activity = row.get("w/s", row.get("tps", fields[0]))
                    severity = "CRITICAL" if "CRITICAL" in str(issues) else "WARNING"
                    summary = f"{dev:<12s} | IOPS: {activity:<8s} | Issues: {', '.join(issues)}"
                    problematic_devices.append((await_val, severity, summary))

        problematic_devices.sort(key=lambda x: x[0], reverse=True)
        top_10 = problematic_devices[:10]
        if top_10:
            for _, severity, msg in top_10:
                if severity == "CRITICAL": print(fail(msg))
                else:                       print(warn(msg))
        else:
            print(ok("No problematic disk I/O detected (all disks < 70% util & < 20ms latency)."))

    def _analyze_congestion(self):
        print_section("4D. Congestion Summary")
        cpu_congestion = mem_congestion = io_congestion = "NONE"

        if self.load1 > 0 and self.cpu_count > 0:
            load_pct = int(self.load1 / self.cpu_count * 100)
            if load_pct >= 100:   cpu_congestion = "CRITICAL"
            elif load_pct >= 80:  cpu_congestion = "HIGH"
            elif load_pct >= 60:  cpu_congestion = "MODERATE"

        if self.cpu_steal and float(self.cpu_steal) >= 5:
            steal_int = int(float(self.cpu_steal))
            if steal_int >= 10 and cpu_congestion != "CRITICAL": cpu_congestion = "CRITICAL (steal)"
            elif steal_int >= 5 and cpu_congestion == "NONE":    cpu_congestion = "MODERATE (steal)"

        if self.used_pct > 0:
            if self.used_pct >= 95:   mem_congestion = "CRITICAL"
            elif self.used_pct >= 85: mem_congestion = "HIGH"
            elif self.used_pct >= 75: mem_congestion = "MODERATE"

        if self.max_await > 50 or self.max_util > 90:      io_congestion = "CRITICAL"
        elif self.max_await >= 20 or self.max_util >= 70:  io_congestion = "HIGH"
        elif self.max_await >= 10 or self.max_util >= 50:  io_congestion = "MODERATE"

        if self.cpu_iowait and float(self.cpu_iowait) >= 10:
            iowait_int = int(float(self.cpu_iowait))
            if iowait_int >= 20 and io_congestion != "CRITICAL": io_congestion = "CRITICAL (iowait)"
            elif iowait_int >= 10 and io_congestion == "NONE":   io_congestion = "MODERATE (iowait)"

        print(fmt("INFO", f"CPU Congestion : {cpu_congestion}"))
        print(fmt("INFO", f"Memory Congestion: {mem_congestion}"))
        print(fmt("INFO", f"I/O Congestion  : {io_congestion}"))
        print()
        if cpu_congestion in ("CRITICAL", "HIGH"):
            print(warn("CPU CONGESTION DETECTED:"))
            if "steal" in cpu_congestion: print(info("  - HIGH STEAL: Migrate to dedicated hosts"))
            else:                          print(info("  - Scale horizontally or right-size workloads"))
        if mem_congestion in ("CRITICAL", "HIGH"):
            print(warn("MEMORY CONGESTION DETECTED:"))
            print(info("  - Add more nodes or upgrade node memory"))
        if io_congestion in ("CRITICAL", "HIGH"):
            print(warn("DISK I/O CONGESTION DETECTED:"))
            print(info("  - For etcd: ensure fast SSD, separate from OS disk"))
            print(info("  - Consider higher IOPS storage class"))
        if cpu_congestion == "NONE" and mem_congestion == "NONE" and io_congestion == "NONE":
            print(ok("No resource congestion detected"))

    def _analyze_file_descriptors(self):
        file_nr = self.sysinfo / "file-nr" if self.sysinfo else None
        if file_nr and file_nr.exists():
            print_section("File descriptor usage:")
            m = re.search(r'(\d+)\s+(\d+)\s+(\d+)', read_file(file_nr))
            if m:
                fd_used, fd_max = int(m.group(1)), int(m.group(3))
                if fd_max > 0:
                    fd_pct = int(fd_used / fd_max * 100)
                    if fd_pct >= 90:
                        self.result.add_issue(f"File descriptors critical: {fd_pct}%"); print(fail(f"File descriptors CRITICAL: {fd_pct}%"))
                    elif fd_pct >= 80: print(warn(f"File descriptors WARNING: {fd_pct}%"))
                    else:              print(ok(f"File descriptors {fd_pct}% used ({fd_used}/{fd_max})"))
            else:
                print(warn("Could not parse file-nr"))

    # ────────────────────────────────────────────────────────────────
    # 5. Networking
    # ────────────────────────────────────────────────────────────────
    def analyze_networking(self):
        print_box("5 / Networking")
        iptables = self.networking / "iptablessave" if self.networking else None
        if iptables and iptables.exists():
            with open(iptables, 'rb') as f:
                ipt_rules = sum(1 for _ in f)
            print(fmt("INFO", f"iptables rules: {ipt_rules} lines"))
            if ipt_rules > 10000:
                print(warn(f"iptables rule count very high ({ipt_rules})"))
            kube_drops = safe_int(sgrep(r'KUBE.*REJECT|DROP.*6443|DROP.*2379|DROP.*10250', iptables, count_only=True))
            if kube_drops > 0:
                self.result.add_issue("iptables DROP rules on Kubernetes ports")
                print(fail(f"iptables DROP rules on Kubernetes ports: {kube_drops}"))
            else:
                print(ok("No DROP rules on critical Kubernetes ports"))

        dmesg = self.sysinfo / "dmesg" if self.sysinfo else None
        if dmesg and dmesg.exists():
            conntrack = safe_int(sgrep(r'nf_conntrack: table full|nf_conntrack: falling behind|conntrack: dropping', dmesg, count_only=True))
            if conntrack > 0:
                self.result.add_issue("conntrack table full")
                print(fail(f"conntrack table full: {conntrack} events"))
            else:
                print(ok("No conntrack table overflow"))

        resolv = self.sysinfo / "etcresolvconf" if self.sysinfo else None
        if resolv and resolv.exists():
            print_section("resolv.conf:")
            for line in read_file(resolv, strip_esc=True).splitlines():
                print(fmt("INFO", f"  {line}"))
            ns_count = safe_int(sgrep(r'^nameserver', resolv, count_only=True))
            if ns_count == 0:
                self.result.add_issue("No nameservers in /etc/resolv.conf")
                print(fail("No nameservers in /etc/resolv.conf"))

        cni_errors = 0
        for ns in ["kube-system", "cattle-system"]:
            if not self.pods_dir: continue
            for f in self.pods_dir.rglob(f"*{ns}*.log"):
                c = safe_int(sgrep(r'level=error|level=fatal|FATA|panic:', f, count_only=True))
                cni_errors += c
        if cni_errors > 0: print(warn(f"CNI component log errors: {cni_errors} lines"))
        else:              print(ok("No CNI component errors"))

    # ────────────────────────────────────────────────────────────────
    # 6. etcd Health
    # ────────────────────────────────────────────────────────────────
    def analyze_etcd(self):
        print_box("6 / etcd Health")
        if not self.etcd_dir:
            print(info("No etcd data directory found in bundle")); return
        print(info(f"etcd data directory: {self.etcd_dir.relative_to(self.root)}"))
        print_section("etcd files collected:")
        for f in sorted(self.etcd_dir.iterdir()):
            if f.is_file():
                size = os.path.getsize(f)
                size_str = f"({size} bytes)" if size else "(empty)"
                print(fmt("INFO", f"  {f.name} {size_str}"))

        self._etcd_alarms()
        self._etcd_members()
        self._etcd_endpoint_health()
        self._etcd_endpoint_status()
        self._etcd_metrics()
        self._etcd_snapshots()
        self._etcd_db_status()
        self._etcd_log_analysis()

    def _etcd_alarms(self):
        print_section("6A. etcd Alarms:")
        alarm_file = self.etcd_dir / "alarmlist"
        if alarm_file and alarm_file.exists():
            content = read_file(alarm_file)
            if not content.strip():
                print(ok("No active etcd alarms"))
            else:
                self.result.add_issue("Active etcd alarms")
                print(fail("Active etcd alarms detected!"))
                for line in content.splitlines():
                    if line.strip(): print(fail(f"  ALARM: {line}"))
        else:
            print(info("alarmlist not found"))

    def _etcd_members(self):
        print_section("6B. etcd Members:")
        member_file = self.etcd_dir / "memberlist"
        if member_file and member_file.exists():
            member_count = started = unstarted = 0
            for line in read_file(member_file).splitlines():
                if not line: continue
                member_count += 1
                if "started=true" in line:
                    started += 1; print(ok(f"  {line}"))
                elif "started=false" in line:
                    unstarted += 1; print(fail(f"  {line}"))
                else:
                    print(info(f"  {line}"))
            print(info(f"Members: {member_count} total, {started} started, {unstarted} unstarted"))
            if unstarted > 0:
                self.result.add_issue(f"etcd has {unstarted} unstarted member(s)")
                print(fail(f"etcd has {unstarted} unstarted member(s)"))
            elif member_count == 1: print(info("Single-node etcd cluster (no HA)"))
            elif member_count == 3: print(ok("3-node etcd cluster (standard HA)"))
            elif member_count == 5: print(ok("5-node etcd cluster (large HA)"))
            elif member_count > 1 and member_count % 2 == 0: print(warn("etcd cluster has even number of members"))
        else:
            print(info("memberlist not found"))

    def _etcd_endpoint_health(self):
        print_section("6C. etcd Endpoint Health:")
        health_file = self.etcd_dir / "endpointhealth"
        if health_file and health_file.exists():
            unhealthy = 0
            for line in read_file(health_file).splitlines():
                if not line: continue
                if re.search(r'unhealthy|fail', line, re.IGNORECASE):
                    unhealthy += 1; print(fail(f"  {line}"))
                elif re.search(r'healthy|success', line, re.IGNORECASE):
                    print(ok(f"  {line}"))
                else:
                    print(info(f"  {line}"))
            if unhealthy > 0:
                self.result.add_issue(f"etcd has {unhealthy} unhealthy endpoint(s)")
                print(fail(f"etcd has {unhealthy} unhealthy endpoint(s)"))
            else:
                print(ok("All etcd endpoints healthy"))
        else:
            print(info("endpointhealth not found"))

    def _etcd_endpoint_status(self):
        print_section("6D. etcd Endpoint Status:")
        status_file = self.etcd_dir / "endpointstatus"
        if status_file and status_file.exists():
            for line in read_file(status_file).splitlines():
                if line: print(fmt("INFO", f"  {line}"))
            db_line = leader_line = ""
            for line in read_file(status_file).splitlines():
                if "DB SIZE" in line: db_line = line
                if "LEADER" in line:  leader_line = line
            if db_line:
                db_bytes = 0
                m = re.search(r'([0-9.]+\.?[0-9]+)\s*(GB|G)', db_line)
                if m: db_bytes = int(float(m.group(1)) * 1073741824)
                else:
                    m = re.search(r'([0-9.]+\.?[0-9]+)\s*(MB|M)', db_line)
                    if m: db_bytes = int(float(m.group(1)) * 1048576)
                db_gb = f"{db_bytes / 1073741824:.2f}" if db_bytes > 0 else "0.00"
                if db_bytes > 8589934592:
                    self.result.add_issue(f"etcd DB size critical: {db_gb}GB (>8GB)"); print(fail(f"etcd DB size CRITICAL: {db_gb}GB"))
                elif db_bytes > 2147483648: print(warn(f"etcd DB size WARNING: {db_gb}GB (>2GB)"))
                elif db_bytes > 0:           print(ok(f"etcd DB size OK: {db_gb}GB"))
            if leader_line:
                if re.search(r'none|<nil>', leader_line, re.IGNORECASE):
                    self.result.add_issue("etcd has no leader!"); print(fail("etcd has no leader!"))
                else: print(ok("etcd leader is defined"))
        else:
            print(info("endpointstatus not found"))

    def _etcd_metrics(self):
        print_section("6E. etcd Metrics:")
        metrics_files = sorted(self.etcd_dir.glob("etcd-metrics-*.txt"))
        if not metrics_files:
            print(info("No etcd-metrics files found")); return
        print(info(f"Found {len(metrics_files)} metrics file(s)"))
        for mfile in metrics_files:
            print(f"\n  --- {mfile.name}:")
            content = read_file(mfile)
            m = re.search(r'^etcd_server_has_leader\s+(\d+)', content, re.MULTILINE)
            if m:
                if int(m.group(1)) == 1: print(ok("  has_leader = 1"))
                else:
                    self.result.add_issue("etcd no leader"); print(fail("  has_leader = 0 (NO LEADER!)"))
            m = re.search(r'^etcd_server_leader_changes_seen_total\s+(\d+)', content, re.MULTILINE)
            if m:
                lc = int(m.group(1))
                if lc > 5:  self.result.add_issue("etcd excessive leader changes: " + str(lc)); print(warn(f"  leader_changes_seen = {lc} (excessive)"))
                elif lc > 0: print(info(f"  leader_changes_seen = {lc}"))
                else:        print(ok("  leader_changes_seen = 0 (stable)"))
            m = re.search(r'etcd_disk_wal_fsync_duration_seconds\{quantile="0.99"\}.*?(\d+\.\d+)', content)
            if m:
                ms = float(m.group(1)) * 1000
                if ms >= 10.0:
                    self.result.add_issue(f"etcd slow WAL: {ms:.1f}ms"); print(fail(f"  WAL fsync (p99) = {ms:.1f}ms (CRITICAL)"))
                elif ms >= 5.0: print(warn(f"  WAL fsync (p99) = {ms:.1f}ms (elevated)"))
                else:           print(ok(f"  WAL fsync (p99) = {ms:.1f}ms"))
            m = re.search(r'^etcd_server_slow_apply_total\s+(\d+)', content, re.MULTILINE)
            if m:
                sa = int(m.group(1))
                if sa > 50: self.result.add_issue(f"etcd excessive slow applies: {sa}"); print(fail(f"  slow_apply_total = {sa} (excessive)"))
                elif sa > 0: print(warn(f"  slow_apply_total = {sa}"))
                else:        print(ok("  slow_apply_total = 0"))
            m = re.search(r'^etcd_mvcc_db_total_size_in_bytes\s+(\d+)', content, re.MULTILINE)
            if m:
                dbm = int(m.group(1))
                if dbm > 0:
                    dgb = f"{dbm / 1073741824:.2f}"
                    if dbm > 8589934592:
                        self.result.add_issue(f"etcd DB critical: {dgb}GB"); print(fail(f"  db_total_size = {dgb}GB (CRITICAL)"))
                    elif dbm > 2147483648: print(warn(f"  db_total_size = {dgb}GB (elevated)"))
                    else:                   print(ok(f"  db_total_size = {dgb}GB"))

    def _etcd_snapshots(self):
        print_section("6F. etcd Snapshots:")
        snap_file = self.etcd_dir / "findserverdbsnapshots"
        if snap_file and snap_file.exists():
            content = read_file(snap_file)
            if content.strip():
                for line in content.splitlines()[:5]:
                    if line.strip(): print(fmt("INFO", f"  {line}"))
                if len(content.splitlines()) > 5: print(info("  ..."))
                if re.search(r'fail|error|corrupt', content, re.IGNORECASE):
                    self.result.add_issue("etcd snapshot errors"); print(fail("Snapshot errors detected"))
        else:
            print(info("findserverdbsnapshots not found"))

    def _etcd_db_status(self):
        print_section("6G. etcd DB Status:")
        db_file = self.etcd_dir / "findserverdbetcd"
        if db_file and db_file.exists():
            for line in read_file(db_file).splitlines():
                if line.strip(): print(fmt("INFO", f"  {line}"))

    def _etcd_log_analysis(self):
        log_files = list(self.etcd_dir.glob("*.log"))
        if not log_files: return
        print_section("6H. etcd Log Analysis (supplementary):")
        print(info(f"Found {len(log_files)} etcd log file(s)"))
        patterns = [
            ("apply_too_long",     r"apply request took too long|apply entries took too long"),
            ("heartbeat_failed",   r"failed to send out heartbeat"),
            ("context_deadline",   r"context deadline exceeded"),
            ("slow_fdatasync",     r"slow fdatasync"),
            ("alarm_nospace",      r"etcd server is running low on space|mvcc: database space exceeded"),
        ]
        any_found = False
        for key, pat in patterns:
            total = 0
            for f in log_files:
                total += safe_int(sgrep(pat, f, count_only=True))
            if total > 0:
                any_found = True
                self.result.add_issue(f"etcd log [{key}]: {total} occurrence(s)")
                print(fail(f"etcd log [{key}]: {total} occurrence(s)"))
                for f in log_files:
                    for m in re.finditer(pat, read_file(f)):
                        print(f"    {m.group(0).strip()[:200]}")
        if not any_found:
            print(ok("No etcd log errors found"))

    # ────────────────────────────────────────────────────────────────
    # 7-9. Rancher, Agent, Pods
    # ────────────────────────────────────────────────────────────────
    def analyze_rancher(self):
        print_box("7 / Rancher Server & Webhook")
        rancher_errs = 0
        if self.pods_dir:
            for f in self.pods_dir.rglob("*cattle-system*rancher*.log"):
                c = safe_int(sgrep(r'level=error|level=fatal|panic:', f, count_only=True))
                rancher_errs += c
                if c > 0:
                    print(warn(f"Rancher errors in {f.name}: {c}"))
                    for m in str(sgrep(r'level=error|level=fatal|panic:', f)).splitlines():
                        print(f"    {m.strip()[:160]}")
        if rancher_errs == 0: print(ok("No Rancher server errors found"))

        webhook_dead = 0
        if self.pods_dir:
            for f in self.pods_dir.rglob("*.log"):
                webhook_dead += safe_int(sgrep(
                    r"rancher-webhook.*context deadline exceeded|failed to call webhook.*rancher|webhook.*timeout", f, count_only=True))
        if webhook_dead > 0:
            self.result.add_issue("rancher-webhook unresponsive")
            print(fail(f"rancher-webhook timeout/deadline: {webhook_dead}"))
        else:
            print(ok("No rancher-webhook timeout errors"))

        webhook_cfg = self.kubectl_dir / "validatingwebhookconfigurations" if self.kubectl_dir else None
        if webhook_cfg and webhook_cfg.exists():
            rules = safe_int(sgrep(r'rules:|webhooks:', webhook_cfg, count_only=True))
            if rules == 0:
                self.result.add_issue("Webhook misconfiguration: 0 rules")
                print(fail("rancher.cattle.io webhook has 0 rules (CVE-2023-22651)"))
            else:
                print(ok("rancher.cattle.io webhook rules present"))

    def analyze_agent_fleet(self):
        print_box("8 / cattle-cluster-agent & Fleet")
        agent_pat = r'level=error|tunnel disconnect|cluster agent disconnected|failed to connect|websocket.*closed|connection.*refused'
        agent_errors = 0
        if self.pods_dir:
            for f in self.pods_dir.rglob("*cattle-cluster-agent*.log"):
                c = safe_int(sgrep(agent_pat, f, count_only=True))
                agent_errors += c
                if c > 0:
                    print(fail(f"cattle-cluster-agent errors in {f.parent.name}: {c}"))
                    for m in str(sgrep(agent_pat, f)).splitlines():
                        print(f"    {m.strip()[:160]}")
        if agent_errors == 0: print(ok("No cattle-cluster-agent connectivity errors"))

        strict_ca = 0
        if self.pods_dir:
            for f in self.pods_dir.rglob("*cattle*.log"):
                strict_ca += safe_int(sgrep(r'Strict CA verification.*error|unable to read CA file|no such file.*serverca', f, count_only=True))
        if strict_ca > 0:
            self.result.add_issue("Strict CA verification error")
            print(fail(f"Strict CA error: {strict_ca} hit(s)"))
        else:
            print(ok("No strict CA verification errors"))

        fleet_errs = 0
        if self.pods_dir:
            for f in self.pods_dir.rglob("*fleet*.log"):
                fleet_errs += safe_int(sgrep(r'level=error|"level":"error"|reconciler error', f, count_only=True))
        if fleet_errs > 0: print(warn(f"Fleet log errors: {fleet_errs} lines"))
        else:              print(ok("No Fleet log errors"))

    def analyze_pods(self):
        print_box("9 / Pod Health (All Namespaces)")
        pods_file = self.kubectl_dir / "pods" if self.kubectl_dir else None
        if pods_file and pods_file.exists():
            lines = [l for l in read_file(pods_file).splitlines() if l and not l.startswith("NAMESPACE") and not l.startswith("NAME ")]
            total = len(lines)
            running   = sum(1 for l in lines if "Running" in l)
            pending   = sum(1 for l in lines if "Pending" in l)
            failed    = sum(1 for l in lines if re.search(r'Failed|OOMKilled|CrashLoopBackOff', l))
            completed = sum(1 for l in lines if "Completed" in l)
            print(f"  [INFO] Pods: total={total}  running={running}  pending={pending}  failed/crash={failed}  completed={completed}")
            if pending > 0:
                self.result.add_issue(f"{pending} Pending pod(s)"); print(fail(f"Pending pods: {pending}"))
                for l in lines:
                    if "Pending" in l: print(f"    {l}")
            else: print(ok("No Pending pods"))
            if failed > 0:
                self.result.add_issue(f"{failed} Failed/CrashLoop pod(s)"); print(fail(f"Failed/CrashLoop pods: {failed}"))
                for l in lines:
                    if re.search(r'Failed|OOMKilled|CrashLoopBackOff', l): print(f"    {l}")
            else: print(ok("No Failed/CrLoop pods"))

        for ns in ["kube-system", "cattle-system", "cattle-fleet-system"]:
            crash_count = 0
            if self.pods_dir:
                for f in self.pods_dir.rglob(f"*{ns}*.log"):
                    crash_count += safe_int(sgrep(r'panic:|fatal error|OOMKilled|CrashLoopBackOff', f, count_only=True))
            if crash_count > 0: print(warn(f"{ns}: {crash_count} panic/OOM/crash lines"))

    # ────────────────────────────────────────────────────────────────
    # 10-11. Bug Signatures (data-driven from bug_signatures.txt)
    # ────────────────────────────────────────────────────────────────
    def detect_bugs(self):
        print_box("10 / Known Rancher & RKE2/k3s Bug Signatures")
        print(fmt("INFO", f"Loaded {len(self.signatures)} signatures from bug_signatures.txt"))
        print()

        for sig in self.signatures:
            section(f"{sig.bug_id}: {sig.description}")
            self._evaluate_signature(sig)
            print()

    def _evaluate_signature(self, sig: BugSignature):
        """Evaluate a single bug signature against the bundle."""
        # ── Condition pre-checks ────────────────────────────────────
        if sig.condition == "calico_skip":
            if "Calico" in self.cni:
                print(ok(f"{sig.bug_id}: Skipped — Calico CNI detected"))
                self.result.set_status(sig.bug_id, "N/A"); return
        if sig.condition == "version_2.7.2_only":
            if "v2.7.2" not in self.rancher_version:
                print(ok(f"{sig.bug_id}: Not v2.7.2 — not applicable"))
                self.result.set_status(sig.bug_id, "N/A"); return

        # ── Version-based check (operator == 'version') ─────────────
        if sig.operator == "version":
            for scope in sig.scopes:
                if scope.startswith("version:"):
                    substr = scope.split(":", 1)[1]
                    if substr in self.rancher_version:
                        print(warn(f"{sig.bug_id}: Rancher {self.rancher_version} matches '{substr}' — verify manually"))
                        self.result.set_status(sig.bug_id, "WARN"); return
            print(ok(f"{sig.bug_id}: Version check clear"))
            self.result.set_status(sig.bug_id, "N/A"); return

        # ── Pattern-based checks ────────────────────────────────────
        total_count = 0
        for scope in sig.scopes:
            total_count += self._count_in_scope(scope, sig.pattern)

        # Apply operator
        detected = False
        if sig.operator == ">":
            detected = total_count > sig.threshold
        elif sig.operator == "==0":
            detected = total_count == 0

        if detected:
            self.result.add_issue(f"{sig.bug_id}: {sig.description} (count={total_count})")
            if sig.severity == "FAIL":
                print(fail(f"{sig.bug_id}: DETECTED — {sig.description} (count={total_count})"))
            else:
                print(warn(f"{sig.bug_id}: DETECTED — {sig.description} (count={total_count})"))
            self.result.set_status(sig.bug_id, "DETECTED")
        else:
            print(ok(f"{sig.bug_id}: Clear — {sig.description} (count={total_count})"))
            self.result.set_status(sig.bug_id, "CLEAR")

    def _count_in_scope(self, scope: str, pattern: str) -> int:
        """Count regex matches in all files covered by the given scope."""
        if scope.startswith("pods_log:"):
            if not self.pods_dir: return 0
            glob_pat = scope.split(":", 1)[1]
            return sum(safe_int(sgrep(pattern, f, count_only=True))
                       for f in self.pods_dir.rglob(glob_pat) if f.is_file())

        if scope.startswith("etcd_log:"):
            if not self.etcd_dir: return 0
            glob_pat = scope.split(":", 1)[1]
            return sum(safe_int(sgrep(pattern, f, count_only=True))
                       for f in self.etcd_dir.glob(glob_pat) if f.is_file())

        if scope.startswith("kube_log:"):
            if not self.root: return 0
            glob_pat = scope.split(":", 1)[1]
            return sum(safe_int(sgrep(pattern, f, count_only=True))
                       for f in self.root.rglob(glob_pat) if f.is_file())

        if scope == "iptables":
            ipt = self.networking / "iptablessave" if self.networking else None
            if not ipt or not ipt.exists(): return 0
            return safe_int(sgrep(pattern, ipt, count_only=True))

        if scope == "etcd_snap":
            if not self.etcd_dir: return 0
            snap = self.etcd_dir / "findserverdbsnapshots"
            if not snap.exists(): return 0
            return safe_int(sgrep(pattern, snap, count_only=True))

        return 0

    # ──────────────────────────────────────────────────────────────────────
    # Summary & Output
    # ──────────────────────────────────────────────────────────────
    def print_summary(self):
        print("\n" + "═" * 64)
        print(f"  Triage Summary  [{self.bundle_name}]")
        print("═" * 64)

        if not self.result.has_issues and not self.result.warnings:
            print("\n  RESULT: All checks passed — no critical issues or warnings found\n")
        else:
            if self.result.issues:
                print(f"\n  CRITICAL ISSUES ({len(self.result.issues)}):")
                for i, msg in enumerate(self.result.issues, 1):
                    print(f"    {i}. {msg}")
            if self.result.warnings:
                print(f"\n  WARNINGS ({len(self.result.warnings)}):")
                for i, msg in enumerate(self.result.warnings, 1):
                    print(f"    {i}. {msg}")

        # Bug Detection Status Table (rendered from loaded signatures)
        print("\n" + "═" * 64)
        print("  Bug Detection Status  (driven by bug_signatures.txt)")
        print("═" * 64)
        print()
        print("  +--------+------------+--------------------------------------------+------------------+")
        print("  | ID     | Status     | Description                                | Affects          |")
        print("  +--------+------------+--------------------------------------------+------------------+")

        status_map = {
            "DETECTED": "[DETECTED]",
            "CLEAR":    "[CLEAR]   ",
            "WARN":     "[WARN]    ",
            "N/A":      "[N/A]     ",
            "SKIP":     "[SKIP]    ",
        }
        for sig in self.signatures:
            st = status_map.get(self.result.get_status(sig.bug_id), "[SKIP]    ")
            print(f"  | {sig.bug_id:<6s} | {st} | {sig.description:<42.42s} | {sig.affects:<16.16s} |")

        print("  +--------+------------+--------------------------------------------+------------------+")
        print()
        print("  Status: [DETECTED]=found  [CLEAR]=none  [WARN]=risk  [N/A]=n/a  [SKIP]=no data")
        print(f"  Completed at: {datetime.datetime.now()}")
        print("")

    def cleanup(self):
        if self.work_dir and self.work_dir.exists():
            try:
                shutil.rmtree(self.work_dir)
                print(fmt("INFO", f"Cleaned up temporary directory: {self.work_dir}"))
            except Exception as e:
                print(warn(f"Failed to clean up temporary directory {self.work_dir}: {e}"))

    # ──────────────────────────────────────────────────────────────
    def run(self):
        print("\nRancher Log Bundle Triage")
        print(f"Bundle : {self.bundle_path}")
        print("")
        try:
            self.extract()
            self.analyze_versions()
            self.detect_versions()
            self.analyze_os()
            self.analyze_cni_csi()
            self.analyze_nodes()
            self.analyze_certs()
            self.analyze_disk()
            self.analyze_cpu_mem()
            self.analyze_networking()
            self.analyze_etcd()
            self.analyze_rancher()
            self.analyze_agent_fleet()
            self.analyze_pods()
            self.detect_bugs()
            self.print_summary()
        except Exception as e:
            print(f"\nFATAL: {e}")
            sys.exit(1)
        finally:
            self.cleanup()


# ──────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 rancher-bundle-triage.py <rancher-bundle.tar.gz>")
        sys.exit(1)

    bundle_path = sys.argv[1]
    if not os.path.exists(bundle_path):
        print(f"ERROR: Not found: {bundle_path}")
        sys.exit(1)

    # Load bug signatures from the txt file located next to this script.
    sig_file = Path(__file__).resolve().parent / "bug_signatures.txt"
    signatures = load_bug_signatures(sig_file)
    if not signatures:
        print(f"WARN: No bug signatures loaded from {sig_file} — bug detection will be skipped.")
    else:
        print(f"Loaded {len(signatures)} bug signatures from {sig_file}")

    analyzer = BundleAnalyzer(bundle_path, signatures)
    analyzer.run()
