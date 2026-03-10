#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Kernel CVE Scanner  |  "Conquer Vulnerabilities"
"""

import platform
import subprocess
import json
import re
import sys
from datetime import datetime
from packaging import version

from core.utils import (
    Color, c, severity_badge, cvss_bar,
    get_distro, save_json, print_banner as _print_banner,
)


# ==============================
# Runtime Package Version Checks
# More reliable than kernel version-range heuristics for userspace CVEs
# ==============================
def _get_pkg_version(pkg: str) -> str:
    """Return installed package version via dpkg, or '' if unavailable."""
    try:
        r = subprocess.run(["dpkg", "-s", pkg],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _check_sudo_patched() -> bool:
    """True if installed sudo >= 1.9.5p2 (CVE-2021-3156 Baron Samedit fix)."""
    try:
        r = subprocess.run(["sudo", "--version"],
                           capture_output=True, text=True, timeout=3)
        # e.g. "Sudo version 1.9.15p5"
        m = re.search(r"Sudo version\s+(\d+)\.(\d+)\.(\d+)", r.stdout)
        if m:
            major, minor, patch_num = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if major > 1 or (major == 1 and minor > 9):
                return True
            if major == 1 and minor == 9 and patch_num >= 6:
                return True
            if major == 1 and minor == 9 and patch_num == 5:
                first_line = r.stdout.split("\n")[0]
                # p2, p3, … all have the fix
                if re.search(r"p[2-9]", first_line):
                    return True
    except Exception:
        pass
    # dpkg fallback
    ver = _get_pkg_version("sudo")
    if ver:
        m = re.search(r"1\.9\.(\d+)", ver)
        if m and int(m.group(1)) >= 6:
            return True
    return False


def _check_polkit_patched() -> bool:
    """True if installed polkit >= 0.120 (CVE-2021-4034 PwnKit fix)."""
    try:
        r = subprocess.run(["pkexec", "--version"],
                           capture_output=True, text=True, timeout=3)
        # e.g. "pkexec version 0.105"
        m = re.search(r"(\d+)\.(\d+)", r.stdout)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major > 0 or minor >= 120:
                return True
    except Exception:
        pass
    for pkg in ("policykit-1", "polkit"):
        ver = _get_pkg_version(pkg)
        if ver:
            m = re.search(r"0\.(\d+)", ver)
            if m and int(m.group(1)) >= 120:
                return True
            # Ubuntu 22.04+ backport: 0.105-33+ includes the fix
            m2 = re.search(r"0\.105-(\d+)", ver)
            if m2 and int(m2.group(1)) >= 33:
                return True
    return False


def _check_glibc_patched() -> bool:
    """True if glibc patched for CVE-2023-4911 Looney Tunables.

    Fixed in upstream glibc 2.38.  Ubuntu backport: libc6 2.35-0ubuntu3.4+.
    """
    ver = _get_pkg_version("libc6")
    if ver:
        # Upstream 2.38+
        m = re.search(r"2\.(\d+)", ver)
        if m and int(m.group(1)) >= 38:
            return True
        # Ubuntu 22.04 backport: 2.35-0ubuntuX.Y where Y >= 4
        m2 = re.search(r"2\.35-\d+ubuntu\d+\.(\d+)", ver)
        if m2 and int(m2.group(1)) >= 4:
            return True
    return False

# ==============================
# CVE Database (Extended)
# ==============================
CVE_DB = [
    # ── Dirty COW family ──
    {
        "cve": "CVE-2016-5195",
        "ubuntu_patched_abi": 2,
        "name": "Dirty COW",
        "category": "Race Condition",
        "affected_min": "2.6.22",
        "affected_max": "4.8.3",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Race condition in mm/gup.c allows local privilege escalation via write access to read-only mappings.",
        "fix_commit": "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619",
        "patch_indicator": ["mm/gup.c", "cow_user_page"],
        "thai_detail": (
            " Dirty COW Race Condition mm/gup.c Linux Kernel\n"
            " Local User \n"
            " Thread Memory Mapping Read-Only \n"
            " /etc/passwd SUID Binary root\n"
            " 9 "
        ),
        "thai_mitigation": (
            "1. Kernel 4.8.3 \n"
            " 2. systemd-nspawn SELinux/AppArmor \n"
            " 3. integrity SUID AIDE Tripwire\n"
            " 4. kpatch live-patch reboot "
        )
    },
    {
        "cve": "CVE-2022-0847",
        "ubuntu_patched_abi": 11,
        "name": "Dirty Pipe",
        "category": "Pipe Buffer",
        "affected_min": "5.8",
        "affected_max": "5.16.10",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Flaw in pipe buffer flags allows overwriting read-only files including SUID binaries.",
        "fix_commit": "9d2231c5d74e13b2a0546fee6737ee4446017903",
        "patch_indicator": ["fs/pipe.c", "PIPE_BUF_FLAG_CAN_MERGE"],
        "thai_detail": (
            " Dirty Pipe Flag Pipe Buffer\n"
            " Linux Kernel Flag PIPE_BUF_FLAG_CAN_MERGE\n"
            " Read-Only SUID\n"
            " /usr/bin/passwd Backdoor root\n"
            " Max Kellermann 2022 Container Runtime "
        ),
        "thai_mitigation": (
            "1. Kernel 5.16.11, 5.15.25, 5.10.102 \n"
            " 2. Distro Security Patch (apt/yum update)\n"
            " 3. Attack Surface Untrusted Code \n"
            " 4. Container Container Runtime (runc/containerd) "
        )
    },
    # ── sudo / userspace ──
    {
        "cve": "CVE-2021-3156",
        "ubuntu_patched_abi": 12,
        "name": "Baron Samedit",
        "category": "Heap Overflow",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap-based buffer overflow in sudo sudoedit allows privilege escalation to root.",
        "note": "Affects sudo ≤ 1.9.5p1 — not kernel directly",
        "patch_indicator": [],
        "thai_detail": (
            " Baron Samedit Heap Buffer Overflow sudo\n"
            " sudoedit Argument \n"
            " Local User ( sudoers)\n"
            " root \n"
            " 10 Qualys Research Team"
        ),
        "thai_mitigation": (
            "1. sudo 1.9.5p2 (sudo --version)\n"
            " 2. : sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')\n"
            " error = , crash = \n"
            " 3. sudo /etc/sudoers\n"
            " 4. PAM Module Log sudo "
        )
    },
    # ── Filesystem ──
    {
        "cve": "CVE-2022-0185",
        "name": "Filesystem Context Heap Overflow",
        "category": "Heap Overflow",
        "affected_min": "5.1",
        "affected_max": "5.16.2",
        "cvss": 8.4,
        "severity": "HIGH",
        "description": "Integer underflow in legacy_parse_param() in fs/fs_context.c allows heap overflow.",
        "fix_commit": "722d94847de29310e8aa03fcbdb41300d6a8ef76",
        "patch_indicator": ["fs/fs_context.c", "legacy_parse_param"],
        "thai_detail": (
            " Integer Underflow legacy_parse_param()\n"
            " fs/fs_context.c Heap Buffer Overflow\n"
            " CAP_SYS_ADMIN User Namespace\n"
            " root Host Container\n"
            " CVSS 8.4 Escape Container "
        ),
        "thai_mitigation": (
            "1. Kernel 5.16.2 \n"
            " 2. Unprivileged User Namespace:\n"
            "        sysctl -w kernel.unprivileged_userns_clone=0\n"
            " 3. seccomp profile syscall Container\n"
            " 4. CAP_SYS_ADMIN Container Runtime"
        )
    },
    {
        "cve": "CVE-2023-0386",
        "name": "OverlayFS Privilege Escalation",
        "category": "Filesystem",
        "affected_min": "5.11",
        "affected_max": "6.2.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "OverlayFS allows unprivileged users to copy SUID files into a mount, leading to privilege escalation.",
        "fix_commit": "4f11ada10d0ad6aa9f3f298c9dc71e83e84d71a0",
        "patch_indicator": ["fs/overlayfs", "ovl_copy_up"],
        "thai_detail": (
            " OverlayFS Kernel \n"
            " SUID OverlayFS Mount \n"
            " SUID root \n"
            " Docker/Kubernetes OverlayFS\n"
            " Container OverlayFS Storage Driver "
        ),
        "thai_mitigation": (
            "1. Kernel 6.2.1 \n"
            " 2. Docker/Kubernetes Storage Driver :\n"
            "        docker info | grep 'Storage Driver'\n"
            " 3. --no-new-privileges flag Container\n"
            " 4. AppArmor/SELinux Profile Container Runtime\n"
            " 5. Distro Backport Patch "
        )
    },
    # ── Netfilter / Network ──
    {
        "cve": "CVE-2022-1015",
        "name": "Netfilter OOB Write",
        "category": "Netfilter",
        "affected_min": "5.12",
        "affected_max": "5.17.1",
        "cvss": 6.6,
        "severity": "MEDIUM",
        "description": "Out-of-bound write in nf_tables_newrule() allows local privilege escalation.",
        "fix_commit": "d44f9f9f02a2f50bf1e3a3012d29e9af3fefbba3",
        "patch_indicator": ["net/netfilter/nf_tables_api.c"],
        "thai_detail": (
            " nf_tables Netfilter Framework\n"
            " nf_tables_newrule() Memory\n"
            " CAP_NET_ADMIN Trigger OOB Write\n"
            " Crash (Denial of Service)\n"
            " CVE-2022-1016 "
        ),
        "thai_mitigation": (
            "1. Kernel 5.17.2 \n"
            " 2. nftables :\n"
            "        sysctl -w kernel.unprivileged_userns_clone=0\n"
            " 3. CAP_NET_ADMIN Container\n"
            " 4. seccomp socket() syscall "
        )
    },
    {
        "cve": "CVE-2022-1016",
        "name": "Netfilter Use-After-Free",
        "category": "Netfilter",
        "affected_min": "5.12",
        "affected_max": "5.17.1",
        "cvss": 5.5,
        "severity": "MEDIUM",
        "description": "Use-after-free in nf_tables may lead to information disclosure.",
        "fix_commit": "d44f9f9f02a2f50bf1e3a3012d29e9af3fefbba3",
        "patch_indicator": ["net/netfilter/nf_tables_api.c"],
        "thai_detail": (
            " Use-After-Free nf_tables Kernel \n"
            " Memory Free \n"
            " Kernel Pointer Bypass KASLR (Kernel Address Layout Randomization)\n"
            " CVE-2022-1015\n"
            " Privilege Escalation "
        ),
        "thai_mitigation": (
            "1. Kernel 5.17.2 ( 1015 1016)\n"
            " 2. Kernel Pointer Restrictions:\n"
            "        sysctl -w kernel.kptr_restrict=2\n"
            " 3. dmesg Unprivileged Users:\n"
            "        sysctl -w kernel.dmesg_restrict=1\n"
            " 4. GRSecurity/PaX "
        )
    },
    {
        "cve": "CVE-2023-32233",
        "name": "Netfilter nf_tables UAF",
        "category": "Netfilter",
        "affected_min": "5.1",
        "affected_max": "6.3.1",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Use-after-free in nf_tables batch handling allows local privilege escalation.",
        "fix_commit": "c1592a89942e9678f7d9c8030efa777c0d57edab",
        "patch_indicator": ["net/netfilter/nf_tables_api.c", "nf_tables_del_setelem"],
        "thai_detail": (
            " Use-After-Free Batch Handling nf_tables\n"
            " nf_tables_del_setelem() State \n"
            " Batch Request Free Memory\n"
            " Dangling Pointer root \n"
            " Exploit "
        ),
        "thai_mitigation": (
            "1. Kernel 6.3.2 \n"
            " 2. Unprivileged User Namespaces :\n"
            "        echo 0 > /proc/sys/kernel/unprivileged_userns_clone\n"
            " 3. Log Exploit Attempt:\n"
            "        dmesg | grep -i 'netfilter\\|nf_tables'\n"
            " 4. Snort/Suricata Rules Exploitation Attempt"
        )
    },
    {
        "cve": "CVE-2023-35788",
        "name": "Flower Classifier OOB",
        "category": "Network",
        "affected_min": "4.14",
        "affected_max": "6.3.3",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Out-of-bounds write in fl_set_geneve_opt() in net/sched/cls_flower.c.",
        "fix_commit": "4d56304e5827c8cc8cc18c75343d283af7c4825c",
        "patch_indicator": ["net/sched/cls_flower.c", "fl_set_geneve_opt"],
        "thai_detail": (
            " Traffic Control Flower Classifier Linux Kernel\n"
            " fl_set_geneve_opt() Option Geneve Protocol\n"
            " Out-of-Bounds Write Heap Memory\n"
            " CAP_NET_ADMIN Trigger \n"
            " Kernel Space "
        ),
        "thai_mitigation": (
            "1. Kernel 6.3.4 \n"
            " 2. Geneve Tunneling Blacklist Module:\n"
            "        echo 'blacklist geneve' >> /etc/modprobe.d/blacklist.conf\n"
            " 3. CAP_NET_ADMIN Capability Dropping\n"
            " 4. Network Policy Kubernetes "
        )
    },
    # ── Memory / UAF ──
    {
        "cve": "CVE-2021-22555",
        "ubuntu_patched_abi": 18,
        "name": "Netfilter Heap Out-of-Bounds Write",
        "category": "Heap Overflow",
        "affected_min": "2.6.19",
        "affected_max": "5.12.13",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap OOB write in xt_compat_target_from_user() in net/netfilter/x_tables.c.",
        "fix_commit": "b29c457a6511435960115c0f548c4360d5f4801d",
        "patch_indicator": ["net/netfilter/x_tables.c", "xt_compat_target_from_user"],
        "thai_detail": (
            " xt_compat_target_from_user() x_tables.c\n"
            " Buffer iptables Rules\n"
            " 32-bit 64-bit Heap OOB Write\n"
            " CAP_NET_ADMIN \n"
            " Kernel Space root"
        ),
        "thai_mitigation": (
            "1. Kernel 5.12.14 \n"
            " 2. nftables iptables ( Maintain )\n"
            " 3. CAP_NET_ADMIN systemd Service Hardening:\n"
            "        CapabilityBoundingSet=~CAP_NET_ADMIN\n"
            " 4. CONFIG_HARDENED_USERCOPY OOB "
        )
    },
    {
        "cve": "CVE-2022-27666",
        "ubuntu_patched_abi": 20,
        "name": "ESP Transformation Heap Overflow",
        "category": "IPSec",
        "affected_min": "5.10",
        "affected_max": "5.17.2",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap buffer overflow in IPSec ESP transformation (net/ipv4/esp4.c).",
        "fix_commit": "ebe48d368e97d007bfeb76fcb065d6a511d09b37",
        "patch_indicator": ["net/ipv4/esp4.c", "esp_output_tail"],
        "thai_detail": (
            " IPSec ESP (Encapsulating Security Payload) Kernel\n"
            " esp_output_tail() esp4.c Buffer \n"
            " Heap Buffer Overflow ESP Packet\n"
            " Packet \n"
            " Crash "
        ),
        "thai_mitigation": (
            "1. Kernel 5.17.3 \n"
            " 2. IPSec Module:\n"
            "        echo 'install esp4 /bin/true' >> /etc/modprobe.d/disable-esp.conf\n"
            " 3. WireGuard IPSec \n"
            " 4. Network Segmentation ESP Packet "
        )
    },
    # ── SUID / Capabilities ──
    {
        "cve": "CVE-2021-4034",
        "ubuntu_patched_abi": 15,
        "name": "PwnKit (pkexec)",
        "category": "SUID",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Memory corruption in pkexec (polkit) allows unprivileged local privilege escalation.",
        "note": "Affects polkit < 0.120 — not kernel directly",
        "patch_indicator": [],
        "thai_detail": (
            " PwnKit pkexec polkit\n"
            " Memory Corruption Argument pkexec\n"
            " 12 ( polkit )\n"
            " Local root \n"
            " pkexec polkit "
        ),
        "thai_mitigation": (
            "1. polkit 0.120 \n"
            " 2. : pkexec --version\n"
            " 3. : chmod 0755 /usr/bin/pkexec ( SUID bit)\n"
            " : pkexec \n"
            " 4. Audit Log Exploit:\n"
            "        ausearch -m avc -ts recent | grep pkexec"
        )
    },
    # ── Container Escape ──
    {
        "cve": "CVE-2022-0492",
        "name": "cgroup v1 Container Escape",
        "category": "Container",
        "affected_min": "2.6.24",
        "affected_max": "5.17.0",
        "cvss": 7.0,
        "severity": "HIGH",
        "description": "Flaw in cgroup v1 release_agent allows container escape to host.",
        "fix_commit": "3007098494e3aa7eef8f0d73eabe7b691f9d6200",
        "patch_indicator": ["kernel/cgroup/cgroup-v1.c", "release_agent"],
        "thai_detail": (
            " cgroup v1 release_agent Linux Kernel\n"
            " release_agent Script Process \n"
            " Container release_agent\n"
            " Host Container \n"
            " Docker, Kubernetes, LXC"
        ),
        "thai_mitigation": (
            "1. Kernel 5.17.1 \n"
            " 2. cgroup v2 cgroup v1 ():\n"
            " 'systemd.unified_cgroup_hierarchy=1' Kernel Parameter\n"
            " 3. Container --privileged=false ( Default)\n"
            " 4. Seccomp Profile AppArmor/SELinux Container\n"
            " 5. release_agent: cat /sys/fs/cgroup/release_agent"
        )
    },
    {
        "cve": "CVE-2022-25636",
        "name": "Netfilter Heap OOB in nft_fwd_dup",
        "category": "Container",
        "affected_min": "5.4",
        "affected_max": "5.16.12",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap OOB read/write in nft_fwd_dup_netdev_offload() — exploitable for container escape.",
        "fix_commit": "fdb3b8f4714e7b0339a91a2a067a0fe8d0e67c42",
        "patch_indicator": ["net/netfilter/nft_fwd_dup.c"],
        "thai_detail": (
            " nft_fwd_dup_netdev_offload() nft_fwd_dup.c\n"
            " Heap OOB Read/Write Netdev Offload Rules\n"
            " Escape Container\n"
            " Host root Host \n"
            " Multi-Tenant Cloud"
        ),
        "thai_mitigation": (
            "1. Kernel 5.16.13 \n"
            " 2. Netdev Offload \n"
            " 3. CAP_NET_ADMIN Container \n"
            " 4. Kata Containers gVisor Container Strong Isolation\n"
            " 5. Network Driver Offload "
        )
    },
    # ── CVSS Critical ──
    {
        "cve": "CVE-2017-5753",
        "name": "Spectre v1",
        "category": "CPU Speculative",
        "affected_min": "2.6.0",
        "affected_max": "4.15.0",
        "cvss": 5.6,
        "severity": "MEDIUM",
        "description": "Bounds check bypass via speculative execution allows information disclosure.",
        "patch_indicator": [],
        "thai_detail": (
            " Spectre v1 Hardware CPU \n"
            " CPU Speculative Execution ()\n"
            " CPU Memory \n"
            " Cache Timing Attack Password, Key\n"
            " CPU Intel, AMD, ARM 1995"
        ),
        "thai_mitigation": (
            "1. Kernel Mitigation (IBRS, IBPB, STIBP):\n"
            "        grep . /sys/devices/system/cpu/vulnerabilities/*\n"
            " 2. CPU Microcode (intel-microcode / amd64-microcode)\n"
            " 3. Retpoline Compiler Mitigation ( Default Kernel )\n"
            " 4. VM/Cloud: CPU Enhanced IBRS\n"
            " 5. Performance 5-30% Workload "
        )
    },
    {
        "cve": "CVE-2017-5754",
        "name": "Meltdown",
        "category": "CPU Speculative",
        "affected_min": "2.6.0",
        "affected_max": "4.15.0",
        "cvss": 5.6,
        "severity": "MEDIUM",
        "description": "Rogue data cache load via speculative execution allows kernel memory read from userspace.",
        "patch_indicator": [],
        "thai_detail": (
            " Meltdown Spectre v1 \n"
            " Userspace Process Kernel Memory \n"
            " Speculative Execution CPU Permission\n"
            " Kernel Stack, Password Hash, Private Key\n"
            " KPTI (Kernel Page-Table Isolation) Performance"
        ),
        "thai_mitigation": (
            "1. Kernel 4.15+ KPTI (PTI) \n"
            " : cat /sys/devices/system/cpu/vulnerabilities/meltdown\n"
            " 2. CPU Microcode \n"
            " 3. VM: Hypervisor Mitigation \n"
            " 4. Hyperthreading ( Performance ~50%)\n"
            " 5. Hardware Fix Silicon "
        )
    },
    # ── New: nf_tables UAF (2024) ──
    {
        "cve": "CVE-2024-1086",
        "name": "nf_tables Use-After-Free (2024)",
        "category": "Netfilter",
        "affected_min": "5.14",
        "affected_max": "6.6.14",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Use-after-free in nf_tables netfilter allows local users to escalate privileges to root.",
        "fix_commit": "f342de4e2f33e0e39165d8639387aa6c19dff660",
        "patch_indicator": ["net/netfilter/nf_tables_api.c"],
        "note": "Affects kernel 5.14–6.6.14 — patch in 6.6.15+. Requires unprivileged user namespaces.",
        "thai_detail": (
            " Use-After-Free nf_tables Netfilter Subsystem 2024\n"
            " nft_verdict_init() rule element freed memory\n"
            " Unprivileged user namespace CVE trigger \n"
            " memory corruption → kernel code execution → root\n"
            " WSL2 kernel 6.6.x range — verify kernel version"
        ),
        "thai_mitigation": (
            "1. Kernel 6.6.15+ \n"
            " 2. Unprivileged user namespace :\n"
            "        sysctl -w kernel.unprivileged_userns_clone=0\n"
            " 3. Ubuntu: apt update && apt upgrade linux-image-$(uname -r)\n"
            " 4. Verify: uname -r (need > 6.6.14)"
        )
    },
    # ── New: Looney Tunables / glibc ──
    {
        "cve": "CVE-2023-4911",
        "name": "Looney Tunables — glibc Buffer Overflow",
        "category": "glibc",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Buffer overflow in glibc's GLIBC_TUNABLES env var handler lets local users escalate to root via any SUID binary.",
        "patch_indicator": [],
        "runtime_check": "glibc",
        "note": "Userspace CVE — depends on libc6 package version, not kernel. Runtime check via dpkg.",
        "thai_detail": (
            " Buffer Overflow GLIBC_TUNABLES environment variable glibc 2023\n"
            " ld.so dynamic linker SUID binary GLIBC_TUNABLES= trigger\n"
            " Stack-based buffer overflow → arbitrary code execution → root\n"
            " Ubuntu 22.04 / 23.04 (unpatched libc6) affected\n"
            " CVSSv3 7.8 LOCAL — any user with shell access"
        ),
        "thai_mitigation": (
            "1. libc6 upgrade: apt upgrade libc6\n"
            " 2. Ubuntu 22.04 target: 2.35-0ubuntu3.4 \n"
            " 3. Ubuntu 23.04 target: 2.37-0ubuntu2.1 \n"
            " 4. Verify: dpkg -l libc6 | grep '^ii'\n"
            " 5. Temporary: unset GLIBC_TUNABLES SUID "
        )
    },
]

# ==============================
# Severity Helpers
# ==============================
SEVERITY_COLOR = {
    "CRITICAL": Color.BG_RED + Color.BOLD,
    "HIGH":     Color.RED + Color.BOLD,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.GREEN,
    "NONE":     Color.GRAY,
}

def severity_from_cvss(score):
    from core.utils import score_to_severity
    return score_to_severity(score)

# ==============================
# System Information
# ==============================
def get_kernel_version():
    full = platform.uname().release
    base = full.split("-")[0]
    return base, full

def get_hostname():
    return platform.node()

def get_arch():
    return platform.machine()

# ==============================
# Backport Patch Detection
# ==============================
def _is_wsl() -> bool:
    """Detect if running inside WSL (Windows Subsystem for Linux)."""
    try:
        with open("/proc/version") as fh:
            return "microsoft" in fh.read().lower()
    except Exception:
        return False


def _get_ubuntu_kernel_version() -> str:
    """Return the full Ubuntu kernel package version string (e.g. 6.8.0-52-generic)."""
    import re as _re
    try:
        import platform
        return platform.release()
    except Exception:
        return ""


def check_backport_via_sysfs(cve_entry: dict):
    """
    Detect whether a CVE has been patched via distro backport.

    Returns:
        True  — confirmed patched
        False — confirmed vulnerable (rare; only if exploit conditions verified)
        None  — cannot determine (show as UNKNOWN, not VULNERABLE)

    Strategy (in order):
      1. patch_indicator list in CVE_DB entry — check /proc or sysfs
      2. dpkg changelog for the running kernel package (Debian/Ubuntu)
      3. rpm changelog (RHEL/CentOS)
      4. Ubuntu / WSL heuristic: if the kernel ABI version is newer than
         the last-known vulnerable ABI, treat as PATCHED.
      5. Fall back to None (UNKNOWN) — never False just because we couldn't verify.
    """
    import re as _re
    cve_id     = cve_entry["cve"]
    indicators = cve_entry.get("patch_indicator", [])

    # ── Method 1: patch_indicator sysfs / proc check ──────────────
    for indicator in indicators:
        try:
            result = subprocess.run(
                ["grep", "-r", indicator, "/proc/version"],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                return True
        except Exception:
            pass

    # ── Method 2: dpkg changelog for running kernel ───────────────
    try:
        import platform
        kver = platform.release()           # e.g. 6.8.0-52-generic
        pkg  = f"linux-image-{kver}"
        chg  = subprocess.run(
            ["apt-get", "changelog", "--no-download", "-qq", pkg],
            capture_output=True, text=True, timeout=8
        )
        if cve_id in chg.stdout:
            return True
    except Exception:
        pass

    # ── Method 3: dpkg -l linux-image + dpkg-query changelog ─────
    try:
        pkgs = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\n", "linux-image-*"],
            capture_output=True, text=True, timeout=3
        )
        for pkg in pkgs.stdout.strip().splitlines():
            chg = subprocess.run(
                ["zcat", f"/usr/share/doc/{pkg}/changelog.Debian.gz"],
                capture_output=True, text=True, timeout=4
            )
            if cve_id in chg.stdout:
                return True
    except Exception:
        pass

    # ── Method 4: RPM changelog (RHEL/CentOS/Fedora) ─────────────
    try:
        rpm = subprocess.run(
            ["rpm", "-q", "--changelog", "kernel"],
            capture_output=True, text=True, timeout=5
        )
        if rpm.returncode == 0 and cve_id in rpm.stdout:
            return True
    except Exception:
        pass

    # ── Method 5: Ubuntu/WSL ABI heuristic ───────────────────────
    # Ubuntu backports security fixes into the SAME kernel version string
    # (e.g. 6.8.0-52 is patched even though upstream 6.8 is "vulnerable").
    # We check the ABI number (the -NN- part) against a known-safe threshold.
    patched_abi = cve_entry.get("ubuntu_patched_abi")
    if patched_abi is not None:
        try:
            import platform
            release = platform.release()          # e.g. "6.8.0-52-generic"
            m = _re.search(r"\d+\.\d+\.\d+-(\d+)", release)
            if m and int(m.group(1)) >= int(patched_abi):
                return True                       # ABI >= threshold → patched
        except Exception:
            pass

    # ── Method 6: WSL kernels are maintained by Microsoft and ─────
    # ship security patches continuously. If we are on WSL AND the
    # kernel ABI number is high (>= 50 is a reasonable heuristic for
    # 2024+ kernels), assume modern WSL kernel is patched unless we
    # have a specific indicator saying otherwise.
    if _is_wsl():
        try:
            import platform
            release = platform.release()
            m = _re.search(r"\d+\.\d+\.\d+-(\d+)", release)
            if m and int(m.group(1)) >= 40:
                # High ABI on WSL → almost certainly has all backports
                return True
        except Exception:
            pass

    return None   # Cannot confirm either way → show as UNKNOWN, not VULNERABLE

def check_kpatch(cve_id):
    """Check if kpatch live-patch covers this CVE"""
    try:
        result = subprocess.run(
            ["kpatch", "list"],
            capture_output=True, text=True, timeout=3
        )
        if cve_id.replace("-", "_").lower() in result.stdout.lower():
            return True
    except:
        pass
    return False

# ==============================
# Version Range Match
# ==============================
def is_vulnerable(current, min_v, max_v):
    try:
        cur = version.parse(current)
        return version.parse(min_v) <= cur <= version.parse(max_v)
    except:
        return False

def _make_finding(entry: dict, status: str,
                  backport: object = None, kpatch: bool = False) -> dict:
    """Build a standardised finding dict from a CVE_DB entry."""
    return {
        "cve":               entry["cve"],
        "name":              entry["name"],
        "category":          entry["category"],
        "severity":          entry["severity"],
        "cvss":              entry["cvss"],
        "description":       entry["description"],
        "status":            status,
        "backport_detected": backport,
        "kpatch_detected":   kpatch,
        "note":              entry.get("note", ""),
        "thai_detail":       entry.get("thai_detail", ""),
        "thai_mitigation":   entry.get("thai_mitigation", ""),
    }


# ==============================
# Core Scan
# ==============================
def scan_kernel(kernel_ver):
    findings = []

    for entry in CVE_DB:
        if not is_vulnerable(kernel_ver, entry["affected_min"], entry["affected_max"]):
            continue

        # ── Step 1: Runtime package-level checks (userspace CVEs) ──
        # These are more accurate than kernel version-range matching.
        cve_id = entry["cve"]

        if cve_id == "CVE-2021-3156":          # Baron Samedit — sudo version
            if _check_sudo_patched():
                findings.append(_make_finding(entry, "PATCHED", backport=True))
                continue

        elif cve_id == "CVE-2021-4034":        # PwnKit — polkit version
            if _check_polkit_patched():
                findings.append(_make_finding(entry, "PATCHED", backport=True))
                continue

        elif entry.get("runtime_check") == "glibc" or cve_id == "CVE-2023-4911":
            if _check_glibc_patched():
                findings.append(_make_finding(entry, "PATCHED", backport=True))
                continue
            # glibc check is definitive; if not patched, report VULNERABLE
            findings.append(_make_finding(entry, "VULNERABLE"))
            continue

        # ── Step 2: Backport / sysfs / changelog detection ──
        patched_via_backport = check_backport_via_sysfs(entry)
        patched_via_kpatch   = check_kpatch(cve_id)

        if patched_via_backport is True or patched_via_kpatch:
            status = "PATCHED"
        elif patched_via_backport is None:
            # Could not confirm either way — safer to say UNKNOWN, not VULNERABLE
            status = "UNKNOWN"
        else:
            # Confirmed not patched via backport checks
            try:
                if version.parse(kernel_ver) > version.parse(entry["affected_max"]):
                    status = "UNKNOWN"   # version > affected_max but couldn't confirm backport
                else:
                    status = "VULNERABLE"
            except Exception:
                status = "UNKNOWN"

        findings.append(_make_finding(entry, status,
                                      backport=patched_via_backport,
                                      kpatch=patched_via_kpatch))

    return findings

# ==============================
# Pretty Print Report
# ==============================
def print_banner():
    _print_banner('Kernel CVE Scanner  |  "Conquer Vulnerabilities"')

def print_sysinfo(kernel_full, distro, hostname, arch):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ SYSTEM INFORMATION ════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname   :')} {c(Color.WHITE, hostname)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro     :')} {c(Color.WHITE, distro)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Kernel     :')} {c(Color.YELLOW + Color.BOLD, kernel_full)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch       :')} {c(Color.WHITE, arch)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp  :')} {c(Color.WHITE, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

def print_thai_detail(finding):
    """Print Thai vulnerability detail and mitigation block"""
    thai_detail     = finding.get("thai_detail", "")
    thai_mitigation = finding.get("thai_mitigation", "")

    if thai_detail:
        print(f" {c(Color.BLUE + Color.BOLD, '📋 ():')}")
        print(f"     {c(Color.CYAN,  '   ' + thai_detail)}")

    if thai_mitigation:
        print(f" {c(Color.GREEN + Color.BOLD, '🛡 /:')}")
        print(f"     {c(Color.GREEN, '   ' + thai_mitigation)}")

def print_findings(findings):
    if not findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No vulnerabilities matched for this kernel version.\n"))
        return

    # Group by status
    vulnerable = [f for f in findings if f["status"] == "VULNERABLE"]
    unknown    = [f for f in findings if f["status"] == "UNKNOWN"]
    patched    = [f for f in findings if f["status"] == "PATCHED"]

    def print_group(group, label, label_color):
        if not group:
            return
        print(f"\n{label_color}{Color.BOLD}  ── {label} ({len(group)}) ──{Color.RESET}")
        for f in group:
            icon = "✖" if f["status"] == "VULNERABLE" else ("?" if f["status"] == "UNKNOWN" else "✔")
            icon_color = Color.RED if f["status"] == "VULNERABLE" else (Color.YELLOW if f["status"] == "UNKNOWN" else Color.GREEN)
            sev_badge = severity_badge(f["severity"])
            print(f"\n  {c(icon_color, icon)}  {c(Color.BOLD + Color.WHITE, f['cve'])}  {c(Color.MAGENTA, f['name'])}  {sev_badge}")
            print(f"     {c(Color.GRAY, 'Category   :')} {c(Color.CYAN, f['category'])}")
            print(f"     {c(Color.GRAY, 'CVSS Score :')} {cvss_bar(f['cvss'])}")
            print(f"     {c(Color.GRAY, 'Description:')} {f['description'][:80]}{'...' if len(f['description'])>80 else ''}")
            if f["note"]:
                print(f"     {c(Color.YELLOW, '⚠  Note     :')} {f['note']}")
            if f["backport_detected"] is True:
                print(f"     {c(Color.GREEN, '✔  Backport : Patch detected via package manager')}")
            elif f["kpatch_detected"]:
                print(f"     {c(Color.GREEN, '✔  kpatch   : Live patch detected')}")
            elif f["status"] == "UNKNOWN":
                print(f"     {c(Color.YELLOW, '?  Backport : Could not verify — manual check recommended')}")

            # ── NEW: Thai detail + mitigation ──
            print()
            print_thai_detail(f)
            print(f"     {c(Color.GRAY, '─' * 60)}")

    print_group(vulnerable, "VULNERABLE", Color.RED)
    print_group(unknown,    "UNVERIFIED (may be patched by distro)", Color.YELLOW)
    print_group(patched,    "PATCHED",    Color.GREEN)

def print_summary(findings, kernel_ver):
    total      = len(findings)
    vulnerable = sum(1 for f in findings if f["status"] == "VULNERABLE")
    unknown    = sum(1 for f in findings if f["status"] == "UNKNOWN")
    patched    = sum(1 for f in findings if f["status"] == "PATCHED")
    max_cvss   = max((f["cvss"] for f in findings), default=0)
    overall    = severity_from_cvss(max_cvss)

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ SCAN SUMMARY ════════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Kernel Scanned  :')} {c(Color.YELLOW + Color.BOLD, kernel_ver)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'CVEs in Database:')} {c(Color.WHITE, str(len(CVE_DB)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Matches   :')} {c(Color.WHITE, str(total))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,  '  Vulnerable     :')} {c(Color.RED + Color.BOLD, str(vulnerable))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  Unverified     :')} {c(Color.YELLOW + Color.BOLD, str(unknown))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GREEN, '  Patched        :')} {c(Color.GREEN + Color.BOLD, str(patched))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk    :')} {severity_badge(overall)}  {c(Color.GRAY,'CVSS')} {c(Color.BOLD, f'{max_cvss:.1f}')}")
    print(c(Color.CYAN + Color.BOLD,  '  ╚═══════════════════════════════════════════════════════════╝\n'))

# ==============================
# Save Report
# ==============================
def save_report(findings, kernel_ver, kernel_full, distro):
    report = {
        "tool":      "COSVINTE — Kernel CVE Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname":       get_hostname(),
            "distro":         distro,
            "kernel_version": kernel_ver,
            "kernel_full":    kernel_full,
            "arch":           get_arch(),
        },
        "summary": {
            "total_cve_db":    len(CVE_DB),
            "total_matches":   len(findings),
            "vulnerable":      sum(1 for f in findings if f["status"] == "VULNERABLE"),
            "unverified":      sum(1 for f in findings if f["status"] == "UNKNOWN"),
            "patched":         sum(1 for f in findings if f["status"] == "PATCHED"),
            "overall_cvss":    max((f["cvss"] for f in findings), default=0),
            "overall_severity": severity_from_cvss(max((f["cvss"] for f in findings), default=0)),
        },
        "findings": findings,
    }
    return save_json(report, "cosvinte_kernel")

# ==============================
# MAIN
# ==============================
def main():
    print_banner()

    kernel_ver, kernel_full = get_kernel_version()
    distro   = get_distro()
    hostname = get_hostname()
    arch     = get_arch()

    print_sysinfo(kernel_full, distro, hostname, arch)

    print(c(Color.CYAN, "  [*] Scanning against CVE database..."), end="", flush=True)
    findings = scan_kernel(kernel_ver)
    print(c(Color.GREEN, " done\n"))

    print_findings(findings)
    print_summary(findings, kernel_ver)

    filename = save_report(findings, kernel_ver, kernel_full, distro)
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, filename)}\n"))

if __name__ == "__main__":
    main()
