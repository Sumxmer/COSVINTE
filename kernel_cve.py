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

# ==============================
# ANSI Color Codes
# ==============================
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[40m"

def c(color, text):
    """Wrap text with color and reset"""
    return f"{color}{text}{Color.RESET}"

# ==============================
# CVE Database (Extended)
# ==============================
CVE_DB = [
    # ── Dirty COW family ──
    {
        "cve": "CVE-2016-5195",
        "name": "Dirty COW",
        "category": "Race Condition",
        "affected_min": "2.6.22",
        "affected_max": "4.8.3",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Race condition in mm/gup.c allows local privilege escalation via write access to read-only mappings.",
        "fix_commit": "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619",
        "patch_indicator": ["mm/gup.c", "cow_user_page"]
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe",
        "category": "Pipe Buffer",
        "affected_min": "5.8",
        "affected_max": "5.16.10",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Flaw in pipe buffer flags allows overwriting read-only files including SUID binaries.",
        "fix_commit": "9d2231c5d74e13b2a0546fee6737ee4446017903",
        "patch_indicator": ["fs/pipe.c", "PIPE_BUF_FLAG_CAN_MERGE"]
    },
    # ── sudo / userspace ──
    {
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit",
        "category": "Heap Overflow",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap-based buffer overflow in sudo sudoedit allows privilege escalation to root.",
        "note": "Affects sudo ≤ 1.9.5p1 — not kernel directly",
        "patch_indicator": []
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
        "patch_indicator": ["fs/fs_context.c", "legacy_parse_param"]
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
        "patch_indicator": ["fs/overlayfs", "ovl_copy_up"]
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
        "patch_indicator": ["net/netfilter/nf_tables_api.c"]
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
        "patch_indicator": ["net/netfilter/nf_tables_api.c"]
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
        "patch_indicator": ["net/netfilter/nf_tables_api.c", "nf_tables_del_setelem"]
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
        "patch_indicator": ["net/sched/cls_flower.c", "fl_set_geneve_opt"]
    },
    # ── Memory / UAF ──
    {
        "cve": "CVE-2021-22555",
        "name": "Netfilter Heap Out-of-Bounds Write",
        "category": "Heap Overflow",
        "affected_min": "2.6.19",
        "affected_max": "5.12.13",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap OOB write in xt_compat_target_from_user() in net/netfilter/x_tables.c.",
        "fix_commit": "b29c457a6511435960115c0f548c4360d5f4801d",
        "patch_indicator": ["net/netfilter/x_tables.c", "xt_compat_target_from_user"]
    },
    {
        "cve": "CVE-2022-27666",
        "name": "ESP Transformation Heap Overflow",
        "category": "IPSec",
        "affected_min": "5.10",
        "affected_max": "5.17.2",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap buffer overflow in IPSec ESP transformation (net/ipv4/esp4.c).",
        "fix_commit": "ebe48d368e97d007bfeb76fcb065d6a511d09b37",
        "patch_indicator": ["net/ipv4/esp4.c", "esp_output_tail"]
    },
    # ── SUID / Capabilities ──
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit (pkexec)",
        "category": "SUID",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Memory corruption in pkexec (polkit) allows unprivileged local privilege escalation.",
        "note": "Affects polkit < 0.120 — not kernel directly",
        "patch_indicator": []
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
        "patch_indicator": ["kernel/cgroup/cgroup-v1.c", "release_agent"]
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
        "patch_indicator": ["net/netfilter/nft_fwd_dup.c"]
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
        "patch_indicator": []
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
        "patch_indicator": []
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
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"

def severity_badge(sev):
    color = SEVERITY_COLOR.get(sev, Color.GRAY)
    return f"{color} {sev} {Color.RESET}"

def cvss_bar(score, width=20):
    filled = int((score / 10.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 7:
        color = Color.RED
    elif score >= 4:
        color = Color.YELLOW
    else:
        color = Color.GREEN
    return f"{color}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"

# ==============================
# System Information
# ==============================
def get_kernel_version():
    full = platform.uname().release
    base = full.split("-")[0]
    return base, full

def get_distro():
    try:
        result = subprocess.run(["lsb_release", "-d"], capture_output=True, text=True)
        return result.stdout.strip().replace("Description:", "").strip()
    except:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        return line.split("=")[1].strip().strip('"')
        except:
            return "Unknown"

def get_hostname():
    return platform.node()

def get_arch():
    return platform.machine()

# ==============================
# Backport Patch Detection
# ==============================
def check_backport_via_sysfs(cve_entry):
    """
    Try to detect if a patch has been backported by distros
    using /proc/sys or changelog heuristics.
    """
    indicators = cve_entry.get("patch_indicator", [])
    if not indicators:
        return None  # Cannot determine

    # Method 1: Check kernel config (some distros expose patch notes)
    try:
        result = subprocess.run(
            ["grep", "-r"] + indicators[:1] + ["/proc/version"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            return True
    except:
        pass

    # Method 2: Check package changelog (Debian/Ubuntu)
    try:
        pkg_result = subprocess.run(
            ["dpkg", "-l", "linux-image*"],
            capture_output=True, text=True, timeout=3
        )
        if pkg_result.returncode == 0:
            cve_id = cve_entry["cve"]
            changelog = subprocess.run(
                ["apt-get", "changelog", f"linux-image-$(uname -r)", "--no-download"],
                capture_output=True, text=True, timeout=5
            )
            if cve_id in changelog.stdout:
                return True
    except:
        pass

    # Method 3: Check RPM changelog (RHEL/CentOS/Fedora)
    try:
        rpm_result = subprocess.run(
            ["rpm", "-q", "--changelog", "kernel"],
            capture_output=True, text=True, timeout=5
        )
        if rpm_result.returncode == 0:
            cve_id = cve_entry["cve"]
            if cve_id in rpm_result.stdout:
                return True
    except:
        pass

    return None  # Unknown

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

# ==============================
# Core Scan
# ==============================
def scan_kernel(kernel_ver):
    findings = []

    for entry in CVE_DB:
        if is_vulnerable(kernel_ver, entry["affected_min"], entry["affected_max"]):
            # Check backport
            patched_via_backport = check_backport_via_sysfs(entry)
            patched_via_kpatch   = check_kpatch(entry["cve"])

            patched = patched_via_backport or patched_via_kpatch
            status  = "PATCHED" if patched else ("UNKNOWN" if patched_via_backport is None else "VULNERABLE")

            findings.append({
                "cve":         entry["cve"],
                "name":        entry["name"],
                "category":    entry["category"],
                "severity":    entry["severity"],
                "cvss":        entry["cvss"],
                "description": entry["description"],
                "status":      status,
                "backport_detected": patched_via_backport,
                "kpatch_detected":   patched_via_kpatch,
                "note":        entry.get("note", "")
            })

    return findings

# ==============================
# Pretty Print Report
# ==============================
def print_banner():
    banner = f"""
{Color.CYAN}{Color.BOLD}
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
{Color.RESET}{Color.GRAY}         Kernel CVE Scanner  |  "Conquer Vulnerabilities"{Color.RESET}
"""
    print(banner)

def print_sysinfo(kernel_full, distro, hostname, arch):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ SYSTEM INFORMATION ════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname   :')} {c(Color.WHITE, hostname)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro     :')} {c(Color.WHITE, distro)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Kernel     :')} {c(Color.YELLOW + Color.BOLD, kernel_full)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch       :')} {c(Color.WHITE, arch)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp  :')} {c(Color.WHITE, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

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
        "tool": "COSVINTE",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": get_hostname(),
            "distro": distro,
            "kernel_version": kernel_ver,
            "kernel_full": kernel_full,
            "arch": get_arch()
        },
        "summary": {
            "total_cve_db": len(CVE_DB),
            "total_matches": len(findings),
            "vulnerable": sum(1 for f in findings if f["status"] == "VULNERABLE"),
            "unverified": sum(1 for f in findings if f["status"] == "UNKNOWN"),
            "patched": sum(1 for f in findings if f["status"] == "PATCHED"),
            "overall_cvss": max((f["cvss"] for f in findings), default=0),
            "overall_severity": severity_from_cvss(max((f["cvss"] for f in findings), default=0))
        },
        "findings": findings
    }

    filename = f"cosvinte_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    return filename

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
