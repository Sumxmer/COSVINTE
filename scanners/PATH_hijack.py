#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — PATH Hijack Scanner  |  "Conquer Vulnerabilities"
"""

import os
import json
import stat
import pwd
import subprocess
import platform
from datetime import datetime

from core.utils import (
    Color, c, severity_badge, cvss_bar,
    get_distro, system_info, save_json, print_banner as _print_banner,
)

# ==============================
# CVE Database
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit — pkexec ENV Injection",
        "category": "SUID / Polkit",
        "description": "pkexec fails to handle argv/envp correctly, allowing environment variable injection to load malicious shared objects as root.",
        "description_th": "pkexec argv/envp inject environment variable shared object root",
        "impact_th": " (non-root) root Linux distribution pkexec SUID ",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade polkit >= 0.120 or: chmod 0755 /usr/bin/pkexec",
        "prevention_th": [
            " polkit 0.120 : apt upgrade policykit-1",
            " SUID bit : chmod 0755 /usr/bin/pkexec",
            " exploit : ausearch -c pkexec --raw | aureport -f",
            " AppArmor/SELinux profile pkexec action ",
        ],
        "trigger": {
            "needs_suid_binary": ["pkexec", "polkit"],
            "needs_writable_path": False,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2019-14287",
        "name": "sudo -u#-1 Runas Bypass",
        "category": "sudo",
        "description": "sudo allows a user to run commands as UID -1 (resolves to 0/root) if sudoers allows runas ALL, bypassing restrictions.",
        "description_th": "sudo command UID -1 resolve UID 0 (root) sudoers runas ALL ",
        "impact_th": " sudo 'sudo -u#-1 /bin/bash' root shell root ",
        "cvss": 8.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.8.28 and audit /etc/sudoers for 'ALL' runas entries.",
        "prevention_th": [
            " sudo 1.8.28 : apt upgrade sudo",
            " sudoers ALL: grep -i 'runas.*all' /etc/sudoers /etc/sudoers.d/*",
            " 'ALL' runas spec user/group ",
            " 'sudo -l' audit user ",
        ],
        "trigger": {
            "needs_suid_binary": ["sudo"],
            "needs_writable_path": False,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2010-3847",
        "name": "LD_PRELOAD / LD_AUDIT Hijack",
        "category": "Dynamic Linker",
        "description": "SUID binaries that do not sanitize LD_PRELOAD / LD_AUDIT environment variables allow loading attacker-controlled shared libraries as root.",
        "description_th": "SUID binary LD_PRELOAD LD_AUDIT dynamic linker shared library root",
        "impact_th": " .so file malicious code LD_PRELOAD SUID binary library root",
        "cvss": 7.2,
        "severity": "HIGH",
        "remediation": "Ensure ld.so ignores LD_PRELOAD for SUID binaries (default in modern glibc). Audit SUID binaries.",
        "prevention_th": [
            " glibc LD_PRELOAD SUID binary ",
            " environment variable shell: unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH",
            " env_reset sudoers environment sudo: Defaults env_reset",
            " LD_PRELOAD /etc/environment, /etc/profile, .bashrc",
            " seccomp/AppArmor syscall SUID binary ",
        ],
        "trigger": {
            "needs_suid_binary": [],
            "needs_writable_path": False,
            "needs_env_var": ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]
        }
    },
    {
        "cve": "CVE-2016-2779",
        "name": "runuser Insecure PATH",
        "category": "PATH Hijack",
        "description": "runuser/su does not sanitize PATH, allowing attackers to place malicious binaries in world-writable PATH dirs that get executed as root.",
        "description_th": "runuser su PATH variable binary PATH directory binary root",
        "impact_th": " world-writable directory PATH /tmp binary command script root script binary ",
        "cvss": 7.0,
        "severity": "HIGH",
        "remediation": "Remove world-writable directories from PATH. Use absolute paths in scripts.",
        "prevention_th": [
            " world-writable directory PATH /tmp /var/tmp",
            " path absolute script /usr/bin/python3 python3",
            " secure PATH /etc/environment: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            " 'env -i' script environment ",
            "audit script root privilege absolute path",
        ],
        "trigger": {
            "needs_suid_binary": ["su", "runuser"],
            "needs_writable_path": True,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2015-1318",
        "name": "OverlayFS Local Privilege Escalation",
        "category": "Filesystem / PATH",
        "description": "Ubuntu OverlayFS allows unprivileged users to mount overlayfs on arbitrary paths, combined with PATH hijack to escalate privileges.",
        "description_th": "Ubuntu mount overlayfs path PATH hijack ",
        "impact_th": " overlayfs layer /bin /usr/bin binary binary world-writable PATH directory exploit ",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "remediation": "Upgrade kernel. Restrict user namespaces: sysctl -w kernel.unprivileged_userns_clone=0",
        "prevention_th": [
            " kernel patch ",
            " unprivileged user namespace: sysctl -w kernel.unprivileged_userns_clone=0",
            " reboot: echo 'kernel.unprivileged_userns_clone=0' >> /etc/sysctl.conf",
            " world-writable directory PATH attack surface",
        ],
        "trigger": {
            "needs_suid_binary": [],
            "needs_writable_path": True,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2017-1000367",
        "name": "sudo Insecure PATH (Sudosmash)",
        "category": "sudo / PATH",
        "description": "sudo on Linux reads /proc/[pid]/stat to determine terminal device. Combined with PATH hijack in writable dir, allows privilege escalation.",
        "description_th": "sudo /proc/[pid]/stat terminal device parse world-writable PATH directory ",
        "impact_th": " sudo binary world-writable directory symlink file root shell ",
        "cvss": 6.3,
        "severity": "MEDIUM",
        "remediation": "Upgrade sudo >= 1.8.21. Ensure no world-writable dirs appear before /usr/bin in PATH.",
        "prevention_th": [
            " sudo 1.8.21 ",
            " world-writable directory PATH /usr/bin",
            " PATH : echo $PATH | tr ':' '\\n' | while read p; do ls -ld \"$p\"; done",
            " secure_path sudoers override PATH : Defaults secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ],
        "trigger": {
            "needs_suid_binary": ["sudo"],
            "needs_writable_path": True,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2023-22809",
        "name": "sudoedit PATH Arbitrary File Edit",
        "category": "sudo",
        "description": "sudoedit allows users to append extra flags controlling the editor. Combined with writable PATH, arbitrary files can be edited as root.",
        "description_th": "sudoedit flag editor writable PATH SUDO_EDITOR set root",
        "impact_th": " SUDO_EDITOR VISUAL script sudoedit script root /etc/passwd /etc/sudoers ",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.9.12p2. Restrict SUDO_EDITOR and VISUAL env vars.",
        "prevention_th": [
            " sudo 1.9.12p2 ",
            " env_delete sudoers env var : Defaults env_delete+='SUDO_EDITOR VISUAL EDITOR'",
            " editor sudoers: Defaults editor=/usr/bin/nano:/usr/bin/vim",
            " SUDO_EDITOR VISUAL set environment: env | grep -E 'EDITOR|VISUAL'",
        ],
        "trigger": {
            "needs_suid_binary": ["sudo"],
            "needs_writable_path": False,
            "needs_env_var": ["SUDO_EDITOR", "VISUAL", "EDITOR"]
        }
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe — SUID Binary Overwrite",
        "category": "Kernel / SUID",
        "description": "Dirty Pipe allows overwriting arbitrary read-only files including SUID binaries via pipe buffer flags, enabling privilege escalation.",
        "description_th": " Linux kernel read-only SUID binary pipe buffer ",
        "impact_th": " SUID binary /usr/bin/passwd shellcode binary root shell read-only owned by root",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade kernel >= 5.16.11 / 5.15.25 / 5.10.102",
        "prevention_th": [
            " kernel 5.16.11, 5.15.25, 5.10.102 ",
            " kernel : uname -r",
            " attack surface SUID binary ",
            " integrity checking IMA SUID binary",
            "Monitor kernel exploit attempt auditd: auditctl -a always,exit -F arch=b64 -S open -F exit=-EACCES",
        ],
        "trigger": {
            "needs_suid_binary": [],
            "needs_writable_path": False,
            "needs_env_var": [],
            "needs_any_suid": True
        }
    },
    {
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit — sudo Heap Overflow",
        "category": "sudo",
        "description": "Heap-based buffer overflow in sudoedit (triggered by trailing backslash) allows unprivileged local users to gain root.",
        "description_th": " heap buffer overflow sudoedit backslash argument code root",
        "impact_th": " argument trailing backslash sudoedit trigger heap overflow heap exploitation root password",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.9.5p2",
        "prevention_th": [
            " sudo 1.9.5p2 : apt upgrade sudo",
            " sudo : sudo --version",
            " exploit : grep 'sudo' /var/log/auth.log | grep -i 'error\\|segfault'",
            " aliasas block sudoedit ",
        ],
        "trigger": {
            "needs_suid_binary": ["sudo"],
            "needs_writable_path": False,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2019-18634",
        "name": "sudo pwfeedback Stack Overflow",
        "category": "sudo",
        "description": "Buffer overflow in sudo pwfeedback feature allows privilege escalation when a user can run sudo commands.",
        "description_th": " stack buffer overflow sudo pwfeedback feature '*' password input overflow",
        "impact_th": " password pipe sudo overflow stack buffer execution flow root shell",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.8.31 or disable pwfeedback in sudoers.",
        "prevention_th": [
            " sudo 1.8.31 ",
            " pwfeedback /etc/sudoers: Defaults !pwfeedback",
            " pwfeedback : sudo -l | grep pwfeedback",
            " grep -r 'pwfeedback' /etc/sudoers /etc/sudoers.d/ audit ",
        ],
        "trigger": {
            "needs_suid_binary": ["sudo"],
            "needs_writable_path": False,
            "needs_env_var": []
        }
    },
    {
        "cve": "CVE-2014-0196",
        "name": "n_tty Race Condition via SUID",
        "category": "Kernel / TTY",
        "description": "Race condition in Linux kernel tty layer allows local privilege escalation; exploitable via SUID tty-attached binaries.",
        "description_th": "Race condition tty layer Linux kernel SUID binary attach tty ",
        "impact_th": " SUID binary tty trigger race condition kernel execute code root — SUID binary ",
        "cvss": 6.9,
        "severity": "MEDIUM",
        "remediation": "Upgrade kernel >= 3.14.3. Apply distro patches.",
        "prevention_th": [
            " kernel 3.14.3 apply distro security patch",
            " SUID binary : find / -perm -4000 -type f 2>/dev/null",
            " systemd sandboxing service tty: PrivateTmp=yes, NoNewPrivileges=yes",
        ],
        "trigger": {
            "needs_suid_binary": [],
            "needs_writable_path": False,
            "needs_env_var": [],
            "needs_any_suid": True
        }
    },
    {
        "cve": "CVE-2017-7308",
        "name": "AF_PACKET via Writable PATH Escalation",
        "category": "Network / PATH",
        "description": "AF_PACKET socket combined with world-writable PATH directories allows crafting race conditions for privilege escalation.",
        "description_th": "AF_PACKET socket world-writable PATH directory race condition ",
        "impact_th": " AF_PACKET socket ( cap_net_raw) PATH directory trigger race condition kernel network stack root",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade kernel >= 4.10.6. Restrict raw socket capabilities.",
        "prevention_th": [
            " kernel 4.10.6 ",
            " AF_PACKET socket: sysctl -w net.core.bpf_jit_harden=2",
            " world-writable directory PATH attack vector",
            " cap_net_raw process ",
            " seccomp profile block socket(AF_PACKET) syscall process ",
        ],
        "trigger": {
            "needs_suid_binary": [],
            "needs_writable_path": True,
            "needs_env_var": []
        }
    },
]

# ==============================
# Dangerous ENV var descriptions (Thai)
# ==============================
ENV_VAR_INFO = {
    "LD_PRELOAD": {
        "desc_th": " dynamic linker shared library library override function SUID binary",
        "risk": "HIGH"
    },
    "LD_AUDIT": {
        "desc_th": " audit library dynamic linker inject code LD_PRELOAD",
        "risk": "HIGH"
    },
    "LD_LIBRARY_PATH": {
        "desc_th": " directory shared library library ",
        "risk": "HIGH"
    },
    "SUDO_EDITOR": {
        "desc_th": " editor sudoedit set script root privilege",
        "risk": "MEDIUM"
    },
    "VISUAL": {
        "desc_th": " visual editor sudo inherit env_reset set",
        "risk": "MEDIUM"
    },
    "EDITOR": {
        "desc_th": " default text editor sudo program ",
        "risk": "MEDIUM"
    },
    "PYTHONPATH": {
        "desc_th": " directory Python module Python binary SUID capability module ",
        "risk": "MEDIUM"
    },
    "PERL5LIB": {
        "desc_th": " directory Perl module PYTHONPATH inject malicious Perl module",
        "risk": "MEDIUM"
    },
    "RUBYLIB": {
        "desc_th": " directory Ruby library override standard library code ",
        "risk": "MEDIUM"
    },
    "JAVA_TOOL_OPTIONS": {
        "desc_th": " JVM options Java process inject Java agent ",
        "risk": "MEDIUM"
    },
    "NODE_OPTIONS": {
        "desc_th": " Node.js runtime options malicious module disable security feature Node",
        "risk": "MEDIUM"
    },
    "DYLD_INSERT_LIBRARIES": {
        "desc_th": "macOS equivalent LD_PRELOAD dynamic library library ",
        "risk": "HIGH"
    },
}

# ==============================
# System Info
# ==============================
def get_current_user():
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except:
        return "unknown"

# ==============================
# PATH Analysis
# ==============================
def get_path_owner(path):
    try:
        uid = os.stat(path).st_uid
        return pwd.getpwuid(uid).pw_name
    except:
        return "unknown"

def is_world_writable(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except:
        return False

def is_relative_path(path):
    return not os.path.isabs(path)

def path_exists(path):
    return os.path.isdir(path)

def scan_path():
    path_env  = os.environ.get("PATH", "")
    path_dirs = [p for p in path_env.split(":") if p]
    findings  = []

    for idx, directory in enumerate(path_dirs):
        entry = {
            "directory":      directory,
            "order":          idx + 1,
            "exists":         path_exists(directory),
            "relative":       is_relative_path(directory),
            "world_writable": False,
            "owner":          "N/A",
            "risk":           "OK",
            "issues":         []
        }

        if entry["relative"]:
            entry["issues"].append("Relative path — hijackable")
            entry["risk"] = "HIGH"

        if entry["exists"]:
            entry["world_writable"] = is_world_writable(directory)
            entry["owner"]          = get_path_owner(directory)

            if entry["world_writable"]:
                entry["issues"].append("World-writable")
                entry["risk"] = "HIGH"

            if entry["world_writable"] and idx < 3:
                entry["issues"].append("Appears early in PATH (position #%d)" % (idx + 1))
        else:
            entry["issues"].append("Directory does not exist — phantom PATH entry")
            entry["risk"] = "MEDIUM"

        findings.append(entry)

    return findings

# ==============================
# Environment Variable Scan
# ==============================
DANGEROUS_ENV_VARS = [
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH",
    "SUDO_EDITOR", "VISUAL", "EDITOR",
    "PYTHONPATH", "PERL5LIB", "RUBYLIB",
    "JAVA_TOOL_OPTIONS", "NODE_OPTIONS",
    "DYLD_INSERT_LIBRARIES",
]

def scan_env_vars():
    findings = []
    for var in DANGEROUS_ENV_VARS:
        val = os.environ.get(var)
        if val:
            info = ENV_VAR_INFO.get(var, {})
            findings.append({
                "variable": var,
                "value":    val[:80] + ("..." if len(val) > 80 else ""),
                "risk":     info.get("risk", "MEDIUM"),
                "desc_th":  info.get("desc_th", ""),
            })
    return findings

# ==============================
# SUID Binary Scan
# ==============================
KNOWN_SUID_DANGEROUS = [
    "nmap", "vim", "less", "more", "nano", "awk", "gawk",
    "find", "cp", "mv", "chmod", "chown", "python", "python3",
    "perl", "ruby", "bash", "sh", "dash", "env", "tee",
    "wget", "curl", "tar", "zip", "strace", "gdb",
    "pkexec", "sudo", "su", "newgrp", "passwd",
    "docker", "lxc", "runc",
]

def scan_suid_binaries():
    results = []
    try:
        proc = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True,
            stderr=subprocess.DEVNULL, timeout=30
        )
        for line in proc.stdout.strip().split("\n"):
            if not line:
                continue
            binary_name = os.path.basename(line).lower()
            binary_base = binary_name.rstrip("0123456789.-")

            dangerous = any(
                binary_name.startswith(d) or binary_base == d
                for d in KNOWN_SUID_DANGEROUS
            )

            results.append({
                "path":      line.strip(),
                "binary":    binary_name,
                "dangerous": dangerous,
            })
    except Exception:
        pass

    results.sort(key=lambda x: (0 if x["dangerous"] else 1, x["binary"]))
    return results

# ==============================
# CVE Correlation
# ==============================
def correlate_cve(path_findings, env_findings, suid_findings):
    has_writable_path = any(f["world_writable"] for f in path_findings)
    has_relative_path = any(f["relative"] for f in path_findings)
    env_vars_present  = {f["variable"] for f in env_findings}
    suid_binaries     = {os.path.basename(s["path"]).lower() for s in suid_findings}
    has_any_suid      = len(suid_findings) > 0

    hits = []
    for cve in CVE_DB:
        t = cve["trigger"]
        matched_reasons = []

        if t.get("needs_suid_binary"):
            found_suid = [b for b in t["needs_suid_binary"]
                          if any(s.startswith(b) for s in suid_binaries)]
            if not found_suid:
                continue
            matched_reasons.append(f"SUID binary found: {', '.join(found_suid)}")

        if t.get("needs_any_suid") and not has_any_suid:
            continue
        elif t.get("needs_any_suid"):
            matched_reasons.append(f"{len(suid_findings)} SUID binaries present")

        if t.get("needs_writable_path"):
            if not (has_writable_path or has_relative_path):
                continue
            if has_writable_path:
                matched_reasons.append("World-writable PATH directory detected")
            if has_relative_path:
                matched_reasons.append("Relative PATH entry detected")

        if t.get("needs_env_var"):
            found_env = [v for v in t["needs_env_var"] if v in env_vars_present]
            if not found_env:
                continue
            matched_reasons.append(f"Dangerous env var set: {', '.join(found_env)}")

        hits.append({**cve, "matched_reasons": matched_reasons})

    return sorted(hits, key=lambda x: x["cvss"], reverse=True)

# ==============================
# Pretty Output
# ==============================
def print_banner():
    _print_banner('PATH Hijack Scanner  |  "Conquer Vulnerabilities"')

def print_sysinfo():
    print(c(Color.CYAN + Color.BOLD, "  ╔══ SYSTEM INFORMATION ════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname  :')} {c(Color.WHITE, platform.node())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro    :')} {c(Color.WHITE, get_distro())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch      :')} {c(Color.WHITE, platform.machine())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'User      :')} {c(Color.YELLOW, get_current_user())} {c(Color.GRAY, '(UID: ' + str(os.getuid()) + ')')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp :')} {c(Color.WHITE, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

def print_path_analysis(findings):
    print(c(Color.CYAN + Color.BOLD, f"\n  ── PATH ANALYSIS ({len(findings)} entries) ──\n"))

    for f in findings:
        order_str = c(Color.GRAY, f"[#{f['order']:02d}]")

        if not f["exists"]:
            icon  = c(Color.GRAY, "✗")
            color = Color.GRAY
        elif f["world_writable"] or f["relative"]:
            icon  = c(Color.RED + Color.BOLD, "!")
            color = Color.RED
        else:
            icon  = c(Color.GREEN, "✔")
            color = Color.WHITE

        print(f"  {icon} {order_str} {c(color + Color.BOLD, f['directory'])}")

        if f["exists"]:
            print(f"      {c(Color.GRAY,'owner:')} {c(Color.CYAN, f['owner'])}  "
                  f"{c(Color.GRAY,'writable:')} {c(Color.RED + Color.BOLD, 'YES') if f['world_writable'] else c(Color.GREEN,'no')}  "
                  f"{c(Color.GRAY,'relative:')} {c(Color.RED + Color.BOLD, 'YES') if f['relative'] else c(Color.GREEN,'no')}")

        if f["issues"]:
            for issue in f["issues"]:
                print(f"      {c(Color.ORANGE, '⚠')} {c(Color.YELLOW, issue)}")

def print_env_analysis(findings):
    if not findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No dangerous environment variables detected.\n"))
        return

    print(c(Color.RED + Color.BOLD, f"\n  ── DANGEROUS ENV VARS ({len(findings)}) ──\n"))
    for f in findings:
        risk_c = Color.RED if f["risk"] == "HIGH" else Color.YELLOW
        print(f"  {c(risk_c + Color.BOLD, '!')}  {c(Color.WHITE + Color.BOLD, f['variable'])} {severity_badge(f['risk'])}")
        print(f"     {c(Color.GRAY,'value   :')} {c(Color.YELLOW, f['value'])}")
        # Thai description
        if f.get("desc_th"):
            print(f" {c(Color.CYAN,'📋 :')} {c(Color.WHITE, f['desc_th'][:90])}{'...' if len(f['desc_th'])>90 else ''}")

def print_suid_analysis(findings):
    dangerous = [f for f in findings if f["dangerous"]]
    safe      = [f for f in findings if not f["dangerous"]]

    print(c(Color.CYAN + Color.BOLD, f"\n  ── SUID BINARIES ({len(findings)} total) ──\n"))

    if dangerous:
        print(c(Color.RED, f"  {Color.BOLD}⚠ High-risk SUID binaries ({len(dangerous)}):{Color.RESET}"))
        for f in dangerous[:15]:
            print(f"    {c(Color.RED + Color.BOLD,'▸')}  {c(Color.WHITE, f['path'])}")

    if safe:
        print(c(Color.GRAY, f"\n  Standard SUID binaries ({len(safe)}):"))
        for f in safe[:10]:
            print(f"    {c(Color.GRAY,'·')}  {c(Color.GRAY, f['path'])}")
        if len(safe) > 10:
            print(c(Color.GRAY, f"    ... and {len(safe)-10} more"))

def print_cve(cve_findings):
    if not cve_findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No CVE correlations triggered.\n"))
        return

    print(c(Color.RED + Color.BOLD, f"\n  ── CVE CORRELATIONS ({len(cve_findings)}) ──"))

    for entry in cve_findings:
        print(f"\n  {c(Color.RED + Color.BOLD, '✖')}  {c(Color.BOLD + Color.WHITE, entry['cve'])}  "
              f"{c(Color.MAGENTA, entry['name'])}  {severity_badge(entry['severity'])}")
        print(f"     {c(Color.GRAY,'Category    :')} {c(Color.CYAN, entry['category'])}")
        print(f"     {c(Color.GRAY,'CVSS Score  :')} {cvss_bar(entry['cvss'])}")
        # English description (short)
        print(f"     {c(Color.GRAY,'Description :')} {entry['description'][:85]}{'...' if len(entry['description'])>85 else ''}")
        # Thai vulnerability explanation
        if entry.get("description_th"):
            print(f" {c(Color.CYAN,'📋 :')} {c(Color.WHITE, entry['description_th'][:90])}{'...' if len(entry['description_th'])>90 else ''}")
        if entry.get("impact_th"):
            print(f" {c(Color.ORANGE,'⚡ :')} {c(Color.YELLOW, entry['impact_th'][:90])}{'...' if len(entry['impact_th'])>90 else ''}")
        print(f"     {c(Color.GRAY,'Triggered by:')}")
        for reason in entry["matched_reasons"]:
            print(f"       {c(Color.ORANGE,'→')} {c(Color.YELLOW, reason)}")
        # Thai prevention tips
        if entry.get("prevention_th"):
            print(f" {c(Color.GREEN + Color.BOLD,'🛡 :')}")
            for i, tip in enumerate(entry["prevention_th"], 1):
                print(f"       {c(Color.GREEN, f'  {i}.')} {c(Color.GRAY, tip[:85])}{'...' if len(tip)>85 else ''}")
        else:
            print(f"     {c(Color.GREEN,'✦  Fix      :')} {c(Color.GRAY, entry['remediation'])}")

def print_summary(path_f, env_f, suid_f, cve_f):
    writable_count = sum(1 for f in path_f if f["world_writable"])
    relative_count = sum(1 for f in path_f if f["relative"])
    phantom_count  = sum(1 for f in path_f if not f["exists"])
    dangerous_suid = sum(1 for f in suid_f if f["dangerous"])
    max_cvss       = max((c_["cvss"] for c_ in cve_f), default=0)

    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        if score > 0:  return "LOW"
        return "NONE"

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ SCAN SUMMARY ════════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'PATH Entries       :')} {c(Color.WHITE, str(len(path_f)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,  '  World-Writable   :')} {c(Color.RED + Color.BOLD, str(writable_count))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,  '  Relative PATH    :')} {c(Color.RED + Color.BOLD, str(relative_count))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  Phantom (missing):')} {c(Color.YELLOW + Color.BOLD, str(phantom_count))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Dangerous Env Vars :')} {c(Color.YELLOW + Color.BOLD, str(len(env_f)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'SUID Binaries      :')} {c(Color.WHITE, str(len(suid_f)))}  "
          f"{c(Color.RED,'(dangerous: ' + str(dangerous_suid) + ')')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'CVE Correlations   :')} {c(Color.RED + Color.BOLD, str(len(cve_f)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk Score :')} {severity_badge(sev(max_cvss))}  {c(Color.GRAY,'CVSS')} {c(Color.BOLD, f'{max_cvss:.1f}')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚═══════════════════════════════════════════════════════════╝\n'))

# ==============================
# Save Report
# ==============================
def save_report(path_f, env_f, suid_f, cve_f):
    from core.utils import score_to_severity
    max_cvss = max((c_["cvss"] for c_ in cve_f), default=0)
    report = {
        "tool":      "COSVINTE — PATH Hijack Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            **system_info(),
            "user": get_current_user(),
            "uid":  os.getuid(),
        },
        "summary": {
            "path_entries":       len(path_f),
            "writable_path_dirs": sum(1 for f in path_f if f["world_writable"]),
            "relative_path_dirs": sum(1 for f in path_f if f["relative"]),
            "phantom_path_dirs":  sum(1 for f in path_f if not f["exists"]),
            "dangerous_env_vars": len(env_f),
            "suid_binaries":      len(suid_f),
            "dangerous_suid":     sum(1 for f in suid_f if f["dangerous"]),
            "cve_correlations":   len(cve_f),
            "overall_cvss":       max_cvss,
            "overall_severity":   score_to_severity(max_cvss),
        },
        "path_analysis":    path_f,
        "env_var_findings": env_f,
        "suid_binaries":    suid_f,
        "cve_correlations": [{k: v for k, v in e.items() if k != "trigger"} for e in cve_f],
    }
    return save_json(report, "cosvinte_path")

# ==============================
# MAIN
# ==============================
def main():
    print_banner()
    print_sysinfo()

    print(c(Color.CYAN, "  [*] Analyzing PATH variable..."), end="", flush=True)
    path_f = scan_path()
    print(c(Color.GREEN, f" {len(path_f)} entries\n"))

    print(c(Color.CYAN, "  [*] Scanning environment variables..."), end="", flush=True)
    env_f = scan_env_vars()
    print(c(Color.GREEN, f" {len(env_f)} suspicious\n"))

    print(c(Color.CYAN, "  [*] Scanning SUID binaries (this may take a moment)..."), end="", flush=True)
    suid_f = scan_suid_binaries()
    print(c(Color.GREEN, f" {len(suid_f)} found\n"))

    print(c(Color.CYAN, "  [*] Correlating CVEs..."), end="", flush=True)
    cve_f = correlate_cve(path_f, env_f, suid_f)
    print(c(Color.GREEN, f" {len(cve_f)} matched\n"))

    print_path_analysis(path_f)
    print_env_analysis(env_f)
    print_suid_analysis(suid_f)
    print_cve(cve_f)
    print_summary(path_f, env_f, suid_f, cve_f)

    fname = save_report(path_f, env_f, suid_f, cve_f)
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, fname)}\n"))

if __name__ == "__main__":
    main()
