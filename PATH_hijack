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

# ==============================
# ANSI Colors
# ==============================
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    ORANGE  = "\033[38;5;208m"
    BLUE    = "\033[94m"
    BG_RED  = "\033[41m"

def c(color, text):
    return f"{color}{text}{Color.RESET}"

def severity_badge(sev):
    colors = {
        "CRITICAL": Color.BG_RED + Color.BOLD,
        "HIGH":     Color.RED + Color.BOLD,
        "MEDIUM":   Color.YELLOW,
        "LOW":      Color.GREEN,
    }
    return f"{colors.get(sev, Color.GRAY)} {sev} {Color.RESET}"

def cvss_bar(score, width=20):
    filled = int((score / 10.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    color = Color.RED if score >= 7 else (Color.YELLOW if score >= 4 else Color.GREEN)
    return f"{color}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"

# ==============================
# CVE Database — เฉพาะเจาะจง
# trigger_conditions: สิ่งที่ต้องตรวจพบ
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit — pkexec ENV Injection",
        "category": "SUID / Polkit",
        "description": "pkexec fails to handle argv/envp correctly, allowing environment variable injection to load malicious shared objects as root.",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade polkit >= 0.120 or: chmod 0755 /usr/bin/pkexec",
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
        "cvss": 8.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.8.28 and audit /etc/sudoers for 'ALL' runas entries.",
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
        "cvss": 7.2,
        "severity": "HIGH",
        "remediation": "Ensure ld.so ignores LD_PRELOAD for SUID binaries (default in modern glibc). Audit SUID binaries.",
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
        "cvss": 7.0,
        "severity": "HIGH",
        "remediation": "Remove world-writable directories from PATH. Use absolute paths in scripts.",
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
        "cvss": 6.5,
        "severity": "MEDIUM",
        "remediation": "Upgrade kernel. Restrict user namespaces: sysctl -w kernel.unprivileged_userns_clone=0",
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
        "cvss": 6.3,
        "severity": "MEDIUM",
        "remediation": "Upgrade sudo >= 1.8.21. Ensure no world-writable dirs appear before /usr/bin in PATH.",
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
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.9.12p2. Restrict SUDO_EDITOR and VISUAL env vars.",
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
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade kernel >= 5.16.11 / 5.15.25 / 5.10.102",
        "trigger": {
            "needs_suid_binary": [],   # any SUID binary is a target
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
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.9.5p2",
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
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.8.31 or disable pwfeedback in sudoers.",
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
        "cvss": 6.9,
        "severity": "MEDIUM",
        "remediation": "Upgrade kernel >= 3.14.3. Apply distro patches.",
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
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade kernel >= 4.10.6. Restrict raw socket capabilities.",
        "trigger": {
            "needs_suid_binary": [],
            "needs_writable_path": True,
            "needs_env_var": []
        }
    },
]

# ==============================
# System Info
# ==============================
def get_distro():
    try:
        r = subprocess.run(["lsb_release", "-d"], capture_output=True, text=True)
        return r.stdout.replace("Description:", "").strip()
    except:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        return line.split("=")[1].strip().strip('"')
        except:
            return "Unknown"

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
            "directory":     directory,
            "order":         idx + 1,
            "exists":        path_exists(directory),
            "relative":      is_relative_path(directory),
            "world_writable": False,
            "owner":         "N/A",
            "risk":          "OK",
            "issues":        []
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

            # High-risk position: writable early in PATH (first 3)
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
    "DYLD_INSERT_LIBRARIES",  # macOS equiv
]

def scan_env_vars():
    findings = []
    for var in DANGEROUS_ENV_VARS:
        val = os.environ.get(var)
        if val:
            risk = "HIGH" if var in ["LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"] else "MEDIUM"
            findings.append({
                "variable": var,
                "value":    val[:80] + ("..." if len(val) > 80 else ""),
                "risk":     risk
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
            # strip version numbers e.g. python3.10 → python3
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

    # Sort: dangerous first
    results.sort(key=lambda x: (0 if x["dangerous"] else 1, x["binary"]))
    return results

# ==============================
# Precise CVE Correlation
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

        # Check SUID binary requirement
        if t.get("needs_suid_binary"):
            found_suid = [b for b in t["needs_suid_binary"]
                          if any(s.startswith(b) for s in suid_binaries)]
            if not found_suid:
                continue
            matched_reasons.append(f"SUID binary found: {', '.join(found_suid)}")

        # Check any SUID
        if t.get("needs_any_suid") and not has_any_suid:
            continue
        elif t.get("needs_any_suid"):
            matched_reasons.append(f"{len(suid_findings)} SUID binaries present")

        # Check writable PATH requirement
        if t.get("needs_writable_path"):
            if not (has_writable_path or has_relative_path):
                continue
            if has_writable_path:
                matched_reasons.append("World-writable PATH directory detected")
            if has_relative_path:
                matched_reasons.append("Relative PATH entry detected")

        # Check env var requirement
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
    print(f"""
{c(Color.CYAN + Color.BOLD, '''
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝''')}
{c(Color.GRAY, '         PATH Hijack Scanner  |  "Conquer Vulnerabilities"')}
""")

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
        print(f"     {c(Color.GRAY,'value:')} {c(Color.YELLOW, f['value'])}")

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
        print(f"     {c(Color.GRAY,'Category   :')} {c(Color.CYAN, entry['category'])}")
        print(f"     {c(Color.GRAY,'CVSS Score :')} {cvss_bar(entry['cvss'])}")
        print(f"     {c(Color.GRAY,'Description:')} {entry['description'][:85]}{'...' if len(entry['description'])>85 else ''}")
        print(f"     {c(Color.GRAY,'Triggered by:')}")
        for reason in entry["matched_reasons"]:
            print(f"       {c(Color.ORANGE,'→')} {c(Color.YELLOW, reason)}")
        print(f"     {c(Color.GREEN,'✦  Fix     :')} {c(Color.GRAY, entry['remediation'])}")

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
    max_cvss = max((c_["cvss"] for c_ in cve_f), default=0)

    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "NONE"

    report = {
        "tool": "COSVINTE — PATH Hijack Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": platform.node(),
            "distro":   get_distro(),
            "arch":     platform.machine(),
            "user":     get_current_user(),
            "uid":      os.getuid(),
        },
        "summary": {
            "path_entries":         len(path_f),
            "writable_path_dirs":   sum(1 for f in path_f if f["world_writable"]),
            "relative_path_dirs":   sum(1 for f in path_f if f["relative"]),
            "phantom_path_dirs":    sum(1 for f in path_f if not f["exists"]),
            "dangerous_env_vars":   len(env_f),
            "suid_binaries":        len(suid_f),
            "dangerous_suid":       sum(1 for f in suid_f if f["dangerous"]),
            "cve_correlations":     len(cve_f),
            "overall_cvss":         max_cvss,
            "overall_severity":     sev(max_cvss),
        },
        "path_analysis":    path_f,
        "env_var_findings": env_f,
        "suid_binaries":    suid_f,
        "cve_correlations": [
            {k: v for k, v in e.items() if k != "trigger"}
            for e in cve_f
        ],
    }

    fname = f"cosvinte_path_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(report, f, indent=4)
    return fname

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
