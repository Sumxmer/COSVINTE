#!/usr/bin/env python3

import os
import json
import stat
import pwd
import subprocess
import platform
from datetime import datetime

from core.utils import (
    Color, c, severity_badge, cvss_bar,
    get_distro, save_json, print_banner as _print_banner,
)

# ==============================
# Capability Risk Database
# Full description + CVE mapping + exploit notes
# ==============================
# 15 vulnerable capabilities 
CAP_DB = {
    "cap_sys_admin": {
        "severity": "CRITICAL",
        "base_score": 9.5,
        "description": "Effectively equivalent to root. Allows mount, pivot_root, kernel module load, arbitrary namespace ops.",
        "description_th": " root mount filesystem, kernel module, namespace ",
        "impact_th": " container, rootkit kernel, ",
        "exploit": "docker escape, kernel module injection, overlay mount abuse",
        "cves": ["CVE-2022-0492", "CVE-2022-25636", "CVE-2021-22555"],
        "remediation": "Remove cap_sys_admin. Use specific caps instead. Never assign to untrusted binaries.",
        "prevention_th": [
            " cap_sys_admin binary ",
            " capability cap_net_admin network ",
            " AppArmor SELinux ",
            ": getcap -r / 2>/dev/null",
        ],
    },
    "cap_setuid": {
        "severity": "CRITICAL",
        "base_score": 9.0,
        "description": "Allows setting arbitrary UID — attacker can switch to UID 0 (root) at will.",
        "description_th": " UID UID 0 (root) root ",
        "impact_th": " binary scripting interpreter python perl os.setuid(0) root ",
        "exploit": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "cves": ["CVE-2021-4034", "CVE-2019-14287"],
        "remediation": "Remove cap_setuid from all non-essential binaries. Audit with: getcap -r / 2>/dev/null",
        "prevention_th": [
            " cap_setuid interpreter (python, perl, ruby, node ) ",
            " binary : getcap -r / 2>/dev/null | grep setuid",
            " sudo least-privilege capability",
            " audit log UID : auditctl -a always,exit -F arch=b64 -S setuid",
        ],
    },
    "cap_setgid": {
        "severity": "HIGH",
        "base_score": 8.0,
        "description": "Allows setting arbitrary GID — attacker can join privileged groups (shadow, disk, docker).",
        "description_th": " GID group shadow, disk, docker",
        "impact_th": " group 'shadow' /etc/shadow group 'disk' raw disk ",
        "exploit": "Switch to GID of 'shadow' group to read /etc/shadow hashes",
        "cves": ["CVE-2021-4034"],
        "remediation": "Remove cap_setgid. Ensure binaries only have minimum required capabilities.",
        "prevention_th": [
            " cap_setgid binary group",
            " group : getent group shadow disk docker",
            " /etc/shadow root: chmod 000 /etc/shadow",
            " PAM module group",
        ],
    },
    "cap_dac_override": {
        "severity": "HIGH",
        "base_score": 7.5,
        "description": "Bypasses all file read/write/execute permission checks — can read /etc/shadow, /root/.",
        "description_th": " (read/write/execute) /etc/shadow /root/",
        "impact_th": " password hash, /etc/passwd backdoor account, binary SUID",
        "exploit": "Read /etc/shadow, overwrite /etc/passwd, modify SUID binaries",
        "cves": ["CVE-2023-4911", "CVE-2016-1247"],
        "remediation": "Remove cap_dac_override. Use ACLs for specific file access instead.",
        "prevention_th": [
            " cap_dac_override POSIX ACL ",
            " immutable flag : chattr +i /etc/passwd /etc/shadow",
            " IMA (Integrity Measurement Architecture) ",
            " integrity AIDE Tripwire ",
        ],
    },
    "cap_dac_read_search": {
        "severity": "HIGH",
        "base_score": 7.0,
        "description": "Bypasses file read and directory search permission checks — allows reading any file.",
        "description_th": " directory ",
        "impact_th": " private key, config files, database credentials permission ",
        "exploit": "tar -czf /tmp/shadow.tar.gz /etc/shadow",
        "cves": ["CVE-2014-8990"],
        "remediation": "Remove cap_dac_read_search. Restrict to specific backup tools only.",
        "prevention_th": [
            " cap_dac_read_search backup tool ",
            " sensitive encryption at rest ",
            " audit log sensitive: auditctl -w /etc/shadow -p r",
            " sensitive files filesystem access control ",
        ],
    },
    "cap_net_admin": {
        "severity": "MEDIUM",
        "base_score": 6.5,
        "description": "Full network configuration access — can modify routing, firewall rules, sniff traffic.",
        "description_th": " network routing table, firewall, traffic ",
        "impact_th": " firewall rules port, ARP spoofing , redirect traffic attacker-controlled server",
        "exploit": "iptables -F (flush all firewall rules), ARP spoofing, traffic capture",
        "cves": ["CVE-2020-14386", "CVE-2016-8655"],
        "remediation": "Limit to network management daemons only. Never assign to scripting languages.",
        "prevention_th": [
            " cap_net_admin daemon network ( NetworkManager)",
            " cap_net_admin scripting interpreter general-purpose tools",
            " network namespace network environment process",
            " firewall rules : iptables -L -n -v",
        ],
    },
    "cap_net_raw": {
        "severity": "MEDIUM",
        "base_score": 6.0,
        "description": "Allows raw socket creation — enables network sniffing, spoofing, and ICMP manipulation.",
        "description_th": " raw socket network traffic, packet, ICMP ",
        "impact_th": " credentials network, ARP poisoning MITM attack, inject packet ",
        "exploit": "tcpdump credential capture, ARP/ICMP spoofing, packet injection",
        "cves": ["CVE-2020-14386"],
        "remediation": "Limit cap_net_raw to specific tools (ping, tcpdump). Never assign broadly.",
        "prevention_th": [
            " cap_net_raw tool ping tcpdump path ",
            " network encryption (TLS/HTTPS) sniffing",
            " Dynamic ARP Inspection switch ARP spoofing",
            "Monitor network anomaly IDS Suricata Snort",
        ],
    },
    "cap_sys_ptrace": {
        "severity": "HIGH",
        "base_score": 8.5,
        "description": "Allows ptrace on any process — can inject code into running processes including root-owned ones.",
        "description_th": " ptrace process process root inject code dump memory process ",
        "impact_th": " credentials memory process password manager SSH agent, inject shellcode process ",
        "exploit": "Inject shellcode into /sbin/init or any privileged process",
        "cves": ["CVE-2019-13272", "CVE-2021-3492"],
        "remediation": "Remove cap_sys_ptrace. Set sysctl kernel.yama.ptrace_scope=2.",
        "prevention_th": [
            " kernel.yama.ptrace_scope=2 /etc/sysctl.conf ptrace",
            " cap_sys_ptrace binary debugger ",
            " seccomp profile ptrace syscall process ",
            " ASLR PIE exploit ptrace ",
        ],
    },
    "cap_sys_module": {
        "severity": "CRITICAL",
        "base_score": 9.8,
        "description": "Allows loading/unloading kernel modules — complete kernel code execution as root.",
        "description_th": " kernel module code kernel OS ",
        "impact_th": " rootkit kernel antivirus system monitor, , backdoor ",
        "exploit": "insmod /tmp/rootkit.ko — full kernel rootkit installation",
        "cves": ["CVE-2019-2025"],
        "remediation": "Remove immediately. Lock kernel modules: sysctl kernel.modules_disabled=1",
        "prevention_th": [
            " kernel modules boot: sysctl -w kernel.modules_disabled=1",
            " Secure Boot kernel module signing module ",
            " DKMS module ",
            " kernel module : lsmod | grep -v '^Module'",
            " read-only root filesystem module ",
        ],
    },
    "cap_chown": {
        "severity": "HIGH",
        "base_score": 7.8,
        "description": "Allows changing file ownership arbitrarily — can take ownership of any file including /etc/passwd.",
        "description_th": " owner /etc/passwd, /etc/shadow, binary SUID",
        "impact_th": " ownership /etc/shadow password hash, chown binary SUID backdoor",
        "exploit": "chown attacker /etc/shadow && read hashes",
        "cves": ["CVE-2021-4034"],
        "remediation": "Remove cap_chown from non-essential binaries. Audit carefully.",
        "prevention_th": [
            " cap_chown binary ",
            " immutable flag : chattr +i /etc/passwd /etc/shadow /etc/sudoers",
            " filesystem monitoring ownership ",
            " ownership SUID binary : find / -perm -4000 -ls 2>/dev/null",
        ],
    },
    "cap_fowner": {
        "severity": "MEDIUM",
        "base_score": 6.5,
        "description": "Bypasses permission checks for operations requiring file ownership match.",
        "description_th": " chmod, chown, attribute ",
        "impact_th": " chmod 777 sensitive permission directory trojan",
        "exploit": "chmod 777 /etc/shadow — make sensitive files world-readable",
        "cves": [],
        "remediation": "Remove cap_fowner. Use targeted file ACLs instead.",
        "prevention_th": [
            " cap_fowner POSIX ACL ",
            "Monitor permission auditd",
            " Linux Security Module (LSM) AppArmor policy ",
        ],
    },
    "cap_sys_rawio": {
        "severity": "CRITICAL",
        "base_score": 9.2,
        "description": "Raw I/O access to block devices — can read/write raw disk including /dev/sda.",
        "description_th": " block device (raw I/O) disk /dev/sda filesystem",
        "impact_th": " disk '' , MBR/GPT bootkit, disk",
        "exploit": "dd if=/dev/sda | grep -a password — extract credentials from raw disk",
        "cves": [],
        "remediation": "Remove immediately. Never assign to user-accessible binaries.",
        "prevention_th": [
            " cap_sys_rawio user-space binary capability ",
            " /dev/sda block device udev rules",
            " disk LUKS ",
            " raw disk access audit log: auditctl -w /dev/sda -p rw",
        ],
    },
    "cap_kill": {
        "severity": "LOW",
        "base_score": 3.5,
        "description": "Allows sending signals to any process — can kill critical system daemons.",
        "description_th": " signal process process root kill daemon ",
        "impact_th": " kill process systemd, syslog, security daemon logging activity",
        "exploit": "kill -9 1 (kill init/systemd) causing system crash",
        "cves": [],
        "remediation": "Restrict to specific process management tools only.",
        "prevention_th": [
            " cap_kill process management tool ",
            " systemd service protection: ProtectSystem=strict, ProtectHome=true",
            " watchdog critical daemon restart ",
        ],
    },
    "cap_sys_chroot": {
        "severity": "MEDIUM",
        "base_score": 6.0,
        "description": "Allows chroot to arbitrary directories — combined with other caps can escape sandbox.",
        "description_th": " chroot directory capability chroot sandbox ",
        "impact_th": " chroot environment root filesystem cap_sys_chroot capability ",
        "exploit": "chroot escape combined with cap_sys_admin or writable filesystem",
        "cves": ["CVE-2015-1318"],
        "remediation": "Remove cap_sys_chroot or combine with seccomp/AppArmor restrictions.",
        "prevention_th": [
            " container technology Docker systemd-nspawn chroot isolate ",
            " seccomp profile syscall process chroot",
            " chroot directory writable filesystem ",
        ],
    },
    "cap_audit_write": {
        "severity": "LOW",
        "base_score": 3.0,
        "description": "Allows writing to kernel audit log — can be used to obscure attack traces.",
        "description_th": " kernel audit log log ",
        "impact_th": " inject audit entry activity forensics incident response ",
        "exploit": "Inject false audit entries to cover tracks during an attack",
        "cves": [],
        "remediation": "Only assign to audit daemons. Monitor audit log integrity.",
        "prevention_th": [
            " cap_audit_write auditd daemon ",
            " audit log remote server (log aggregator) real-time ",
            " log integrity verification signing audit logs",
            "Monitor audit log SIEM tool",
        ],
    },
}

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

def get_file_owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except:
        return "unknown"

def is_world_writable(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except:
        return False

def is_setuid(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_ISUID)
    except:
        return False

def is_setgid(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_ISGID)
    except:
        return False

def get_file_type(path):
    try:
        mode = os.stat(path).st_mode
        if stat.S_ISREG(mode):  return "binary"
        if stat.S_ISDIR(mode):  return "directory"
        if stat.S_ISLNK(mode):  return "symlink"
    except:
        pass
    return "unknown"

# ==============================
# Get Capabilities
# ==============================
def get_capabilities():
    try:
        result = subprocess.run(
            ["getcap", "-r", "/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True, timeout=60
        )
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        return lines
    except FileNotFoundError:
        print(c(Color.YELLOW, "  ⚠  'getcap' not found. Install: apt install libcap2-bin"))
        return []
    except Exception as e:
        print(c(Color.RED, f"  ✖  getcap error: {e}"))
        return []

# ==============================
# Parse & Analyze Capabilities
# ==============================
def parse_cap_line(line):
    """Parse: /usr/bin/python3 = cap_setuid+ep"""
    if "=" not in line:
        return None, None, None
    parts = line.split("=", 1)
    path = parts[0].strip()
    cap_str = parts[1].strip().lower()

    cap_types = []
    if "+e" in cap_str or "=ep" in cap_str or "eip" in cap_str:
        cap_types.append("effective")
    if "+p" in cap_str or "=p" in cap_str:
        cap_types.append("permitted")
    if "+i" in cap_str or "=i" in cap_str:
        cap_types.append("inheritable")

    return path, cap_str, cap_types if cap_types else ["permitted"]


def min_severity(a: str, b: str) -> str:
    """Return the less severe of two severity strings."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return a if order.get(a, 9) >= order.get(b, 9) else b

def _wsl_detected() -> bool:
    try:
        with open("/proc/version") as fh:
            return "microsoft" in fh.read().lower()
    except Exception:
        return False


# Capabilities that are HIGH severity on bare metal but LOW on WSL
_WSL_REDUCED_CAPS = {"cap_net_admin", "cap_net_raw", "cap_net_bind_service"}

# Capabilities that require exploitable conditions beyond just existing
_REQUIRES_WRITABLE_PATH = {"cap_dac_override", "cap_dac_read_search"}


def analyze_capabilities(lines):
    findings = []
    seen = set()

    for line in lines:
        path, cap_str, cap_types = parse_cap_line(line)
        if not path:
            continue

        for cap_name, cap_info in CAP_DB.items():
            if cap_name not in cap_str:
                continue

            key = f"{path}:{cap_name}"
            if key in seen:
                continue
            seen.add(key)

            writable  = is_world_writable(path)
            suid      = is_setuid(path)
            owner     = get_file_owner(path)
            ftype     = get_file_type(path)

            score = cap_info["base_score"]
            risk_factors = []

            if writable:
                score += 0.5
                risk_factors.append("world-writable (+0.5)")
            if suid:
                score += 0.3
                risk_factors.append("SUID bit set (+0.3)")
            if owner != "root":
                score += 0.2
                risk_factors.append(f"owned by non-root: {owner} (+0.2)")
            if "effective" in cap_types:
                risk_factors.append("effective capability (immediately usable)")

            score = min(round(score, 1), 10.0)

            binary_name = os.path.basename(path).lower()
            is_interpreter = any(x in binary_name for x in [
                "python", "perl", "ruby", "node", "php",
                "bash", "sh", "dash", "lua", "tcl",
            ])
            if is_interpreter:
                risk_factors.append(f"scripting interpreter — trivial exploitation")
                score = min(score + 0.5, 10.0)

            findings.append({
                "binary":           path,
                "binary_name":      binary_name,
                "capability":       cap_name,
                "cap_type":         ", ".join(cap_types),
                "severity":         cap_info["severity"],
                "risk_score":       score,
                "owner":            owner,
                "world_writable":   writable,
                "suid":             suid,
                "file_type":        ftype,
                "is_interpreter":   is_interpreter,
                "risk_factors":     risk_factors,
                "description":      cap_info["description"],
                "description_th":   cap_info.get("description_th", ""),
                "impact_th":        cap_info.get("impact_th", ""),
                "exploit_hint":     cap_info["exploit"],
                "cves":             cap_info["cves"],
                "remediation":      cap_info["remediation"],
                "prevention_th":    cap_info.get("prevention_th", []),
            })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    # ── Post-process: reduce false positives ─────────────────────
    wsl = _wsl_detected()
    refined = []
    for f in findings:
        cap = f.get("capability", "").lower()

        # On WSL, network capabilities can't reach the real network stack
        if wsl and any(c in cap for c in _WSL_REDUCED_CAPS):
            f["severity"]      = "LOW"
            f["risk_score"]    = min(f.get("risk_score", 5.0), 3.0)
            f["false_positive_note"] = (
                "WSL environment detected — network capabilities have limited "
                "exploitability because WSL2 networking is NATed through Windows."
            )

        # cap_dac_override only matters if a writable sensitive path exists
        if any(c in cap for c in _REQUIRES_WRITABLE_PATH):
            import os as _os
            sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
            if not any(_os.access(p, _os.W_OK) for p in sensitive):
                f["false_positive_note"] = (
                    "cap_dac_override is present but no sensitive file "
                    "(/etc/passwd, /etc/shadow, /etc/sudoers) is currently "
                    "writable — exploitation requires additional conditions."
                )
                f["severity"]   = min_severity(f.get("severity", "HIGH"), "MEDIUM")
                f["risk_score"] = min(f.get("risk_score", 7.0), 5.0)

        refined.append(f)
    return refined

# ==============================
# Simulate Lab Environment
# ==============================
def setup_lab():
    """Create fake getcap output for testing"""
    print(c(Color.CYAN, "\n  [*] Using Lab Simulation mode\n"))
    fake_lines = [
        "/usr/bin/python3.11 = cap_setuid+ep",
        "/usr/bin/perl = cap_dac_override+ep",
        "/usr/bin/tcpdump = cap_net_raw+ep",
        "/usr/bin/ping = cap_net_raw+p",
        "/usr/sbin/dumpcap = cap_net_admin,cap_net_raw+ep",
        "/usr/bin/vim.basic = cap_dac_read_search+ep",
        "/usr/local/bin/custom_tool = cap_sys_admin+ep",
        "/usr/bin/node = cap_setuid,cap_setgid+ep",
    ]
    return fake_lines

# ==============================
# Pretty Output
# ==============================
def print_banner():
    _print_banner('Linux Capability Scanner  |  "Conquer Vulnerabilities"')

def print_sysinfo(mode_label):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ SYSTEM INFORMATION ════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname  :')} {c(Color.WHITE,  platform.node())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro    :')} {c(Color.WHITE,  get_distro())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch      :')} {c(Color.WHITE,  platform.machine())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Mode      :')} {c(Color.YELLOW, mode_label)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Caps in DB:')} {c(Color.WHITE,  str(len(CAP_DB)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp :')} {c(Color.WHITE,  datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

def print_findings(findings):
    if not findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No dangerous capabilities found on this system.\n"))
        return

    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        groups.get(f["severity"], groups["LOW"]).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        group = groups[sev]
        if not group:
            continue

        sev_color = {
            "CRITICAL": Color.BG_RED + Color.BOLD,
            "HIGH":     Color.RED + Color.BOLD,
            "MEDIUM":   Color.YELLOW + Color.BOLD,
            "LOW":      Color.GREEN,
        }.get(sev, Color.GRAY)

        print(f"\n{sev_color}  ── {sev} ({len(group)}) ──{Color.RESET}")

        for f in group:
            interp_icon = c(Color.RED + Color.BOLD, " 🐍INTERPRETER") if f["is_interpreter"] else ""
            ww_icon     = c(Color.ORANGE, " ✎WRITABLE") if f["world_writable"] else ""
            suid_icon   = c(Color.YELLOW, " ⚑SUID") if f["suid"] else ""

            print(f"\n  {c(Color.RED + Color.BOLD, '✖')}  {c(Color.WHITE + Color.BOLD, f['binary'])}{interp_icon}{ww_icon}{suid_icon}")
            print(f"     {c(Color.GRAY,'Capability  :')} {c(Color.MAGENTA + Color.BOLD, f['capability'])}  "
                  f"{c(Color.GRAY,'type:')} {c(Color.CYAN, f['cap_type'])}")
            print(f"     {c(Color.GRAY,'Risk Score  :')} {cvss_bar(f['risk_score'])}")
            print(f"     {c(Color.GRAY,'Owner       :')} {c(Color.CYAN, f['owner'])}  "
                  f"{c(Color.GRAY,'file:')} {c(Color.CYAN, f['file_type'])}")

            # English description (truncated)
            print(f"     {c(Color.GRAY,'Description :')} {f['description'][:80]}{'...' if len(f['description'])>80 else ''}")

            # ── Thai vulnerability explanation ──
            if f.get("description_th"):
                print(f" {c(Color.CYAN,'📋 :')} {c(Color.WHITE, f['description_th'][:90])}{'...' if len(f['description_th'])>90 else ''}")
            if f.get("impact_th"):
                print(f" {c(Color.ORANGE,'⚡ :')} {c(Color.YELLOW, f['impact_th'][:90])}{'...' if len(f['impact_th'])>90 else ''}")

            if f["risk_factors"]:
                print(f"     {c(Color.ORANGE,'⚠  Factors   :')} {c(Color.YELLOW, ' | '.join(f['risk_factors'][:3]))}")

            if f["exploit_hint"]:
                print(f"     {c(Color.RED,'💀 Exploit   :')} {c(Color.GRAY, f['exploit_hint'][:75])}")

            if f["cves"]:
                cve_str = "  ".join(c(Color.CYAN, cv) for cv in f["cves"][:3])
                print(f"     {c(Color.GRAY,'CVEs        :')} {cve_str}")

            # ── Prevention tips in Thai ──
            if f.get("prevention_th"):
                print(f" {c(Color.GREEN + Color.BOLD,'🛡 :')}")
                for i, tip in enumerate(f["prevention_th"], 1):
                    print(f"       {c(Color.GREEN, f'  {i}.')} {c(Color.GRAY, tip[:85])}{'...' if len(tip)>85 else ''}")
            else:
                print(f"     {c(Color.GREEN,'✦  Fix       :')} {c(Color.GRAY, f['remediation'][:80])}")

def print_summary(findings):
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low      = sum(1 for f in findings if f["severity"] == "LOW")
    interps  = sum(1 for f in findings if f["is_interpreter"])
    ww       = sum(1 for f in findings if f["world_writable"])
    max_score = max((f["risk_score"] for f in findings), default=0)

    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        if score > 0:  return "LOW"
        return "NONE"

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ SCAN SUMMARY ════════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Binaries with Caps :')} {c(Color.WHITE + Color.BOLD, str(len(findings)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.BG_RED + Color.BOLD,'  CRITICAL               :')} {c(Color.RED + Color.BOLD, str(critical))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,   '  HIGH                   :')} {c(Color.RED + Color.BOLD, str(high))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  MEDIUM                 :')} {c(Color.YELLOW + Color.BOLD, str(medium))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GREEN, '  LOW                    :')} {c(Color.GREEN + Color.BOLD, str(low))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Scripting Interpreters   :')} {c(Color.RED + Color.BOLD if interps else Color.GREEN, str(interps))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'World-Writable Binaries  :')} {c(Color.RED + Color.BOLD if ww else Color.GREEN, str(ww))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk Score       :')} {severity_badge(sev(max_score))}  {c(Color.GRAY,'Score')} {c(Color.BOLD, f'{max_score:.1f}')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚═══════════════════════════════════════════════════════════╝\n'))

# ==============================
# MAIN (standalone run)
# ==============================
def main():
    print_banner()

    print(c(Color.CYAN + Color.BOLD, "  Select Mode:"))
    print(f"  {c(Color.WHITE,'1')} {c(Color.GRAY,'─')} Real Scan (getcap -r /)")
    print(f"  {c(Color.WHITE,'2')} {c(Color.GRAY,'─')} Lab Simulation (safe demo)\n")

    mode = input(c(Color.CYAN, "  Enter choice [1/2]: ")).strip()

    if mode == "2":
        lines      = setup_lab()
        mode_label = "Lab Simulation"
    else:
        mode_label = "Real Scan"
        print(c(Color.CYAN, "\n  [*] Running getcap -r / (may take a moment)..."), end="", flush=True)
        lines = get_capabilities()
        print(c(Color.GREEN, f" {len(lines)} entries found\n"))

    print_sysinfo(mode_label)

    print(c(Color.CYAN, "  [*] Analyzing capabilities..."), end="", flush=True)
    findings = analyze_capabilities(lines)
    print(c(Color.GREEN, f" {len(findings)} findings\n"))

    print_findings(findings)
    print_summary(findings)

    from core.utils import system_info, save_json, score_to_severity
    max_score = max((f["risk_score"] for f in findings), default=0)
    report = {
        "tool":      "COSVINTE — Linux Capability Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    system_info(),
        "summary": {
            "total_findings":   len(findings),
            "critical":         sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":             sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":           sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":              sum(1 for f in findings if f["severity"] == "LOW"),
            "interpreters":     sum(1 for f in findings if f["is_interpreter"]),
            "world_writable":   sum(1 for f in findings if f["world_writable"]),
            "overall_score":    max_score,
            "overall_severity": score_to_severity(max_score),
        },
        "findings": findings,
    }
    fname = save_json(report, "cosvinte_caps")
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, fname)}\n"))

if __name__ == "__main__":
    main()
