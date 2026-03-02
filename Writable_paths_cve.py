#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Writable Path Scanner  |  "Conquer Vulnerabilities"
"""

import os
import json
import stat
import platform
import subprocess
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
# Each CVE has path_patterns that must match
# for correlation to trigger
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2016-1247",
        "name": "Apache Log Dir Writable",
        "description": "World-writable Apache log directory allows local users to replace log files with symlinks, leading to privilege escalation via logrotate.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Web Server",
        "path_patterns": [
            "/var/log/apache", "/var/log/apache2",
            "/var/log/httpd", "/var/log/nginx"
        ],
        "remediation": "chmod 755 /var/log/apache2 && chown root:adm /var/log/apache2"
    },
    {
        "cve": "CVE-2017-1000117",
        "name": "systemd tmpfiles Writable Path",
        "description": "World-writable directories processed by systemd-tmpfiles can be abused to create arbitrary files as root during boot.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "System Service",
        "path_patterns": [
            "/tmp", "/var/tmp", "/run",
            "/var/run", "/dev/shm"
        ],
        "remediation": "chmod 1777 /tmp && chmod 1777 /var/tmp"
    },
    {
        "cve": "CVE-2015-1838",
        "name": "Tomcat Writable Webapps",
        "description": "World-writable Tomcat webapps directory allows unauthenticated file upload leading to remote code execution.",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "category": "Web Server",
        "path_patterns": [
            "/var/lib/tomcat", "/opt/tomcat",
            "/usr/share/tomcat", "/srv/tomcat"
        ],
        "remediation": "chown -R tomcat:tomcat /var/lib/tomcat && chmod 750 /var/lib/tomcat/webapps"
    },
    {
        "cve": "CVE-2018-15686",
        "name": "Docker Symlink Writable Escalation",
        "description": "World-writable Docker runtime directories allow symlink attacks for privilege escalation to root.",
        "cvss": 8.0,
        "severity": "HIGH",
        "category": "Container",
        "path_patterns": [
            "/var/lib/docker", "/run/docker",
            "/var/run/docker", "/etc/docker"
        ],
        "remediation": "chmod 700 /var/lib/docker && chown root:docker /run/docker.sock"
    },
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit — pkexec Writable PATH",
        "description": "World-writable directories in PATH allow injection of malicious shared objects loaded by pkexec, leading to root privilege escalation.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "SUID / Polkit",
        "path_patterns": [
            "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/usr/local/sbin",
            "/bin", "/sbin"
        ],
        "remediation": "chmod 755 /usr/bin /usr/sbin && patch polkit to >= 0.120"
    },
    {
        "cve": "CVE-2019-14287",
        "name": "sudo -u#-1 Bypass",
        "description": "World-writable /etc/sudoers.d directory allows injecting sudo rules to run commands as root.",
        "cvss": 8.8,
        "severity": "HIGH",
        "category": "sudo",
        "path_patterns": [
            "/etc/sudoers", "/etc/sudoers.d",
            "/etc/sudo.conf"
        ],
        "remediation": "chmod 440 /etc/sudoers && chmod 750 /etc/sudoers.d"
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe — Writable Pipe Abuse",
        "description": "World-writable /proc entries combined with Dirty Pipe allow overwriting read-only files via pipe buffer manipulation.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel",
        "path_patterns": [
            "/proc/sysrq-trigger",
            "/proc/sys/fs/pipe-max-size",
            "/proc/sys/fs/pipe-user-pages-soft"
        ],
        "remediation": "Upgrade kernel to >= 5.16.11 / 5.15.25 / 5.10.102"
    },
    {
        "cve": "CVE-2023-4911",
        "name": "Looney Tunables — ld.so Writable",
        "description": "World-writable glibc loader config or lib path allows buffer overflow in GLIBC_TUNABLES leading to root escalation.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "glibc",
        "path_patterns": [
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d/",
            "/etc/ld.so.preload",
            "/lib/x86_64-linux-gnu/libc",
            "/lib/x86_64-linux-gnu/ld-linux",
            "/usr/lib/x86_64-linux-gnu/libc",
            "/lib64/ld-linux"
        ],
        "remediation": "chmod 755 /usr/lib && upgrade glibc to patched version"
    },
    {
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit — sudo Heap Overflow",
        "description": "World-writable /etc or sudo binary allows replacement/tampering leading to heap overflow exploitation.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "sudo",
        "path_patterns": [
            "/etc/sudo.conf",
            "/etc/sudoers",
            "/etc/sudoers.d/",
            "/usr/bin/sudo",
            "/usr/sbin/sudo"
        ],
        "remediation": "Upgrade sudo to >= 1.9.5p2 && chmod 755 /etc"
    },
    {
        "cve": "CVE-2017-16995",
        "name": "eBPF Writable Map Privilege Escalation",
        "description": "World-writable /sys/fs/bpf or unprivileged BPF maps allow kernel memory manipulation for local privilege escalation.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel",
        "path_patterns": [
            "/sys/fs/bpf",
            "/sys/kernel/debug/bpf"
        ],
        "remediation": "sysctl -w kernel.unprivileged_bpf_disabled=1 && chmod 700 /sys/fs/bpf"
    },
    {
        "cve": "CVE-2016-8655",
        "name": "Packet Socket Race Condition",
        "description": "World-writable /proc/net entries combined with race condition allow local privilege escalation via packet socket.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel / Network",
        "path_patterns": [
            "/proc/net", "/proc/sys/net"
        ],
        "remediation": "Upgrade kernel and restrict /proc access via hidepid mount option"
    },
    {
        "cve": "CVE-2020-14386",
        "name": "AF_PACKET Heap Overflow via Writable Net",
        "description": "World-writable network proc files enable exploitation of memory corruption in AF_PACKET socket handling.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Network",
        "path_patterns": [
            "/proc/sys/net", "/proc/net/dev"
        ],
        "remediation": "Upgrade kernel to >= 5.9 and apply network namespace restrictions"
    },
    {
        "cve": "CVE-2019-13272",
        "name": "ptrace PTRACE_TRACEME Privilege Escalation",
        "description": "World-writable /proc/[pid] directories allow ptrace abuse for privilege escalation.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Process",
        "path_patterns": [
            "/proc/sys/kernel/yama/ptrace_scope",
            "/proc/sys/kernel/perf_event_paranoid"
        ],
        "remediation": "sysctl -w kernel.yama.ptrace_scope=1"
    },
    {
        "cve": "CVE-2018-1000001",
        "name": "glibc realpath() Buffer Underflow",
        "description": "World-writable glibc paths allow buffer underflow in realpath() used by SUID programs.",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "glibc",
        "path_patterns": [
            "/etc/ld.so.conf",
            "/etc/ld.so.preload",
            "/lib/x86_64-linux-gnu/libc",
            "/lib/x86_64-linux-gnu/ld-linux",
            "/usr/lib/x86_64-linux-gnu/libc",
            "/lib64/ld-linux"
        ],
        "remediation": "Upgrade glibc to >= 2.26 and restrict lib directory permissions"
    },
    {
        "cve": "CVE-2015-5195",
        "name": "NTP Writable Config Privilege Escalation",
        "description": "World-writable NTP configuration or log paths allow local users to escalate privileges via ntpd.",
        "cvss": 5.0,
        "severity": "MEDIUM",
        "category": "Service",
        "path_patterns": [
            "/etc/ntp.conf", "/var/log/ntpstats",
            "/var/lib/ntp"
        ],
        "remediation": "chmod 644 /etc/ntp.conf && chown ntp:ntp /var/lib/ntp"
    },
]

# ==============================
# Sensitive Paths to Scan
# ==============================
SCAN_ROOTS = [
    "/etc", "/usr/bin", "/usr/sbin",
    "/usr/lib", "/usr/lib64",
    "/var/www", "/var/log",
    "/var/lib", "/opt",
    "/tmp", "/var/tmp",
    "/run", "/proc/sys/kernel",
    "/sys/fs/bpf", "/lib",
]

# ==============================
# Whitelist — known-safe paths (suppress false positives)
# ==============================

# Symlinks shipped by OS packages inside systemd dirs
# are designed to be symlinks — not attacker-controlled.
WHITELIST_PREFIXES = [
    # systemd dirs — symlinks shipped by OS packages
    "/usr/lib/systemd/",
    "/lib/systemd/",
    "/etc/systemd/",
    "/run/systemd/",
    # X11 / display socket dirs — sticky-bit, expected behaviour
    "/tmp/.X11-unix",
    "/tmp/.XIM-unix",
    "/tmp/.ICE-unix",
    "/tmp/.font-unix",
    "/tmp/.dbus-unix",
    # User-private runtime (pipewire, pulseaudio)
    "/run/user/",
    # Standard runtime dirs with sticky bit — normal OS
    "/run/lock",
    "/run/screen",
    "/run/shm",
    # VMware DnD virtualisation artifact
    "/tmp/VMwareDnD",
    # PHP session dir — sticky bit, root-owned, expected
    "/var/lib/php/sessions",
    # Unix domain sockets owned by daemons — IPC, not exploitable writable files
    "/run/ssh-unix-local/",
    "/run/pcscd/",
    "/run/dbus/",
    "/run/avahi-daemon/",
    "/run/cups/",
    "/run/bluetooth/",
    # ns_last_pid — writable by design for user namespaces, not a Dirty Pipe vector
    "/proc/sys/kernel/ns_last_pid",
]

def is_whitelisted(path):
    """Return True for known-safe OS paths that are world-writable by design."""
    p = path.rstrip("/")
    for prefix in WHITELIST_PREFIXES:
        pfx = prefix.rstrip("/")
        if p == pfx or p.startswith(pfx + "/"):
            return True

    # Unix domain sockets anywhere under /run are IPC endpoints, not dangerous
    try:
        if p.startswith("/run/") and stat.S_ISSOCK(os.lstat(p).st_mode):
            return True
    except:
        pass

    # Systemd unit-file symlinks (.service .socket .target etc.) safe OS design
    UNIT_EXTS = (
        ".service", ".socket", ".target", ".mount",
        ".automount", ".swap", ".path", ".timer",
        ".slice", ".scope", ".link", ".network", ".netdev",
    )
    if os.path.islink(p) and p.endswith(UNIT_EXTS):
        try:
            target = os.readlink(p)
            if target == "/dev/null" or "/usr/lib/" in target or "/lib/" in target:
                return True
        except:
            pass

    return False

# ==============================
# Detection Logic
# ==============================
def is_world_writable(path):
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IWOTH)
    except:
        return False

def is_sticky_bit_set(path):
    """Sticky bit on world-writable dir = safer"""
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_ISVTX)
    except:
        return False

def get_owner(path):
    try:
        import pwd
        uid = os.stat(path).st_uid
        return pwd.getpwuid(uid).pw_name
    except:
        return "unknown"

def path_type(path):
    try:
        if os.path.islink(path):   return "symlink"
        if os.path.isdir(path):    return "directory"
        if os.path.isfile(path):   return "file"
    except:
        pass
    return "unknown"

# ==============================
# Scan
# ==============================
def scan_writable_paths():
    findings = []
    visited  = set()

    for base in SCAN_ROOTS:
        if not os.path.exists(base):
            continue
        try:
            for root, dirs, files in os.walk(base, followlinks=False):
                for name in dirs + files:
                    full_path = os.path.join(root, name)
                    if full_path in visited:
                        continue
                    visited.add(full_path)

                    if is_world_writable(full_path):
                        # Skip known-safe OS paths (systemd symlinks, X sockets, etc.)
                        if is_whitelisted(full_path):
                            continue

                        sticky   = is_sticky_bit_set(full_path)
                        ptype    = path_type(full_path)
                        owner    = get_owner(full_path)

                        # Sticky bit on dir reduces risk (e.g. /tmp)
                        risk = "MEDIUM" if sticky else "HIGH"

                        findings.append({
                            "path":    full_path,
                            "type":    ptype,
                            "owner":   owner,
                            "sticky":  sticky,
                            "risk":    risk,
                        })
        except PermissionError:
            continue

    return findings

# ==============================
# Precise CVE Correlation
# ==============================
def correlate_cve(writable_findings):
    """
    Match each CVE only when a writable path matches
    one of its specific path_patterns — not blindly all CVEs.
    """
    writable_paths = [f["path"] for f in writable_findings]
    cve_hits = {}

    for cve in CVE_DB:
        matched_paths = []
        for pattern in cve["path_patterns"]:
            for wp in writable_paths:
                # Exact match OR: wp IS the pattern, or wp is directly inside
                # the pattern dir (not deeper subdirs of unrelated packages)
                if wp == pattern:
                    matched_paths.append(wp)
                elif pattern.endswith("/") and wp.startswith(pattern):
                    # pattern explicitly ends with / = subtree match intended
                    matched_paths.append(wp)
                elif not pattern.endswith("/") and wp.startswith(pattern + "/"):
                    # Only one level deep (e.g. /etc/sudoers.d/file — not /usr/lib/systemd/...)
                    # Allow only if the remainder has no more slashes
                    remainder = wp[len(pattern)+1:]
                    if "/" not in remainder:
                        matched_paths.append(wp)

        if matched_paths:
            cve_hits[cve["cve"]] = {
                **cve,
                "matched_paths": list(set(matched_paths))[:5]  # limit to 5
            }

    return list(cve_hits.values())

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
{c(Color.GRAY, '         Writable Path Scanner  |  "Conquer Vulnerabilities"')}
""")

def print_sysinfo():
    hostname = platform.node()
    distro   = get_distro()
    arch     = platform.machine()
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(c(Color.CYAN + Color.BOLD, "  ╔══ SYSTEM INFORMATION ════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname  :')} {c(Color.WHITE, hostname)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro    :')} {c(Color.WHITE, distro)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch      :')} {c(Color.WHITE, arch)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Scan Roots:')} {c(Color.YELLOW, str(len(SCAN_ROOTS)) + ' directories')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp :')} {c(Color.WHITE, ts)}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

def print_writable(findings):
    if not findings:
        print(c(Color.GREEN + Color.BOLD, "  ✔  No world-writable sensitive paths found.\n"))
        return

    print(c(Color.RED + Color.BOLD, f"\n  ── WORLD-WRITABLE PATHS ({len(findings)}) ──\n"))
    for f in findings[:20]:  # cap display at 20
        sticky_note = c(Color.YELLOW, " [sticky]") if f["sticky"] else ""
        type_icon   = "📁" if f["type"] == "directory" else ("🔗" if f["type"] == "symlink" else "📄")
        risk_color  = Color.YELLOW if f["risk"] == "MEDIUM" else Color.RED
        print(f"  {c(risk_color, '▸')}  {type_icon}  {c(Color.WHITE, f['path'])}{sticky_note}")
        print(f"       {c(Color.GRAY, 'owner:')} {c(Color.CYAN, f['owner'])}  "
              f"{c(Color.GRAY, 'type:')} {c(Color.CYAN, f['type'])}  "
              f"{c(Color.GRAY, 'risk:')} {severity_badge(f['risk'])}")

    if len(findings) > 20:
        print(c(Color.GRAY, f"\n  ... and {len(findings) - 20} more (see JSON report)\n"))

def print_cve(cve_findings):
    if not cve_findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No CVE correlations triggered.\n"))
        return

    print(c(Color.RED + Color.BOLD, f"\n  ── CVE CORRELATIONS ({len(cve_findings)}) ──"))

    for entry in sorted(cve_findings, key=lambda x: x["cvss"], reverse=True):
        print(f"\n  {c(Color.RED + Color.BOLD, '✖')}  {c(Color.BOLD + Color.WHITE, entry['cve'])}  "
              f"{c(Color.MAGENTA, entry['name'])}  {severity_badge(entry['severity'])}")
        print(f"     {c(Color.GRAY, 'Category   :')} {c(Color.CYAN, entry['category'])}")
        print(f"     {c(Color.GRAY, 'CVSS Score :')} {cvss_bar(entry['cvss'])}")
        print(f"     {c(Color.GRAY, 'Description:')} {entry['description'][:85]}{'...' if len(entry['description'])>85 else ''}")
        print(f"     {c(Color.GRAY, 'Matched    :')} {c(Color.YELLOW, str(len(entry['matched_paths'])) + ' path(s)')}")
        for mp in entry["matched_paths"][:3]:
            print(f"       {c(Color.ORANGE, '→')} {c(Color.WHITE, mp)}")
        print(f"     {c(Color.GREEN, '✦  Fix     :')} {c(Color.GRAY, entry['remediation'])}")

def print_summary(writable, cve_hits):
    high_cve  = sum(1 for c_ in cve_hits if c_["severity"] == "HIGH")
    med_cve   = sum(1 for c_ in cve_hits if c_["severity"] == "MEDIUM")
    max_cvss  = max((c_["cvss"] for c_ in cve_hits), default=0)

    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "NONE"

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ SCAN SUMMARY ════════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Writable Paths Found :')} {c(Color.YELLOW + Color.BOLD, str(len(writable)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'CVE Correlations     :')} {c(Color.RED + Color.BOLD, str(len(cve_hits)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,  '  HIGH               :')} {c(Color.RED + Color.BOLD, str(high_cve))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  MEDIUM             :')} {c(Color.YELLOW + Color.BOLD, str(med_cve))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk Score   :')} {severity_badge(sev(max_cvss))}  {c(Color.GRAY,'CVSS')} {c(Color.BOLD, f'{max_cvss:.1f}')}")
    print(c(Color.CYAN + Color.BOLD,  '  ╚═══════════════════════════════════════════════════════════╝\n'))

# ==============================
# Save Report
# ==============================
def save_report(writable, cve_hits):
    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "NONE"

    max_cvss = max((c_["cvss"] for c_ in cve_hits), default=0)

    report = {
        "tool": "COSVINTE — Writable Path Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": platform.node(),
            "distro":   get_distro(),
            "arch":     platform.machine(),
        },
        "summary": {
            "total_writable_paths": len(writable),
            "total_cve_correlations": len(cve_hits),
            "overall_cvss":     max_cvss,
            "overall_severity": sev(max_cvss),
        },
        "writable_paths": writable,
        "cve_correlations": [
            {k: v for k, v in entry.items() if k != "path_patterns"}
            for entry in cve_hits
        ]
    }

    fname = f"cosvinte_writable_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(report, f, indent=4)
    return fname

# ==============================
# MAIN
# ==============================
def main():
    print_banner()
    print_sysinfo()

    print(c(Color.CYAN, "  [*] Scanning world-writable paths..."), end="", flush=True)
    writable = scan_writable_paths()
    print(c(Color.GREEN, f" found {len(writable)}\n"))

    print(c(Color.CYAN, "  [*] Correlating CVEs..."), end="", flush=True)
    cve_hits = correlate_cve(writable)
    print(c(Color.GREEN, f" {len(cve_hits)} matched\n"))

    print_writable(writable)
    print_cve(cve_hits)
    print_summary(writable, cve_hits)

    fname = save_report(writable, cve_hits)
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, fname)}\n"))

if __name__ == "__main__":
    main()
