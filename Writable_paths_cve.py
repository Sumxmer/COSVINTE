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

from cosvinte_utils import (
    Color, c, severity_badge, cvss_bar,
    get_distro, system_info, save_json, print_banner as _print_banner,
)

# ==============================
# CVE Database
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2016-1247",
        "name": "Apache Log Dir Writable",
        "description": "World-writable Apache log directory allows local users to replace log files with symlinks, leading to privilege escalation via logrotate.",
        "description_th": " directory log Apache log file symlink logrotate root",
        "impact_th": " symlink log directory /etc/passwd authorized_keys logrotate → overwrite root",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Web Server",
        "path_patterns": [
            "/var/log/apache", "/var/log/apache2",
            "/var/log/httpd", "/var/log/nginx"
        ],
        "remediation": "chmod 755 /var/log/apache2 && chown root:adm /var/log/apache2",
        "prevention_th": [
            " permission : chmod 755 /var/log/apache2 && chown root:adm /var/log/apache2",
            " logrotate config create permission : grep -r 'create' /etc/logrotate.d/apache2",
            " ACL apache user log : setfacl -m u:www-data:w /var/log/apache2",
            "Monitor symlink log directory: auditctl -w /var/log/apache2 -p wa",
        ],
    },
    {
        "cve": "CVE-2017-1000117",
        "name": "systemd tmpfiles Writable Path",
        "description": "World-writable directories processed by systemd-tmpfiles can be abused to create arbitrary files as root during boot.",
        "description_th": "systemd-tmpfiles directory boot directory file process root",
        "impact_th": " config file /tmp /var/tmp boot systemd-tmpfiles spec attacker root backdoor ",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "System Service",
        "path_patterns": [
            "/tmp", "/var/tmp", "/run",
            "/var/run", "/dev/shm"
        ],
        "remediation": "chmod 1777 /tmp && chmod 1777 /var/tmp",
        "prevention_th": [
            " sticky bit user file : chmod 1777 /tmp && chmod 1777 /var/tmp",
            "Mount /tmp noexec,nosuid execution: mount -o remount,noexec,nosuid /tmp",
            " /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid,size=1G 0 0",
            "Monitor file /tmp: auditctl -w /tmp -p wa -k tmp_write",
        ],
    },
    {
        "cve": "CVE-2015-1838",
        "name": "Tomcat Writable Webapps",
        "description": "World-writable Tomcat webapps directory allows unauthenticated file upload leading to remote code execution.",
        "description_th": " directory webapps Tomcat WAR file web shell Remote Code Execution",
        "impact_th": " .war file JSP shell /var/lib/tomcat/webapps/ → Tomcat deploy → web shell server tomcat user",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "category": "Web Server",
        "path_patterns": [
            "/var/lib/tomcat", "/opt/tomcat",
            "/usr/share/tomcat", "/srv/tomcat"
        ],
        "remediation": "chown -R tomcat:tomcat /var/lib/tomcat && chmod 750 /var/lib/tomcat/webapps",
        "prevention_th": [
            " permission: chown -R tomcat:tomcat /var/lib/tomcat && chmod 750 /var/lib/tomcat/webapps",
            " auto-deploy Tomcat config: <Host autoDeploy=\"false\" deployOnStartup=\"false\">",
            " Tomcat Manager app copy file IP whitelist",
            " webapps directory: auditctl -w /var/lib/tomcat/webapps -p wa",
        ],
    },
    {
        "cve": "CVE-2018-15686",
        "name": "Docker Symlink Writable Escalation",
        "description": "World-writable Docker runtime directories allow symlink attacks for privilege escalation to root.",
        "description_th": "Docker runtime directory symlink Docker daemon root container",
        "impact_th": " symlink /var/lib/docker /run/docker /etc/shadow → Docker daemon symlink access overwrite root",
        "cvss": 8.0,
        "severity": "HIGH",
        "category": "Container",
        "path_patterns": [
            "/var/lib/docker", "/run/docker",
            "/var/run/docker", "/etc/docker"
        ],
        "remediation": "chmod 700 /var/lib/docker && chown root:docker /run/docker.sock",
        "prevention_th": [
            " permission: chmod 700 /var/lib/docker && chown root:docker /run/docker.sock",
            " user docker group root: getent group docker",
            " rootless Docker container root: dockerd-rootless-setuptool.sh install",
            " Docker Content Trust verify image: export DOCKER_CONTENT_TRUST=1",
        ],
    },
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit — pkexec Writable PATH",
        "description": "World-writable directories in PATH allow injection of malicious shared objects loaded by pkexec, leading to root privilege escalation.",
        "description_th": " directory PATH shared object pkexec root pkexec environment ",
        "impact_th": " .so file malicious code writable PATH directory → pkexec library root → root shell Linux distro",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "SUID / Polkit",
        "path_patterns": [
            "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/usr/local/sbin",
            "/bin", "/sbin"
        ],
        "remediation": "chmod 755 /usr/bin /usr/sbin && patch polkit to >= 0.120",
        "prevention_th": [
            " polkit : apt upgrade policykit-1",
            " permission directory : chmod 755 /usr/bin /usr/sbin /usr/local/bin",
            " SUID bit pkexec : chmod 0755 /usr/bin/pkexec",
            " directory PATH : for d in $(echo $PATH | tr ':' ' '); do ls -ld $d; done",
        ],
    },
    {
        "cve": "CVE-2019-14287",
        "name": "sudo -u#-1 Bypass",
        "description": "World-writable /etc/sudoers.d directory allows injecting sudo rules to run commands as root.",
        "description_th": " /etc/sudoers.d rule command root bug sudo -u#-1 resolve UID 0",
        "impact_th": " /etc/sudoers.d/ rule 'attacker ALL=(ALL) NOPASSWD: ALL' → sudo password → root shell",
        "cvss": 8.8,
        "severity": "HIGH",
        "category": "sudo",
        "path_patterns": [
            "/etc/sudoers", "/etc/sudoers.d",
            "/etc/sudo.conf"
        ],
        "remediation": "chmod 440 /etc/sudoers && chmod 750 /etc/sudoers.d",
        "prevention_th": [
            " permission : chmod 440 /etc/sudoers && chmod 750 /etc/sudoers.d",
            " sudoers file : ls -la /etc/sudoers.d/ && visudo -c",
            " sudo: apt upgrade sudo",
            "Monitor sudoers: auditctl -w /etc/sudoers -p wa -k sudoers_change",
            " 'sudo -l' rule : sudo -l -U username",
        ],
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe — Writable Pipe Abuse",
        "description": "World-writable /proc entries combined with Dirty Pipe allow overwriting read-only files via pipe buffer manipulation.",
        "description_th": " Linux kernel pipe buffer flags clear page cache read-only /proc entries ",
        "impact_th": " /etc/passwd SUID binary /usr/bin/sudo pipe write → backdoor user binary root",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel",
        "path_patterns": [
            "/proc/sysrq-trigger",
            "/proc/sys/fs/pipe-max-size",
            "/proc/sys/fs/pipe-user-pages-soft"
        ],
        "remediation": "Upgrade kernel to >= 5.16.11 / 5.15.25 / 5.10.102",
        "prevention_th": [
            " kernel : apt upgrade linux-image-$(uname -r)",
            " kernel: uname -r ( >= 5.16.11, 5.15.25, 5.10.102)",
            " IMA ",
            "Mount /proc hidepid=2 process: mount -o remount,hidepid=2 /proc",
        ],
    },
    {
        "cve": "CVE-2023-4911",
        "name": "Looney Tunables — ld.so Writable",
        "description": "World-writable glibc loader config or lib path allows buffer overflow in GLIBC_TUNABLES leading to root escalation.",
        "description_th": " glibc loader config library path /etc/ld.so.preload library version malicious code → buffer overflow GLIBC_TUNABLES → root",
        "impact_th": " /etc/ld.so.preload path malicious library → SUID binary library → root shell SUID binary ",
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
        "remediation": "chmod 755 /usr/lib && upgrade glibc to patched version",
        "prevention_th": [
            " glibc : apt upgrade libc6",
            " permission: chmod 644 /etc/ld.so.conf && chmod 755 /etc/ld.so.conf.d",
            " /etc/ld.so.preload entry : cat /etc/ld.so.preload",
            " ld.so.preload immutable flag: chattr +i /etc/ld.so.preload",
            " integrity glibc library: debsums libc6",
        ],
    },
    {
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit — sudo Heap Overflow",
        "description": "World-writable /etc or sudo binary allows replacement/tampering leading to heap overflow exploitation.",
        "description_th": " /etc sudo binary sudoers config binary trigger heap buffer overflow sudoedit root password",
        "impact_th": " argument sudoedit trigger heap overflow exploit execute code root — writable /etc sudoers exploit ",
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
        "remediation": "Upgrade sudo to >= 1.9.5p2 && chmod 755 /etc",
        "prevention_th": [
            " sudo : apt upgrade sudo ( >= 1.9.5p2)",
            " permission /etc: chmod 755 /etc",
            " integrity sudo binary: debsums sudo",
            " sudoers immutable flag: chattr +i /etc/sudoers",
            " sudo: sudo --version",
        ],
    },
    {
        "cve": "CVE-2017-16995",
        "name": "eBPF Writable Map Privilege Escalation",
        "description": "World-writable /sys/fs/bpf or unprivileged BPF maps allow kernel memory manipulation for local privilege escalation.",
        "description_th": " /sys/fs/bpf BPF map manipulate kernel memory ",
        "impact_th": " BPF program kernel memory arbitrary address → credential structure process → root exploit ",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel",
        "path_patterns": [
            "/sys/fs/bpf",
            "/sys/kernel/debug/bpf"
        ],
        "remediation": "sysctl -w kernel.unprivileged_bpf_disabled=1 && chmod 700 /sys/fs/bpf",
        "prevention_th": [
            " unprivileged BPF : sysctl -w kernel.unprivileged_bpf_disabled=1",
            ": echo 'kernel.unprivileged_bpf_disabled=1' >> /etc/sysctl.conf",
            " permission: chmod 700 /sys/fs/bpf",
            " seccomp block bpf() syscall process ",
            " kernel BPF verifier ",
        ],
    },
    {
        "cve": "CVE-2016-8655",
        "name": "Packet Socket Race Condition",
        "description": "World-writable /proc/net entries combined with race condition allow local privilege escalation via packet socket.",
        "description_th": " /proc/net race condition packet socket handler kernel ",
        "impact_th": " trigger race condition packet socket /proc/net entries kernel execute code kernel",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel / Network",
        "path_patterns": [
            "/proc/net", "/proc/sys/net"
        ],
        "remediation": "Upgrade kernel and restrict /proc access via hidepid mount option",
        "prevention_th": [
            " kernel patch",
            "Mount /proc hidepid=2: mount -o remount,hidepid=2 /proc",
            " /etc/fstab: proc /proc proc defaults,hidepid=2 0 0",
            " raw socket: sysctl -w net.core.bpf_jit_harden=2",
        ],
    },
    {
        "cve": "CVE-2020-14386",
        "name": "AF_PACKET Heap Overflow via Writable Net",
        "description": "World-writable network proc files enable exploitation of memory corruption in AF_PACKET socket handling.",
        "description_th": " /proc/sys/net /proc/net/dev network parameter trigger memory corruption AF_PACKET socket handling",
        "impact_th": " network settings writable /proc/sys/net AF_PACKET socket trigger heap overflow → execute code kernel → root",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Network",
        "path_patterns": [
            "/proc/sys/net", "/proc/net/dev"
        ],
        "remediation": "Upgrade kernel to >= 5.9 and apply network namespace restrictions",
        "prevention_th": [
            " kernel 5.9 ",
            " /proc/sys/net: chmod 555 /proc/sys/net",
            " network namespace isolate network process",
            " unprivileged packet socket: sysctl -w net.core.bpf_jit_harden=2",
        ],
    },
    {
        "cve": "CVE-2019-13272",
        "name": "ptrace PTRACE_TRACEME Privilege Escalation",
        "description": "World-writable /proc/[pid] directories allow ptrace abuse for privilege escalation.",
        "description_th": " /proc/sys/kernel/yama/ptrace_scope ptrace_scope 0 ptrace process process root",
        "impact_th": " 0 /proc/sys/kernel/yama/ptrace_scope → ptrace process → inject shellcode process root → root shell",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Process",
        "path_patterns": [
            "/proc/sys/kernel/yama/ptrace_scope",
            "/proc/sys/kernel/perf_event_paranoid"
        ],
        "remediation": "sysctl -w kernel.yama.ptrace_scope=1",
        "prevention_th": [
            " ptrace_scope : sysctl -w kernel.yama.ptrace_scope=2",
            ": echo 'kernel.yama.ptrace_scope=2' >> /etc/sysctl.conf",
            " permission: chmod 444 /proc/sys/kernel/yama/ptrace_scope",
            " seccomp block ptrace syscall process debugger",
        ],
    },
    {
        "cve": "CVE-2018-1000001",
        "name": "glibc realpath() Buffer Underflow",
        "description": "World-writable glibc paths allow buffer underflow in realpath() used by SUID programs.",
        "description_th": " glibc library path library version malicious code SUID program realpath() buffer underflow",
        "impact_th": " /lib/x86_64-linux-gnu/libc library → SUID program library → buffer underflow → execute arbitrary code root",
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
        "remediation": "Upgrade glibc to >= 2.26 and restrict lib directory permissions",
        "prevention_th": [
            " glibc: apt upgrade libc6 ( >= 2.26)",
            " permission library directory: chmod 755 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu",
            " integrity library: debsums libc6",
            " immutable flag: chattr +i /etc/ld.so.preload /etc/ld.so.conf",
        ],
    },
    {
        "cve": "CVE-2015-5195",
        "name": "NTP Writable Config Privilege Escalation",
        "description": "World-writable NTP configuration or log paths allow local users to escalate privileges via ntpd.",
        "description_th": " NTP config log directory config ntpd action symlink log directory exploit logrotate",
        "impact_th": " /etc/ntp.conf 'keys /etc/shadow' directive ntpd sensitive, symlink /var/log/ntpstats logrotate ",
        "cvss": 5.0,
        "severity": "MEDIUM",
        "category": "Service",
        "path_patterns": [
            "/etc/ntp.conf", "/var/log/ntpstats",
            "/var/lib/ntp"
        ],
        "remediation": "chmod 644 /etc/ntp.conf && chown ntp:ntp /var/lib/ntp",
        "prevention_th": [
            " permission: chmod 644 /etc/ntp.conf && chown ntp:ntp /var/lib/ntp && chmod 750 /var/lib/ntp",
            " config directive : cat /etc/ntp.conf",
            " chrony ntpd security model ",
            "Monitor : auditctl -w /etc/ntp.conf -p wa -k ntp_config",
        ],
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
# Whitelist — known-safe paths
# ==============================
WHITELIST_PREFIXES = [
    "/usr/lib/systemd/",
    "/lib/systemd/",
    "/etc/systemd/",
    "/run/systemd/",
    "/tmp/.X11-unix",
    "/tmp/.XIM-unix",
    "/tmp/.ICE-unix",
    "/tmp/.font-unix",
    "/tmp/.dbus-unix",
    "/run/user/",
    "/run/lock",
    "/run/screen",
    "/run/shm",
    "/tmp/VMwareDnD",
    "/var/lib/php/sessions",
    "/run/ssh-unix-local/",
    "/run/pcscd/",
    "/run/dbus/",
    "/run/avahi-daemon/",
    "/run/cups/",
    "/run/bluetooth/",
    "/proc/sys/kernel/ns_last_pid",
]

def is_whitelisted(path):
    p = path.rstrip("/")
    for prefix in WHITELIST_PREFIXES:
        pfx = prefix.rstrip("/")
        if p == pfx or p.startswith(pfx + "/"):
            return True
    try:
        if p.startswith("/run/") and stat.S_ISSOCK(os.lstat(p).st_mode):
            return True
    except:
        pass
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
                        if is_whitelisted(full_path):
                            continue
                        sticky = is_sticky_bit_set(full_path)
                        ptype  = path_type(full_path)
                        owner  = get_owner(full_path)
                        risk   = "MEDIUM" if sticky else "HIGH"
                        findings.append({
                            "path":   full_path,
                            "type":   ptype,
                            "owner":  owner,
                            "sticky": sticky,
                            "risk":   risk,
                        })
        except PermissionError:
            continue
    return findings

# ==============================
# CVE Correlation
# ==============================
def correlate_cve(writable_findings):
    writable_paths = [f["path"] for f in writable_findings]
    cve_hits = {}
    for cve in CVE_DB:
        matched_paths = []
        for pattern in cve["path_patterns"]:
            for wp in writable_paths:
                if wp == pattern:
                    matched_paths.append(wp)
                elif pattern.endswith("/") and wp.startswith(pattern):
                    matched_paths.append(wp)
                elif not pattern.endswith("/") and wp.startswith(pattern + "/"):
                    remainder = wp[len(pattern)+1:]
                    if "/" not in remainder:
                        matched_paths.append(wp)
        if matched_paths:
            cve_hits[cve["cve"]] = {
                **cve,
                "matched_paths": list(set(matched_paths))[:5]
            }
    return list(cve_hits.values())

# ==============================
# Pretty Output
# ==============================
def print_banner():
    _print_banner('Writable Path Scanner  |  "Conquer Vulnerabilities"')

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
    for f in findings[:20]:
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
        print(f"     {c(Color.GRAY, 'Category    :')} {c(Color.CYAN, entry['category'])}")
        print(f"     {c(Color.GRAY, 'CVSS Score  :')} {cvss_bar(entry['cvss'])}")
        # English description
        print(f"     {c(Color.GRAY, 'Description :')} {entry['description'][:85]}{'...' if len(entry['description'])>85 else ''}")
        # Thai vulnerability explanation
        if entry.get("description_th"):
            print(f" {c(Color.CYAN, '📋 :')} {c(Color.WHITE, entry['description_th'][:90])}{'...' if len(entry['description_th'])>90 else ''}")
        if entry.get("impact_th"):
            print(f" {c(Color.ORANGE, '⚡ :')} {c(Color.YELLOW, entry['impact_th'][:90])}{'...' if len(entry['impact_th'])>90 else ''}")
        # Matched paths
        print(f"     {c(Color.GRAY, 'Matched     :')} {c(Color.YELLOW, str(len(entry['matched_paths'])) + ' path(s)')}")
        for mp in entry["matched_paths"][:3]:
            print(f"       {c(Color.ORANGE, '→')} {c(Color.WHITE, mp)}")
        # Thai prevention tips
        if entry.get("prevention_th"):
            print(f" {c(Color.GREEN + Color.BOLD, '🛡 :')}")
            for i, tip in enumerate(entry["prevention_th"], 1):
                print(f"       {c(Color.GREEN, f'  {i}.')} {c(Color.GRAY, tip[:85])}{'...' if len(tip)>85 else ''}")
        else:
            print(f"     {c(Color.GREEN, '✦  Fix      :')} {c(Color.GRAY, entry['remediation'])}")

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
    print(c(Color.CYAN + Color.BOLD, '  ╚═══════════════════════════════════════════════════════════╝\n'))

# ==============================
# Save Report
# ==============================
def save_report(writable, cve_hits):
    from cosvinte_utils import score_to_severity
    max_cvss = max((c_["cvss"] for c_ in cve_hits), default=0)
    report = {
        "tool":      "COSVINTE — Writable Path Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    system_info(),
        "summary": {
            "total_writable_paths":   len(writable),
            "total_cve_correlations": len(cve_hits),
            "overall_cvss":           max_cvss,
            "overall_severity":       score_to_severity(max_cvss),
        },
        "writable_paths": writable,
        "cve_correlations": [
            {k: v for k, v in entry.items() if k != "path_patterns"}
            for entry in cve_hits
        ],
    }
    return save_json(report, "cosvinte_writable")

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
