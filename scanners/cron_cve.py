#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Cron CVE Scanner  |  "Conquer Vulnerabilities"
"""

import os
import json
import stat
import shutil
import subprocess
import platform
import pwd
from datetime import datetime
from packaging import version

from core.utils import (
    Color, c, severity_badge, cvss_bar,
    get_distro, save_json, print_banner as _print_banner,
)

def severity_from_cvss(score):
    from core.utils import score_to_severity
    return score_to_severity(score)

# ==============================
# CVE Database
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2016-1247",
        "name": "Debian Cron Log Dir Privilege Escalation",
        "software": ["debian cron"],
        "affected_version": "<3.0.0",
        "cvss": 7.8,
        "category": "File Permission",
        "description": "World-writable /var/log/cron allows local users to replace log files with symlinks via logrotate, leading to root privilege escalation.",
        "description_th": " /var/log/cron log file symlink logrotate root ",
        "impact_th": " symlink /var/log/cron → /etc/passwd logrotate → /etc/passwd overwrite → root account ",
        "check": "log_permission",
        "remediation": "chmod 755 /var/log/cron && chown root:adm /var/log/cron",
        "prevention_th": [
            " permission : chmod 755 /var/log/cron && chown root:adm /var/log/cron",
            " logrotate config: grep -r 'create' /etc/logrotate.d/cron",
            "Monitor symlink log dir: auditctl -w /var/log/cron -p wa -k cron_log",
            " ACL world-writable: setfacl -m u:cron:rw /var/log/cron",
        ],
    },
    {
        "cve": "CVE-2019-9706",
        "name": "Cronie Use-After-Free",
        "software": ["cronie"],
        "affected_version": "<1.5.3",
        "cvss": 7.2,
        "category": "Memory Corruption",
        "description": "Use-after-free in Cronie allows local users to cause denial of service or escalate privileges via malformed crontab.",
        "description_th": " use-after-free cronie free memory memory free execution",
        "impact_th": " crontab format trigger use-after-free → cronie crash (DoS) execute arbitrary code cron daemon root",
        "check": "symlink_check",
        "remediation": "Upgrade cronie >= 1.5.3",
        "prevention_th": [
            " cronie : apt upgrade cron yum upgrade cronie",
            ": cron --version dpkg -l cron",
            " crontab user : /etc/cron.allow",
            "Monitor crontab changes: auditctl -w /var/spool/cron -p wa -k crontab_mod",
        ],
    },
    {
        "cve": "CVE-2017-9525",
        "name": "Vixie Cron Group Crontab Privilege Escalation",
        "software": ["vixie", "vixie-cron", "debian cron", "cronie"],
        "affected_version": "<999.0",
        "cvss": 6.5,
        "category": "Permission",
        "description": "Cron sets SGID on crontab binary, allowing members of the crontab group to escalate privileges.",
        "description_th": "Vixie cron SGID bit /usr/bin/crontab group 'crontab' crontab group crontab ",
        "impact_th": " group 'crontab' crontab user SGID group crontab ",
        "check": "crontab_sgid",
        "remediation": "chmod g-s /usr/bin/crontab && upgrade vixie-cron",
        "prevention_th": [
            " SGID bit: chmod g-s /usr/bin/crontab",
            " group crontab: getent group crontab",
            " user crontab group: gpasswd -d username crontab",
            " vixie-cron ",
        ],
    },
    {
        "cve": "CVE-2019-13224",
        "name": "dcron Privilege Escalation",
        "software": ["dcron"],
        "affected_version": "<4.5",
        "cvss": 7.5,
        "category": "Access Control",
        "description": "dcron allows local users to run cron jobs as other users due to insufficient permission checks.",
        "description_th": "dcron permission cron job user root",
        "impact_th": " crontab entry user job → dcron command user → shell root",
        "check": "version_only",
        "remediation": "Upgrade dcron >= 4.5",
        "prevention_th": [
            " dcron 4.5 ",
            " cronie debian cron maintain ",
            " user cron /etc/cron.allow: echo 'root' > /etc/cron.allow",
            "Monitor cron job user : grep CRON /var/log/syslog",
        ],
    },
    {
        "cve": "CVE-2023-22467",
        "name": "Cronie Crontab Buffer Overflow",
        "software": ["cronie"],
        "affected_version": "<1.6.1",
        "cvss": 8.4,
        "category": "Buffer Overflow",
        "description": "Buffer overflow in cronie crontab parsing allows local privilege escalation.",
        "description_th": " buffer overflow cronie parse crontab file crontab entry overflow buffer execution flow",
        "impact_th": " crontab field buffer → stack/heap overflow → overwrite return address → execute shellcode crond daemon (root)",
        "check": "version_only",
        "remediation": "Upgrade cronie >= 1.6.1",
        "prevention_th": [
            " cronie 1.6.1 : apt upgrade cron",
            ": dpkg -l cron | grep cron",
            " crontab user : chmod 600 /var/spool/cron/crontabs/*",
            " stack protection: kernel ASLR: cat /proc/sys/kernel/randomize_va_space",
        ],
    },
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit via Cron Environment Injection",
        "software": ["cronie", "debian cron", "vixie", "dcron"],
        "affected_version": "<999.0",
        "cvss": 7.8,
        "category": "ENV Injection",
        "description": "Cron jobs that execute pkexec or polkit-dependent scripts are vulnerable to environment variable injection leading to root escalation.",
        "description_th": "Cron job pkexec script polkit inject environment variable pkexec argv/envp",
        "impact_th": " environment variable cron job → cron pkexec → pkexec malicious shared object env var → root shell ",
        "check": "cron_env_injection",
        "remediation": "Audit cron jobs for pkexec usage. Upgrade polkit >= 0.120.",
        "prevention_th": [
            " polkit : apt upgrade policykit-1",
            " cron job pkexec: grep -r 'pkexec' /etc/cron*",
            " pkexec sudo policy ",
            " SUID pkexec : chmod 0755 /usr/bin/pkexec",
            " env var cron : env_reset /etc/sudoers",
        ],
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe via Cron Log Overwrite",
        "software": ["cronie", "debian cron", "vixie", "dcron"],
        "affected_version": "<999.0",
        "cvss": 7.8,
        "category": "Kernel",
        "description": "World-writable cron log files combined with Dirty Pipe kernel vulnerability allow overwriting read-only files as root.",
        "description_th": " cron log file Dirty Pipe kernel read-only file pipe buffer cron ",
        "impact_th": " writable cron log file descriptor trigger Dirty Pipe → SUID binary /etc/passwd → root",
        "check": "log_permission",
        "remediation": "chmod 640 /var/log/cron && Upgrade kernel >= 5.16.11",
        "prevention_th": [
            " permission cron log: chmod 640 /var/log/cron && chown root:adm /var/log/cron",
            " kernel 5.16.11, 5.15.25, 5.10.102: apt upgrade linux-image-$(uname -r)",
            " kernel: uname -r",
            " IMA SUID binary",
        ],
    },
    {
        "cve": "CVE-2016-2779",
        "name": "Cron Insecure Temp File Creation",
        "software": ["vixie", "vixie-cron", "debian cron"],
        "affected_version": "<4.1",
        "cvss": 7.0,
        "category": "Temp File",
        "description": "Cron creates temporary files insecurely in /tmp, allowing symlink attacks by local users to overwrite arbitrary files.",
        "description_th": "Cron temporary file /tmp symlink attack symlink temp file cron ",
        "impact_th": " /tmp/cron_tmp_XXXX → /etc/shadow → cron temp file follow symlink → /etc/shadow content ",
        "check": "world_writable_tmp",
        "remediation": "Ensure /tmp has sticky bit: chmod 1777 /tmp",
        "prevention_th": [
            " sticky bit /tmp: chmod 1777 /tmp",
            "Mount /tmp noexec,nosuid: mount -o remount,noexec,nosuid /tmp",
            " mkstemp() tempnam() script ( developer)",
            " cron mkstemp() ",
            " cron script /tmp: grep -r '/tmp' /etc/cron*",
        ],
    },
    {
        "cve": "CVE-2018-15686",
        "name": "Cron Symlink Attack via cron.d",
        "software": ["cronie", "debian cron"],
        "affected_version": "<1.5.5",
        "cvss": 8.0,
        "category": "Symlink",
        "description": "Malicious symlinks in /etc/cron.d allow cron to execute attacker-controlled files as root.",
        "description_th": " /etc/cron.d symlink cron daemon follow symlink execute root ",
        "impact_th": " symlink /etc/cron.d script → cron script root → root shell persistent",
        "check": "symlink_check",
        "remediation": "chmod 755 /etc/cron.d && audit symlinks: find /etc/cron.d -type l",
        "prevention_th": [
            " symlink cron.d: find /etc/cron.d -type l -ls",
            " symlink : find /etc/cron.d -type l -delete",
            " permission: chmod 755 /etc/cron.d && chown root:root /etc/cron.d",
            " cronie/cron: apt upgrade cron",
            "Monitor cron.d: auditctl -w /etc/cron.d -p wa -k crond_change",
        ],
    },
    {
        "cve": "CVE-2019-14287",
        "name": "Cron sudo Runas Bypass",
        "software": ["cronie", "debian cron", "vixie", "dcron"],
        "affected_version": "<999.0",
        "cvss": 8.8,
        "category": "sudo",
        "description": "Cron jobs using sudo with runas ALL are vulnerable to sudo -u#-1 bypass, allowing privilege escalation to root.",
        "description_th": "Cron job sudo runas ALL sudo -u#-1 resolve UID 0 (root) ",
        "impact_th": "Cron script 'sudo -u ... command' exploit 'sudo -u#-1 /bin/bash' → root shell sudoers root ",
        "check": "crontab_sudo_all",
        "remediation": "Upgrade sudo >= 1.8.28. Audit crontabs for sudo ALL entries.",
        "prevention_th": [
            " sudo 1.8.28 : apt upgrade sudo",
            " cron job sudo: grep -r 'sudo' /etc/cron* /var/spool/cron/",
            " sudo ALL user/command sudoers",
            " 'Defaults!command noexec' command injection",
            "Audit sudoers : visudo -c && sudo -l",
        ],
    },
    {
        "cve": "CVE-2020-12100",
        "name": "Cron Arbitrary File Read via Symlink",
        "software": ["cronie"],
        "affected_version": "<1.5.5",
        "cvss": 5.5,
        "category": "Information Disclosure",
        "description": "Cronie follows symlinks when reading crontab files, allowing local users to read arbitrary files as the cron daemon.",
        "description_th": "cronie symlink crontab file symlink /var/spool/cron sensitive cron daemon ",
        "impact_th": " symlink /var/spool/cron/username → /etc/shadow → cron daemon /etc/shadow log error messages content /etc/shadow",
        "check": "symlink_check",
        "remediation": "Upgrade cronie >= 1.5.5. Audit /var/spool/cron for symlinks.",
        "prevention_th": [
            " cronie 1.5.5 ",
            " symlink spool: find /var/spool/cron -type l -ls",
            " permission: chmod 700 /var/spool/cron && chmod 600 /var/spool/cron/*",
            " crontab : crontab -r -u suspicious_user",
        ],
    },
    {
        "cve": "CVE-2015-1318",
        "name": "OverlayFS via Cron Script",
        "software": ["debian cron", "cronie"],
        "affected_version": "<999.0",
        "cvss": 6.5,
        "category": "Filesystem",
        "description": "Cron scripts running as root that use overlayfs paths are vulnerable to container escape / privilege escalation.",
        "description_th": "Cron script root script inject command overlayfs escape container",
        "impact_th": " world-writable cron script reverse shell command → cron script → root shell scheduled",
        "check": "cron_script_writable",
        "remediation": "Audit /etc/cron.* scripts for writable files. chmod 755 /etc/cron.d",
        "prevention_th": [
            " world-writable script: find /etc/cron* -perm -002 -type f -ls",
            " permission script : chmod 755 /etc/cron.d/* && chown root:root /etc/cron.d/*",
            " content cron script : md5sum /etc/cron.d/*",
            " AIDE Tripwire monitor cron script",
            " kernel patch overlayfs: apt upgrade linux-image-$(uname -r)",
        ],
    },
]

# ==============================
# Version Matching
# ==============================
def match_version(current, rule):
    import re as _re
    # <999.0 was a legacy "always flag" sentinel — now we require
    # actual runtime evidence from the check_map instead of auto-flagging.
    # Returning True here means the VERSION matches; the check_map condition
    # still must pass before a finding is recorded.
    if rule in ("<999.0", "<=999.0"):
        return True   # version matches; runtime check still required
    try:
        if rule.startswith("<="):
            return version.parse(current) < version.parse(rule[2:]) or                    version.parse(current) == version.parse(rule[2:])
        if rule.startswith("<"):
            return version.parse(current) < version.parse(rule[1:])
    except Exception:
        pass
    # Fallback: numeric prefix comparison (handles "3.0pl1", "1.5.3-1+b1" etc.)
    def nums(s):
        return [int(x) for x in _re.findall(r"\d+", s)]
    cur = nums(current)
    thr_str = rule.lstrip("<=>")
    thr = nums(thr_str)
    length = max(len(cur), len(thr))
    cur += [0] * (length - len(cur))
    thr += [0] * (length - len(thr))
    if rule.startswith("<="):
        return cur <= thr
    if rule.startswith("<"):
        return cur < thr
    return False

# ==============================
# Detection Checks
# ==============================
def check_log_permission(base_path):
    for log_path in [
        os.path.join(base_path, "var/log/cron"),
        os.path.join(base_path, "var/log/cron.log"),
        "/var/log/syslog",
    ]:
        if os.path.exists(log_path):
            try:
                mode = os.stat(log_path).st_mode
                if bool(mode & stat.S_IWOTH):
                    return True, log_path
            except:
                pass
    return False, None

def check_symlink(base_path):
    found = []
    for cron_dir in [
        os.path.join(base_path, "etc/cron.d"),
        os.path.join(base_path, "var/spool/cron"),
        "/etc/cron.d",
        "/var/spool/cron",
    ]:
        if os.path.exists(cron_dir):
            try:
                for root, dirs, files in os.walk(cron_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        if os.path.islink(fp):
                            found.append(fp)
            except:
                pass
    return len(found) > 0, found

def check_crontab_sgid(base_path):
    for crontab_path in ["/usr/bin/crontab", "/bin/crontab"]:
        if os.path.exists(crontab_path):
            try:
                mode = os.stat(crontab_path).st_mode
                if bool(mode & stat.S_ISGID):
                    return True, crontab_path
            except:
                pass
    return False, None

def check_world_writable_tmp(base_path):
    tmp = os.path.join(base_path, "tmp") if base_path != "/" else "/tmp"
    if os.path.exists(tmp):
        try:
            mode = os.stat(tmp).st_mode
            is_writable = bool(mode & stat.S_IWOTH)
            has_sticky  = bool(mode & stat.S_ISVTX)
            if is_writable and not has_sticky:
                return True, tmp
        except:
            pass
    return False, None

def check_cron_env_injection(base_path):
    cron_dirs = [
        "/etc/cron.d", "/etc/cron.daily",
        "/etc/cron.weekly", "/etc/cron.hourly",
        os.path.join(base_path, "etc/cron.d"),
    ]
    found = []
    for d in cron_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for root, _, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, "r", errors="ignore") as fh:
                            content = fh.read()
                            if "pkexec" in content or "LD_PRELOAD" in content:
                                found.append(fp)
                    except:
                        pass
        except:
            pass
    return len(found) > 0, found

def check_crontab_sudo_all(base_path):
    cron_dirs = [
        "/etc/cron.d", "/var/spool/cron/crontabs",
        os.path.join(base_path, "etc/cron.d"),
    ]
    found = []
    for d in cron_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for root, _, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, "r", errors="ignore") as fh:
                            for line in fh:
                                if "sudo" in line and not line.strip().startswith("#"):
                                    found.append(f"{fp}: {line.strip()[:60]}")
                    except:
                        pass
        except:
            pass
    return len(found) > 0, found

def check_cron_script_writable(base_path):
    found = []
    for d in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.hourly"]:
        if not os.path.exists(d):
            continue
        try:
            for root, dirs, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        mode = os.stat(fp).st_mode
                        if bool(mode & stat.S_IWOTH):
                            found.append(fp)
                    except:
                        pass
        except:
            pass
    return len(found) > 0, found

# ==============================
# Auto-detect cron type & version
# ==============================
def detect_cron():
    candidates = [
        ("cronie",      ["cronie", "crond"]),
        ("debian cron", ["cron"]),
        ("vixie",       ["vixie-cron", "cron"]),
        ("dcron",       ["dcron", "crond"]),
    ]

    detected_type    = None
    detected_version = None

    for ctype, pkgs in candidates:
        for pkg in pkgs:
            try:
                r = subprocess.run(
                    ["dpkg", "-s", pkg],
                    capture_output=True, text=True, timeout=3
                )
                if r.returncode == 0 and "installed" in r.stdout:
                    for line in r.stdout.split("\n"):
                        if line.startswith("Version:"):
                            detected_version = line.split(":", 1)[1].strip().split("-")[0]
                            detected_type    = ctype
                            return detected_type, detected_version
            except:
                pass

    for ctype, pkgs in candidates:
        for pkg in pkgs:
            try:
                r = subprocess.run(
                    ["rpm", "-q", "--queryformat", "%{VERSION}", pkg],
                    capture_output=True, text=True, timeout=3
                )
                if r.returncode == 0 and r.stdout.strip():
                    detected_version = r.stdout.strip()
                    detected_type    = ctype
                    return detected_type, detected_version
            except:
                pass

    for binary in ["crond", "cron"]:
        try:
            r = subprocess.run(
                [binary, "--version"],
                capture_output=True, text=True, timeout=3
            )
            out = (r.stdout + r.stderr).lower()
            import re
            m = re.search(r"(\d+\.\d+[\.\d]*)", out)
            if m:
                detected_version = m.group(1)
                if "cronie" in out:
                    detected_type = "cronie"
                elif "vixie" in out:
                    detected_type = "vixie"
                else:
                    detected_type = "debian cron"
                return detected_type, detected_version
        except:
            pass

    return None, None

# ==============================
# Run Scan
# ==============================

def _cron_is_running(cron_type: str) -> bool:
    """Return True only if the named cron daemon appears active via systemctl/ps."""
    service_names = {
        "cronie":     ["crond", "cron"],
        "debian cron": ["cron"],
        "vixie":      ["cron", "vixie-cron"],
        "dcron":      ["dcron", "crond"],
    }
    candidates = service_names.get(cron_type.lower(), ["cron", "crond"])

    # Check systemctl
    for svc in candidates:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=2
            )
            if r.stdout.strip() == "active":
                return True
        except Exception:
            pass

    # Fallback: check ps
    try:
        r = subprocess.run(["pgrep", "-x", "cron", "crond"],
                           capture_output=True, text=True, timeout=2)
        if r.returncode == 0:
            return True
    except Exception:
        pass

    return False


def run_scan(cron_type, cron_version, base_path="/"):
    findings = []

    log_vuln,    log_path     = check_log_permission(base_path)
    sym_vuln,    sym_paths    = check_symlink(base_path)
    sgid_vuln,   sgid_path    = check_crontab_sgid(base_path)
    tmp_vuln,    tmp_path     = check_world_writable_tmp(base_path)
    env_vuln,    env_paths    = check_cron_env_injection(base_path)
    sudo_vuln,   sudo_paths   = check_crontab_sudo_all(base_path)
    script_vuln, script_paths = check_cron_script_writable(base_path)

    check_map = {
        "log_permission":     (log_vuln,    {"path": log_path}),
        "symlink_check":      (sym_vuln,    {"paths": sym_paths}),
        "crontab_sgid":       (sgid_vuln,   {"path": sgid_path}),
        "world_writable_tmp": (tmp_vuln,    {"path": tmp_path}),
        "cron_env_injection": (env_vuln,    {"paths": env_paths}),
        "crontab_sudo_all":   (sudo_vuln,   {"lines": sudo_paths}),
        "cron_script_writable":(script_vuln, {"paths": script_paths}),
        # version_only: only flag if cron daemon is actually running
        "version_only": (_cron_is_running(cron_type), {}),
    }

    cron_type_lower = cron_type.lower()

    for entry in CVE_DB:
        if not any(cron_type_lower == s.lower() for s in entry["software"]):
            continue
        if not match_version(cron_version, entry["affected_version"]):
            continue

        check_key = entry["check"]
        vulnerable, detail = check_map.get(check_key, (False, {}))

        if vulnerable:
            findings.append({
                "cve":            entry["cve"],
                "name":           entry["name"],
                "category":       entry["category"],
                "cvss":           entry["cvss"],
                "severity":       severity_from_cvss(entry["cvss"]),
                "description":    entry["description"],
                "description_th": entry.get("description_th", ""),
                "impact_th":      entry.get("impact_th", ""),
                "remediation":    entry["remediation"],
                "prevention_th":  entry.get("prevention_th", []),
                "check":          check_key,
                "detail":         detail,
            })

    return findings, {
        "log_permission":   (log_vuln,    log_path),
        "symlink_check":    (sym_vuln,    sym_paths),
        "sgid_check":       (sgid_vuln,   sgid_path),
        "tmp_sticky":       (tmp_vuln,    tmp_path),
        "env_injection":    (env_vuln,    env_paths),
        "sudo_in_crontab":  (sudo_vuln,   sudo_paths),
        "writable_scripts": (script_vuln, script_paths),
    }

# ==============================
# Lab Environment
# ==============================
def setup_lab_environment():
    print(c(Color.CYAN, "\n  [*] Setting up LAB environment..."))
    base = "./lab_env"

    os.makedirs(base + "/etc/cron.d",  exist_ok=True)
    os.makedirs(base + "/var/log",     exist_ok=True)
    os.makedirs(base + "/tmp",         exist_ok=True)
    os.makedirs(base + "/usr/bin",     exist_ok=True)

    log_file = base + "/var/log/cron"
    with open(log_file, "w") as f:
        f.write("fake cron log entry\n")
    os.chmod(log_file, 0o666)

    target = base + "/etc/passwd_fake"
    with open(target, "w") as f:
        f.write("root:x:0:0:root:/root:/bin/bash\n")
    symlink_path = base + "/etc/cron.d/malicious_link"
    if not os.path.exists(symlink_path):
        os.symlink(os.path.abspath(target), symlink_path)

    os.chmod(base + "/tmp", 0o777)

    cron_script = base + "/etc/cron.d/backup"
    with open(cron_script, "w") as f:
        f.write("*/5 * * * * root pkexec /usr/bin/backup.sh\n")

    print(c(Color.GREEN, "  [+] LAB ready at ./lab_env"))
    print(c(Color.GRAY,  "      ├── var/log/cron       (world-writable)"))
    print(c(Color.GRAY,  "      ├── etc/cron.d/malicious_link  (symlink)"))
    print(c(Color.GRAY,  "      ├── tmp/               (no sticky bit)"))
    print(c(Color.GRAY,  "      └── etc/cron.d/backup  (pkexec injection)"))
    return base

# ==============================
# Pretty Output
# ==============================
def print_banner():
    _print_banner('Cron CVE Scanner  |  "Conquer Vulnerabilities"')

def print_sysinfo(cron_type, cron_version, mode_label, base_path):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ SCAN INFORMATION ═══════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname   :')} {c(Color.WHITE,  platform.node())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro     :')} {c(Color.WHITE,  get_distro())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Mode       :')} {c(Color.YELLOW, mode_label)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Cron Type  :')} {c(Color.MAGENTA + Color.BOLD, cron_type)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Cron Ver   :')} {c(Color.YELLOW, cron_version)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Scan Path  :')} {c(Color.WHITE,  base_path)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp  :')} {c(Color.WHITE,  datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

def print_checks(checks):
    print(c(Color.CYAN + Color.BOLD, "\n  ── DETECTION CHECKS ──\n"))
    labels = {
        "log_permission":   "Cron log world-writable",
        "symlink_check":    "Symlinks in cron.d / spool",
        "sgid_check":       "crontab SGID bit",
        "tmp_sticky":       "/tmp without sticky bit",
        "env_injection":    "pkexec / LD_PRELOAD in cron jobs",
        "sudo_in_crontab":  "sudo usage in crontabs",
        "writable_scripts": "World-writable cron scripts",
    }
    for key, (vuln, detail) in checks.items():
        label = labels.get(key, key)
        if vuln:
            icon  = c(Color.RED + Color.BOLD, "  ✖ FOUND  ")
            extra = ""
            if isinstance(detail, str) and detail:
                extra = f"  {c(Color.ORANGE,'→')} {c(Color.YELLOW, detail)}"
            elif isinstance(detail, list) and detail:
                extra = f"  {c(Color.ORANGE,'→')} {c(Color.YELLOW, str(detail[0])[:60])}"
        else:
            icon  = c(Color.GREEN, "  ✔ OK     ")
            extra = ""
        print(f"  {icon} {c(Color.WHITE, label)}{extra}")

def print_findings(findings):
    if not findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No CVE matches found for this cron configuration.\n"))
        return

    print(c(Color.RED + Color.BOLD, f"\n  ── CVE FINDINGS ({len(findings)}) ──"))

    for f in sorted(findings, key=lambda x: x["cvss"], reverse=True):
        print(f"\n  {c(Color.RED + Color.BOLD, '✖')}  {c(Color.BOLD + Color.WHITE, f['cve'])}  "
              f"{c(Color.MAGENTA, f['name'])}  {severity_badge(f['severity'])}")
        print(f"     {c(Color.GRAY,'Category    :')} {c(Color.CYAN, f['category'])}")
        print(f"     {c(Color.GRAY,'CVSS Score  :')} {cvss_bar(f['cvss'])}")
        # English description
        print(f"     {c(Color.GRAY,'Description :')} {f['description'][:85]}{'...' if len(f['description'])>85 else ''}")
        # Thai vulnerability explanation
        if f.get("description_th"):
            print(f" {c(Color.CYAN,'📋 :')} {c(Color.WHITE, f['description_th'][:90])}{'...' if len(f['description_th'])>90 else ''}")
        if f.get("impact_th"):
            print(f" {c(Color.ORANGE,'⚡ :')} {c(Color.YELLOW, f['impact_th'][:90])}{'...' if len(f['impact_th'])>90 else ''}")
        # Evidence
        detail = f.get("detail", {})
        if detail.get("path"):
            print(f"     {c(Color.ORANGE,'→ Evidence  :')} {c(Color.YELLOW, str(detail['path']))}")
        elif detail.get("paths"):
            for p in detail["paths"][:2]:
                print(f"     {c(Color.ORANGE,'→ Evidence  :')} {c(Color.YELLOW, str(p)[:70])}")
        elif detail.get("lines"):
            for line in detail["lines"][:2]:
                print(f"     {c(Color.ORANGE,'→ Evidence  :')} {c(Color.YELLOW, str(line)[:70])}")
        # Thai prevention tips
        if f.get("prevention_th"):
            print(f" {c(Color.GREEN + Color.BOLD,'🛡 :')}")
            for i, tip in enumerate(f["prevention_th"], 1):
                print(f"       {c(Color.GREEN, f'  {i}.')} {c(Color.GRAY, tip[:85])}{'...' if len(tip)>85 else ''}")
        else:
            print(f"     {c(Color.GREEN,'✦  Fix      :')} {c(Color.GRAY, f['remediation'])}")

def print_summary(cron_type, cron_version, findings, checks):
    high     = sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL"))
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
    max_cvss = max((f["cvss"] for f in findings), default=0)
    checks_triggered = sum(1 for v, _ in checks.values() if v)

    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        if score > 0:  return "LOW"
        return "NONE"

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ SCAN SUMMARY ════════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Cron Software      :')} {c(Color.MAGENTA + Color.BOLD, cron_type)}  v{c(Color.YELLOW, cron_version)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'CVEs in Database   :')} {c(Color.WHITE, str(len(CVE_DB)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Checks Triggered   :')} {c(Color.YELLOW + Color.BOLD, str(checks_triggered))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total CVE Findings :')} {c(Color.RED + Color.BOLD, str(len(findings)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,  '  HIGH / CRITICAL  :')} {c(Color.RED + Color.BOLD, str(high))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  MEDIUM           :')} {c(Color.YELLOW + Color.BOLD, str(medium))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk Score :')} {severity_badge(sev(max_cvss))}  {c(Color.GRAY,'CVSS')} {c(Color.BOLD, f'{max_cvss:.1f}')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚═══════════════════════════════════════════════════════════╝\n'))


# ==============================
# Save Report
# ==============================
def save_report(cron_type, cron_version, findings, checks, base_path):
    from core.utils import system_info, score_to_severity
    max_cvss = max((f["cvss"] for f in findings), default=0)
    report = {
        "tool":      "COSVINTE — Cron CVE Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    system_info(),
        "scan":      {"cron_type": cron_type, "cron_version": cron_version, "base_path": base_path},
        "checks": {
            k: {"vulnerable": bool(v), "detail": str(d) if d else None}
            for k, (v, d) in checks.items()
        },
        "summary": {
            "total_cve_db":     len(CVE_DB),
            "total_findings":   len(findings),
            "overall_cvss":     max_cvss,
            "overall_severity": score_to_severity(max_cvss),
        },
        "findings": [{k: v for k, v in f.items() if k != "detail"} for f in findings],
    }
    return save_json(report, "cosvinte_cron")

# ==============================
# MAIN
# ==============================
def main():
    print_banner()

    print(c(Color.CYAN + Color.BOLD, "  Select Mode:"))
    print(f"  {c(Color.WHITE, '1')} {c(Color.GRAY,'─')} Real Scan (auto-detect or manual)")
    print(f"  {c(Color.WHITE, '2')} {c(Color.GRAY,'─')} Lab Simulation (safe test environment)")
    print(f"  {c(Color.WHITE, '3')} {c(Color.GRAY,'─')} Manual Input\n")

    mode = input(c(Color.CYAN, "  Enter choice [1/2/3]: ")).strip()

    if mode == "2":
        base         = setup_lab_environment()
        cron_type    = "cronie"
        cron_version = "1.4.0"
        mode_label   = "Lab Simulation"

    elif mode == "3":
        base = "/"
        print()
        cron_type    = input(c(Color.CYAN, "  Cron type (cronie/vixie/dcron/debian cron): ")).strip()
        cron_version = input(c(Color.CYAN, "  Cron version (e.g. 1.4.0): ")).strip()
        mode_label   = "Manual Input"

    else:
        base       = "/"
        mode_label = "Auto-Detect"
        print(c(Color.CYAN, "\n  [*] Auto-detecting cron software..."), end="", flush=True)
        cron_type, cron_version = detect_cron()

        if cron_type and cron_version:
            print(c(Color.GREEN, f" found: {cron_type} v{cron_version}\n"))
        else:
            print(c(Color.YELLOW, " not detected\n"))
            print(c(Color.YELLOW, "  Could not auto-detect cron. Switching to manual input.\n"))
            cron_type    = input(c(Color.CYAN, "  Cron type (cronie/vixie/dcron/debian cron): ")).strip()
            cron_version = input(c(Color.CYAN, "  Cron version (e.g. 1.4.0): ")).strip()
            mode_label   = "Manual Input"

    print()
    print_sysinfo(cron_type, cron_version, mode_label, base)

    print(c(Color.CYAN, "  [*] Running detection checks..."), end="", flush=True)
    findings, checks = run_scan(cron_type, cron_version, base)
    print(c(Color.GREEN, " done\n"))

    print_checks(checks)
    print_findings(findings)
    print_summary(cron_type, cron_version, findings, checks)

    fname = save_report(cron_type, cron_version, findings, checks, base)
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, fname)}\n"))

if __name__ == "__main__":
    main()
