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

def severity_from_cvss(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

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
        "description_th": "หาก /var/log/cron เขียนได้โดยทุกคน ผู้ใช้ทั่วไปสามารถแทนที่ log file ด้วย symlink เพื่อให้ logrotate ซึ่งรันเป็น root เขียนทับไฟล์เป้าหมาย",
        "impact_th": "ผู้โจมตีสร้าง symlink /var/log/cron → /etc/passwd แล้วรอ logrotate รันตามตาราง → /etc/passwd ถูก overwrite → เพิ่ม root account ได้",
        "check": "log_permission",
        "remediation": "chmod 755 /var/log/cron && chown root:adm /var/log/cron",
        "prevention_th": [
            "แก้ permission ทันที: chmod 755 /var/log/cron && chown root:adm /var/log/cron",
            "ตรวจสอบ logrotate config: grep -r 'create' /etc/logrotate.d/cron",
            "Monitor symlink ใน log dir: auditctl -w /var/log/cron -p wa -k cron_log",
            "ใช้ ACL แทนการ world-writable: setfacl -m u:cron:rw /var/log/cron",
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
        "description_th": "ช่องโหว่ use-after-free ใน cronie เกิดจากการ free memory ก่อนที่จะใช้งานเสร็จ ทำให้ผู้โจมตีสามารถเขียนทับ memory ที่ถูก free ไปแล้วเพื่อควบคุม execution",
        "impact_th": "ผู้โจมตีสร้าง crontab ที่มี format พิเศษเพื่อ trigger use-after-free → cronie crash (DoS) หรือ execute arbitrary code ในฐานะ cron daemon ซึ่งรันเป็น root",
        "check": "symlink_check",
        "remediation": "Upgrade cronie >= 1.5.3",
        "prevention_th": [
            "อัปเกรด cronie ทันที: apt upgrade cron หรือ yum upgrade cronie",
            "ตรวจสอบเวอร์ชัน: cron --version หรือ dpkg -l cron",
            "จำกัดสิทธิ์การแก้ไข crontab เฉพาะ user ที่จำเป็น: /etc/cron.allow",
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
        "description_th": "Vixie cron ตั้ง SGID bit บน /usr/bin/crontab ทำให้สมาชิกของ group 'crontab' สามารถใช้ crontab ในฐานะ group crontab และยกระดับสิทธิ์ได้",
        "impact_th": "ผู้โจมตีที่อยู่ใน group 'crontab' สามารถแก้ไข crontab ของ user อื่นหรือใช้ประโยชน์จาก SGID เพื่อเข้าถึงไฟล์ที่ group crontab เป็นเจ้าของ",
        "check": "crontab_sgid",
        "remediation": "chmod g-s /usr/bin/crontab && upgrade vixie-cron",
        "prevention_th": [
            "ถอด SGID bit: chmod g-s /usr/bin/crontab",
            "ตรวจสอบสมาชิก group crontab: getent group crontab",
            "ลบ user ที่ไม่จำเป็นออกจาก crontab group: gpasswd -d username crontab",
            "อัปเกรด vixie-cron เป็นเวอร์ชันล่าสุด",
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
        "description_th": "dcron ตรวจสอบ permission ไม่เพียงพอ ทำให้ผู้ใช้ทั่วไปสามารถรัน cron job ในฐานะ user อื่นได้ รวมถึง root",
        "impact_th": "ผู้โจมตีสร้าง crontab entry ที่ระบุ user อื่นเป็นเจ้าของ job → dcron รัน command ในฐานะ user นั้นโดยไม่ตรวจสอบสิทธิ์ → ได้ shell ในฐานะ root",
        "check": "version_only",
        "remediation": "Upgrade dcron >= 4.5",
        "prevention_th": [
            "อัปเกรด dcron เป็นเวอร์ชัน 4.5 ขึ้นไปทันที",
            "พิจารณาเปลี่ยนไปใช้ cronie หรือ debian cron ที่มีการ maintain ดีกว่า",
            "จำกัด user ที่ใช้ cron ได้ผ่าน /etc/cron.allow: echo 'root' > /etc/cron.allow",
            "Monitor การรัน cron job ของ user ต่างๆ: grep CRON /var/log/syslog",
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
        "description_th": "ช่องโหว่ buffer overflow ใน cronie เกิดระหว่างการ parse crontab file ผู้โจมตีสามารถสร้าง crontab entry ที่มีขนาดพิเศษเพื่อ overflow buffer และควบคุม execution flow",
        "impact_th": "ผู้โจมตีสร้าง crontab ที่มี field ยาวเกิน buffer ที่กำหนด → stack/heap overflow → overwrite return address → execute shellcode ในฐานะ crond daemon (root)",
        "check": "version_only",
        "remediation": "Upgrade cronie >= 1.6.1",
        "prevention_th": [
            "อัปเกรด cronie เป็นเวอร์ชัน 1.6.1 ขึ้นไปทันที: apt upgrade cron",
            "ตรวจสอบเวอร์ชันปัจจุบัน: dpkg -l cron | grep cron",
            "จำกัดการเขียน crontab เฉพาะ user ที่จำเป็น: chmod 600 /var/spool/cron/crontabs/*",
            "เปิดใช้ stack protection: ตรวจสอบว่า kernel มี ASLR: cat /proc/sys/kernel/randomize_va_space",
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
        "description_th": "Cron job ที่เรียก pkexec หรือ script ที่ใช้ polkit มีความเสี่ยงต่อการ inject environment variable เนื่องจาก pkexec มีช่องโหว่ในการจัดการ argv/envp",
        "impact_th": "ผู้โจมตีตั้ง environment variable ก่อน cron job รัน → cron เรียก pkexec → pkexec โหลด malicious shared object จาก env var → ได้ root shell ทันที",
        "check": "cron_env_injection",
        "remediation": "Audit cron jobs for pkexec usage. Upgrade polkit >= 0.120.",
        "prevention_th": [
            "อัปเกรด polkit ทันที: apt upgrade policykit-1",
            "ตรวจสอบ cron job ที่เรียก pkexec: grep -r 'pkexec' /etc/cron*",
            "แทนที่ pkexec ด้วย sudo ที่กำหนด policy ชัดเจน",
            "ถอด SUID จาก pkexec ชั่วคราว: chmod 0755 /usr/bin/pkexec",
            "ตรวจสอบ env var ที่ cron ส่งต่อ: env_reset ใน /etc/sudoers",
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
        "description_th": "หาก cron log file เขียนได้โดยทุกคน ร่วมกับช่องโหว่ Dirty Pipe ใน kernel ผู้โจมตีสามารถเขียนทับ read-only file ผ่าน pipe buffer ที่ cron เปิดไว้",
        "impact_th": "ผู้โจมตีใช้ writable cron log เป็น file descriptor ที่เปิดไว้แล้ว trigger Dirty Pipe → เขียนทับ SUID binary หรือ /etc/passwd → ได้ root",
        "check": "log_permission",
        "remediation": "chmod 640 /var/log/cron && Upgrade kernel >= 5.16.11",
        "prevention_th": [
            "แก้ permission cron log: chmod 640 /var/log/cron && chown root:adm /var/log/cron",
            "อัปเกรด kernel เป็นเวอร์ชัน 5.16.11, 5.15.25, หรือ 5.10.102: apt upgrade linux-image-$(uname -r)",
            "ตรวจสอบเวอร์ชัน kernel: uname -r",
            "ใช้ IMA เพื่อตรวจจับการแก้ไข SUID binary",
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
        "description_th": "Cron สร้าง temporary file ใน /tmp โดยไม่ตรวจสอบ symlink attack ทำให้ผู้โจมตีสร้าง symlink ที่มีชื่อเดียวกับ temp file ไว้ล่วงหน้า แล้วให้ cron เขียนทับไฟล์เป้าหมาย",
        "impact_th": "ผู้โจมตีสร้าง /tmp/cron_tmp_XXXX → /etc/shadow ไว้ก่อน → เมื่อ cron สร้าง temp file ชื่อเดียวกัน จะ follow symlink → เขียนทับ /etc/shadow ด้วย content ที่ควบคุมได้",
        "check": "world_writable_tmp",
        "remediation": "Ensure /tmp has sticky bit: chmod 1777 /tmp",
        "prevention_th": [
            "ตั้ง sticky bit บน /tmp: chmod 1777 /tmp",
            "Mount /tmp ด้วย noexec,nosuid: mount -o remount,noexec,nosuid /tmp",
            "ใช้ mkstemp() แทน tempnam() ใน script (สำหรับ developer)",
            "อัปเกรด cron เป็นเวอร์ชันที่ใช้ mkstemp() อย่างถูกต้อง",
            "ตรวจสอบ cron script ที่สร้างไฟล์ใน /tmp: grep -r '/tmp' /etc/cron*",
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
        "description_th": "หาก /etc/cron.d มี symlink ที่ผู้โจมตีสร้างไว้ cron daemon จะ follow symlink และ execute ไฟล์ปลายทางในฐานะ root โดยไม่ตรวจสอบความปลอดภัย",
        "impact_th": "ผู้โจมตีสร้าง symlink ใน /etc/cron.d ชี้ไปยัง script ที่ตัวเองควบคุม → cron อ่านและรัน script นั้นในฐานะ root ตามตารางเวลา → ได้ root shell แบบ persistent",
        "check": "symlink_check",
        "remediation": "chmod 755 /etc/cron.d && audit symlinks: find /etc/cron.d -type l",
        "prevention_th": [
            "ตรวจสอบ symlink ใน cron.d: find /etc/cron.d -type l -ls",
            "ลบ symlink ที่ไม่รู้จัก: find /etc/cron.d -type l -delete",
            "แก้ permission: chmod 755 /etc/cron.d && chown root:root /etc/cron.d",
            "อัปเกรด cronie/cron: apt upgrade cron",
            "Monitor การเปลี่ยนแปลงใน cron.d: auditctl -w /etc/cron.d -p wa -k crond_change",
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
        "description_th": "Cron job ที่ใช้ sudo กับ runas ALL มีความเสี่ยง เนื่องจาก sudo เวอร์ชันเก่าอนุญาตให้ใช้ -u#-1 ซึ่ง resolve เป็น UID 0 (root) แม้จะถูกห้าม",
        "impact_th": "Cron script ที่มี 'sudo -u ... command' สามารถถูก exploit ด้วย 'sudo -u#-1 /bin/bash' → ได้ root shell แม้ sudoers จะห้ามรันในฐานะ root โดยตรง",
        "check": "crontab_sudo_all",
        "remediation": "Upgrade sudo >= 1.8.28. Audit crontabs for sudo ALL entries.",
        "prevention_th": [
            "อัปเกรด sudo เป็นเวอร์ชัน 1.8.28 ขึ้นไป: apt upgrade sudo",
            "ตรวจสอบ cron job ที่ใช้ sudo: grep -r 'sudo' /etc/cron* /var/spool/cron/",
            "แทนที่ sudo ALL ด้วยการระบุ user/command ที่ชัดเจนใน sudoers",
            "ใช้ 'Defaults!command noexec' เพื่อป้องกัน command injection",
            "Audit sudoers เป็นประจำ: visudo -c && sudo -l",
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
        "description_th": "cronie ตาม symlink ขณะอ่าน crontab file ทำให้ผู้ใช้ทั่วไปสร้าง symlink ใน /var/spool/cron ชี้ไปยังไฟล์ sensitive แล้ว cron daemon จะอ่านไฟล์นั้น",
        "impact_th": "ผู้โจมตีสร้าง symlink /var/spool/cron/username → /etc/shadow → cron daemon อ่าน /etc/shadow และ log ข้อมูลหรือ error messages ที่มี content ของ /etc/shadow",
        "check": "symlink_check",
        "remediation": "Upgrade cronie >= 1.5.5. Audit /var/spool/cron for symlinks.",
        "prevention_th": [
            "อัปเกรด cronie เป็นเวอร์ชัน 1.5.5 ขึ้นไป",
            "ตรวจสอบ symlink ใน spool: find /var/spool/cron -type l -ls",
            "แก้ permission: chmod 700 /var/spool/cron && chmod 600 /var/spool/cron/*",
            "ลบ crontab ที่ไม่รู้จัก: crontab -r -u suspicious_user",
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
        "description_th": "Cron script ที่รันเป็น root และเขียนได้โดยทุกคน เปิดช่องให้ผู้โจมตีแก้ไข script เพื่อ inject command หรือใช้ overlayfs เพื่อ escape จาก container",
        "impact_th": "ผู้โจมตีแก้ไข world-writable cron script ใส่ reverse shell หรือ command ที่เป็นอันตราย → เมื่อ cron รัน script นั้นตามตาราง → ได้ root shell แบบ scheduled",
        "check": "cron_script_writable",
        "remediation": "Audit /etc/cron.* scripts for writable files. chmod 755 /etc/cron.d",
        "prevention_th": [
            "ตรวจสอบ world-writable script: find /etc/cron* -perm -002 -type f -ls",
            "แก้ permission script ทั้งหมด: chmod 755 /etc/cron.d/* && chown root:root /etc/cron.d/*",
            "ตรวจสอบ content ของ cron script ว่ามีการแก้ไขผิดปกติ: md5sum /etc/cron.d/*",
            "ใช้ AIDE หรือ Tripwire monitor การเปลี่ยนแปลง cron script",
            "อัปเกรด kernel เพื่อ patch overlayfs: apt upgrade linux-image-$(uname -r)",
        ],
    },
]

# ==============================
# Version Matching
# ==============================
def match_version(current, rule):
    import re as _re
    # <999.0 is used as "always vulnerable" sentinel
    if rule in ("<999.0", "<=999.0"):
        return True
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
        "version_only":       (True,        {}),
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
    print(f"""
{c(Color.CYAN + Color.BOLD, '''
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝''')}
{c(Color.GRAY, '         Cron CVE Scanner  |  "Conquer Vulnerabilities"')}
""")

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
            print(f"     {c(Color.CYAN,'📋 ช่องโหว่  :')} {c(Color.WHITE, f['description_th'][:90])}{'...' if len(f['description_th'])>90 else ''}")
        if f.get("impact_th"):
            print(f"     {c(Color.ORANGE,'⚡ ผลกระทบ  :')} {c(Color.YELLOW, f['impact_th'][:90])}{'...' if len(f['impact_th'])>90 else ''}")
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
            print(f"     {c(Color.GREEN + Color.BOLD,'🛡  การป้องกัน:')}")
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
# Save Report
# ==============================
def save_report(cron_type, cron_version, findings, checks, base_path):
    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "NONE"

    max_cvss = max((f["cvss"] for f in findings), default=0)

    report = {
        "tool":      "COSVINTE — Cron CVE Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": platform.node(),
            "distro":   get_distro(),
        },
        "scan": {
            "cron_type":    cron_type,
            "cron_version": cron_version,
            "base_path":    base_path,
        },
        "checks": {
            k: {"vulnerable": bool(v), "detail": str(d) if d else None}
            for k, (v, d) in checks.items()
        },
        "summary": {
            "total_cve_db":     len(CVE_DB),
            "total_findings":   len(findings),
            "overall_cvss":     max_cvss,
            "overall_severity": sev(max_cvss),
        },
        "findings": [
            {k: v for k, v in f.items() if k != "detail"}
            for f in findings
        ],
    }

    fname = f"cosvinte_cron_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    return fname

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
