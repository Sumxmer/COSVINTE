#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Linux Capability Scanner  |  "Conquer Vulnerabilities"
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
    BG_RED  = "\033[41m"
    BG_YELLOW = "\033[43m"

def c(color, text):
    return f"{color}{text}{Color.RESET}"

def severity_badge(sev):
    colors = {
        "CRITICAL": Color.BG_RED + Color.BOLD,
        "HIGH":     Color.RED + Color.BOLD,
        "MEDIUM":   Color.YELLOW + Color.BOLD,
        "LOW":      Color.GREEN,
    }
    return f"{colors.get(sev, Color.GRAY)} {sev} {Color.RESET}"

def cvss_bar(score, width=20):
    filled = int((score / 10.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 9:   color = Color.BG_RED + Color.BOLD
    elif score >= 7: color = Color.RED
    elif score >= 4: color = Color.YELLOW
    else:            color = Color.GREEN
    return f"{color}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"

# ==============================
# Capability Risk Database
# Full description + CVE mapping + exploit notes
# ==============================
CAP_DB = {
    "cap_sys_admin": {
        "severity": "CRITICAL",
        "base_score": 9.5,
        "description": "Effectively equivalent to root. Allows mount, pivot_root, kernel module load, arbitrary namespace ops.",
        "description_th": "เทียบเท่า root โดยสมบูรณ์ ช่วยให้สามารถ mount filesystem, โหลด kernel module, จัดการ namespace ได้อย่างอิสระ",
        "impact_th": "ผู้โจมตีสามารถหลบหนีออกจาก container, ฝัง rootkit ระดับ kernel, และยึดครองระบบทั้งหมดได้",
        "exploit": "docker escape, kernel module injection, overlay mount abuse",
        "cves": ["CVE-2022-0492", "CVE-2022-25636", "CVE-2021-22555"],
        "remediation": "Remove cap_sys_admin. Use specific caps instead. Never assign to untrusted binaries.",
        "prevention_th": [
            "ลบ cap_sys_admin ออกจากทุก binary ที่ไม่จำเป็น",
            "ใช้ capability เฉพาะเจาะจงแทน เช่น cap_net_admin สำหรับงาน network เท่านั้น",
            "เปิดใช้ AppArmor หรือ SELinux เพื่อจำกัดสิทธิ์เพิ่มเติม",
            "ตรวจสอบสม่ำเสมอด้วย: getcap -r / 2>/dev/null",
        ],
    },
    "cap_setuid": {
        "severity": "CRITICAL",
        "base_score": 9.0,
        "description": "Allows setting arbitrary UID — attacker can switch to UID 0 (root) at will.",
        "description_th": "อนุญาตให้เปลี่ยน UID เป็นค่าใดก็ได้ รวมถึง UID 0 (root) ทำให้ผู้โจมตียกระดับสิทธิ์เป็น root ได้ทันที",
        "impact_th": "หาก binary นี้เป็น scripting interpreter เช่น python หรือ perl ผู้โจมตีสามารถรัน os.setuid(0) เพื่อเป็น root ได้ในทันที",
        "exploit": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "cves": ["CVE-2021-4034", "CVE-2019-14287"],
        "remediation": "Remove cap_setuid from all non-essential binaries. Audit with: getcap -r / 2>/dev/null",
        "prevention_th": [
            "ลบ cap_setuid ออกจาก interpreter ทุกตัว (python, perl, ruby, node ฯลฯ) ทันที",
            "ตรวจสอบ binary ทั้งหมดด้วย: getcap -r / 2>/dev/null | grep setuid",
            "ใช้ sudo ที่กำหนดสิทธิ์แบบ least-privilege แทนการใช้ capability",
            "เปิดใช้ audit log เพื่อตรวจจับการเปลี่ยน UID ผิดปกติ: auditctl -a always,exit -F arch=b64 -S setuid",
        ],
    },
    "cap_setgid": {
        "severity": "HIGH",
        "base_score": 8.0,
        "description": "Allows setting arbitrary GID — attacker can join privileged groups (shadow, disk, docker).",
        "description_th": "อนุญาตให้เปลี่ยน GID เป็นค่าใดก็ได้ ผู้โจมตีสามารถเข้าร่วม group ที่มีสิทธิ์สูง เช่น shadow, disk, หรือ docker",
        "impact_th": "การเข้าถึง group 'shadow' เปิดให้อ่าน /etc/shadow ได้ ส่วน group 'disk' เปิดให้เข้าถึง raw disk โดยตรง",
        "exploit": "Switch to GID of 'shadow' group to read /etc/shadow hashes",
        "cves": ["CVE-2021-4034"],
        "remediation": "Remove cap_setgid. Ensure binaries only have minimum required capabilities.",
        "prevention_th": [
            "ลบ cap_setgid ออกจาก binary ที่ไม่จำเป็นต้องเปลี่ยน group",
            "ตรวจสอบสมาชิกของ group ที่มีสิทธิ์สูง: getent group shadow disk docker",
            "จำกัดสิทธิ์ /etc/shadow ให้อ่านได้เฉพาะ root: chmod 000 /etc/shadow",
            "ใช้ PAM module เพื่อจำกัดการเปลี่ยน group",
        ],
    },
    "cap_dac_override": {
        "severity": "HIGH",
        "base_score": 7.5,
        "description": "Bypasses all file read/write/execute permission checks — can read /etc/shadow, /root/.",
        "description_th": "ข้ามการตรวจสอบสิทธิ์ไฟล์ทั้งหมด (read/write/execute) สามารถอ่านหรือเขียนไฟล์ใดก็ได้บนระบบ รวมถึง /etc/shadow และ /root/",
        "impact_th": "ผู้โจมตีสามารถอ่านไฟล์ password hash, แก้ไข /etc/passwd เพื่อเพิ่ม backdoor account, หรือเขียนทับ binary ที่มี SUID",
        "exploit": "Read /etc/shadow, overwrite /etc/passwd, modify SUID binaries",
        "cves": ["CVE-2023-4911", "CVE-2016-1247"],
        "remediation": "Remove cap_dac_override. Use ACLs for specific file access instead.",
        "prevention_th": [
            "ลบ cap_dac_override และใช้ POSIX ACL เพื่อให้สิทธิ์เฉพาะไฟล์ที่ต้องการแทน",
            "ตั้งค่า immutable flag ให้ไฟล์สำคัญ: chattr +i /etc/passwd /etc/shadow",
            "ใช้ IMA (Integrity Measurement Architecture) เพื่อตรวจจับการแก้ไขไฟล์",
            "ตรวจสอบ integrity ของไฟล์ระบบด้วย AIDE หรือ Tripwire เป็นประจำ",
        ],
    },
    "cap_dac_read_search": {
        "severity": "HIGH",
        "base_score": 7.0,
        "description": "Bypasses file read and directory search permission checks — allows reading any file.",
        "description_th": "ข้ามการตรวจสอบสิทธิ์การอ่านไฟล์และการค้นหาใน directory ทำให้อ่านไฟล์ใดก็ได้โดยไม่ต้องมีสิทธิ์",
        "impact_th": "ผู้โจมตีสามารถนำข้อมูลลับออกจากระบบ เช่น private key, config files, database credentials โดยไม่ทิ้งร่องรอยในระบบ permission ปกติ",
        "exploit": "tar -czf /tmp/shadow.tar.gz /etc/shadow",
        "cves": ["CVE-2014-8990"],
        "remediation": "Remove cap_dac_read_search. Restrict to specific backup tools only.",
        "prevention_th": [
            "จำกัด cap_dac_read_search เฉพาะ backup tool ที่ได้รับการตรวจสอบแล้วเท่านั้น",
            "เข้ารหัสไฟล์ sensitive ด้วย encryption at rest แม้จะถูกอ่านได้ก็ไม่มีประโยชน์",
            "ใช้ audit log ตรวจจับการเข้าถึงไฟล์ sensitive: auditctl -w /etc/shadow -p r",
            "แยก sensitive files ไปไว้ใน filesystem ที่มี access control เข้มงวด",
        ],
    },
    "cap_net_admin": {
        "severity": "MEDIUM",
        "base_score": 6.5,
        "description": "Full network configuration access — can modify routing, firewall rules, sniff traffic.",
        "description_th": "เข้าถึงการตั้งค่า network ทั้งหมด สามารถแก้ไข routing table, กฎ firewall, และดักฟัง traffic ในระบบ",
        "impact_th": "ผู้โจมตีสามารถล้าง firewall rules เพื่อเปิด port, ทำ ARP spoofing เพื่อดักข้อมูล, หรือ redirect traffic ไปยัง attacker-controlled server",
        "exploit": "iptables -F (flush all firewall rules), ARP spoofing, traffic capture",
        "cves": ["CVE-2020-14386", "CVE-2016-8655"],
        "remediation": "Limit to network management daemons only. Never assign to scripting languages.",
        "prevention_th": [
            "จำกัด cap_net_admin เฉพาะ daemon ที่จัดการ network เท่านั้น (เช่น NetworkManager)",
            "ห้ามกำหนด cap_net_admin ให้กับ scripting interpreter หรือ general-purpose tools",
            "ใช้ network namespace เพื่อแยก network environment ของแต่ละ process",
            "ตรวจสอบ firewall rules เป็นประจำ: iptables -L -n -v",
        ],
    },
    "cap_net_raw": {
        "severity": "MEDIUM",
        "base_score": 6.0,
        "description": "Allows raw socket creation — enables network sniffing, spoofing, and ICMP manipulation.",
        "description_th": "อนุญาตให้สร้าง raw socket ทำให้สามารถดักฟัง network traffic, ปลอมแปลง packet, และจัดการ ICMP ได้โดยตรง",
        "impact_th": "ผู้โจมตีสามารถดักจับ credentials ที่ส่งผ่าน network, ทำ ARP poisoning เพื่อทำ MITM attack, หรือ inject packet ที่เป็นอันตราย",
        "exploit": "tcpdump credential capture, ARP/ICMP spoofing, packet injection",
        "cves": ["CVE-2020-14386"],
        "remediation": "Limit cap_net_raw to specific tools (ping, tcpdump). Never assign broadly.",
        "prevention_th": [
            "จำกัด cap_net_raw เฉพาะ tool ที่จำเป็นจริงๆ เช่น ping หรือ tcpdump ที่ระบุ path ชัดเจน",
            "ใช้ network encryption (TLS/HTTPS) ทุกที่เพื่อลดผลกระทบจาก sniffing",
            "เปิดใช้ Dynamic ARP Inspection บน switch เพื่อป้องกัน ARP spoofing",
            "Monitor network anomaly ด้วย IDS เช่น Suricata หรือ Snort",
        ],
    },
    "cap_sys_ptrace": {
        "severity": "HIGH",
        "base_score": 8.5,
        "description": "Allows ptrace on any process — can inject code into running processes including root-owned ones.",
        "description_th": "อนุญาตให้ใช้ ptrace กับ process ใดก็ได้ รวมถึง process ที่ root เป็นเจ้าของ ทำให้สามารถ inject code หรือ dump memory ของ process ที่กำลังทำงานอยู่",
        "impact_th": "ผู้โจมตีสามารถดึง credentials จาก memory ของ process เช่น password manager หรือ SSH agent, หรือ inject shellcode เข้าสู่ process ที่มีสิทธิ์สูง",
        "exploit": "Inject shellcode into /sbin/init or any privileged process",
        "cves": ["CVE-2019-13272", "CVE-2021-3492"],
        "remediation": "Remove cap_sys_ptrace. Set sysctl kernel.yama.ptrace_scope=2.",
        "prevention_th": [
            "ตั้งค่า kernel.yama.ptrace_scope=2 ใน /etc/sysctl.conf เพื่อจำกัด ptrace",
            "ลบ cap_sys_ptrace ออกจาก binary ที่ไม่ใช่ debugger โดยเฉพาะ",
            "ใช้ seccomp profile เพื่อบล็อก ptrace syscall สำหรับ process ที่ไม่จำเป็น",
            "เปิดใช้ ASLR และ PIE เพื่อเพิ่มความยากในการ exploit แม้จะ ptrace ได้",
        ],
    },
    "cap_sys_module": {
        "severity": "CRITICAL",
        "base_score": 9.8,
        "description": "Allows loading/unloading kernel modules — complete kernel code execution as root.",
        "description_th": "อนุญาตให้โหลดหรือถอด kernel module ออก ทำให้สามารถรัน code ระดับ kernel ได้อย่างสมบูรณ์ เทียบเท่ากับการควบคุม OS ทั้งหมด",
        "impact_th": "ผู้โจมตีสามารถติดตั้ง rootkit ระดับ kernel ที่ซ่อนตัวจาก antivirus และ system monitor, ขโมยข้อมูลทุกอย่างบนระบบ, หรือสร้าง backdoor ถาวร",
        "exploit": "insmod /tmp/rootkit.ko — full kernel rootkit installation",
        "cves": ["CVE-2019-2025"],
        "remediation": "Remove immediately. Lock kernel modules: sysctl kernel.modules_disabled=1",
        "prevention_th": [
            "ล็อค kernel modules ทันทีหลัง boot: sysctl -w kernel.modules_disabled=1",
            "เปิดใช้ Secure Boot และ kernel module signing เพื่อยืนยัน module ก่อนโหลด",
            "ใช้ DKMS เฉพาะสำหรับ module ที่เชื่อถือได้เท่านั้น",
            "ตรวจสอบ kernel module ที่โหลดอยู่เป็นประจำ: lsmod | grep -v '^Module'",
            "พิจารณาใช้ read-only root filesystem เพื่อป้องกันการวาง module ใหม่",
        ],
    },
    "cap_chown": {
        "severity": "HIGH",
        "base_score": 7.8,
        "description": "Allows changing file ownership arbitrarily — can take ownership of any file including /etc/passwd.",
        "description_th": "อนุญาตให้เปลี่ยน owner ของไฟล์ใดก็ได้ รวมถึงไฟล์ระบบสำคัญ เช่น /etc/passwd, /etc/shadow, หรือ binary ที่มี SUID",
        "impact_th": "ผู้โจมตีสามารถยึด ownership ของ /etc/shadow เพื่ออ่าน password hash, หรือ chown binary ที่มี SUID เพื่อแก้ไขและฝัง backdoor",
        "exploit": "chown attacker /etc/shadow && read hashes",
        "cves": ["CVE-2021-4034"],
        "remediation": "Remove cap_chown from non-essential binaries. Audit carefully.",
        "prevention_th": [
            "ลบ cap_chown ออกจาก binary ทั้งหมดที่ไม่ต้องการจริงๆ",
            "ตั้งค่า immutable flag ให้ไฟล์ระบบสำคัญ: chattr +i /etc/passwd /etc/shadow /etc/sudoers",
            "ใช้ filesystem monitoring เพื่อแจ้งเตือนเมื่อ ownership ของไฟล์เปลี่ยน",
            "ตรวจสอบ ownership ของ SUID binary เป็นประจำ: find / -perm -4000 -ls 2>/dev/null",
        ],
    },
    "cap_fowner": {
        "severity": "MEDIUM",
        "base_score": 6.5,
        "description": "Bypasses permission checks for operations requiring file ownership match.",
        "description_th": "ข้ามการตรวจสอบสิทธิ์ที่ต้องการให้ผู้ใช้เป็นเจ้าของไฟล์ ทำให้สามารถ chmod, chown, หรือแก้ไข attribute ของไฟล์ที่ตัวเองไม่ได้เป็นเจ้าของ",
        "impact_th": "ผู้โจมตีสามารถ chmod 777 ไฟล์ sensitive ใดก็ได้ เพื่อให้ทุกคนอ่านได้ หรือแก้ไข permission ของ directory เพื่อฝัง trojan",
        "exploit": "chmod 777 /etc/shadow — make sensitive files world-readable",
        "cves": [],
        "remediation": "Remove cap_fowner. Use targeted file ACLs instead.",
        "prevention_th": [
            "ลบ cap_fowner และใช้ POSIX ACL แทนเพื่อให้สิทธิ์เฉพาะเจาะจง",
            "Monitor การเปลี่ยนแปลง permission ของไฟล์ด้วย auditd",
            "ใช้ Linux Security Module (LSM) เช่น AppArmor เพื่อกำหนด policy เพิ่มเติม",
        ],
    },
    "cap_sys_rawio": {
        "severity": "CRITICAL",
        "base_score": 9.2,
        "description": "Raw I/O access to block devices — can read/write raw disk including /dev/sda.",
        "description_th": "เข้าถึง block device โดยตรง (raw I/O) สามารถอ่านหรือเขียนข้อมูลดิบบน disk ทั้งหมด รวมถึง /dev/sda โดยไม่ผ่าน filesystem",
        "impact_th": "ผู้โจมตีสามารถดึงข้อมูลทุกอย่างจาก disk รวมถึงข้อมูลที่ถูก 'ลบ' ไปแล้ว, แก้ไข MBR/GPT เพื่อฝัง bootkit, หรือทำลายข้อมูลทั้ง disk",
        "exploit": "dd if=/dev/sda | grep -a password — extract credentials from raw disk",
        "cves": [],
        "remediation": "Remove immediately. Never assign to user-accessible binaries.",
        "prevention_th": [
            "ลบ cap_sys_rawio ออกทันที ไม่มีเหตุผลใดที่ user-space binary ทั่วไปต้องการ capability นี้",
            "จำกัดการเข้าถึง /dev/sda และ block device อื่นๆ ด้วย udev rules",
            "เข้ารหัส disk ทั้งหมดด้วย LUKS เพื่อให้ข้อมูลดิบไม่มีประโยชน์แม้ถูกอ่าน",
            "ตรวจสอบ raw disk access ผ่าน audit log: auditctl -w /dev/sda -p rw",
        ],
    },
    "cap_kill": {
        "severity": "LOW",
        "base_score": 3.5,
        "description": "Allows sending signals to any process — can kill critical system daemons.",
        "description_th": "อนุญาตให้ส่ง signal ไปยัง process ใดก็ได้ รวมถึง process ของ root สามารถ kill daemon สำคัญของระบบได้",
        "impact_th": "ผู้โจมตีสามารถ kill process ระบบสำคัญ เช่น systemd, syslog, หรือ security daemon เพื่อทำให้ระบบ logging หยุดทำงานและซ่อน activity",
        "exploit": "kill -9 1 (kill init/systemd) causing system crash",
        "cves": [],
        "remediation": "Restrict to specific process management tools only.",
        "prevention_th": [
            "จำกัด cap_kill เฉพาะ process management tool ที่จำเป็น",
            "ใช้ systemd service protection: ProtectSystem=strict, ProtectHome=true",
            "ตั้งค่า watchdog สำหรับ critical daemon เพื่อ restart อัตโนมัติ",
        ],
    },
    "cap_sys_chroot": {
        "severity": "MEDIUM",
        "base_score": 6.0,
        "description": "Allows chroot to arbitrary directories — combined with other caps can escape sandbox.",
        "description_th": "อนุญาตให้ chroot ไปยัง directory ใดก็ได้ เมื่อใช้ร่วมกับ capability อื่น สามารถหลบหนีออกจาก chroot sandbox ได้",
        "impact_th": "ผู้โจมตีที่ถูกกักไว้ใน chroot environment สามารถหลบหนีออกมายัง root filesystem ได้ หากมี cap_sys_chroot ร่วมกับ capability อื่น",
        "exploit": "chroot escape combined with cap_sys_admin or writable filesystem",
        "cves": ["CVE-2015-1318"],
        "remediation": "Remove cap_sys_chroot or combine with seccomp/AppArmor restrictions.",
        "prevention_th": [
            "ใช้ container technology เช่น Docker หรือ systemd-nspawn แทน chroot เพราะมีการ isolate ที่ดีกว่า",
            "เพิ่ม seccomp profile เพื่อจำกัด syscall สำหรับ process ที่อยู่ใน chroot",
            "ตรวจสอบว่า chroot directory ไม่มี writable filesystem ที่ผู้โจมตีสามารถนำไปใช้ได้",
        ],
    },
    "cap_audit_write": {
        "severity": "LOW",
        "base_score": 3.0,
        "description": "Allows writing to kernel audit log — can be used to obscure attack traces.",
        "description_th": "อนุญาตให้เขียนข้อมูลลงใน kernel audit log สามารถใช้เพื่อฝัง log ปลอมหรือสร้างความสับสนในระหว่างการโจมตี",
        "impact_th": "ผู้โจมตีสามารถ inject audit entry ปลอมเพื่อปิดบัง activity ที่เป็นอันตราย ทำให้การ forensics และ incident response ทำได้ยากขึ้น",
        "exploit": "Inject false audit entries to cover tracks during an attack",
        "cves": [],
        "remediation": "Only assign to audit daemons. Monitor audit log integrity.",
        "prevention_th": [
            "จำกัด cap_audit_write เฉพาะ auditd daemon เท่านั้น",
            "ส่ง audit log ไปยัง remote server (log aggregator) แบบ real-time เพื่อป้องกันการแก้ไข",
            "ใช้ log integrity verification เช่น signing audit logs",
            "Monitor ความผิดปกติใน audit log ด้วย SIEM tool",
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
    return findings

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
    print(f"""
{c(Color.CYAN + Color.BOLD, '''
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝''')}
{c(Color.GRAY, '         Linux Capability Scanner  |  "Conquer Vulnerabilities"')}
""")

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
                print(f"     {c(Color.CYAN,'📋 ช่องโหว่   :')} {c(Color.WHITE, f['description_th'][:90])}{'...' if len(f['description_th'])>90 else ''}")
            if f.get("impact_th"):
                print(f"     {c(Color.ORANGE,'⚡ ผลกระทบ   :')} {c(Color.YELLOW, f['impact_th'][:90])}{'...' if len(f['impact_th'])>90 else ''}")

            if f["risk_factors"]:
                print(f"     {c(Color.ORANGE,'⚠  Factors   :')} {c(Color.YELLOW, ' | '.join(f['risk_factors'][:3]))}")

            if f["exploit_hint"]:
                print(f"     {c(Color.RED,'💀 Exploit   :')} {c(Color.GRAY, f['exploit_hint'][:75])}")

            if f["cves"]:
                cve_str = "  ".join(c(Color.CYAN, cv) for cv in f["cves"][:3])
                print(f"     {c(Color.GRAY,'CVEs        :')} {cve_str}")

            # ── Prevention tips in Thai ──
            if f.get("prevention_th"):
                print(f"     {c(Color.GREEN + Color.BOLD,'🛡  การป้องกัน:')}")
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
# Save Report
# ==============================
def save_report(findings):
    max_score = max((f["risk_score"] for f in findings), default=0)

    def sev(score):
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "NONE"

    report = {
        "tool":      "COSVINTE — Linux Capability Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": platform.node(),
            "distro":   get_distro(),
            "arch":     platform.machine(),
        },
        "summary": {
            "total_findings":   len(findings),
            "critical":         sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":             sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":           sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":              sum(1 for f in findings if f["severity"] == "LOW"),
            "interpreters":     sum(1 for f in findings if f["is_interpreter"]),
            "world_writable":   sum(1 for f in findings if f["world_writable"]),
            "overall_score":    max_score,
            "overall_severity": sev(max_score),
        },
        "findings": findings,
    }

    fname = f"cosvinte_caps_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4, ensure_ascii=False)
    return fname

# ==============================
# MAIN
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

    fname = save_report(findings)
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, fname)}\n"))

if __name__ == "__main__":
    main()
