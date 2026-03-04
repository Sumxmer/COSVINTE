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
# CVE Database
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit — pkexec ENV Injection",
        "category": "SUID / Polkit",
        "description": "pkexec fails to handle argv/envp correctly, allowing environment variable injection to load malicious shared objects as root.",
        "description_th": "pkexec จัดการ argv/envp ไม่ถูกต้อง ทำให้ผู้โจมตีสามารถ inject environment variable เพื่อโหลด shared object ที่เป็นอันตรายในฐานะ root",
        "impact_th": "ผู้ใช้งานทั่วไป (non-root) สามารถยกระดับสิทธิ์เป็น root ได้ทันทีบน Linux distribution แทบทุกตัว เนื่องจาก pkexec มักถูกติดตั้งแบบ SUID เป็นค่าเริ่มต้น",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade polkit >= 0.120 or: chmod 0755 /usr/bin/pkexec",
        "prevention_th": [
            "อัปเกรด polkit เป็นเวอร์ชัน 0.120 ขึ้นไปทันที: apt upgrade policykit-1",
            "หากอัปเกรดไม่ได้ทันที ให้ถอด SUID bit ชั่วคราว: chmod 0755 /usr/bin/pkexec",
            "ตรวจสอบว่ามีการ exploit แล้วหรือยัง: ausearch -c pkexec --raw | aureport -f",
            "ใช้ AppArmor/SELinux profile สำหรับ pkexec เพื่อจำกัด action ที่ทำได้",
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
        "description_th": "sudo อนุญาตให้รัน command ด้วย UID -1 ซึ่ง resolve เป็น UID 0 (root) ได้ เมื่อ sudoers ตั้งค่า runas เป็น ALL ทำให้ข้ามข้อจำกัดที่ตั้งไว้",
        "impact_th": "ผู้ใช้ที่ได้รับอนุญาตให้รัน sudo ในบางรูปแบบ สามารถใช้ 'sudo -u#-1 /bin/bash' เพื่อได้ root shell แม้จะถูกห้ามรันในฐานะ root โดยตรง",
        "cvss": 8.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.8.28 and audit /etc/sudoers for 'ALL' runas entries.",
        "prevention_th": [
            "อัปเกรด sudo เป็นเวอร์ชัน 1.8.28 ขึ้นไป: apt upgrade sudo",
            "ตรวจสอบ sudoers ทุกบรรทัดที่มี ALL: grep -i 'runas.*all' /etc/sudoers /etc/sudoers.d/*",
            "หลีกเลี่ยงการใช้ 'ALL' ใน runas spec ให้ระบุ user/group ที่อนุญาตอย่างชัดเจน",
            "ใช้ 'sudo -l' เพื่อ audit สิทธิ์ที่แต่ละ user มีอยู่เป็นประจำ",
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
        "description_th": "SUID binary ที่ไม่กรอง LD_PRELOAD หรือ LD_AUDIT ออก จะทำให้ dynamic linker โหลด shared library ของผู้โจมตีในฐานะ root",
        "impact_th": "ผู้โจมตีสร้าง .so file ที่มี malicious code แล้วตั้ง LD_PRELOAD ให้ชี้ไปที่ไฟล์นั้น เมื่อ SUID binary ถูกรัน library จะโหลดโดยอัตโนมัติด้วยสิทธิ์ root",
        "cvss": 7.2,
        "severity": "HIGH",
        "remediation": "Ensure ld.so ignores LD_PRELOAD for SUID binaries (default in modern glibc). Audit SUID binaries.",
        "prevention_th": [
            "ตรวจสอบว่า glibc เวอร์ชันปัจจุบันกรอง LD_PRELOAD สำหรับ SUID binary โดยอัตโนมัติ",
            "ลบ environment variable ที่เป็นอันตรายออกจาก shell: unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH",
            "ใช้ env_reset ใน sudoers เพื่อล้าง environment ก่อนรัน sudo: Defaults env_reset",
            "ตรวจสอบว่าไม่มี LD_PRELOAD ใน /etc/environment, /etc/profile, หรือ .bashrc",
            "ใช้ seccomp/AppArmor เพื่อจำกัด syscall ที่ SUID binary ใช้ได้",
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
        "description_th": "runuser และ su ไม่ทำการกรอง PATH variable ทำให้ผู้โจมตีวาง binary ปลอมไว้ใน PATH directory ที่ทุกคนเขียนได้ เพื่อให้ถูกรันแทน binary จริงในฐานะ root",
        "impact_th": "หากมี world-writable directory อยู่ต้น PATH เช่น /tmp ผู้โจมตีวาง binary ชื่อเดียวกับ command ที่ script root ใช้งาน เมื่อ script รัน binary ของผู้โจมตีจะถูกเรียกแทน",
        "cvss": 7.0,
        "severity": "HIGH",
        "remediation": "Remove world-writable directories from PATH. Use absolute paths in scripts.",
        "prevention_th": [
            "ลบ world-writable directory ออกจาก PATH ทันที โดยเฉพาะ /tmp และ /var/tmp",
            "ใช้ path แบบ absolute ใน script ทุกตัว เช่น /usr/bin/python3 แทน python3",
            "ตั้งค่า secure PATH ใน /etc/environment: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "ใช้ 'env -i' เมื่อรัน script ที่ต้องการ environment ที่สะอาด",
            "audit script ที่รันด้วย root privilege ทุกตัวให้ใช้ absolute path",
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
        "description_th": "Ubuntu อนุญาตให้ผู้ใช้ทั่วไป mount overlayfs บน path ใดก็ได้ เมื่อใช้ร่วมกับ PATH hijack ทำให้ยกระดับสิทธิ์ได้",
        "impact_th": "ผู้โจมตีสร้าง overlayfs layer ที่ซ้อนทับ /bin หรือ /usr/bin เพื่อให้ binary ที่ตัวเองควบคุมถูกรันแทน binary จริง เมื่อมี world-writable PATH directory ร่วมด้วยจะ exploit ได้ง่ายขึ้น",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "remediation": "Upgrade kernel. Restrict user namespaces: sysctl -w kernel.unprivileged_userns_clone=0",
        "prevention_th": [
            "อัปเกรด kernel เป็นเวอร์ชันที่ได้รับการ patch แล้ว",
            "ปิด unprivileged user namespace: sysctl -w kernel.unprivileged_userns_clone=0",
            "ทำให้ค่านี้คงอยู่หลัง reboot: echo 'kernel.unprivileged_userns_clone=0' >> /etc/sysctl.conf",
            "ลบ world-writable directory ออกจาก PATH เพื่อลด attack surface",
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
        "description_th": "sudo อ่าน /proc/[pid]/stat เพื่อระบุ terminal device และมีช่องโหว่ในการ parse ข้อมูลนั้น เมื่อรวมกับ world-writable PATH directory ทำให้ยกระดับสิทธิ์ได้",
        "impact_th": "ผู้โจมตีสามารถบังคับให้ sudo โหลด binary จาก world-writable directory โดยการสร้าง symlink หรือ file ที่มีชื่อพิเศษ และได้ root shell ในที่สุด",
        "cvss": 6.3,
        "severity": "MEDIUM",
        "remediation": "Upgrade sudo >= 1.8.21. Ensure no world-writable dirs appear before /usr/bin in PATH.",
        "prevention_th": [
            "อัปเกรด sudo เป็นเวอร์ชัน 1.8.21 ขึ้นไป",
            "ตรวจสอบและลบ world-writable directory ออกจาก PATH โดยเฉพาะที่อยู่ก่อน /usr/bin",
            "ตรวจสอบ PATH ปัจจุบัน: echo $PATH | tr ':' '\\n' | while read p; do ls -ld \"$p\"; done",
            "ใช้ secure_path ใน sudoers เพื่อ override PATH เสมอ: Defaults secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
        "description_th": "sudoedit อนุญาตให้ผู้ใช้แนบ flag พิเศษเพื่อควบคุม editor ที่ใช้งาน เมื่อใช้ร่วมกับ writable PATH หรือ SUDO_EDITOR ที่ถูก set ผู้โจมตีสามารถแก้ไขไฟล์ใดก็ได้ในฐานะ root",
        "impact_th": "ผู้โจมตีตั้ง SUDO_EDITOR หรือ VISUAL ให้ชี้ไปยัง script ที่เป็นอันตราย แล้วรัน sudoedit เพื่อให้ script นั้นถูกเรียกด้วยสิทธิ์ root สามารถแก้ไข /etc/passwd หรือ /etc/sudoers ได้",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.9.12p2. Restrict SUDO_EDITOR and VISUAL env vars.",
        "prevention_th": [
            "อัปเกรด sudo เป็นเวอร์ชัน 1.9.12p2 ขึ้นไปทันที",
            "เพิ่ม env_delete ใน sudoers เพื่อลบ env var อันตราย: Defaults env_delete+='SUDO_EDITOR VISUAL EDITOR'",
            "กำหนด editor ที่อนุญาตอย่างชัดเจนใน sudoers: Defaults editor=/usr/bin/nano:/usr/bin/vim",
            "ตรวจสอบว่า SUDO_EDITOR และ VISUAL ไม่ได้ถูก set ใน environment: env | grep -E 'EDITOR|VISUAL'",
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
        "description_th": "ช่องโหว่ใน Linux kernel ทำให้สามารถเขียนทับไฟล์ read-only ใดก็ได้รวมถึง SUID binary ผ่าน pipe buffer โดยไม่ต้องมีสิทธิ์พิเศษ",
        "impact_th": "ผู้โจมตีเขียนทับ SUID binary เช่น /usr/bin/passwd ด้วย shellcode แล้วรัน binary นั้นเพื่อได้ root shell แม้ไฟล์จะเป็น read-only และ owned by root",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade kernel >= 5.16.11 / 5.15.25 / 5.10.102",
        "prevention_th": [
            "อัปเกรด kernel เป็นเวอร์ชัน 5.16.11, 5.15.25, หรือ 5.10.102 ขึ้นไปทันที",
            "ตรวจสอบเวอร์ชัน kernel ปัจจุบัน: uname -r",
            "หากอัปเกรดไม่ได้ ลด attack surface โดยลบ SUID binary ที่ไม่จำเป็น",
            "ใช้ integrity checking เช่น IMA เพื่อตรวจจับการเปลี่ยนแปลง SUID binary",
            "Monitor kernel exploit attempt ด้วย auditd: auditctl -a always,exit -F arch=b64 -S open -F exit=-EACCES",
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
        "description_th": "ช่องโหว่ heap buffer overflow ใน sudoedit เกิดจากการจัดการ backslash ที่ท้าย argument ไม่ถูกต้อง ทำให้ผู้ใช้ทั่วไปสามารถรัน code ในฐานะ root",
        "impact_th": "ผู้โจมตีส่ง argument พิเศษที่มี trailing backslash ไปยัง sudoedit เพื่อ trigger heap overflow แล้วใช้เทคนิค heap exploitation เพื่อรันคำสั่งในฐานะ root โดยไม่ต้องรู้ password",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.9.5p2",
        "prevention_th": [
            "อัปเกรด sudo เป็นเวอร์ชัน 1.9.5p2 ขึ้นไปทันที: apt upgrade sudo",
            "ตรวจสอบเวอร์ชัน sudo ที่ใช้งานอยู่: sudo --version",
            "ตรวจสอบว่า exploit แล้วหรือยัง: grep 'sudo' /var/log/auth.log | grep -i 'error\\|segfault'",
            "ถ้าอัปเกรดไม่ได้ ใช้ aliasas เพื่อ block sudoedit ชั่วคราว",
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
        "description_th": "ช่องโหว่ stack buffer overflow ใน sudo เกิดจาก pwfeedback feature ที่แสดง '*' ขณะพิมพ์ password เมื่อรับ input ยาวเกินกำหนดจะเกิด overflow",
        "impact_th": "ผู้โจมตีส่ง password ยาวมากผ่าน pipe ไปยัง sudo เพื่อ overflow stack buffer แล้วควบคุม execution flow เพื่อได้ root shell",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade sudo >= 1.8.31 or disable pwfeedback in sudoers.",
        "prevention_th": [
            "อัปเกรด sudo เป็นเวอร์ชัน 1.8.31 ขึ้นไป",
            "ปิด pwfeedback ใน /etc/sudoers: Defaults !pwfeedback",
            "ตรวจสอบว่า pwfeedback เปิดอยู่หรือไม่: sudo -l | grep pwfeedback",
            "ใช้ grep -r 'pwfeedback' /etc/sudoers /etc/sudoers.d/ เพื่อ audit การตั้งค่า",
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
        "description_th": "Race condition ใน tty layer ของ Linux kernel ทำให้ผู้โจมตีสามารถใช้ SUID binary ที่ attach กับ tty เพื่อยกระดับสิทธิ์ได้",
        "impact_th": "ผู้โจมตีใช้ SUID binary เพื่อเปิด tty แล้ว trigger race condition ใน kernel เพื่อ execute code ในฐานะ root — เหมาะสำหรับระบบที่มี SUID binary จำนวนมาก",
        "cvss": 6.9,
        "severity": "MEDIUM",
        "remediation": "Upgrade kernel >= 3.14.3. Apply distro patches.",
        "prevention_th": [
            "อัปเกรด kernel เป็นเวอร์ชัน 3.14.3 ขึ้นไป หรือ apply distro security patch",
            "ลด SUID binary ที่ไม่จำเป็นออกจากระบบ: find / -perm -4000 -type f 2>/dev/null",
            "ใช้ systemd sandboxing สำหรับ service ที่ใช้ tty: PrivateTmp=yes, NoNewPrivileges=yes",
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
        "description_th": "AF_PACKET socket เมื่อใช้ร่วมกับ world-writable PATH directory ทำให้สามารถสร้าง race condition เพื่อยกระดับสิทธิ์ได้",
        "impact_th": "ผู้โจมตีที่มีสิทธิ์สร้าง AF_PACKET socket (หรือผ่าน cap_net_raw) ร่วมกับ PATH directory ที่เขียนได้ สามารถ trigger race condition ใน kernel network stack เพื่อได้ root",
        "cvss": 7.8,
        "severity": "HIGH",
        "remediation": "Upgrade kernel >= 4.10.6. Restrict raw socket capabilities.",
        "prevention_th": [
            "อัปเกรด kernel เป็นเวอร์ชัน 4.10.6 ขึ้นไป",
            "จำกัดการสร้าง AF_PACKET socket: sysctl -w net.core.bpf_jit_harden=2",
            "ลบ world-writable directory ออกจาก PATH เพื่อตัด attack vector",
            "จำกัด cap_net_raw ไม่ให้มอบให้ process ที่ไม่จำเป็น",
            "ใช้ seccomp profile เพื่อ block socket(AF_PACKET) syscall สำหรับ process ทั่วไป",
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
        "desc_th": "บังคับให้ dynamic linker โหลด shared library ที่กำหนดก่อน library อื่น อาจถูกใช้ override function ใน SUID binary",
        "risk": "HIGH"
    },
    "LD_AUDIT": {
        "desc_th": "กำหนด audit library สำหรับ dynamic linker สามารถใช้ inject code ในลักษณะเดียวกับ LD_PRELOAD",
        "risk": "HIGH"
    },
    "LD_LIBRARY_PATH": {
        "desc_th": "เพิ่ม directory ค้นหา shared library สามารถใช้โหลด library ปลอมแทนของจริงได้",
        "risk": "HIGH"
    },
    "SUDO_EDITOR": {
        "desc_th": "กำหนด editor ที่ sudoedit ใช้งาน หากถูก set เป็น script อันตราย จะถูกรันด้วย root privilege",
        "risk": "MEDIUM"
    },
    "VISUAL": {
        "desc_th": "กำหนด visual editor ที่ใช้งาน sudo อาจ inherit ค่านี้ไปได้หาก env_reset ไม่ถูก set",
        "risk": "MEDIUM"
    },
    "EDITOR": {
        "desc_th": "กำหนด default text editor อาจถูก sudo หรือ program อื่นใช้งาน",
        "risk": "MEDIUM"
    },
    "PYTHONPATH": {
        "desc_th": "เพิ่ม directory ค้นหา Python module หาก Python binary มี SUID หรือ capability ผู้โจมตีโหลด module ปลอมได้",
        "risk": "MEDIUM"
    },
    "PERL5LIB": {
        "desc_th": "เพิ่ม directory ค้นหา Perl module คล้ายกับ PYTHONPATH สามารถใช้ inject malicious Perl module",
        "risk": "MEDIUM"
    },
    "RUBYLIB": {
        "desc_th": "เพิ่ม directory ค้นหา Ruby library สามารถ override standard library ด้วย code ที่เป็นอันตราย",
        "risk": "MEDIUM"
    },
    "JAVA_TOOL_OPTIONS": {
        "desc_th": "กำหนด JVM options ที่ใช้กับทุก Java process บนระบบ อาจถูกใช้ inject Java agent ที่เป็นอันตราย",
        "risk": "MEDIUM"
    },
    "NODE_OPTIONS": {
        "desc_th": "กำหนด Node.js runtime options สามารถใช้โหลด malicious module หรือ disable security feature ของ Node",
        "risk": "MEDIUM"
    },
    "DYLD_INSERT_LIBRARIES": {
        "desc_th": "macOS equivalent ของ LD_PRELOAD บังคับโหลด dynamic library ก่อน library อื่น",
        "risk": "HIGH"
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
        print(f"     {c(Color.GRAY,'value   :')} {c(Color.YELLOW, f['value'])}")
        # Thai description
        if f.get("desc_th"):
            print(f"     {c(Color.CYAN,'📋 อธิบาย :')} {c(Color.WHITE, f['desc_th'][:90])}{'...' if len(f['desc_th'])>90 else ''}")

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
            print(f"     {c(Color.CYAN,'📋 ช่องโหว่  :')} {c(Color.WHITE, entry['description_th'][:90])}{'...' if len(entry['description_th'])>90 else ''}")
        if entry.get("impact_th"):
            print(f"     {c(Color.ORANGE,'⚡ ผลกระทบ  :')} {c(Color.YELLOW, entry['impact_th'][:90])}{'...' if len(entry['impact_th'])>90 else ''}")
        print(f"     {c(Color.GRAY,'Triggered by:')}")
        for reason in entry["matched_reasons"]:
            print(f"       {c(Color.ORANGE,'→')} {c(Color.YELLOW, reason)}")
        # Thai prevention tips
        if entry.get("prevention_th"):
            print(f"     {c(Color.GREEN + Color.BOLD,'🛡  การป้องกัน:')}")
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
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
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
