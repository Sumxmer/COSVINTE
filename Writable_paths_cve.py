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
# CVE Database
# ==============================
CVE_DB = [
    {
        "cve": "CVE-2016-1247",
        "name": "Apache Log Dir Writable",
        "description": "World-writable Apache log directory allows local users to replace log files with symlinks, leading to privilege escalation via logrotate.",
        "description_th": "หาก directory log ของ Apache เขียนได้โดยทุกคน ผู้ใช้ทั่วไปสามารถแทนที่ log file ด้วย symlink เพื่อให้ logrotate ทำงานกับไฟล์ที่ตัวเองเลือกในฐานะ root",
        "impact_th": "ผู้โจมตีสร้าง symlink ใน log directory ชี้ไปยัง /etc/passwd หรือ authorized_keys แล้วรอให้ logrotate รัน → ไฟล์เป้าหมายถูก overwrite ด้วยสิทธิ์ root",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Web Server",
        "path_patterns": [
            "/var/log/apache", "/var/log/apache2",
            "/var/log/httpd", "/var/log/nginx"
        ],
        "remediation": "chmod 755 /var/log/apache2 && chown root:adm /var/log/apache2",
        "prevention_th": [
            "แก้ permission ทันที: chmod 755 /var/log/apache2 && chown root:adm /var/log/apache2",
            "ตรวจสอบ logrotate config ว่า create ไฟล์ด้วย permission ที่ถูกต้อง: grep -r 'create' /etc/logrotate.d/apache2",
            "ใช้ ACL เพื่อให้ apache user เขียนได้เฉพาะ log ของตัวเอง: setfacl -m u:www-data:w /var/log/apache2",
            "Monitor การสร้าง symlink ใน log directory: auditctl -w /var/log/apache2 -p wa",
        ],
    },
    {
        "cve": "CVE-2017-1000117",
        "name": "systemd tmpfiles Writable Path",
        "description": "World-writable directories processed by systemd-tmpfiles can be abused to create arbitrary files as root during boot.",
        "description_th": "systemd-tmpfiles ประมวลผล directory ที่กำหนดไว้ระหว่าง boot หาก directory เหล่านั้นเขียนได้โดยทุกคน ผู้โจมตีสามารถวาง file ที่เป็นอันตรายซึ่งจะถูกสร้างหรือ process ในฐานะ root",
        "impact_th": "ผู้โจมตีวาง config file ใน /tmp หรือ /var/tmp ก่อน boot จากนั้น systemd-tmpfiles อ่านและดำเนินการตาม spec ของ attacker ด้วยสิทธิ์ root ทำให้สามารถสร้าง backdoor ได้",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "System Service",
        "path_patterns": [
            "/tmp", "/var/tmp", "/run",
            "/var/run", "/dev/shm"
        ],
        "remediation": "chmod 1777 /tmp && chmod 1777 /var/tmp",
        "prevention_th": [
            "ตั้ง sticky bit เพื่อป้องกันไม่ให้ user ลบ file ของคนอื่น: chmod 1777 /tmp && chmod 1777 /var/tmp",
            "Mount /tmp ด้วย noexec,nosuid เพื่อป้องกัน execution: mount -o remount,noexec,nosuid /tmp",
            "ทำให้ค่านี้คงอยู่ใน /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid,size=1G 0 0",
            "Monitor การเขียน file ที่ผิดปกติใน /tmp: auditctl -w /tmp -p wa -k tmp_write",
        ],
    },
    {
        "cve": "CVE-2015-1838",
        "name": "Tomcat Writable Webapps",
        "description": "World-writable Tomcat webapps directory allows unauthenticated file upload leading to remote code execution.",
        "description_th": "หาก directory webapps ของ Tomcat เขียนได้โดยทุกคน ผู้โจมตีสามารถอัปโหลด WAR file ที่เป็น web shell เข้าไปได้โดยตรง นำไปสู่ Remote Code Execution",
        "impact_th": "ผู้โจมตีคัดลอก .war file ที่มี JSP shell เข้า /var/lib/tomcat/webapps/ → Tomcat deploy อัตโนมัติ → ได้ web shell รันคำสั่งบน server ด้วยสิทธิ์ของ tomcat user",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "category": "Web Server",
        "path_patterns": [
            "/var/lib/tomcat", "/opt/tomcat",
            "/usr/share/tomcat", "/srv/tomcat"
        ],
        "remediation": "chown -R tomcat:tomcat /var/lib/tomcat && chmod 750 /var/lib/tomcat/webapps",
        "prevention_th": [
            "แก้ permission: chown -R tomcat:tomcat /var/lib/tomcat && chmod 750 /var/lib/tomcat/webapps",
            "ปิด auto-deploy ใน Tomcat config: <Host autoDeploy=\"false\" deployOnStartup=\"false\">",
            "ใช้ Tomcat Manager app แทนการ copy file โดยตรง และกำหนด IP whitelist",
            "ตรวจสอบการเปลี่ยนแปลงใน webapps directory: auditctl -w /var/lib/tomcat/webapps -p wa",
        ],
    },
    {
        "cve": "CVE-2018-15686",
        "name": "Docker Symlink Writable Escalation",
        "description": "World-writable Docker runtime directories allow symlink attacks for privilege escalation to root.",
        "description_th": "Docker runtime directory ที่เขียนได้โดยทุกคน เปิดช่องให้ผู้โจมตีสร้าง symlink เพื่อให้ Docker daemon ซึ่งรันเป็น root เข้าถึงหรือแก้ไขไฟล์ภายนอก container",
        "impact_th": "ผู้โจมตีสร้าง symlink ใน /var/lib/docker หรือ /run/docker ชี้ไปยัง /etc/shadow → เมื่อ Docker daemon ประมวลผล symlink นั้น ไฟล์ปลายทางจะถูก access หรือ overwrite ด้วยสิทธิ์ root",
        "cvss": 8.0,
        "severity": "HIGH",
        "category": "Container",
        "path_patterns": [
            "/var/lib/docker", "/run/docker",
            "/var/run/docker", "/etc/docker"
        ],
        "remediation": "chmod 700 /var/lib/docker && chown root:docker /run/docker.sock",
        "prevention_th": [
            "จำกัด permission: chmod 700 /var/lib/docker && chown root:docker /run/docker.sock",
            "ตรวจสอบ user ที่อยู่ใน docker group เพราะเทียบเท่า root: getent group docker",
            "ใช้ rootless Docker เพื่อรัน container โดยไม่ต้องใช้ root: dockerd-rootless-setuptool.sh install",
            "เปิดใช้ Docker Content Trust เพื่อ verify image: export DOCKER_CONTENT_TRUST=1",
        ],
    },
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit — pkexec Writable PATH",
        "description": "World-writable directories in PATH allow injection of malicious shared objects loaded by pkexec, leading to root privilege escalation.",
        "description_th": "หาก directory ใน PATH เขียนได้โดยทุกคน ผู้โจมตีวาง shared object ปลอมซึ่ง pkexec จะโหลดด้วยสิทธิ์ root เนื่องจาก pkexec ไม่กรอง environment อย่างถูกต้อง",
        "impact_th": "ผู้โจมตีวาง .so file ที่มี malicious code ใน writable PATH directory → pkexec โหลด library นั้นในฐานะ root → ได้ root shell ทันที ช่องโหว่นี้ทำงานได้บน Linux ทุก distro",
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
            "อัปเกรด polkit ทันที: apt upgrade policykit-1",
            "แก้ permission directory ที่เป็นปัญหา: chmod 755 /usr/bin /usr/sbin /usr/local/bin",
            "ถอด SUID bit จาก pkexec ชั่วคราว: chmod 0755 /usr/bin/pkexec",
            "ตรวจสอบ directory ใน PATH ที่เขียนได้: for d in $(echo $PATH | tr ':' ' '); do ls -ld $d; done",
        ],
    },
    {
        "cve": "CVE-2019-14287",
        "name": "sudo -u#-1 Bypass",
        "description": "World-writable /etc/sudoers.d directory allows injecting sudo rules to run commands as root.",
        "description_th": "หาก /etc/sudoers.d เขียนได้โดยทุกคน ผู้โจมตีเพิ่ม rule ใหม่เข้าไปเพื่อให้ตัวเองรัน command ในฐานะ root ได้ ร่วมกับ bug ใน sudo ที่ -u#-1 resolve เป็น UID 0",
        "impact_th": "ผู้โจมตีสร้างไฟล์ใน /etc/sudoers.d/ ที่มี rule 'attacker ALL=(ALL) NOPASSWD: ALL' → รัน sudo โดยไม่ต้องใส่ password → ได้ root shell",
        "cvss": 8.8,
        "severity": "HIGH",
        "category": "sudo",
        "path_patterns": [
            "/etc/sudoers", "/etc/sudoers.d",
            "/etc/sudo.conf"
        ],
        "remediation": "chmod 440 /etc/sudoers && chmod 750 /etc/sudoers.d",
        "prevention_th": [
            "แก้ permission ทันที: chmod 440 /etc/sudoers && chmod 750 /etc/sudoers.d",
            "ตรวจสอบ sudoers file ที่ผิดปกติ: ls -la /etc/sudoers.d/ && visudo -c",
            "อัปเกรด sudo: apt upgrade sudo",
            "Monitor การเปลี่ยนแปลง sudoers: auditctl -w /etc/sudoers -p wa -k sudoers_change",
            "ใช้ 'sudo -l' เพื่อตรวจสอบ rule ที่มีอยู่: sudo -l -U username",
        ],
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe — Writable Pipe Abuse",
        "description": "World-writable /proc entries combined with Dirty Pipe allow overwriting read-only files via pipe buffer manipulation.",
        "description_th": "ช่องโหว่ใน Linux kernel ทำให้ pipe buffer flags ไม่ถูก clear ผู้โจมตีสามารถเขียนทับ page cache ของไฟล์ read-only ผ่าน /proc entries ที่เขียนได้",
        "impact_th": "ผู้โจมตีเขียนทับ /etc/passwd หรือ SUID binary เช่น /usr/bin/sudo ผ่าน pipe โดยไม่ต้องมีสิทธิ์ write → เพิ่ม backdoor user หรือแก้ไข binary เพื่อได้ root",
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
            "อัปเกรด kernel ทันที: apt upgrade linux-image-$(uname -r)",
            "ตรวจสอบเวอร์ชัน kernel: uname -r (ต้องการ >= 5.16.11, 5.15.25, หรือ 5.10.102)",
            "ใช้ IMA เพื่อตรวจจับการแก้ไขไฟล์ระบบสำคัญ",
            "Mount /proc ด้วย hidepid=2 เพื่อจำกัดการมองเห็น process: mount -o remount,hidepid=2 /proc",
        ],
    },
    {
        "cve": "CVE-2023-4911",
        "name": "Looney Tunables — ld.so Writable",
        "description": "World-writable glibc loader config or lib path allows buffer overflow in GLIBC_TUNABLES leading to root escalation.",
        "description_th": "หาก glibc loader config หรือ library path เขียนได้ ผู้โจมตีแก้ไข /etc/ld.so.preload หรือแทนที่ library จริงด้วย version ที่มี malicious code → buffer overflow ใน GLIBC_TUNABLES → root",
        "impact_th": "ผู้โจมตีแก้ไข /etc/ld.so.preload เพิ่ม path ของ malicious library → ทุก SUID binary ที่รันจะโหลด library นั้นก่อน → ได้ root shell ทันทีเมื่อ SUID binary ถูกเรียก",
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
            "อัปเกรด glibc ทันที: apt upgrade libc6",
            "แก้ permission: chmod 644 /etc/ld.so.conf && chmod 755 /etc/ld.so.conf.d",
            "ตรวจสอบ /etc/ld.so.preload ว่ามี entry ผิดปกติหรือไม่: cat /etc/ld.so.preload",
            "ล็อค ld.so.preload ด้วย immutable flag: chattr +i /etc/ld.so.preload",
            "ตรวจ integrity ของ glibc library: debsums libc6",
        ],
    },
    {
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit — sudo Heap Overflow",
        "description": "World-writable /etc or sudo binary allows replacement/tampering leading to heap overflow exploitation.",
        "description_th": "หาก /etc หรือ sudo binary เขียนได้ ผู้โจมตีแทนที่ sudoers config หรือ binary เพื่อ trigger heap buffer overflow ใน sudoedit ทำให้ได้ root โดยไม่ต้องรู้ password",
        "impact_th": "ผู้โจมตีส่ง argument พิเศษไปยัง sudoedit เพื่อ trigger heap overflow แล้ว exploit เพื่อ execute code เป็น root — หากรวมกับ writable /etc จะสามารถแก้ไข sudoers ก่อน exploit ได้",
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
            "อัปเกรด sudo ทันที: apt upgrade sudo (ต้องการ >= 1.9.5p2)",
            "แก้ permission /etc: chmod 755 /etc",
            "ตรวจสอบ integrity ของ sudo binary: debsums sudo",
            "ล็อค sudoers ด้วย immutable flag: chattr +i /etc/sudoers",
            "ตรวจสอบเวอร์ชัน sudo: sudo --version",
        ],
    },
    {
        "cve": "CVE-2017-16995",
        "name": "eBPF Writable Map Privilege Escalation",
        "description": "World-writable /sys/fs/bpf or unprivileged BPF maps allow kernel memory manipulation for local privilege escalation.",
        "description_th": "หาก /sys/fs/bpf เขียนได้โดยทุกคน ผู้โจมตีสร้าง BPF map ที่เป็นอันตรายเพื่อ manipulate kernel memory โดยตรง นำไปสู่การยกระดับสิทธิ์",
        "impact_th": "ผู้โจมตีใช้ BPF program เพื่อเขียนลง kernel memory ที่ arbitrary address → แก้ไข credential structure ของ process → ยกระดับสิทธิ์เป็น root โดยไม่ต้องใช้ exploit อื่น",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel",
        "path_patterns": [
            "/sys/fs/bpf",
            "/sys/kernel/debug/bpf"
        ],
        "remediation": "sysctl -w kernel.unprivileged_bpf_disabled=1 && chmod 700 /sys/fs/bpf",
        "prevention_th": [
            "ปิด unprivileged BPF ทันที: sysctl -w kernel.unprivileged_bpf_disabled=1",
            "ทำให้ค่าคงอยู่: echo 'kernel.unprivileged_bpf_disabled=1' >> /etc/sysctl.conf",
            "จำกัด permission: chmod 700 /sys/fs/bpf",
            "ใช้ seccomp เพื่อ block bpf() syscall สำหรับ process ที่ไม่ต้องการ",
            "อัปเกรด kernel เป็นเวอร์ชันที่มี BPF verifier ที่ปลอดภัยกว่า",
        ],
    },
    {
        "cve": "CVE-2016-8655",
        "name": "Packet Socket Race Condition",
        "description": "World-writable /proc/net entries combined with race condition allow local privilege escalation via packet socket.",
        "description_th": "หาก /proc/net เขียนได้ ผู้โจมตีสามารถใช้ร่วมกับ race condition ใน packet socket handler ของ kernel เพื่อยกระดับสิทธิ์",
        "impact_th": "ผู้โจมตี trigger race condition โดยสร้าง packet socket และแก้ไข /proc/net entries พร้อมกัน ทำให้ kernel ใช้ข้อมูลที่ผิดพลาดและ execute code ในฐานะ kernel",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Kernel / Network",
        "path_patterns": [
            "/proc/net", "/proc/sys/net"
        ],
        "remediation": "Upgrade kernel and restrict /proc access via hidepid mount option",
        "prevention_th": [
            "อัปเกรด kernel เป็นเวอร์ชันที่ได้รับการ patch",
            "Mount /proc ด้วย hidepid=2: mount -o remount,hidepid=2 /proc",
            "ทำให้คงอยู่ใน /etc/fstab: proc /proc proc defaults,hidepid=2 0 0",
            "จำกัดการสร้าง raw socket: sysctl -w net.core.bpf_jit_harden=2",
        ],
    },
    {
        "cve": "CVE-2020-14386",
        "name": "AF_PACKET Heap Overflow via Writable Net",
        "description": "World-writable network proc files enable exploitation of memory corruption in AF_PACKET socket handling.",
        "description_th": "หาก /proc/sys/net หรือ /proc/net/dev เขียนได้ ผู้โจมตีสามารถแก้ไข network parameter เพื่อ trigger memory corruption ใน AF_PACKET socket handling",
        "impact_th": "ผู้โจมตีแก้ไข network settings ผ่าน writable /proc/sys/net แล้วสร้าง AF_PACKET socket เพื่อ trigger heap overflow → execute code ในฐานะ kernel → root",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Network",
        "path_patterns": [
            "/proc/sys/net", "/proc/net/dev"
        ],
        "remediation": "Upgrade kernel to >= 5.9 and apply network namespace restrictions",
        "prevention_th": [
            "อัปเกรด kernel เป็นเวอร์ชัน 5.9 ขึ้นไป",
            "จำกัดสิทธิ์ /proc/sys/net: chmod 555 /proc/sys/net",
            "ใช้ network namespace เพื่อ isolate network ของแต่ละ process",
            "ปิด unprivileged packet socket: sysctl -w net.core.bpf_jit_harden=2",
        ],
    },
    {
        "cve": "CVE-2019-13272",
        "name": "ptrace PTRACE_TRACEME Privilege Escalation",
        "description": "World-writable /proc/[pid] directories allow ptrace abuse for privilege escalation.",
        "description_th": "หาก /proc/sys/kernel/yama/ptrace_scope เขียนได้ ผู้โจมตีสามารถตั้งค่า ptrace_scope เป็น 0 แล้ว ptrace process ใดก็ได้รวมถึง process ของ root",
        "impact_th": "ผู้โจมตีเขียน 0 ลงใน /proc/sys/kernel/yama/ptrace_scope → ptrace process ที่มีสิทธิ์สูง → inject shellcode เข้าสู่ process ที่รันเป็น root → ได้ root shell",
        "cvss": 7.8,
        "severity": "HIGH",
        "category": "Process",
        "path_patterns": [
            "/proc/sys/kernel/yama/ptrace_scope",
            "/proc/sys/kernel/perf_event_paranoid"
        ],
        "remediation": "sysctl -w kernel.yama.ptrace_scope=1",
        "prevention_th": [
            "ตั้งค่า ptrace_scope ให้ปลอดภัย: sysctl -w kernel.yama.ptrace_scope=2",
            "ทำให้คงอยู่: echo 'kernel.yama.ptrace_scope=2' >> /etc/sysctl.conf",
            "แก้ permission: chmod 444 /proc/sys/kernel/yama/ptrace_scope",
            "ใช้ seccomp เพื่อ block ptrace syscall สำหรับ process ที่ไม่ใช่ debugger",
        ],
    },
    {
        "cve": "CVE-2018-1000001",
        "name": "glibc realpath() Buffer Underflow",
        "description": "World-writable glibc paths allow buffer underflow in realpath() used by SUID programs.",
        "description_th": "หาก glibc library path เขียนได้ ผู้โจมตีแทนที่ library จริงด้วย version ที่มีช่องโหว่หรือ malicious code ทำให้ SUID program ที่เรียก realpath() เกิด buffer underflow",
        "impact_th": "ผู้โจมตีแทนที่ /lib/x86_64-linux-gnu/libc ด้วย library ที่มีช่องโหว่ → SUID program โหลด library นั้น → buffer underflow → execute arbitrary code เป็น root",
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
            "อัปเกรด glibc: apt upgrade libc6 (ต้องการ >= 2.26)",
            "แก้ permission library directory: chmod 755 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu",
            "ตรวจสอบ integrity ของ library: debsums libc6",
            "ตั้ง immutable flag: chattr +i /etc/ld.so.preload /etc/ld.so.conf",
        ],
    },
    {
        "cve": "CVE-2015-5195",
        "name": "NTP Writable Config Privilege Escalation",
        "description": "World-writable NTP configuration or log paths allow local users to escalate privileges via ntpd.",
        "description_th": "หาก NTP config หรือ log directory เขียนได้ ผู้ใช้ทั่วไปสามารถแก้ไข config เพื่อให้ ntpd ทำ action ที่เป็นอันตราย หรือสร้าง symlink ใน log directory เพื่อ exploit logrotate",
        "impact_th": "ผู้โจมตีแก้ไข /etc/ntp.conf เพิ่ม 'keys /etc/shadow' หรือ directive ที่ทำให้ ntpd อ่านไฟล์ sensitive, หรือสร้าง symlink ใน /var/log/ntpstats เพื่อให้ logrotate เขียนทับไฟล์สำคัญ",
        "cvss": 5.0,
        "severity": "MEDIUM",
        "category": "Service",
        "path_patterns": [
            "/etc/ntp.conf", "/var/log/ntpstats",
            "/var/lib/ntp"
        ],
        "remediation": "chmod 644 /etc/ntp.conf && chown ntp:ntp /var/lib/ntp",
        "prevention_th": [
            "แก้ permission: chmod 644 /etc/ntp.conf && chown ntp:ntp /var/lib/ntp && chmod 750 /var/lib/ntp",
            "ตรวจสอบ config ว่าไม่มี directive ผิดปกติ: cat /etc/ntp.conf",
            "ใช้ chrony แทน ntpd ซึ่งมี security model ที่ดีกว่า",
            "Monitor การเปลี่ยนแปลง: auditctl -w /etc/ntp.conf -p wa -k ntp_config",
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
            print(f"     {c(Color.CYAN, '📋 ช่องโหว่  :')} {c(Color.WHITE, entry['description_th'][:90])}{'...' if len(entry['description_th'])>90 else ''}")
        if entry.get("impact_th"):
            print(f"     {c(Color.ORANGE, '⚡ ผลกระทบ  :')} {c(Color.YELLOW, entry['impact_th'][:90])}{'...' if len(entry['impact_th'])>90 else ''}")
        # Matched paths
        print(f"     {c(Color.GRAY, 'Matched     :')} {c(Color.YELLOW, str(len(entry['matched_paths'])) + ' path(s)')}")
        for mp in entry["matched_paths"][:3]:
            print(f"       {c(Color.ORANGE, '→')} {c(Color.WHITE, mp)}")
        # Thai prevention tips
        if entry.get("prevention_th"):
            print(f"     {c(Color.GREEN + Color.BOLD, '🛡  การป้องกัน:')}")
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
            "total_writable_paths":   len(writable),
            "total_cve_correlations": len(cve_hits),
            "overall_cvss":           max_cvss,
            "overall_severity":       sev(max_cvss),
        },
        "writable_paths": writable,
        "cve_correlations": [
            {k: v for k, v in entry.items() if k != "path_patterns"}
            for entry in cve_hits
        ]
    }
    fname = f"cosvinte_writable_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
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
