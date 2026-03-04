#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Kernel CVE Scanner  |  "Conquer Vulnerabilities"
"""

import platform
import subprocess
import json
import re
import sys
from datetime import datetime
from packaging import version

# ==============================
# ANSI Color Codes
# ==============================
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[40m"

def c(color, text):
    """Wrap text with color and reset"""
    return f"{color}{text}{Color.RESET}"

# ==============================
# CVE Database (Extended)
# ==============================
CVE_DB = [
    # ── Dirty COW family ──
    {
        "cve": "CVE-2016-5195",
        "name": "Dirty COW",
        "category": "Race Condition",
        "affected_min": "2.6.22",
        "affected_max": "4.8.3",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Race condition in mm/gup.c allows local privilege escalation via write access to read-only mappings.",
        "fix_commit": "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619",
        "patch_indicator": ["mm/gup.c", "cow_user_page"],
        "thai_detail": (
            "ช่องโหว่ Dirty COW เกิดจาก Race Condition ใน mm/gup.c ของ Linux Kernel\n"
            "     ผู้โจมตีที่มีสิทธิ์ Local User สามารถใช้ประโยชน์จากจังหวะแข่งขัน\n"
            "     ระหว่าง Thread เพื่อเขียนข้อมูลลงใน Memory Mapping แบบ Read-Only ได้\n"
            "     เช่น แก้ไขไฟล์ /etc/passwd หรือ SUID Binary เพื่อยกระดับสิทธิ์เป็น root\n"
            "     ช่องโหว่นี้มีอายุกว่า 9 ปีก่อนถูกค้นพบ ถือว่าเป็นหนึ่งในช่องโหว่ที่อันตรายที่สุด"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็นเวอร์ชัน 4.8.3 ขึ้นไปโดยเร็วที่สุด\n"
            "     2. ใช้ systemd-nspawn หรือ SELinux/AppArmor เพื่อจำกัดสิทธิ์ผู้ใช้\n"
            "     3. ตรวจสอบ integrity ของไฟล์ SUID ด้วย AIDE หรือ Tripwire\n"
            "     4. ในกรณีฉุกเฉิน ใช้ kpatch live-patch โดยไม่ต้อง reboot ระบบ"
        )
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Dirty Pipe",
        "category": "Pipe Buffer",
        "affected_min": "5.8",
        "affected_max": "5.16.10",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Flaw in pipe buffer flags allows overwriting read-only files including SUID binaries.",
        "fix_commit": "9d2231c5d74e13b2a0546fee6737ee4446017903",
        "patch_indicator": ["fs/pipe.c", "PIPE_BUF_FLAG_CAN_MERGE"],
        "thai_detail": (
            "ช่องโหว่ Dirty Pipe เกิดจากการตั้งค่า Flag ผิดพลาดใน Pipe Buffer\n"
            "     ของ Linux Kernel โดยเฉพาะ Flag PIPE_BUF_FLAG_CAN_MERGE\n"
            "     ผู้โจมตีสามารถเขียนทับไฟล์ที่ Read-Only ได้ รวมถึงไฟล์ SUID\n"
            "     เช่น /usr/bin/passwd เพื่อฝัง Backdoor หรือยกระดับสิทธิ์เป็น root\n"
            "     ค้นพบโดย Max Kellermann ในปี 2022 มีผลกระทบต่อ Container Runtime ด้วย"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.16.11, 5.15.25, หรือ 5.10.102 ขึ้นไป\n"
            "     2. ตรวจสอบว่า Distro ออก Security Patch แล้วหรือยัง (apt/yum update)\n"
            "     3. ลด Attack Surface โดยจำกัดการรัน Untrusted Code บนระบบ\n"
            "     4. ระบบ Container ควรอัปเดต Container Runtime (runc/containerd) ด้วย"
        )
    },
    # ── sudo / userspace ──
    {
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit",
        "category": "Heap Overflow",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap-based buffer overflow in sudo sudoedit allows privilege escalation to root.",
        "note": "Affects sudo ≤ 1.9.5p1 — not kernel directly",
        "patch_indicator": [],
        "thai_detail": (
            "ช่องโหว่ Baron Samedit เกิดจาก Heap Buffer Overflow ใน sudo\n"
            "     โดยเฉพาะคำสั่ง sudoedit ที่จัดการ Argument อย่างไม่ปลอดภัย\n"
            "     ผู้โจมตีที่มีบัญชี Local User ธรรมดา (ไม่ต้องอยู่ใน sudoers)\n"
            "     สามารถยกระดับสิทธิ์เป็น root ได้ทันที ไม่ต้องรู้รหัสผ่าน\n"
            "     ช่องโหว่นี้มีมานานกว่า 10 ปี ค้นพบโดย Qualys Research Team"
        ),
        "thai_mitigation": (
            "1. อัปเดต sudo เป็นเวอร์ชัน 1.9.5p2 ขึ้นไป (sudo --version)\n"
            "     2. ตรวจสอบ: sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')\n"
            "        ถ้าขึ้น error = ปลอดภัย, ถ้า crash = ยังมีช่องโหว่\n"
            "     3. จำกัดสิทธิ์ sudo ให้เฉพาะผู้ใช้ที่จำเป็นใน /etc/sudoers\n"
            "     4. ใช้ PAM Module เพิ่มเติมเพื่อ Log การใช้งาน sudo ทุกครั้ง"
        )
    },
    # ── Filesystem ──
    {
        "cve": "CVE-2022-0185",
        "name": "Filesystem Context Heap Overflow",
        "category": "Heap Overflow",
        "affected_min": "5.1",
        "affected_max": "5.16.2",
        "cvss": 8.4,
        "severity": "HIGH",
        "description": "Integer underflow in legacy_parse_param() in fs/fs_context.c allows heap overflow.",
        "fix_commit": "722d94847de29310e8aa03fcbdb41300d6a8ef76",
        "patch_indicator": ["fs/fs_context.c", "legacy_parse_param"],
        "thai_detail": (
            "ช่องโหว่นี้เกิดจาก Integer Underflow ในฟังก์ชัน legacy_parse_param()\n"
            "     ใน fs/fs_context.c ทำให้เกิด Heap Buffer Overflow\n"
            "     ผู้โจมตีที่มีสิทธิ์ CAP_SYS_ADMIN ภายใน User Namespace\n"
            "     สามารถยกระดับสิทธิ์เป็น root บน Host ได้ อันตรายมากบนระบบ Container\n"
            "     CVSS สูงถึง 8.4 เพราะสามารถ Escape จาก Container ออกมาได้"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.16.2 ขึ้นไป\n"
            "     2. ปิดการใช้ Unprivileged User Namespace:\n"
            "        sysctl -w kernel.unprivileged_userns_clone=0\n"
            "     3. ใช้ seccomp profile จำกัด syscall ใน Container\n"
            "     4. ตรวจสอบและจำกัด CAP_SYS_ADMIN ใน Container Runtime"
        )
    },
    {
        "cve": "CVE-2023-0386",
        "name": "OverlayFS Privilege Escalation",
        "category": "Filesystem",
        "affected_min": "5.11",
        "affected_max": "6.2.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "OverlayFS allows unprivileged users to copy SUID files into a mount, leading to privilege escalation.",
        "fix_commit": "4f11ada10d0ad6aa9f3f298c9dc71e83e84d71a0",
        "patch_indicator": ["fs/overlayfs", "ovl_copy_up"],
        "thai_detail": (
            "ช่องโหว่ OverlayFS เกิดจากการที่ Kernel อนุญาตให้ผู้ใช้ทั่วไป\n"
            "     คัดลอกไฟล์ SUID เข้าไปใน OverlayFS Mount ได้\n"
            "     ทำให้ผู้โจมตีสร้างไฟล์ SUID ของตัวเองและรันด้วยสิทธิ์ root ได้\n"
            "     อันตรายมากในสภาพแวดล้อม Docker/Kubernetes ที่ใช้ OverlayFS\n"
            "     เพราะ Container ใช้ OverlayFS เป็น Storage Driver หลัก"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 6.2.1 ขึ้นไป\n"
            "     2. ตรวจสอบ Docker/Kubernetes ใช้ Storage Driver อะไร:\n"
            "        docker info | grep 'Storage Driver'\n"
            "     3. ใช้ --no-new-privileges flag เมื่อรัน Container\n"
            "     4. เปิด AppArmor/SELinux Profile สำหรับ Container Runtime\n"
            "     5. ตรวจสอบว่า Distro ออก Backport Patch แล้วหรือยัง"
        )
    },
    # ── Netfilter / Network ──
    {
        "cve": "CVE-2022-1015",
        "name": "Netfilter OOB Write",
        "category": "Netfilter",
        "affected_min": "5.12",
        "affected_max": "5.17.1",
        "cvss": 6.6,
        "severity": "MEDIUM",
        "description": "Out-of-bound write in nf_tables_newrule() allows local privilege escalation.",
        "fix_commit": "d44f9f9f02a2f50bf1e3a3012d29e9af3fefbba3",
        "patch_indicator": ["net/netfilter/nf_tables_api.c"],
        "thai_detail": (
            "ช่องโหว่นี้อยู่ใน nf_tables ของ Netfilter Framework\n"
            "     ฟังก์ชัน nf_tables_newrule() มีการเขียนข้อมูลเกินขอบเขต Memory\n"
            "     ผู้โจมตีที่มีสิทธิ์ CAP_NET_ADMIN สามารถ Trigger OOB Write\n"
            "     เพื่อยกระดับสิทธิ์หรือทำให้ระบบ Crash (Denial of Service)\n"
            "     มักถูกใช้คู่กับ CVE-2022-1016 เพื่อโจมตีแบบต่อเนื่อง"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.17.2 ขึ้นไป\n"
            "     2. จำกัดการเข้าถึง nftables สำหรับผู้ใช้ทั่วไป:\n"
            "        sysctl -w kernel.unprivileged_userns_clone=0\n"
            "     3. ตรวจสอบและจำกัด CAP_NET_ADMIN ใน Container\n"
            "     4. ใช้ seccomp เพื่อบล็อก socket() syscall ที่ไม่จำเป็น"
        )
    },
    {
        "cve": "CVE-2022-1016",
        "name": "Netfilter Use-After-Free",
        "category": "Netfilter",
        "affected_min": "5.12",
        "affected_max": "5.17.1",
        "cvss": 5.5,
        "severity": "MEDIUM",
        "description": "Use-after-free in nf_tables may lead to information disclosure.",
        "fix_commit": "d44f9f9f02a2f50bf1e3a3012d29e9af3fefbba3",
        "patch_indicator": ["net/netfilter/nf_tables_api.c"],
        "thai_detail": (
            "ช่องโหว่ Use-After-Free ใน nf_tables ทำให้ Kernel อ่านข้อมูล\n"
            "     จาก Memory ที่ถูก Free ไปแล้ว นำไปสู่การรั่วไหลของข้อมูลสำคัญ\n"
            "     เช่น Kernel Pointer ที่ใช้ Bypass KASLR (Kernel Address Layout Randomization)\n"
            "     มักถูกใช้เป็นขั้นตอนแรกของการโจมตีก่อนใช้ CVE-2022-1015\n"
            "     เพื่อทำการ Privilege Escalation แบบสมบูรณ์"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.17.2 ขึ้นไป (แก้ทั้ง 1015 และ 1016)\n"
            "     2. เปิด Kernel Pointer Restrictions:\n"
            "        sysctl -w kernel.kptr_restrict=2\n"
            "     3. ปิด dmesg สำหรับ Unprivileged Users:\n"
            "        sysctl -w kernel.dmesg_restrict=1\n"
            "     4. ใช้ GRSecurity/PaX ถ้าต้องการความปลอดภัยสูงสุด"
        )
    },
    {
        "cve": "CVE-2023-32233",
        "name": "Netfilter nf_tables UAF",
        "category": "Netfilter",
        "affected_min": "5.1",
        "affected_max": "6.3.1",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Use-after-free in nf_tables batch handling allows local privilege escalation.",
        "fix_commit": "c1592a89942e9678f7d9c8030efa777c0d57edab",
        "patch_indicator": ["net/netfilter/nf_tables_api.c", "nf_tables_del_setelem"],
        "thai_detail": (
            "ช่องโหว่ Use-After-Free ใน Batch Handling ของ nf_tables\n"
            "     เกิดจากการที่ nf_tables_del_setelem() ไม่ตรวจสอบ State ให้ถูกต้อง\n"
            "     ผู้โจมตีสามารถสร้าง Batch Request พิเศษเพื่อ Free Memory\n"
            "     แล้วใช้ Dangling Pointer นั้นยกระดับสิทธิ์เป็น root ได้\n"
            "     มี Exploit สาธารณะแล้ว ถือว่าอันตรายมากและต้องแพตช์ทันที"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 6.3.2 ขึ้นไป โดยด่วน\n"
            "     2. ปิด Unprivileged User Namespaces ชั่วคราว:\n"
            "        echo 0 > /proc/sys/kernel/unprivileged_userns_clone\n"
            "     3. ตรวจสอบ Log หา Exploit Attempt:\n"
            "        dmesg | grep -i 'netfilter\\|nf_tables'\n"
            "     4. ใช้ Snort/Suricata Rules ตรวจจับ Exploitation Attempt"
        )
    },
    {
        "cve": "CVE-2023-35788",
        "name": "Flower Classifier OOB",
        "category": "Network",
        "affected_min": "4.14",
        "affected_max": "6.3.3",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Out-of-bounds write in fl_set_geneve_opt() in net/sched/cls_flower.c.",
        "fix_commit": "4d56304e5827c8cc8cc18c75343d283af7c4825c",
        "patch_indicator": ["net/sched/cls_flower.c", "fl_set_geneve_opt"],
        "thai_detail": (
            "ช่องโหว่อยู่ใน Traffic Control Flower Classifier ของ Linux Kernel\n"
            "     ฟังก์ชัน fl_set_geneve_opt() ไม่ตรวจสอบขนาด Option ของ Geneve Protocol\n"
            "     ทำให้เกิด Out-of-Bounds Write ใน Heap Memory\n"
            "     ผู้โจมตีที่มี CAP_NET_ADMIN สามารถ Trigger เพื่อยกระดับสิทธิ์\n"
            "     หรือรันโค้ดอันตรายใน Kernel Space ได้"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 6.3.4 ขึ้นไป\n"
            "     2. ถ้าไม่ใช้ Geneve Tunneling ให้ Blacklist Module:\n"
            "        echo 'blacklist geneve' >> /etc/modprobe.d/blacklist.conf\n"
            "     3. จำกัดสิทธิ์ CAP_NET_ADMIN ด้วย Capability Dropping\n"
            "     4. ใช้ Network Policy บน Kubernetes เพื่อลดการเข้าถึง"
        )
    },
    # ── Memory / UAF ──
    {
        "cve": "CVE-2021-22555",
        "name": "Netfilter Heap Out-of-Bounds Write",
        "category": "Heap Overflow",
        "affected_min": "2.6.19",
        "affected_max": "5.12.13",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap OOB write in xt_compat_target_from_user() in net/netfilter/x_tables.c.",
        "fix_commit": "b29c457a6511435960115c0f548c4360d5f4801d",
        "patch_indicator": ["net/netfilter/x_tables.c", "xt_compat_target_from_user"],
        "thai_detail": (
            "ช่องโหว่อยู่ในฟังก์ชัน xt_compat_target_from_user() ใน x_tables.c\n"
            "     เกิดจากการคำนวณขนาด Buffer ผิดพลาดเมื่อแปลง iptables Rules\n"
            "     จาก 32-bit ไป 64-bit ทำให้เกิด Heap OOB Write\n"
            "     ผู้โจมตีที่มีสิทธิ์ CAP_NET_ADMIN สามารถใช้เพื่อ\n"
            "     รันโค้ดอันตรายใน Kernel Space หรือยกระดับสิทธิ์เป็น root"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.12.14 ขึ้นไป\n"
            "     2. ใช้ nftables แทน iptables (ปลอดภัยกว่าและได้รับการ Maintain มากกว่า)\n"
            "     3. จำกัด CAP_NET_ADMIN ด้วย systemd Service Hardening:\n"
            "        CapabilityBoundingSet=~CAP_NET_ADMIN\n"
            "     4. เปิด CONFIG_HARDENED_USERCOPY เพื่อตรวจจับ OOB อัตโนมัติ"
        )
    },
    {
        "cve": "CVE-2022-27666",
        "name": "ESP Transformation Heap Overflow",
        "category": "IPSec",
        "affected_min": "5.10",
        "affected_max": "5.17.2",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap buffer overflow in IPSec ESP transformation (net/ipv4/esp4.c).",
        "fix_commit": "ebe48d368e97d007bfeb76fcb065d6a511d09b37",
        "patch_indicator": ["net/ipv4/esp4.c", "esp_output_tail"],
        "thai_detail": (
            "ช่องโหว่อยู่ใน IPSec ESP (Encapsulating Security Payload) ของ Kernel\n"
            "     ฟังก์ชัน esp_output_tail() ใน esp4.c คำนวณขนาด Buffer ผิดพลาด\n"
            "     ทำให้เกิด Heap Buffer Overflow เมื่อประมวลผล ESP Packet\n"
            "     ผู้โจมตีที่อยู่ในระบบเดียวกันสามารถส่ง Packet พิเศษ\n"
            "     เพื่อยกระดับสิทธิ์หรือทำให้ระบบ Crash ได้"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.17.3 ขึ้นไป\n"
            "     2. ถ้าไม่ได้ใช้ IPSec ให้ปิด Module:\n"
            "        echo 'install esp4 /bin/true' >> /etc/modprobe.d/disable-esp.conf\n"
            "     3. ใช้ WireGuard แทน IPSec ซึ่งมีโค้ดน้อยกว่าและปลอดภัยกว่า\n"
            "     4. ตรวจสอบ Network Segmentation ให้ผู้ใช้ไม่สามารถส่ง ESP Packet ได้"
        )
    },
    # ── SUID / Capabilities ──
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit (pkexec)",
        "category": "SUID",
        "affected_min": "0.0.1",
        "affected_max": "999.0.0",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Memory corruption in pkexec (polkit) allows unprivileged local privilege escalation.",
        "note": "Affects polkit < 0.120 — not kernel directly",
        "patch_indicator": [],
        "thai_detail": (
            "ช่องโหว่ PwnKit อยู่ใน pkexec ซึ่งเป็นส่วนหนึ่งของ polkit\n"
            "     เกิดจาก Memory Corruption ในการประมวลผล Argument ของ pkexec\n"
            "     ช่องโหว่มีมานานกว่า 12 ปี (ตั้งแต่ polkit เวอร์ชันแรก)\n"
            "     ผู้ใช้ Local ทุกคนสามารถยกระดับสิทธิ์เป็น root ได้ทันที\n"
            "     ไม่จำเป็นต้องมี pkexec ในระบบก็ได้รับผลกระทบถ้า polkit ติดตั้งอยู่"
        ),
        "thai_mitigation": (
            "1. อัปเดต polkit เป็นเวอร์ชัน 0.120 ขึ้นไปทันที\n"
            "     2. ตรวจสอบเวอร์ชัน: pkexec --version\n"
            "     3. แก้ไขชั่วคราว: chmod 0755 /usr/bin/pkexec (ลบ SUID bit)\n"
            "        หมายเหตุ: อาจทำให้บางแอปที่ใช้ pkexec ไม่ทำงาน\n"
            "     4. ตรวจสอบ Audit Log หาการ Exploit:\n"
            "        ausearch -m avc -ts recent | grep pkexec"
        )
    },
    # ── Container Escape ──
    {
        "cve": "CVE-2022-0492",
        "name": "cgroup v1 Container Escape",
        "category": "Container",
        "affected_min": "2.6.24",
        "affected_max": "5.17.0",
        "cvss": 7.0,
        "severity": "HIGH",
        "description": "Flaw in cgroup v1 release_agent allows container escape to host.",
        "fix_commit": "3007098494e3aa7eef8f0d73eabe7b691f9d6200",
        "patch_indicator": ["kernel/cgroup/cgroup-v1.c", "release_agent"],
        "thai_detail": (
            "ช่องโหว่อยู่ใน cgroup v1 release_agent ของ Linux Kernel\n"
            "     release_agent คือ Script ที่รันเมื่อ Process กลุ่มหนึ่งสิ้นสุด\n"
            "     ผู้โจมตีใน Container สามารถแก้ไข release_agent\n"
            "     เพื่อรันคำสั่งบน Host โดยตรง ทำให้หลุดออกจาก Container ได้\n"
            "     อันตรายมากสำหรับระบบ Docker, Kubernetes, และ LXC"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.17.1 ขึ้นไป\n"
            "     2. ใช้ cgroup v2 แทน cgroup v1 (ปลอดภัยกว่า):\n"
            "        เพิ่ม 'systemd.unified_cgroup_hierarchy=1' ใน Kernel Parameter\n"
            "     3. รัน Container ด้วย --privileged=false (ค่า Default)\n"
            "     4. ใช้ Seccomp Profile และ AppArmor/SELinux บน Container\n"
            "     5. ตรวจสอบ release_agent: cat /sys/fs/cgroup/release_agent"
        )
    },
    {
        "cve": "CVE-2022-25636",
        "name": "Netfilter Heap OOB in nft_fwd_dup",
        "category": "Container",
        "affected_min": "5.4",
        "affected_max": "5.16.12",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Heap OOB read/write in nft_fwd_dup_netdev_offload() — exploitable for container escape.",
        "fix_commit": "fdb3b8f4714e7b0339a91a2a067a0fe8d0e67c42",
        "patch_indicator": ["net/netfilter/nft_fwd_dup.c"],
        "thai_detail": (
            "ช่องโหว่อยู่ในฟังก์ชัน nft_fwd_dup_netdev_offload() ของ nft_fwd_dup.c\n"
            "     เกิด Heap OOB Read/Write เมื่อประมวลผล Netdev Offload Rules\n"
            "     ผู้โจมตีสามารถใช้ประโยชน์เพื่อ Escape ออกจาก Container\n"
            "     ไปยัง Host และยกระดับสิทธิ์เป็น root บน Host ได้\n"
            "     อันตรายมากในสภาพแวดล้อม Multi-Tenant Cloud"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 5.16.13 ขึ้นไป\n"
            "     2. ปิด Netdev Offload ถ้าไม่จำเป็น\n"
            "     3. จำกัด CAP_NET_ADMIN ภายใน Container อย่างเข้มงวด\n"
            "     4. ใช้ Kata Containers หรือ gVisor สำหรับการแยก Container แบบ Strong Isolation\n"
            "     5. ตรวจสอบ Network Driver ที่ใช้ว่ารองรับ Offload หรือไม่"
        )
    },
    # ── CVSS Critical ──
    {
        "cve": "CVE-2017-5753",
        "name": "Spectre v1",
        "category": "CPU Speculative",
        "affected_min": "2.6.0",
        "affected_max": "4.15.0",
        "cvss": 5.6,
        "severity": "MEDIUM",
        "description": "Bounds check bypass via speculative execution allows information disclosure.",
        "patch_indicator": [],
        "thai_detail": (
            "ช่องโหว่ Spectre v1 เป็นปัญหาระดับ Hardware ใน CPU สมัยใหม่\n"
            "     CPU ทำการ Speculative Execution (คาดเดาและรันโค้ดล่วงหน้า)\n"
            "     ผู้โจมตีสามารถหลอก CPU ให้อ่านข้อมูลจาก Memory ที่ไม่มีสิทธิ์\n"
            "     แล้วใช้ Cache Timing Attack เพื่อดึงข้อมูลนั้น เช่น Password, Key\n"
            "     ส่งผลต่อ CPU ของ Intel, AMD, ARM เกือบทุกรุ่นที่ผลิตหลังปี 1995"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel และเปิด Mitigation (IBRS, IBPB, STIBP):\n"
            "        grep . /sys/devices/system/cpu/vulnerabilities/*\n"
            "     2. อัปเดต CPU Microcode (intel-microcode / amd64-microcode)\n"
            "     3. เปิด Retpoline Compiler Mitigation (ค่า Default บน Kernel ใหม่)\n"
            "     4. บน VM/Cloud: ใช้ CPU ที่รองรับ Enhanced IBRS\n"
            "     5. ยอมรับว่าอาจมีผลต่อ Performance 5-30% บน Workload บางประเภท"
        )
    },
    {
        "cve": "CVE-2017-5754",
        "name": "Meltdown",
        "category": "CPU Speculative",
        "affected_min": "2.6.0",
        "affected_max": "4.15.0",
        "cvss": 5.6,
        "severity": "MEDIUM",
        "description": "Rogue data cache load via speculative execution allows kernel memory read from userspace.",
        "patch_indicator": [],
        "thai_detail": (
            "ช่องโหว่ Meltdown รุนแรงกว่า Spectre v1 เพราะอนุญาตให้\n"
            "     Userspace Process อ่าน Kernel Memory ได้โดยตรง\n"
            "     ใช้ Speculative Execution ที่ CPU ทำก่อนตรวจสอบ Permission\n"
            "     ข้อมูลที่รั่วได้ เช่น Kernel Stack, Password Hash, Private Key\n"
            "     แก้ไขด้วย KPTI (Kernel Page-Table Isolation) ซึ่งอาจลด Performance"
        ),
        "thai_mitigation": (
            "1. อัปเดต Kernel เป็น 4.15+ ที่มี KPTI (PTI) เปิดอยู่\n"
            "        ตรวจสอบ: cat /sys/devices/system/cpu/vulnerabilities/meltdown\n"
            "     2. อัปเดต CPU Microcode ให้เป็นเวอร์ชันล่าสุด\n"
            "     3. บน VM: ตรวจสอบว่า Hypervisor รองรับ Mitigation แล้วหรือยัง\n"
            "     4. ปิด Hyperthreading ถ้าต้องการความปลอดภัยสูงสุด (ลด Performance ~50%)\n"
            "     5. ใช้ Hardware รุ่นใหม่ที่ Fix ช่องโหว่ใน Silicon โดยตรง"
        )
    },
]

# ==============================
# Severity Helpers
# ==============================
SEVERITY_COLOR = {
    "CRITICAL": Color.BG_RED + Color.BOLD,
    "HIGH":     Color.RED + Color.BOLD,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.GREEN,
    "NONE":     Color.GRAY,
}

def severity_from_cvss(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"

def severity_badge(sev):
    color = SEVERITY_COLOR.get(sev, Color.GRAY)
    return f"{color} {sev} {Color.RESET}"

def cvss_bar(score, width=20):
    filled = int((score / 10.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 7:
        color = Color.RED
    elif score >= 4:
        color = Color.YELLOW
    else:
        color = Color.GREEN
    return f"{color}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"

# ==============================
# System Information
# ==============================
def get_kernel_version():
    full = platform.uname().release
    base = full.split("-")[0]
    return base, full

def get_distro():
    try:
        result = subprocess.run(["lsb_release", "-d"], capture_output=True, text=True)
        return result.stdout.strip().replace("Description:", "").strip()
    except:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        return line.split("=")[1].strip().strip('"')
        except:
            return "Unknown"

def get_hostname():
    return platform.node()

def get_arch():
    return platform.machine()

# ==============================
# Backport Patch Detection
# ==============================
def check_backport_via_sysfs(cve_entry):
    """
    Try to detect if a patch has been backported by distros
    using /proc/sys or changelog heuristics.
    """
    indicators = cve_entry.get("patch_indicator", [])
    if not indicators:
        return None  # Cannot determine

    # Method 1: Check kernel config (some distros expose patch notes)
    try:
        result = subprocess.run(
            ["grep", "-r"] + indicators[:1] + ["/proc/version"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            return True
    except:
        pass

    # Method 2: Check package changelog (Debian/Ubuntu)
    try:
        pkg_result = subprocess.run(
            ["dpkg", "-l", "linux-image*"],
            capture_output=True, text=True, timeout=3
        )
        if pkg_result.returncode == 0:
            cve_id = cve_entry["cve"]
            changelog = subprocess.run(
                ["apt-get", "changelog", f"linux-image-$(uname -r)", "--no-download"],
                capture_output=True, text=True, timeout=5
            )
            if cve_id in changelog.stdout:
                return True
    except:
        pass

    # Method 3: Check RPM changelog (RHEL/CentOS/Fedora)
    try:
        rpm_result = subprocess.run(
            ["rpm", "-q", "--changelog", "kernel"],
            capture_output=True, text=True, timeout=5
        )
        if rpm_result.returncode == 0:
            cve_id = cve_entry["cve"]
            if cve_id in rpm_result.stdout:
                return True
    except:
        pass

    return None  # Unknown

def check_kpatch(cve_id):
    """Check if kpatch live-patch covers this CVE"""
    try:
        result = subprocess.run(
            ["kpatch", "list"],
            capture_output=True, text=True, timeout=3
        )
        if cve_id.replace("-", "_").lower() in result.stdout.lower():
            return True
    except:
        pass
    return False

# ==============================
# Version Range Match
# ==============================
def is_vulnerable(current, min_v, max_v):
    try:
        cur = version.parse(current)
        return version.parse(min_v) <= cur <= version.parse(max_v)
    except:
        return False

# ==============================
# Core Scan
# ==============================
def scan_kernel(kernel_ver):
    findings = []

    for entry in CVE_DB:
        if is_vulnerable(kernel_ver, entry["affected_min"], entry["affected_max"]):
            # Check backport
            patched_via_backport = check_backport_via_sysfs(entry)
            patched_via_kpatch   = check_kpatch(entry["cve"])

            patched = patched_via_backport or patched_via_kpatch
            status  = "PATCHED" if patched else ("UNKNOWN" if patched_via_backport is None else "VULNERABLE")

            findings.append({
                "cve":         entry["cve"],
                "name":        entry["name"],
                "category":    entry["category"],
                "severity":    entry["severity"],
                "cvss":        entry["cvss"],
                "description": entry["description"],
                "status":      status,
                "backport_detected": patched_via_backport,
                "kpatch_detected":   patched_via_kpatch,
                "note":        entry.get("note", ""),
                "thai_detail":      entry.get("thai_detail", ""),
                "thai_mitigation":  entry.get("thai_mitigation", "")
            })

    return findings

# ==============================
# Pretty Print Report
# ==============================
def print_banner():
    banner = f"""
{Color.CYAN}{Color.BOLD}
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
{Color.RESET}{Color.GRAY}         Kernel CVE Scanner  |  "Conquer Vulnerabilities"{Color.RESET}
"""
    print(banner)

def print_sysinfo(kernel_full, distro, hostname, arch):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ SYSTEM INFORMATION ════════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname   :')} {c(Color.WHITE, hostname)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro     :')} {c(Color.WHITE, distro)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Kernel     :')} {c(Color.YELLOW + Color.BOLD, kernel_full)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch       :')} {c(Color.WHITE, arch)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp  :')} {c(Color.WHITE, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN + Color.BOLD, "  ╚═══════════════════════════════════════════════════════════╝\n"))

def print_thai_detail(finding):
    """Print Thai vulnerability detail and mitigation block"""
    thai_detail     = finding.get("thai_detail", "")
    thai_mitigation = finding.get("thai_mitigation", "")

    if thai_detail:
        print(f"     {c(Color.BLUE + Color.BOLD, '📋 รายละเอียดช่องโหว่ (ภาษาไทย):')}")
        print(f"     {c(Color.CYAN,  '   ' + thai_detail)}")

    if thai_mitigation:
        print(f"     {c(Color.GREEN + Color.BOLD, '🛡  วิธีป้องกัน/แก้ไข:')}")
        print(f"     {c(Color.GREEN, '   ' + thai_mitigation)}")

def print_findings(findings):
    if not findings:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No vulnerabilities matched for this kernel version.\n"))
        return

    # Group by status
    vulnerable = [f for f in findings if f["status"] == "VULNERABLE"]
    unknown    = [f for f in findings if f["status"] == "UNKNOWN"]
    patched    = [f for f in findings if f["status"] == "PATCHED"]

    def print_group(group, label, label_color):
        if not group:
            return
        print(f"\n{label_color}{Color.BOLD}  ── {label} ({len(group)}) ──{Color.RESET}")
        for f in group:
            icon = "✖" if f["status"] == "VULNERABLE" else ("?" if f["status"] == "UNKNOWN" else "✔")
            icon_color = Color.RED if f["status"] == "VULNERABLE" else (Color.YELLOW if f["status"] == "UNKNOWN" else Color.GREEN)
            sev_badge = severity_badge(f["severity"])
            print(f"\n  {c(icon_color, icon)}  {c(Color.BOLD + Color.WHITE, f['cve'])}  {c(Color.MAGENTA, f['name'])}  {sev_badge}")
            print(f"     {c(Color.GRAY, 'Category   :')} {c(Color.CYAN, f['category'])}")
            print(f"     {c(Color.GRAY, 'CVSS Score :')} {cvss_bar(f['cvss'])}")
            print(f"     {c(Color.GRAY, 'Description:')} {f['description'][:80]}{'...' if len(f['description'])>80 else ''}")
            if f["note"]:
                print(f"     {c(Color.YELLOW, '⚠  Note     :')} {f['note']}")
            if f["backport_detected"] is True:
                print(f"     {c(Color.GREEN, '✔  Backport : Patch detected via package manager')}")
            elif f["kpatch_detected"]:
                print(f"     {c(Color.GREEN, '✔  kpatch   : Live patch detected')}")
            elif f["status"] == "UNKNOWN":
                print(f"     {c(Color.YELLOW, '?  Backport : Could not verify — manual check recommended')}")

            # ── NEW: Thai detail + mitigation ──
            print()
            print_thai_detail(f)
            print(f"     {c(Color.GRAY, '─' * 60)}")

    print_group(vulnerable, "VULNERABLE", Color.RED)
    print_group(unknown,    "UNVERIFIED (may be patched by distro)", Color.YELLOW)
    print_group(patched,    "PATCHED",    Color.GREEN)

def print_summary(findings, kernel_ver):
    total      = len(findings)
    vulnerable = sum(1 for f in findings if f["status"] == "VULNERABLE")
    unknown    = sum(1 for f in findings if f["status"] == "UNKNOWN")
    patched    = sum(1 for f in findings if f["status"] == "PATCHED")
    max_cvss   = max((f["cvss"] for f in findings), default=0)
    overall    = severity_from_cvss(max_cvss)

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ SCAN SUMMARY ════════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Kernel Scanned  :')} {c(Color.YELLOW + Color.BOLD, kernel_ver)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'CVEs in Database:')} {c(Color.WHITE, str(len(CVE_DB)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Matches   :')} {c(Color.WHITE, str(total))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,  '  Vulnerable     :')} {c(Color.RED + Color.BOLD, str(vulnerable))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  Unverified     :')} {c(Color.YELLOW + Color.BOLD, str(unknown))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GREEN, '  Patched        :')} {c(Color.GREEN + Color.BOLD, str(patched))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk    :')} {severity_badge(overall)}  {c(Color.GRAY,'CVSS')} {c(Color.BOLD, f'{max_cvss:.1f}')}")
    print(c(Color.CYAN + Color.BOLD,  '  ╚═══════════════════════════════════════════════════════════╝\n'))

# ==============================
# Save Report
# ==============================
def save_report(findings, kernel_ver, kernel_full, distro):
    report = {
        "tool": "COSVINTE",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": get_hostname(),
            "distro": distro,
            "kernel_version": kernel_ver,
            "kernel_full": kernel_full,
            "arch": get_arch()
        },
        "summary": {
            "total_cve_db": len(CVE_DB),
            "total_matches": len(findings),
            "vulnerable": sum(1 for f in findings if f["status"] == "VULNERABLE"),
            "unverified": sum(1 for f in findings if f["status"] == "UNKNOWN"),
            "patched": sum(1 for f in findings if f["status"] == "PATCHED"),
            "overall_cvss": max((f["cvss"] for f in findings), default=0),
            "overall_severity": severity_from_cvss(max((f["cvss"] for f in findings), default=0))
        },
        "findings": findings
    }

    filename = f"cosvinte_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    return filename

# ==============================
# MAIN
# ==============================
def main():
    print_banner()

    kernel_ver, kernel_full = get_kernel_version()
    distro   = get_distro()
    hostname = get_hostname()
    arch     = get_arch()

    print_sysinfo(kernel_full, distro, hostname, arch)

    print(c(Color.CYAN, "  [*] Scanning against CVE database..."), end="", flush=True)
    findings = scan_kernel(kernel_ver)
    print(c(Color.GREEN, " done\n"))

    print_findings(findings)
    print_summary(findings, kernel_ver)

    filename = save_report(findings, kernel_ver, kernel_full, distro)
    print(c(Color.GRAY, f"  Report saved → {c(Color.WHITE + Color.BOLD, filename)}\n"))

if __name__ == "__main__":
    main()
