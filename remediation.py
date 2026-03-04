#!/usr/bin/env python3
"""
  COSVINTE — Remediation Roadmap
  สร้างแผนการแก้ไขที่ prioritize ตาม impact และ effort
  พร้อม command พร้อมรันและ timeline แนะนำ
"""

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
    BG_GREEN = "\033[42m"
    BLUE    = "\033[94m"

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

# ==============================
# Remediation Action Templates
# map finding patterns → fix actions
# ==============================
REMEDIATION_TEMPLATES = {

    # ── Capabilities ──────────────────────────────────────────
    "cap_setuid_interpreter": {
        "title":    "ลบ cap_setuid ออกจาก Interpreter",
        "effort":   "LOW",    # เวลาที่ใช้: LOW=<1h, MEDIUM=1d, HIGH=1w
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-003"],
        "commands": [
            "# ตรวจสอบก่อน",
            "getcap -r / 2>/dev/null | grep -E 'python|perl|ruby|node'",
            "# ลบ capability",
            "setcap -r /usr/bin/python3  # ปรับ path ตามที่พบ",
            "setcap -r /usr/bin/perl",
            "# ยืนยันผล",
            "getcap /usr/bin/python3   # ต้องไม่มี output",
        ],
        "verify": "getcap -r / 2>/dev/null | grep -E 'setuid|sys_admin'",
        "description_th": "ลบ cap_setuid/cap_sys_admin ออกจาก scripting interpreter ทุกตัว เพราะเป็น one-shot privesc",
    },

    "cap_sys_admin": {
        "title":    "ลบ cap_sys_admin ออกจาก binary",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-003", "CHAIN-007"],
        "commands": [
            "# ค้นหา binary ที่มี cap_sys_admin",
            "getcap -r / 2>/dev/null | grep sys_admin",
            "# ลบออก",
            "setcap -r <binary_path>",
            "# ถ้าจำเป็นต้องใช้ ให้ใช้ systemd service restriction แทน",
            "# ใน unit file: AmbientCapabilities=CAP_NET_ADMIN  (ระบุเฉพาะที่ต้องการ)",
        ],
        "verify": "getcap -r / 2>/dev/null | grep sys_admin  # ต้องไม่มี output",
        "description_th": "cap_sys_admin เทียบเท่า root ต้องลบออกทันที ไม่มีกรณีใดที่ควรให้ binary ทั่วไปมี capability นี้",
    },

    "cap_dac_override": {
        "title":    "ลบ cap_dac_override และใช้ ACL แทน",
        "effort":   "MEDIUM",
        "impact":   "HIGH",
        "timeline": "week1",
        "breaks_chains": ["CHAIN-007"],
        "commands": [
            "setcap -r <binary_path>",
            "# ใช้ ACL เพื่อให้สิทธิ์เฉพาะไฟล์ที่ต้องการแทน",
            "setfacl -m u:<service_user>:r /path/to/specific/file",
            "# ล็อคไฟล์ sensitive ด้วย immutable flag",
            "chattr +i /etc/passwd /etc/shadow /etc/sudoers",
        ],
        "verify": "lsattr /etc/passwd | grep -i immutable",
        "description_th": "cap_dac_override ข้ามทุก permission check ควรใช้ ACL ที่เฉพาะเจาะจงแทน",
    },

    # ── Cron ──────────────────────────────────────────────────
    "cron_writable_script": {
        "title":    "แก้ไข Permission ของ Cron Script",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-001", "CHAIN-002"],
        "commands": [
            "# หา cron script ที่เขียนได้",
            "find /etc/cron* /var/spool/cron -type f -perm -o+w 2>/dev/null",
            "# แก้ไข permission",
            "chmod 750 <script_path>",
            "chown root:root <script_path>",
            "# ตรวจสอบ cron job ทั้งหมดที่รันเป็น root",
            "crontab -l && for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null && echo \"--- $u ---\"; done",
        ],
        "verify": "find /etc/cron* -perm -o+w 2>/dev/null  # ต้องไม่มี output",
        "description_th": "ทุก script ที่ cron รันเป็น root ต้อง owned โดย root และเขียนได้เฉพาะ root เท่านั้น",
    },

    "cron_log_writable": {
        "title":    "แก้ไข Permission ของ Cron Log Directory",
        "effort":   "LOW",
        "impact":   "HIGH",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-001"],
        "commands": [
            "chmod 755 /var/log/cron",
            "chown root:adm /var/log/cron",
            "# ตรวจสอบ logrotate config",
            "grep -r 'create' /etc/logrotate.d/cron",
        ],
        "verify": "ls -ld /var/log/cron  # ต้องเห็น drwxr-xr-x",
        "description_th": "Log directory ที่เขียนได้โดยทุกคนเปิดช่องทาง symlink attack ผ่าน logrotate",
    },

    # ── PATH Hijack ───────────────────────────────────────────
    "path_writable_dir": {
        "title":    "แก้ไข Permission ของ PATH Directory",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-002"],
        "commands": [
            "# หา directory ใน PATH ที่เขียนได้",
            "for p in $(echo $PATH | tr ':' '\\n'); do ls -ld $p 2>/dev/null; done | grep -E '^d.......w'",
            "# แก้ไข permission",
            "chmod o-w <writable_path_dir>",
            "chown root:root <writable_path_dir>",
            "# ตรวจสอบว่า PATH ไม่มี relative entry",
            "echo $PATH | tr ':' '\\n' | grep -E '^\\.' ",
        ],
        "verify": "for p in $(echo $PATH | tr ':' '\\n'); do ls -ld $p; done | grep -v '^drwxr-xr-x'",
        "description_th": "PATH directory ที่เขียนได้เปิดช่องให้ hijack command ที่รันโดย cron หรือ SUID binary",
    },

    "path_relative_entry": {
        "title":    "ลบ Relative Entry ออกจาก PATH",
        "effort":   "LOW",
        "impact":   "HIGH",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-002", "CHAIN-008"],
        "commands": [
            "# ตรวจสอบ PATH ปัจจุบัน",
            "echo $PATH",
            "# ลบ '.' หรือ relative path ออกจาก /etc/environment, ~/.bashrc, ~/.profile",
            "grep -n 'PATH' /etc/environment ~/.bashrc ~/.profile /etc/profile",
            "# แก้ไข: ตัดส่วนที่เป็น relative ออก แล้วรัน",
            "source ~/.bashrc",
        ],
        "verify": "echo $PATH | tr ':' '\\n' | grep -E '^\\.'  # ต้องไม่มี output",
        "description_th": "การมี '.' หรือ relative path ใน PATH ทำให้ hijack คำสั่งในฐานะ user ปัจจุบัน",
    },

    # ── Writable Paths ────────────────────────────────────────
    "writable_passwd": {
        "title":    "แก้ไข Permission ของ /etc/passwd และ /etc/shadow",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-004"],
        "commands": [
            "chmod 644 /etc/passwd",
            "chmod 640 /etc/shadow",
            "chown root:root /etc/passwd",
            "chown root:shadow /etc/shadow",
            "# ล็อคด้วย immutable flag",
            "chattr +i /etc/passwd /etc/shadow",
            "# ตรวจสอบ",
            "ls -la /etc/passwd /etc/shadow",
        ],
        "verify": "ls -la /etc/passwd | grep -E '^-rw-r--r--'",
        "description_th": "/etc/passwd ที่เขียนได้โดยทุกคนคือ immediate root — ต้องแก้ทันที",
    },

    "writable_sensitive_dir": {
        "title":    "แก้ไข Permission ของ Directory ที่ Sensitive",
        "effort":   "MEDIUM",
        "impact":   "HIGH",
        "timeline": "week1",
        "breaks_chains": ["CHAIN-001", "CHAIN-006"],
        "commands": [
            "# หา world-writable directories ใน system path",
            "find /etc /usr /bin /sbin -type d -perm -o+w 2>/dev/null",
            "# แก้ไขแต่ละ directory",
            "chmod o-w <directory>",
            "# ใช้ audit เพื่อ monitor การเปลี่ยนแปลง",
            "auditctl -w /etc -p wa -k etc_changes",
        ],
        "verify": "find /etc /usr /bin /sbin -type d -perm -o+w 2>/dev/null  # ต้องไม่มี output",
        "description_th": "Directory ที่เขียนได้ใน system path เปิดช่องให้ hijack library หรือ binary",
    },

    # ── Kernel ────────────────────────────────────────────────
    "kernel_outdated": {
        "title":    "อัปเดต Kernel เป็นเวอร์ชันล่าสุด",
        "effort":   "HIGH",
        "impact":   "CRITICAL",
        "timeline": "week2",
        "breaks_chains": ["CHAIN-005"],
        "commands": [
            "# Ubuntu/Debian",
            "apt update && apt upgrade linux-image-$(uname -r)",
            "# RHEL/CentOS",
            "yum update kernel",
            "# ตรวจสอบเวอร์ชันหลัง reboot",
            "uname -r",
            "# ถ้า reboot ไม่ได้ ใช้ kpatch (kernel live patching)",
            "kpatch list",
        ],
        "verify": "uname -r  # ตรวจสอบว่าเป็น version ใหม่",
        "description_th": "Kernel ที่มีช่องโหว่ต้องอัปเดตทันที ถ้า reboot ไม่ได้ให้ใช้ kpatch",
    },

    "aslr_disabled": {
        "title":    "เปิดใช้งาน ASLR",
        "effort":   "LOW",
        "impact":   "HIGH",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-005"],
        "commands": [
            "# เปิด ASLR ทันที (ไม่ต้อง reboot)",
            "sysctl -w kernel.randomize_va_space=2",
            "# ทำให้ถาวร",
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf",
            "sysctl -p",
        ],
        "verify": "cat /proc/sys/kernel/randomize_va_space  # ต้องเป็น 2",
        "description_th": "ASLR ที่ปิดทำให้ exploit kernel และ heap ง่ายขึ้นมาก เปิดได้ทันทีโดยไม่ต้อง reboot",
    },

    # ── General Hardening ─────────────────────────────────────
    "enable_apparmor": {
        "title":    "เปิดใช้งาน AppArmor/SELinux",
        "effort":   "HIGH",
        "impact":   "HIGH",
        "timeline": "week2",
        "breaks_chains": [],
        "commands": [
            "# Ubuntu: เปิด AppArmor",
            "systemctl enable apparmor && systemctl start apparmor",
            "aa-status",
            "# RHEL/CentOS: เปิด SELinux",
            "setenforce 1",
            "sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config",
        ],
        "verify": "aa-status --enabled || getenforce",
        "description_th": "MAC framework ลดความเสี่ยงรวมได้อย่างมาก ควรเปิดใช้งาน",
    },

    "ptrace_restrict": {
        "title":    "จำกัดสิทธิ์ ptrace",
        "effort":   "LOW",
        "impact":   "MEDIUM",
        "timeline": "week1",
        "breaks_chains": [],
        "commands": [
            "sysctl -w kernel.yama.ptrace_scope=1",
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.conf",
            "sysctl -p",
        ],
        "verify": "cat /proc/sys/kernel/yama/ptrace_scope  # ต้องเป็น 1 หรือ 2",
        "description_th": "ptrace_scope=0 อนุญาตให้ inject code เข้า process ใดก็ได้ ควรเปลี่ยนเป็น 1",
    },
}

# ==============================
# Timeline Definitions
# ==============================
TIMELINES = {
    "immediate": {"label": "ทำทันที (วันนี้)",    "color": Color.BG_RED  + Color.BOLD, "order": 0},
    "week1":     {"label": "ภายใน 1 สัปดาห์",     "color": Color.RED    + Color.BOLD, "order": 1},
    "week2":     {"label": "ภายใน 2 สัปดาห์",     "color": Color.ORANGE + Color.BOLD, "order": 2},
    "month1":    {"label": "ภายใน 1 เดือน",        "color": Color.YELLOW,             "order": 3},
}

EFFORT_LABELS = {
    "LOW":    c(Color.GREEN  + Color.BOLD, "LOW    (< 1 ชั่วโมง)"),
    "MEDIUM": c(Color.YELLOW + Color.BOLD, "MEDIUM (< 1 วัน)    "),
    "HIGH":   c(Color.RED    + Color.BOLD, "HIGH   (> 1 วัน)    "),
}

# ==============================
# Roadmap Builder
# ==============================
def _finding_to_remediation_keys(finding: dict, scanner: str) -> list:
    """Map finding → remediation template keys"""
    keys = []

    if scanner == "caps":
        cap = str(finding.get("capability", "")).lower()
        is_interp = finding.get("is_interpreter", False)
        if is_interp and ("setuid" in cap or "sys_admin" in cap):
            keys.append("cap_setuid_interpreter")
        elif "sys_admin" in cap:
            keys.append("cap_sys_admin")
        elif "dac_override" in cap or "dac_read_search" in cap:
            keys.append("cap_dac_override")

    elif scanner == "cron":
        cat = str(finding.get("category", "")).lower()
        if "permission" in cat or "file" in cat:
            keys.append("cron_writable_script")
            keys.append("cron_log_writable")
        else:
            keys.append("cron_writable_script")

    elif scanner == "path":
        origin = finding.get("_origin", "")
        if finding.get("world_writable"):
            keys.append("path_writable_dir")
        if finding.get("relative"):
            keys.append("path_relative_entry")
        if finding.get("dangerous") or origin == "suid":
            keys.append("path_writable_dir")

    elif scanner == "writable":
        path = str(finding.get("path", ""))
        if "/etc/passwd" in path or "/etc/shadow" in path:
            keys.append("writable_passwd")
        else:
            keys.append("writable_sensitive_dir")

    elif scanner == "kernel":
        status = finding.get("status", "")
        if status in ("VULNERABLE", "UNKNOWN"):
            keys.append("kernel_outdated")
            keys.append("aslr_disabled")

    return keys

def build_roadmap(scored_reports: dict, chains: list) -> list:
    """
    รับ scored_reports และ chains
    คืน list ของ remediation actions เรียงตาม priority
    """
    seen_keys = set()
    actions   = []

    # รวบรวม chains ที่แต่ละ action แก้ได้
    chain_broken_by = {}
    for chain in chains:
        for key, tmpl in REMEDIATION_TEMPLATES.items():
            if chain["id"] in tmpl.get("breaks_chains", []):
                chain_broken_by.setdefault(key, []).append(chain["id"])

    # สร้าง actions จาก findings
    for scanner, report in scored_reports.items():
        if scanner.startswith("_") or not report:
            continue
        for f_key in ("findings", "writable_paths", "path_analysis"):
            for finding in report.get(f_key, []):
                rem_keys = _finding_to_remediation_keys(finding, scanner)
                for rk in rem_keys:
                    if rk in seen_keys:
                        continue
                    tmpl = REMEDIATION_TEMPLATES.get(rk)
                    if not tmpl:
                        continue
                    seen_keys.add(rk)

                    cs  = finding.get("context_scoring", {})
                    adj = cs.get("adjusted_score", 0)

                    actions.append({
                        "key":            rk,
                        "title":          tmpl["title"],
                        "description_th": tmpl["description_th"],
                        "effort":         tmpl["effort"],
                        "impact":         tmpl["impact"],
                        "timeline":       tmpl["timeline"],
                        "commands":       tmpl["commands"],
                        "verify":         tmpl["verify"],
                        "breaks_chains":  chain_broken_by.get(rk, tmpl.get("breaks_chains", [])),
                        "trigger_score":  adj,
                        "trigger_finding": (finding.get("cve") or finding.get("binary") or finding.get("path") or ""),
                    })

    # เพิ่ม general hardening ถ้ายังไม่มี
    context_factors = scored_reports.get("_context_factors", {})
    if context_factors.get("aslr", {}).get("status") != "enabled":
        if "aslr_disabled" not in seen_keys:
            actions.append({**REMEDIATION_TEMPLATES["aslr_disabled"],
                            "key": "aslr_disabled", "trigger_score": 0, "trigger_finding": "ASLR disabled",
                            "breaks_chains": chain_broken_by.get("aslr_disabled", [])})

    if not context_factors.get("mac_enforcement", {}).get("active"):
        if "enable_apparmor" not in seen_keys:
            actions.append({**REMEDIATION_TEMPLATES["enable_apparmor"],
                            "key": "enable_apparmor", "trigger_score": 0, "trigger_finding": "No MAC",
                            "breaks_chains": []})

    # เรียง: immediate ก่อน, แล้ว impact, แล้ว effort (LOW ก่อน)
    tl_order     = {t: v["order"] for t, v in TIMELINES.items()}
    impact_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    effort_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

    actions.sort(key=lambda x: (
        tl_order.get(x["timeline"], 9),
        impact_order.get(x["impact"], 9),
        effort_order.get(x["effort"], 9),
    ))
    return actions

# ==============================
# Pretty Printing
# ==============================
def print_banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝{Color.RESET}
{Color.GRAY}  Remediation Roadmap  |  "Conquer Vulnerabilities"{Color.RESET}
""")

def print_roadmap(actions: list):
    if not actions:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  ไม่พบ remediation actions ที่จำเป็น\n"))
        return

    # Group by timeline
    grouped = {}
    for a in actions:
        tl = a["timeline"]
        grouped.setdefault(tl, []).append(a)

    print(c(Color.CYAN + Color.BOLD, f"\n  ╔══ REMEDIATION ROADMAP ({len(actions)} actions) ════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, 'เรียงตาม: timeline → impact → effort (LOW effort ก่อน)')}")
    print(c(Color.CYAN + Color.BOLD,  "  ╚══════════════════════════════════════════════════════════════╝\n"))

    global_idx = 1

    for tl_key in ("immediate", "week1", "week2", "month1"):
        group = grouped.get(tl_key, [])
        if not group:
            continue

        tl_info  = TIMELINES[tl_key]
        tl_label = tl_info["label"]
        tl_line  = f"══ {tl_label} ({len(group)} actions) ══════════════════════════════"
        print(f"\n  {c(tl_info['color'], tl_line)}")

        for action in group:
            impact_col = {
                "CRITICAL": Color.BG_RED + Color.BOLD,
                "HIGH":     Color.RED + Color.BOLD,
                "MEDIUM":   Color.YELLOW + Color.BOLD,
                "LOW":      Color.GREEN,
            }.get(action["impact"], Color.GRAY)

            print(f"\n  {c(Color.CYAN + Color.BOLD, f'  [{global_idx:02d}]')} {c(Color.WHITE + Color.BOLD, action['title'])}")
            imp_badge = c(impact_col, f" {action['impact']} ")
            eff_label = EFFORT_LABELS.get(action['effort'], action['effort'])
            print(f"        Impact  : {imp_badge}  │  Effort : {eff_label}")

            # Trigger
            if action.get("trigger_finding"):
                print(f"        Trigger : {c(Color.MAGENTA, str(action['trigger_finding'])[:60])}")

            # Chains ที่จะ break
            if action["breaks_chains"]:
                chains_str = c(Color.ORANGE + Color.BOLD, ", ".join(action["breaks_chains"]))
                print(f"        Breaks  : ⚡ {chains_str}  {c(Color.GRAY, '(attack chains)')}")

            # Description Thai
            print(f"        {c(Color.CYAN, '📋 ')} {c(Color.WHITE, action['description_th'])}")

            # Commands
            print(f"        {c(Color.YELLOW + Color.BOLD, '💻 Commands:')}")
            for cmd in action["commands"]:
                if cmd.startswith("#"):
                    print(f"           {c(Color.GRAY, cmd)}")
                else:
                    print(f"           {c(Color.GREEN, '$')} {c(Color.WHITE, cmd)}")

            # Verify
            if action.get("verify"):
                print(f"        {c(Color.BLUE, '✔  Verify   :')} {c(Color.GRAY, action['verify'])}")

            global_idx += 1

def print_summary(actions: list, chains: list):
    immediate = sum(1 for a in actions if a["timeline"] == "immediate")
    week1     = sum(1 for a in actions if a["timeline"] == "week1")
    week2_plus = sum(1 for a in actions if a["timeline"] in ("week2", "month1"))

    # chains ที่ถูก break โดย actions ทั้งหมด
    all_broken = set()
    for a in actions:
        all_broken.update(a.get("breaks_chains", []))
    chains_broken = len(all_broken)
    chains_total  = len(chains)

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ ROADMAP SUMMARY ══════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Actions          :')} {c(Color.WHITE + Color.BOLD, str(len(actions)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.BG_RED  + Color.BOLD,'  ทำทันที              :')} {c(Color.RED   + Color.BOLD, str(immediate))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.ORANGE  + Color.BOLD,'  ภายใน 1 สัปดาห์    :')} {c(Color.ORANGE+ Color.BOLD, str(week1))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,              '  ภายใน 2+ สัปดาห์  :')} {c(Color.YELLOW+ Color.BOLD, str(week2_plus))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Attack Chains Broken   :')} "
          f"{c(Color.GREEN + Color.BOLD, str(chains_broken))} / {c(Color.WHITE, str(chains_total))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'💡 เริ่มจาก [01] ก่อน — action แรกสุดมี impact สูงสุด')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'   ต่อยอดด้วย Context-Aware Scoring เพื่อดู risk จริง')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚══════════════════════════════════════════════════════════════╝\n'))

def roadmap_to_report_dict(actions: list) -> list:
    """แปลง actions เป็น list ที่ JSON serializable"""
    return [{k: v for k, v in a.items()} for a in actions]
