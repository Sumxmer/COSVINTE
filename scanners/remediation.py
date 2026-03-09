#!/usr/bin/env python3
"""
 COSVINTE — Remediation Roadmap
 prioritize impact effort
 command timeline 
"""

from datetime import datetime

from core.utils import (
    Color, c, severity_badge, print_banner as _print_banner,
)

# ==============================
# Remediation Action Templates
# map finding patterns → fix actions
# ==============================
REMEDIATION_TEMPLATES = {

    # ── Capabilities ──────────────────────────────────────────
    "cap_setuid_interpreter": {
        "title":    " cap_setuid Interpreter",
        "effort":   "LOW",    # : LOW=<1h, MEDIUM=1d, HIGH=1w
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-003"],
        "commands": [
            "# ",
            "getcap -r / 2>/dev/null | grep -E 'python|perl|ruby|node'",
            "# capability",
            "setcap -r /usr/bin/python3 # path ",
            "setcap -r /usr/bin/perl",
            "# ",
            "getcap /usr/bin/python3 # output",
        ],
        "verify": "getcap -r / 2>/dev/null | grep -E 'setuid|sys_admin'",
        "description_th": " cap_setuid/cap_sys_admin scripting interpreter one-shot privesc",
    },

    "cap_sys_admin": {
        "title":    " cap_sys_admin binary",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-003", "CHAIN-007"],
        "commands": [
            "# binary cap_sys_admin",
            "getcap -r / 2>/dev/null | grep sys_admin",
            "# ",
            "setcap -r <binary_path>",
            "# systemd service restriction ",
            "# unit file: AmbientCapabilities=CAP_NET_ADMIN ()",
        ],
        "verify": "getcap -r / 2>/dev/null | grep sys_admin # output",
        "description_th": "cap_sys_admin root binary capability ",
    },

    "cap_dac_override": {
        "title":    " cap_dac_override ACL ",
        "effort":   "MEDIUM",
        "impact":   "HIGH",
        "timeline": "week1",
        "breaks_chains": ["CHAIN-007"],
        "commands": [
            "setcap -r <binary_path>",
            "# ACL ",
            "setfacl -m u:<service_user>:r /path/to/specific/file",
            "# sensitive immutable flag",
            "chattr +i /etc/passwd /etc/shadow /etc/sudoers",
        ],
        "verify": "lsattr /etc/passwd | grep -i immutable",
        "description_th": "cap_dac_override permission check ACL ",
    },

    # ── Cron ──────────────────────────────────────────────────
    "cron_writable_script": {
        "title":    " Permission Cron Script",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-001", "CHAIN-002"],
        "commands": [
            "# cron script ",
            "find /etc/cron* /var/spool/cron -type f -perm -o+w 2>/dev/null",
            "# permission",
            "chmod 750 <script_path>",
            "chown root:root <script_path>",
            "# cron job root",
            "crontab -l && for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null && echo \"--- $u ---\"; done",
        ],
        "verify": "find /etc/cron* -perm -o+w 2>/dev/null # output",
        "description_th": " script cron root owned root root ",
    },

    "cron_log_writable": {
        "title":    " Permission Cron Log Directory",
        "effort":   "LOW",
        "impact":   "HIGH",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-001"],
        "commands": [
            "chmod 755 /var/log/cron",
            "chown root:adm /var/log/cron",
            "# logrotate config",
            "grep -r 'create' /etc/logrotate.d/cron",
        ],
        "verify": "ls -ld /var/log/cron # drwxr-xr-x",
        "description_th": "Log directory symlink attack logrotate",
    },

    # ── PATH Hijack ───────────────────────────────────────────
    "path_writable_dir": {
        "title":    " Permission PATH Directory",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-002"],
        "commands": [
            "# directory PATH ",
            "for p in $(echo $PATH | tr ':' '\\n'); do ls -ld $p 2>/dev/null; done | grep -E '^d.......w'",
            "# permission",
            "chmod o-w <writable_path_dir>",
            "chown root:root <writable_path_dir>",
            "# PATH relative entry",
            "echo $PATH | tr ':' '\\n' | grep -E '^\\.' ",
        ],
        "verify": "for p in $(echo $PATH | tr ':' '\\n'); do ls -ld $p; done | grep -v '^drwxr-xr-x'",
        "description_th": "PATH directory hijack command cron SUID binary",
    },

    "path_relative_entry": {
        "title":    " Relative Entry PATH",
        "effort":   "LOW",
        "impact":   "HIGH",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-002", "CHAIN-008"],
        "commands": [
            "# PATH ",
            "echo $PATH",
            "# '.' relative path /etc/environment, ~/.bashrc, ~/.profile",
            "grep -n 'PATH' /etc/environment ~/.bashrc ~/.profile /etc/profile",
            "# : relative ",
            "source ~/.bashrc",
        ],
        "verify": "echo $PATH | tr ':' '\\n' | grep -E '^\\.' # output",
        "description_th": " '.' relative path PATH hijack user ",
    },

    # ── Writable Paths ────────────────────────────────────────
    "writable_passwd": {
        "title":    " Permission /etc/passwd /etc/shadow",
        "effort":   "LOW",
        "impact":   "CRITICAL",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-004"],
        "commands": [
            "chmod 644 /etc/passwd",
            "chmod 640 /etc/shadow",
            "chown root:root /etc/passwd",
            "chown root:shadow /etc/shadow",
            "# immutable flag",
            "chattr +i /etc/passwd /etc/shadow",
            "# ",
            "ls -la /etc/passwd /etc/shadow",
        ],
        "verify": "ls -la /etc/passwd | grep -E '^-rw-r--r--'",
        "description_th": "/etc/passwd immediate root — ",
    },

    "writable_sensitive_dir": {
        "title":    " Permission Directory Sensitive",
        "effort":   "MEDIUM",
        "impact":   "HIGH",
        "timeline": "week1",
        "breaks_chains": ["CHAIN-001", "CHAIN-006"],
        "commands": [
            "# world-writable directories system path",
            "find /etc /usr /bin /sbin -type d -perm -o+w 2>/dev/null",
            "# directory",
            "chmod o-w <directory>",
            "# audit monitor ",
            "auditctl -w /etc -p wa -k etc_changes",
        ],
        "verify": "find /etc /usr /bin /sbin -type d -perm -o+w 2>/dev/null # output",
        "description_th": "Directory system path hijack library binary",
    },

    # ── Kernel ────────────────────────────────────────────────
    "kernel_outdated": {
        "title":    " Kernel ",
        "effort":   "HIGH",
        "impact":   "CRITICAL",
        "timeline": "week2",
        "breaks_chains": ["CHAIN-005"],
        "commands": [
            "# Ubuntu/Debian",
            "apt update && apt upgrade linux-image-$(uname -r)",
            "# RHEL/CentOS",
            "yum update kernel",
            "# reboot",
            "uname -r",
            "# reboot kpatch (kernel live patching)",
            "kpatch list",
        ],
        "verify": "uname -r # version ",
        "description_th": "Kernel reboot kpatch",
    },

    "aslr_disabled": {
        "title":    " ASLR",
        "effort":   "LOW",
        "impact":   "HIGH",
        "timeline": "immediate",
        "breaks_chains": ["CHAIN-005"],
        "commands": [
            "# ASLR ( reboot)",
            "sysctl -w kernel.randomize_va_space=2",
            "# ",
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf",
            "sysctl -p",
        ],
        "verify": "cat /proc/sys/kernel/randomize_va_space # 2",
        "description_th": "ASLR exploit kernel heap reboot",
    },

    # ── General Hardening ─────────────────────────────────────
    "enable_apparmor": {
        "title":    " AppArmor/SELinux",
        "effort":   "HIGH",
        "impact":   "HIGH",
        "timeline": "week2",
        "breaks_chains": [],
        "commands": [
            "# Ubuntu: AppArmor",
            "systemctl enable apparmor && systemctl start apparmor",
            "aa-status",
            "# RHEL/CentOS: SELinux",
            "setenforce 1",
            "sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config",
        ],
        "verify": "aa-status --enabled || getenforce",
        "description_th": "MAC framework ",
    },

    "ptrace_restrict": {
        "title":    " ptrace",
        "effort":   "LOW",
        "impact":   "MEDIUM",
        "timeline": "week1",
        "breaks_chains": [],
        "commands": [
            "sysctl -w kernel.yama.ptrace_scope=1",
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.conf",
            "sysctl -p",
        ],
        "verify": "cat /proc/sys/kernel/yama/ptrace_scope # 1 2",
        "description_th": "ptrace_scope=0 inject code process 1",
    },
}

# ==============================
# Timeline Definitions
# ==============================
TIMELINES = {
    "immediate": {"label": " ()",    "color": Color.BG_RED  + Color.BOLD, "order": 0},
    "week1":     {"label": " 1 ",     "color": Color.RED    + Color.BOLD, "order": 1},
    "week2":     {"label": " 2 ",     "color": Color.ORANGE + Color.BOLD, "order": 2},
    "month1":    {"label": " 1 ",        "color": Color.YELLOW,             "order": 3},
}

EFFORT_LABELS = {
    "LOW":    c(Color.GREEN  + Color.BOLD, "LOW (< 1 )"),
    "MEDIUM": c(Color.YELLOW + Color.BOLD, "MEDIUM (< 1 ) "),
    "HIGH":   c(Color.RED    + Color.BOLD, "HIGH (> 1 ) "),
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
 scored_reports chains
 list remediation actions priority
 """
    seen_keys = set()
    actions   = []

    # chains action 
    chain_broken_by = {}
    for chain in chains:
        for key, tmpl in REMEDIATION_TEMPLATES.items():
            if chain["id"] in tmpl.get("breaks_chains", []):
                chain_broken_by.setdefault(key, []).append(chain["id"])

    # actions findings
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

    # general hardening 
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

    # : immediate , impact, effort (LOW )
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
    _print_banner('Remediation Roadmap  |  "Conquer Vulnerabilities"')

def print_roadmap(actions: list):
    if not actions:
        print(c(Color.GREEN + Color.BOLD, "\n ✔ remediation actions \n"))
        return

    # Group by timeline
    grouped = {}
    for a in actions:
        tl = a["timeline"]
        grouped.setdefault(tl, []).append(a)

    print(c(Color.CYAN + Color.BOLD, f"\n  ╔══ REMEDIATION ROADMAP ({len(actions)} actions) ════════════════════╗"))
    print(f" {c(Color.CYAN,'║')} {c(Color.GRAY, ': timeline → impact → effort (LOW effort )')}")
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

            # Chains break
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

    # chains break actions 
    all_broken = set()
    for a in actions:
        all_broken.update(a.get("breaks_chains", []))
    chains_broken = len(all_broken)
    chains_total  = len(chains)

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ ROADMAP SUMMARY ══════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Actions          :')} {c(Color.WHITE + Color.BOLD, str(len(actions)))}")
    print(f" {c(Color.CYAN,'║')} {c(Color.BG_RED + Color.BOLD,' :')} {c(Color.RED + Color.BOLD, str(immediate))}")
    print(f" {c(Color.CYAN,'║')} {c(Color.ORANGE + Color.BOLD,' 1 :')} {c(Color.ORANGE+ Color.BOLD, str(week1))}")
    print(f" {c(Color.CYAN,'║')} {c(Color.YELLOW, ' 2+ :')} {c(Color.YELLOW+ Color.BOLD, str(week2_plus))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Attack Chains Broken   :')} "
          f"{c(Color.GREEN + Color.BOLD, str(chains_broken))} / {c(Color.WHITE, str(chains_total))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f" {c(Color.CYAN,'║')} {c(Color.YELLOW,'💡 [01] — action impact ')}")
    print(f" {c(Color.CYAN,'║')} {c(Color.YELLOW,' Context-Aware Scoring risk ')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚══════════════════════════════════════════════════════════════╝\n'))

def roadmap_to_report_dict(actions: list) -> list:
    """ actions list JSON serializable"""
    return [{k: v for k, v in a.items()} for a in actions]
