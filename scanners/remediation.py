#!/usr/bin/env python3
"""
  COSVINTE — Remediation Roadmap

  Builds a prioritised, timeline-based remediation plan from scanner findings
  and detected attack chains. Each action includes shell commands and a
  verification step so fixes can be confirmed immediately.
"""

from datetime import datetime

from core.utils import Color, c, severity_badge, print_banner as _print_banner


# ══════════════════════════════════════════════════════════════════
#  REMEDIATION ACTION TEMPLATES
# ══════════════════════════════════════════════════════════════════
# effort   : LOW = under 1 hour | MEDIUM = under 1 day | HIGH = over 1 day
# timeline : immediate | week1 | week2 | month1

REMEDIATION_TEMPLATES = {

    # ── Capabilities ────────────────────────────────────────────
    "cap_setuid_interpreter": {
        "title":         "Remove cap_setuid from Scripting Interpreters",
        "effort":        "LOW",
        "impact":        "CRITICAL",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-003"],
        "commands": [
            "# Identify affected interpreters",
            "getcap -r / 2>/dev/null | grep -E 'python|perl|ruby|node'",
            "# Remove the dangerous capability (replace path as needed)",
            "setcap -r /usr/bin/python3",
            "setcap -r /usr/bin/perl",
            "# Verify the capability is gone (no output = safe)",
            "getcap /usr/bin/python3",
        ],
        "verify":      "getcap -r / 2>/dev/null | grep -E 'setuid|sys_admin'",
        "description": (
            "cap_setuid or cap_sys_admin on a scripting interpreter allows a one-liner "
            "to call setuid(0) and obtain a root shell. Remove immediately."
        ),
    },

    "cap_sys_admin": {
        "title":         "Remove cap_sys_admin from Non-Essential Binaries",
        "effort":        "LOW",
        "impact":        "CRITICAL",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-003", "CHAIN-007"],
        "commands": [
            "# Find binaries with cap_sys_admin",
            "getcap -r / 2>/dev/null | grep sys_admin",
            "# Remove it",
            "setcap -r <binary_path>",
            "# If the binary needs it, restrict via systemd unit instead:",
            "# AmbientCapabilities=CAP_NET_ADMIN  (grant only what is needed)",
        ],
        "verify":      "getcap -r / 2>/dev/null | grep sys_admin  # should be empty",
        "description": (
            "cap_sys_admin is effectively equivalent to root. No ordinary binary "
            "should hold it. Remove and use targeted capabilities in systemd units."
        ),
    },

    "cap_dac_override": {
        "title":         "Remove cap_dac_override and Harden ACLs",
        "effort":        "MEDIUM",
        "impact":        "HIGH",
        "timeline":      "week1",
        "breaks_chains": ["CHAIN-007"],
        "commands": [
            "setcap -r <binary_path>",
            "# Grant per-file access via ACL instead of blanket DAC bypass",
            "setfacl -m u:<service_user>:r /path/to/specific/file",
            "# Protect sensitive files with immutable flag",
            "chattr +i /etc/passwd /etc/shadow /etc/sudoers",
        ],
        "verify":      "lsattr /etc/passwd | grep -i immutable",
        "description": (
            "cap_dac_override bypasses all file permission checks. Replace with "
            "targeted ACL entries on the specific files the service needs to read."
        ),
    },

    # ── Cron ────────────────────────────────────────────────────
    "cron_writable_script": {
        "title":         "Fix Permissions on Cron Scripts",
        "effort":        "LOW",
        "impact":        "CRITICAL",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-001", "CHAIN-002"],
        "commands": [
            "# Find world-writable scripts in cron directories",
            "find /etc/cron* /var/spool/cron -type f -perm -o+w 2>/dev/null",
            "# Fix permissions",
            "chmod 750 <script_path>",
            "chown root:root <script_path>",
            "# Audit all root cron jobs",
            "crontab -l",
            "for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null && echo \"--- $u ---\"; done",
        ],
        "verify":      "find /etc/cron* -perm -o+w 2>/dev/null  # should be empty",
        "description": (
            "World-writable cron scripts can be modified by any user to execute "
            "arbitrary commands as root when the cron cycle runs."
        ),
    },

    "cron_log_writable": {
        "title":         "Fix Permissions on Cron Log Directory",
        "effort":        "LOW",
        "impact":        "HIGH",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-001"],
        "commands": [
            "chmod 755 /var/log/cron",
            "chown root:adm /var/log/cron",
            "# Verify logrotate config creates logs with correct permissions",
            "grep -r 'create' /etc/logrotate.d/cron",
        ],
        "verify":      "ls -ld /var/log/cron  # expect drwxr-xr-x",
        "description": (
            "A world-writable cron log directory enables symlink attacks via "
            "logrotate, potentially overwriting sensitive files as root."
        ),
    },

    # ── PATH Hijack ─────────────────────────────────────────────
    "path_writable_dir": {
        "title":         "Fix Permissions on Writable $PATH Directories",
        "effort":        "LOW",
        "impact":        "CRITICAL",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-002"],
        "commands": [
            "# Find world-writable directories in $PATH",
            "for p in $(echo $PATH | tr ':' '\\n'); do ls -ld \"$p\" 2>/dev/null; done | grep -E '^d.......w'",
            "# Remove world-write permission",
            "chmod o-w <writable_path_dir>",
            "chown root:root <writable_path_dir>",
            "# Remove any relative entries from $PATH",
            "echo $PATH | tr ':' '\\n' | grep -E '^\\.\\.'",
        ],
        "verify":      "for p in $(echo $PATH | tr ':' '\\n'); do ls -ld \"$p\"; done | grep -v '^drwxr-xr-x'",
        "description": (
            "A world-writable directory in $PATH lets an attacker shadow any command "
            "name, affecting cron jobs and SUID binaries that call commands by name."
        ),
    },

    "path_relative_entry": {
        "title":         "Remove Relative Entries from $PATH",
        "effort":        "LOW",
        "impact":        "HIGH",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-002", "CHAIN-008"],
        "commands": [
            "# Show current $PATH",
            "echo $PATH",
            "# Locate where the relative entry is set",
            "grep -n 'PATH' /etc/environment ~/.bashrc ~/.profile /etc/profile",
            "# Remove '.' or relative paths and reload",
            "source ~/.bashrc",
        ],
        "verify":      "echo $PATH | tr ':' '\\n' | grep -E '^\\.\\.'  # should be empty",
        "description": (
            "A relative entry such as '.' in $PATH allows command hijacking when any "
            "program is run from a directory the attacker can write to."
        ),
    },

    # ── Writable Paths ──────────────────────────────────────────
    "writable_passwd": {
        "title":         "Fix Permissions on /etc/passwd and /etc/shadow",
        "effort":        "LOW",
        "impact":        "CRITICAL",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-004"],
        "commands": [
            "chmod 644 /etc/passwd",
            "chmod 640 /etc/shadow",
            "chown root:root   /etc/passwd",
            "chown root:shadow /etc/shadow",
            "# Optionally set immutable to prevent further tampering",
            "chattr +i /etc/passwd /etc/shadow",
            "# Verify",
            "ls -la /etc/passwd /etc/shadow",
        ],
        "verify":      "ls -la /etc/passwd | grep -E '^-rw-r--r--'",
        "description": (
            "A writable /etc/passwd lets any user add a UID-0 account and obtain "
            "root access immediately. This is the most critical finding possible."
        ),
    },

    "writable_sensitive_dir": {
        "title":         "Fix Permissions on Sensitive System Directories",
        "effort":        "MEDIUM",
        "impact":        "HIGH",
        "timeline":      "week1",
        "breaks_chains": ["CHAIN-001", "CHAIN-006"],
        "commands": [
            "# Find world-writable system directories",
            "find /etc /usr /bin /sbin -type d -perm -o+w 2>/dev/null",
            "# Fix each one",
            "chmod o-w <directory>",
            "# Enable audit monitoring",
            "auditctl -w /etc -p wa -k etc_changes",
        ],
        "verify":      "find /etc /usr /bin /sbin -type d -perm -o+w 2>/dev/null  # should be empty",
        "description": (
            "World-writable directories under /etc, /usr, or /bin can be used to "
            "hijack libraries and binaries loaded by SUID programs or system services."
        ),
    },

    # ── Kernel ──────────────────────────────────────────────────
    "kernel_outdated": {
        "title":         "Update the Kernel to a Patched Version",
        "effort":        "HIGH",
        "impact":        "CRITICAL",
        "timeline":      "week2",
        "breaks_chains": ["CHAIN-005"],
        "commands": [
            "# Ubuntu / Debian",
            "apt update && apt upgrade linux-image-$(uname -r)",
            "# RHEL / CentOS",
            "yum update kernel",
            "# Reboot to activate the new kernel",
            "uname -r",
            "# If reboot is not possible, check for live-patch support",
            "kpatch list",
        ],
        "verify":      "uname -r  # confirm version is above the patched threshold",
        "description": (
            "One or more kernel CVEs match the running kernel version. Upgrading "
            "removes the exploit primitive. Live-patching (kpatch) avoids rebooting."
        ),
    },

    "aslr_disabled": {
        "title":         "Enable ASLR (Address Space Layout Randomisation)",
        "effort":        "LOW",
        "impact":        "HIGH",
        "timeline":      "immediate",
        "breaks_chains": ["CHAIN-005"],
        "commands": [
            "# Enable immediately (survives until reboot)",
            "sysctl -w kernel.randomize_va_space=2",
            "# Make it persistent across reboots",
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf",
            "sysctl -p",
        ],
        "verify":      "cat /proc/sys/kernel/randomize_va_space  # expect 2",
        "description": (
            "ASLR randomises the memory layout on each process launch, making kernel "
            "and heap exploits unreliable. Disabling it makes exploits trivially reliable."
        ),
    },

    # ── General Hardening ────────────────────────────────────────
    "enable_apparmor": {
        "title":         "Enable a MAC Framework (AppArmor or SELinux)",
        "effort":        "HIGH",
        "impact":        "HIGH",
        "timeline":      "week2",
        "breaks_chains": [],
        "commands": [
            "# Ubuntu — enable AppArmor",
            "systemctl enable apparmor && systemctl start apparmor",
            "aa-status",
            "# RHEL / CentOS — enable SELinux",
            "setenforce 1",
            "sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config",
        ],
        "verify":      "aa-status --enabled || getenforce",
        "description": (
            "A Mandatory Access Control framework constrains what processes can do "
            "even after a privilege escalation, significantly reducing post-exploit impact."
        ),
    },

    "ptrace_restrict": {
        "title":         "Restrict ptrace to Parent Processes",
        "effort":        "LOW",
        "impact":        "MEDIUM",
        "timeline":      "week1",
        "breaks_chains": [],
        "commands": [
            "sysctl -w kernel.yama.ptrace_scope=1",
            "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.conf",
            "sysctl -p",
        ],
        "verify":      "cat /proc/sys/kernel/yama/ptrace_scope  # expect 1 or 2",
        "description": (
            "ptrace_scope=0 allows any process to trace any other process owned by "
            "the same user. Setting it to 1 restricts tracing to parent processes only."
        ),
    },
}


# ══════════════════════════════════════════════════════════════════
#  TIMELINE DEFINITIONS
# ══════════════════════════════════════════════════════════════════
TIMELINES = {
    "immediate": {"label": "IMMEDIATE (act now)",   "color": Color.BG_RED  + Color.BOLD, "order": 0},
    "week1":     {"label": "WEEK 1",                "color": Color.RED     + Color.BOLD, "order": 1},
    "week2":     {"label": "WEEK 2",                "color": Color.ORANGE  + Color.BOLD, "order": 2},
    "month1":    {"label": "WITHIN 1 MONTH",        "color": Color.YELLOW,               "order": 3},
}

EFFORT_LABELS = {
    "LOW":    c(Color.GREEN  + Color.BOLD, "LOW    (< 1 hour)"),
    "MEDIUM": c(Color.YELLOW + Color.BOLD, "MEDIUM (< 1 day)"),
    "HIGH":   c(Color.RED    + Color.BOLD, "HIGH   (> 1 day)"),
}


# ══════════════════════════════════════════════════════════════════
#  ROADMAP BUILDER
# ══════════════════════════════════════════════════════════════════

def _finding_to_remediation_keys(finding: dict, scanner: str) -> list:
    """Map a finding dict to applicable remediation template keys."""
    keys = []

    if scanner == "caps":
        cap      = str(finding.get("capability", "")).lower()
        is_interp = finding.get("is_interpreter", False)
        if is_interp and ("setuid" in cap or "sys_admin" in cap):
            keys.append("cap_setuid_interpreter")
        elif "sys_admin" in cap:
            keys.append("cap_sys_admin")
        elif "dac_override" in cap or "dac_read_search" in cap:
            keys.append("cap_dac_override")

    elif scanner == "cron":
        cat = str(finding.get("category", "")).lower()
        keys.append("cron_writable_script")
        if "permission" in cat or "file" in cat or "log" in cat:
            keys.append("cron_log_writable")

    elif scanner == "path":
        if finding.get("world_writable"):
            keys.append("path_writable_dir")
        if finding.get("relative"):
            keys.append("path_relative_entry")
        if finding.get("dangerous") or finding.get("_origin") == "suid":
            if "path_writable_dir" not in keys:
                keys.append("path_writable_dir")

    elif scanner == "writable":
        path = str(finding.get("path", ""))
        if "/etc/passwd" in path or "/etc/shadow" in path:
            keys.append("writable_passwd")
        else:
            keys.append("writable_sensitive_dir")

    elif scanner == "kernel":
        if finding.get("status") in ("VULNERABLE", "UNKNOWN"):
            keys.append("kernel_outdated")
            keys.append("aslr_disabled")

    return keys


def build_roadmap(scored_reports: dict) -> list:
    """Build a deduplicated, sorted list of remediation actions.

    Sort order: timeline → impact severity → effort (LOW first).

    Args:
        scored_reports: Output of risk_scoring.score_all_reports().

    Returns:
        List of action dicts ready for print_roadmap().
    """
    seen_keys: set  = set()
    actions:   list = []

    # chain_broken_by is no longer populated (attack_chain module removed)
    chain_broken_by: dict = {}

    # Build actions from findings
    for scanner, report in scored_reports.items():
        if scanner.startswith("_") or not report:
            continue
        for f_key in ("findings", "writable_paths", "path_analysis"):
            for finding in report.get(f_key, []):
                for rk in _finding_to_remediation_keys(finding, scanner):
                    if rk in seen_keys:
                        continue
                    tmpl = REMEDIATION_TEMPLATES.get(rk)
                    if not tmpl:
                        continue
                    seen_keys.add(rk)

                    cs  = finding.get("context_scoring", {})
                    adj = cs.get("adjusted_score", 0)

                    actions.append({
                        "key":             rk,
                        "title":           tmpl["title"],
                        "description":     tmpl["description"],
                        "effort":          tmpl["effort"],
                        "impact":          tmpl["impact"],
                        "timeline":        tmpl["timeline"],
                        "commands":        tmpl["commands"],
                        "verify":          tmpl["verify"],
                        "breaks_chains":   chain_broken_by.get(rk, tmpl.get("breaks_chains", [])),
                        "trigger_score":   adj,
                        "trigger_finding": (
                            finding.get("cve") or finding.get("binary")
                            or finding.get("path") or ""
                        ),
                    })

    # Add general hardening actions based on context factors
    context_factors = scored_reports.get("_context_factors", {})

    if context_factors.get("aslr", {}).get("status") != "enabled":
        if "aslr_disabled" not in seen_keys:
            actions.append({
                **REMEDIATION_TEMPLATES["aslr_disabled"],
                "key":             "aslr_disabled",
                "trigger_score":   0,
                "trigger_finding": "ASLR is disabled",
                "breaks_chains":   chain_broken_by.get("aslr_disabled", []),
            })

    if not context_factors.get("mac_enforcement", {}).get("active"):
        if "enable_apparmor" not in seen_keys:
            actions.append({
                **REMEDIATION_TEMPLATES["enable_apparmor"],
                "key":             "enable_apparmor",
                "trigger_score":   0,
                "trigger_finding": "No MAC framework detected",
                "breaks_chains":   [],
            })

    if context_factors.get("ptrace_scope", {}).get("active") and \
       context_factors["ptrace_scope"].get("weight", 0) > 0:
        if "ptrace_restrict" not in seen_keys:
            actions.append({
                **REMEDIATION_TEMPLATES["ptrace_restrict"],
                "key":             "ptrace_restrict",
                "trigger_score":   0,
                "trigger_finding": "ptrace_scope=0 detected",
                "breaks_chains":   [],
            })

    # Sort: timeline → impact → effort (LOW = cheapest wins)
    tl_order     = {t: v["order"] for t, v in TIMELINES.items()}
    impact_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    effort_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

    actions.sort(key=lambda x: (
        tl_order.get(x["timeline"], 9),
        impact_order.get(x["impact"], 9),
        effort_order.get(x["effort"], 9),
    ))
    return actions


# ══════════════════════════════════════════════════════════════════
#  PRETTY PRINTING
# ══════════════════════════════════════════════════════════════════

def print_banner() -> None:
    _print_banner('Remediation Roadmap  |  "Conquer Vulnerabilities"')


def print_roadmap(actions: list) -> None:
    if not actions:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No remediation actions required.\n"))
        return

    # Group actions by timeline
    grouped: dict = {}
    for a in actions:
        grouped.setdefault(a["timeline"], []).append(a)

    print(c(Color.CYAN + Color.BOLD,
            f"\n  ╔══ REMEDIATION ROADMAP  ({len(actions)} actions) ══════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, 'Sorted by: timeline → impact → effort (cheapest fix first)')}")
    print(c(Color.CYAN + Color.BOLD,
            "  ╚══════════════════════════════════════════════════════════════╝\n"))

    global_idx = 1

    for tl_key in ("immediate", "week1", "week2", "month1"):
        group = grouped.get(tl_key, [])
        if not group:
            continue

        tl_info  = TIMELINES[tl_key]
        tl_line  = f"══ {tl_info['label']}  ({len(group)} action(s)) " + "═" * 32
        print(f"\n  {c(tl_info['color'], tl_line)}")

        for action in group:
            impact_col = {
                "CRITICAL": Color.BG_RED  + Color.BOLD,
                "HIGH":     Color.RED     + Color.BOLD,
                "MEDIUM":   Color.YELLOW  + Color.BOLD,
                "LOW":      Color.GREEN,
            }.get(action["impact"], Color.GRAY)

            print(f"\n  {c(Color.CYAN + Color.BOLD, f'  [{global_idx:02d}]')} "
                  f"{c(Color.WHITE + Color.BOLD, action['title'])}")
            impact_badge = c(impact_col, f" {action['impact']} ")
            print(f"        Impact  : {impact_badge}  "
                  f"│  Effort : {EFFORT_LABELS.get(action['effort'], action['effort'])}")

            if action.get("trigger_finding"):
                print(f"        Trigger : {c(Color.MAGENTA, str(action['trigger_finding'])[:60])}")

            if action["breaks_chains"]:
                pass   # attack_chain module removed — field kept for schema compat

            # Description (word-wrap at 68 chars)
            print(f"        {c(Color.CYAN, '📋')}  {c(Color.WHITE, action['description'])[:120]}")

            # Shell commands
            print(f"        {c(Color.YELLOW + Color.BOLD, '💻  Commands:')}")
            for cmd in action["commands"]:
                if cmd.startswith("#"):
                    print(f"           {c(Color.GRAY, cmd)}")
                else:
                    print(f"           {c(Color.GREEN, '$')} {c(Color.WHITE, cmd)}")

            if action.get("verify"):
                print(f"        {c(Color.BLUE, '✔  Verify :')} {c(Color.GRAY, action['verify'])}")

            global_idx += 1


def print_summary(actions: list) -> None:
    immediate  = sum(1 for a in actions if a["timeline"] == "immediate")
    week1      = sum(1 for a in actions if a["timeline"] == "week1")
    week2_plus = sum(1 for a in actions if a["timeline"] in ("week2", "month1"))

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ ROADMAP SUMMARY ══════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Actions         :')} {c(Color.WHITE + Color.BOLD, str(len(actions)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.BG_RED + Color.BOLD,'  IMMEDIATE           :')} {c(Color.RED    + Color.BOLD, str(immediate))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.ORANGE + Color.BOLD,'  WEEK 1              :')} {c(Color.ORANGE + Color.BOLD, str(week1))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,              '  WEEK 2+             :')} {c(Color.YELLOW + Color.BOLD, str(week2_plus))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW, '💡  Start with action [01] — highest impact, lowest effort.')}")
    print(c(Color.CYAN + Color.BOLD,
            '  ╚══════════════════════════════════════════════════════════════╝\n'))


def roadmap_to_report_dict(actions: list) -> list:
    """Return a JSON-serialisable copy of the roadmap for the combined report."""
    return [dict(a) for a in actions]