#!/usr/bin/env python3
"""
  COSVINTE — Context-Aware Risk Scoring
  ปรับ CVSS score ตาม environment จริงของเครื่องที่กำลัง scan
  ไม่ใช่แค่ base score แต่คำนวณจาก context จริง
"""

import os
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
    BG_DARK = "\033[40m"
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

def score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0:   return "LOW"
    return "NONE"

def score_bar(score: float, width: int = 20) -> str:
    filled = int((score / 10.0) * width)
    bar    = "█" * filled + "░" * (width - filled)
    if score >= 9:   col = Color.BG_RED + Color.BOLD
    elif score >= 7: col = Color.RED
    elif score >= 4: col = Color.YELLOW
    else:            col = Color.GREEN
    return f"{col}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"

# ==============================
# Context Factor Definitions
# แต่ละ factor มี weight และวิธีตรวจสอบ
# ==============================

def _check_aslr() -> dict:
    """ASLR ปิดอยู่ = exploit kernel/heap ง่ายขึ้นมาก"""
    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            val = int(f.read().strip())
        if val == 0:
            return {"active": True,  "weight": +1.5, "label": "ASLR disabled (randomize_va_space=0)",    "label_th": "ASLR ถูกปิด ทำให้ exploit ง่ายขึ้นมาก"}
        if val == 1:
            return {"active": True,  "weight": +0.5, "label": "ASLR partial (randomize_va_space=1)",     "label_th": "ASLR เปิดบางส่วน ยังลดความปลอดภัยอยู่"}
        return     {"active": False, "weight":  0.0, "label": "ASLR fully enabled",                      "label_th": "ASLR เปิดปกติ"}
    except Exception:
        return     {"active": False, "weight": +0.3, "label": "ASLR status unknown",                     "label_th": "ไม่ทราบสถานะ ASLR"}

def _check_user_in_sudo() -> dict:
    """user ปัจจุบันมีสิทธิ์ sudo = privesc ง่ายขึ้น"""
    try:
        r = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0 and "(ALL)" in r.stdout:
            return {"active": True,  "weight": +1.5, "label": "Current user has unrestricted sudo",      "label_th": "user ปัจจุบันมีสิทธิ์ sudo ทุกอย่าง (ALL)"}
        if r.returncode == 0 and r.stdout.strip():
            return {"active": True,  "weight": +0.8, "label": "Current user has limited sudo access",    "label_th": "user ปัจจุบันมีสิทธิ์ sudo บางคำสั่ง"}
    except Exception:
        pass
    return         {"active": False, "weight":  0.0, "label": "No sudo access detected",                 "label_th": "ไม่พบสิทธิ์ sudo"}

def _check_selinux_apparmor() -> dict:
    """SELinux/AppArmor enforcing = exploit ยากขึ้น"""
    # SELinux
    try:
        r = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=2)
        if "Enforcing" in r.stdout:
            return {"active": True,  "weight": -1.0, "label": "SELinux Enforcing",                       "label_th": "SELinux กำลัง Enforcing อยู่ ลดความเสี่ยง"}
        if "Permissive" in r.stdout:
            return {"active": True,  "weight": -0.3, "label": "SELinux Permissive (log only)",           "label_th": "SELinux Permissive (แค่ log ไม่ block)"}
    except Exception:
        pass
    # AppArmor
    try:
        r = subprocess.run(["aa-status", "--enabled"], capture_output=True, timeout=2)
        if r.returncode == 0:
            return {"active": True,  "weight": -0.8, "label": "AppArmor enabled",                        "label_th": "AppArmor เปิดอยู่ ลดความเสี่ยง"}
    except Exception:
        pass
    return         {"active": True,  "weight": +0.5, "label": "No MAC (SELinux/AppArmor) detected",      "label_th": "ไม่มี SELinux/AppArmor ความเสี่ยงสูงขึ้น"}

def _check_dangerous_groups() -> dict:
    """user อยู่ใน group docker/lxd/disk/sudo = escalate ได้เลย"""
    danger_groups = ["docker", "lxd", "disk", "shadow", "sudo", "wheel", "adm"]
    try:
        import grp
        user_groups = [g.gr_name for g in grp.getgrall() if os.getlogin() in g.gr_mem]
        found = [g for g in user_groups if g in danger_groups]
        if found:
            return {"active": True,  "weight": +1.2, "label": f"User in dangerous groups: {', '.join(found)}", "label_th": f"user อยู่ใน group อันตราย: {', '.join(found)}"}
    except Exception:
        pass
    return         {"active": False, "weight":  0.0, "label": "No dangerous group membership",           "label_th": "ไม่อยู่ใน group อันตราย"}

def _check_writable_sensitive() -> dict:
    """ไฟล์ sensitive เขียนได้ = critical ขึ้นทันที"""
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"]
    found = []
    for path in sensitive:
        try:
            if os.access(path, os.W_OK):
                found.append(path)
        except Exception:
            pass
    if found:
        return {"active": True,  "weight": +2.0, "label": f"Sensitive files writable: {', '.join(found)}", "label_th": f"ไฟล์สำคัญเขียนได้: {', '.join(found)}"}
    return     {"active": False, "weight":  0.0, "label": "No sensitive files are writable",             "label_th": "ไม่มีไฟล์สำคัญที่เขียนได้"}

def _check_container() -> dict:
    """อยู่ใน container = escape risk"""
    indicators = [
        "/.dockerenv",
        "/run/.containerenv",
    ]
    for ind in indicators:
        if os.path.exists(ind):
            return {"active": True, "weight": +0.5, "label": "Running inside container (docker/podman)", "label_th": "กำลังรันใน container มีความเสี่ยง container escape"}
    try:
        with open("/proc/1/cgroup") as f:
            if "docker" in f.read() or "lxc" in f.read():
                return {"active": True, "weight": +0.5, "label": "Container environment detected via cgroup", "label_th": "พบ container environment ผ่าน cgroup"}
    except Exception:
        pass
    return {"active": False, "weight": 0.0, "label": "Not in container", "label_th": "ไม่ได้อยู่ใน container"}

def _check_ptrace_scope() -> dict:
    """ptrace_scope=0 = process injection ง่าย"""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            val = int(f.read().strip())
        if val == 0:
            return {"active": True,  "weight": +0.8, "label": "ptrace_scope=0 (unrestricted process tracing)", "label_th": "ptrace ไม่มีข้อจำกัด inject code เข้า process ใดก็ได้"}
        if val == 1:
            return {"active": False, "weight":  0.0, "label": "ptrace_scope=1 (restricted to parent)", "label_th": "ptrace จำกัดเฉพาะ parent process"}
    except Exception:
        pass
    return     {"active": False, "weight":  0.0, "label": "ptrace_scope unknown",                    "label_th": "ไม่ทราบสถานะ ptrace_scope"}

def _check_core_dumps() -> dict:
    """core dump enabled + readable = leak memory"""
    try:
        r = subprocess.run(["ulimit", "-c"], capture_output=True, text=True, shell=True, timeout=2)
        if r.stdout.strip() != "0":
            return {"active": True,  "weight": +0.3, "label": "Core dumps enabled (potential memory leak)", "label_th": "Core dump เปิดอยู่ อาจ leak ข้อมูล sensitive จาก memory"}
    except Exception:
        pass
    return     {"active": False, "weight":  0.0, "label": "Core dumps disabled",                     "label_th": "Core dump ปิดอยู่"}

# ==============================
# Context Collector
# ==============================
def collect_context() -> dict:
    """รวบรวม context factors ทั้งหมดของ environment"""
    factors = {
        "aslr":              _check_aslr(),
        "sudo_access":       _check_user_in_sudo(),
        "mac_enforcement":   _check_selinux_apparmor(),
        "dangerous_groups":  _check_dangerous_groups(),
        "writable_sensitive": _check_writable_sensitive(),
        "container":         _check_container(),
        "ptrace_scope":      _check_ptrace_scope(),
        "core_dumps":        _check_core_dumps(),
    }
    return factors

def total_weight(factors: dict) -> float:
    return sum(f["weight"] for f in factors.values() if f.get("active", False))

# ==============================
# Score Adjuster
# ==============================
def adjust_score(base_score: float, factors: dict, finding_type: str = "general") -> dict:
    """
    ปรับ base CVSS score ตาม context จริง
    คืน dict ที่มี adjusted_score, delta, active_factors
    """
    delta = 0.0
    active = []

    for factor_key, factor in factors.items():
        if not factor.get("active"):
            continue

        w = factor["weight"]

        # บาง factor ใช้กับ finding type เฉพาะ
        if factor_key == "aslr" and finding_type not in ("kernel", "heap", "general"):
            continue
        if factor_key == "container" and finding_type not in ("caps", "general"):
            continue

        delta += w
        active.append({
            "key":      factor_key,
            "label":    factor["label"],
            "label_th": factor["label_th"],
            "weight":   w,
        })

    adjusted = round(min(max(base_score + delta, 0.0), 10.0), 1)

    return {
        "base_score":     base_score,
        "adjusted_score": adjusted,
        "delta":          round(delta, 1),
        "severity_base":  score_to_severity(base_score),
        "severity_adj":   score_to_severity(adjusted),
        "active_factors": active,
        "finding_type":   finding_type,
    }

# ==============================
# Batch Scoring (ใช้กับ findings list)
# ==============================
def score_findings(findings: list, finding_type: str, factors: dict) -> list:
    """
    รับ findings list จาก scanner ใดก็ได้
    คืน findings ใหม่ที่มี adjusted_score เพิ่มเติม
    """
    result = []
    for f in findings:
        base = float(f.get("cvss") or f.get("risk_score") or f.get("base_score") or 0.0)
        adj  = adjust_score(base, factors, finding_type)
        enriched = dict(f)
        enriched["context_scoring"] = adj
        result.append(enriched)
    # เรียงใหม่ตาม adjusted score
    result.sort(key=lambda x: x["context_scoring"]["adjusted_score"], reverse=True)
    return result

def score_all_reports(reports: dict) -> dict:
    """
    รับ reports dict จาก all scanners
    คืน dict เหมือนเดิมแต่ทุก finding มี context_scoring เพิ่ม
    """
    factors = collect_context()
    scored  = {}

    type_map = {
        "caps":     "caps",
        "cron":     "general",
        "kernel":   "kernel",
        "path":     "general",
        "writable": "general",
    }

    for key, report in reports.items():
        if not report:
            scored[key] = report
            continue

        ftype   = type_map.get(key, "general")
        new_rep = dict(report)

        if "findings" in report:
            new_rep["findings"] = score_findings(report["findings"], ftype, factors)

        # บาง scanner ใช้ key ต่างกัน
        if "writable_paths" in report:
            new_rep["writable_paths"] = score_findings(report["writable_paths"], ftype, factors)
        if "path_analysis" in report:
            new_rep["path_analysis"] = score_findings(report["path_analysis"], ftype, factors)

        # ปรับ overall score ใน summary ด้วย
        if "summary" in new_rep:
            old_overall = float(new_rep["summary"].get("overall_cvss", 0))
            new_overall = round(min(max(old_overall + total_weight(factors), 0), 10), 1)
            new_rep["summary"]["overall_cvss_base"]     = old_overall
            new_rep["summary"]["overall_cvss_adjusted"] = new_overall
            new_rep["summary"]["overall_cvss"]          = new_overall
            new_rep["summary"]["overall_severity"]      = score_to_severity(new_overall)

        scored[key] = new_rep

    scored["_context_factors"] = factors
    return scored

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
{Color.GRAY}  Context-Aware Risk Scoring  |  "Conquer Vulnerabilities"{Color.RESET}
""")

def print_context_factors(factors: dict):
    print(c(Color.CYAN + Color.BOLD, "  ╔══ ENVIRONMENT CONTEXT FACTORS ════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'ปัจจัยเหล่านี้ถูกนำมาปรับ CVSS score ตาม environment จริง')}")
    print(f"  {c(Color.CYAN,'║')}")

    for key, factor in factors.items():
        active = factor.get("active", False)
        weight = factor.get("weight", 0.0)
        label  = factor.get("label_th", factor.get("label", key))

        if active and weight > 0:
            icon = c(Color.RED + Color.BOLD,    f"  ✖  [{'+' if weight > 0 else ''}{weight:.1f}]")
        elif active and weight < 0:
            icon = c(Color.GREEN + Color.BOLD,  f"  ✔  [{weight:.1f}]  ")
        else:
            icon = c(Color.GRAY,                f"  ─  [  0.0]")

        print(f"  {c(Color.CYAN,'║')} {icon} {c(Color.WHITE if active else Color.GRAY, label)}")

    tw = total_weight(factors)
    tw_col = Color.RED if tw > 0 else (Color.GREEN if tw < 0 else Color.GRAY)
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Net Score Adjustment :')} {c(tw_col + Color.BOLD, f'{tw:+.1f}')}")
    print(c(Color.CYAN + Color.BOLD, "  ╚════════════════════════════════════════════════════════════╝\n"))

def print_adjusted_finding(finding: dict, idx: int):
    """แสดง finding เดียว พร้อม context scoring"""
    cs   = finding.get("context_scoring", {})
    base = cs.get("base_score", 0)
    adj  = cs.get("adjusted_score", base)
    sev  = cs.get("severity_adj", "UNKNOWN")
    delta = cs.get("delta", 0)
    delta_col = Color.RED if delta > 0 else (Color.GREEN if delta < 0 else Color.GRAY)

    name = (finding.get("name") or finding.get("cve") or
            finding.get("binary") or finding.get("path") or f"Finding #{idx}")

    print(f"\n  {c(Color.WHITE + Color.BOLD, f'{idx}.')} {c(Color.MAGENTA, str(name))}  {severity_badge(sev)}")
    print(f"     Base CVSS  : {score_bar(base)}")
    print(f"     Adjusted   : {score_bar(adj)}  {c(delta_col + Color.BOLD, f'({delta:+.1f} context adjustment)')}")

    if cs.get("active_factors"):
        factors_short = [f["label_th"][:50] for f in cs["active_factors"][:3]]
        print(f"     Factors    : {c(Color.GRAY, ' | '.join(factors_short))}")

def print_top_findings(scored_reports: dict, top_n: int = 10):
    """แสดง top N findings เรียงตาม adjusted score"""
    all_findings = []

    for scanner, report in scored_reports.items():
        if scanner.startswith("_") or not report:
            continue
        for key in ("findings", "writable_paths", "path_analysis"):
            for f in report.get(key, []):
                if "context_scoring" in f:
                    f["_scanner"] = scanner
                    all_findings.append(f)

    all_findings.sort(
        key=lambda x: x["context_scoring"]["adjusted_score"], reverse=True
    )

    print(c(Color.CYAN + Color.BOLD, f"\n  ╔══ TOP {top_n} FINDINGS (Context-Adjusted) ══════════════════════╗"))
    for idx, f in enumerate(all_findings[:top_n], 1):
        cs      = f["context_scoring"]
        scanner = f.get("_scanner", "?")
        name    = (f.get("cve") or f.get("name") or f.get("binary") or f.get("path") or "?")
        adj     = cs["adjusted_score"]
        base    = cs["base_score"]
        delta   = cs["delta"]
        sev     = cs["severity_adj"]
        sev_changed = cs["severity_base"] != sev

        delta_col = Color.RED if delta > 0 else (Color.GREEN if delta < 0 else Color.GRAY)
        change_str = c(Color.ORANGE + Color.BOLD, f" ▲ UPGRADED to {sev}") if sev_changed and delta > 0 else ""

        print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, f'{idx:>2}.')} "
              f"{c(Color.MAGENTA, f'[{scanner}]')} "
              f"{c(Color.WHITE + Color.BOLD, str(name)[:40])}")
        print(f"  {c(Color.CYAN,'║')}       "
              f"Base: {c(Color.GRAY, f'{base:.1f}')}  →  "
              f"Adjusted: {score_bar(adj, width=15)}  "
              f"{c(delta_col, f'({delta:+.1f})')}"
              f"{change_str}")
        print(f"  {c(Color.CYAN,'║')}")

    print(c(Color.CYAN + Color.BOLD, "  ╚══════════════════════════════════════════════════════════════╝\n"))

def print_summary(scored_reports: dict):
    factors = scored_reports.get("_context_factors", {})
    tw      = total_weight(factors)
    tw_col  = Color.RED if tw > 0 else (Color.GREEN if tw < 0 else Color.GRAY)

    # นับ upgraded findings
    upgraded = 0
    for scanner, report in scored_reports.items():
        if scanner.startswith("_") or not report:
            continue
        for key in ("findings", "writable_paths"):
            for f in report.get(key, []):
                cs = f.get("context_scoring", {})
                if cs.get("severity_base") != cs.get("severity_adj") and cs.get("delta", 0) > 0:
                    upgraded += 1

    print(f"\n{c(Color.CYAN + Color.BOLD, '  ╔══ RISK SCORING SUMMARY ════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Net Context Adjustment :')} {c(tw_col + Color.BOLD, f'{tw:+.1f} to all scores')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Findings Upgraded      :')} {c(Color.ORANGE + Color.BOLD if upgraded else Color.GREEN, str(upgraded))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'ℹ  Score นี้สะท้อนความเสี่ยงจริงของ environment นี้')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'   ไม่ใช่แค่ base CVSS score จาก NVD')}")
    print(c(Color.CYAN + Color.BOLD, '  ╚════════════════════════════════════════════════════════════╝\n'))
