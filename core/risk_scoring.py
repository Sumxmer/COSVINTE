#!/usr/bin/env python3
"""
  COSVINTE — Context-Aware Risk Scoring

  Adjusts raw CVSS scores based on the real environment:
  ASLR, sudo access, MAC enforcement, dangerous group memberships,
  writable sensitive files, container presence, ptrace scope, and core dumps.
"""

import os
import pwd
import subprocess
import platform

from core.utils import (
    Color, c, severity_badge,
    score_to_severity, score_bar,
    print_banner as _print_banner,
)


# ══════════════════════════════════════════════════════════════════
#  INDIVIDUAL CONTEXT CHECKS
#  Each returns a factor dict:
#    active  – bool: whether this factor affects the score
#    weight  – float: score delta (positive = more dangerous)
#    label   – English description
# ══════════════════════════════════════════════════════════════════

def _check_aslr() -> dict:
    """ASLR disabled → kernel/heap exploits become significantly easier."""
    try:
        with open("/proc/sys/kernel/randomize_va_space") as fh:
            val = int(fh.read().strip())
        if val == 0:
            return {"active": True,  "weight": +1.5,
                    "label": "ASLR disabled (randomize_va_space=0) — exploits much easier"}
        if val == 1:
            return {"active": True,  "weight": +0.5,
                    "label": "ASLR partial (randomize_va_space=1) — partially effective"}
        return     {"active": False, "weight":  0.0,
                    "label": "ASLR fully enabled (randomize_va_space=2)"}
    except Exception:
        return     {"active": False, "weight": +0.3,
                    "label": "ASLR status unknown"}


def _check_user_in_sudo() -> dict:
    """Unrestricted sudo → privilege escalation is trivial once code runs."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "-l"], capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0 and "(ALL)" in r.stdout:
            return {"active": True,  "weight": +1.5,
                    "label": "Current user has unrestricted sudo (ALL)"}
        if r.returncode == 0 and r.stdout.strip():
            return {"active": True,  "weight": +0.8,
                    "label": "Current user has limited sudo access"}
    except Exception:
        pass
    return         {"active": False, "weight":  0.0,
                    "label": "No sudo access detected"}


def _check_selinux_apparmor() -> dict:
    """SELinux/AppArmor enforcing reduces exploit reliability."""
    try:
        r = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=2)
        if "Enforcing" in r.stdout:
            return {"active": True,  "weight": -1.0,
                    "label": "SELinux Enforcing — exploits harder to land"}
        if "Permissive" in r.stdout:
            return {"active": True,  "weight": -0.3,
                    "label": "SELinux Permissive (logs only, does not block)"}
    except Exception:
        pass
    try:
        r = subprocess.run(["aa-status", "--enabled"], capture_output=True, timeout=2)
        if r.returncode == 0:
            return {"active": True,  "weight": -0.8,
                    "label": "AppArmor enabled"}
    except Exception:
        pass
    return         {"active": True,  "weight": +0.5,
                    "label": "No MAC framework (SELinux/AppArmor) detected"}


def _check_dangerous_groups() -> dict:
    """Membership in docker/lxd/disk/shadow etc. enables escalation."""
    danger_groups = ["docker", "lxd", "disk", "shadow", "sudo", "wheel", "adm"]
    try:
        import grp
        user_name   = os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
        user_groups = [g.gr_name for g in grp.getgrall() if user_name in g.gr_mem]
        found       = [g for g in user_groups if g in danger_groups]
        if found:
            return {"active": True,  "weight": +1.2,
                    "label": f"User is in dangerous group(s): {', '.join(found)}"}
    except Exception:
        pass
    return         {"active": False, "weight":  0.0,
                    "label": "No dangerous group memberships detected"}


def _check_writable_sensitive() -> dict:
    """Writable /etc/passwd or /etc/shadow → instant root."""
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"]
    found     = [p for p in sensitive if os.access(p, os.W_OK)]
    if found:
        return {"active": True,  "weight": +2.0,
                "label": f"Sensitive files are writable: {', '.join(found)}"}
    return     {"active": False, "weight":  0.0,
                "label": "No sensitive files are writable"}


def _check_container() -> dict:
    """Running inside a container adds escape-based risk."""
    for indicator in ("/.dockerenv", "/run/.containerenv"):
        if os.path.exists(indicator):
            return {"active": True, "weight": +0.5,
                    "label": "Running inside container (docker/podman) — escape risk elevated"}
    try:
        with open("/proc/1/cgroup") as fh:
            content = fh.read()
        if "docker" in content or "lxc" in content:
            return {"active": True, "weight": +0.5,
                    "label": "Container environment detected via cgroup"}
    except Exception:
        pass
    return {"active": False, "weight": 0.0,
            "label": "Not running inside a container"}


def _check_ptrace_scope() -> dict:
    """ptrace_scope=0 → unrestricted process injection."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            val = int(fh.read().strip())
        if val == 0:
            return {"active": True,  "weight": +0.8,
                    "label": "ptrace_scope=0 — unrestricted process tracing enabled"}
        return     {"active": False, "weight":  0.0,
                    "label": f"ptrace_scope={val} — restricted process tracing"}
    except Exception:
        return     {"active": False, "weight":  0.0,
                    "label": "ptrace_scope unknown (Yama LSM likely absent)"}


def _check_core_dumps() -> dict:
    """Enabled core dumps can leak sensitive memory content."""
    try:
        r = subprocess.run(
            "ulimit -c", capture_output=True, text=True, shell=True, timeout=2
        )
        if r.stdout.strip() not in ("0", ""):
            return {"active": True,  "weight": +0.3,
                    "label": "Core dumps enabled — potential memory disclosure"}
    except Exception:
        pass
    return         {"active": False, "weight":  0.0,
                    "label": "Core dumps disabled"}


# ══════════════════════════════════════════════════════════════════
#  CONTEXT COLLECTOR
# ══════════════════════════════════════════════════════════════════

def collect_context() -> dict:
    """Run all context checks and return a combined factors dict."""
    return {
        "aslr":               _check_aslr(),
        "sudo_access":        _check_user_in_sudo(),
        "mac_enforcement":    _check_selinux_apparmor(),
        "dangerous_groups":   _check_dangerous_groups(),
        "writable_sensitive": _check_writable_sensitive(),
        "container":          _check_container(),
        "ptrace_scope":       _check_ptrace_scope(),
        "core_dumps":         _check_core_dumps(),
    }


def total_weight(factors: dict) -> float:
    """Sum all active factor weights."""
    return sum(f["weight"] for f in factors.values() if f.get("active", False))


# ══════════════════════════════════════════════════════════════════
#  SCORE ADJUSTER
# ══════════════════════════════════════════════════════════════════

def adjust_score(base_score: float, factors: dict, finding_type: str = "general") -> dict:
    """Adjust a base CVSS score using the environment context factors.

    Args:
        base_score:   Raw CVSS score (0.0–10.0).
        factors:      Result of collect_context().
        finding_type: One of 'caps', 'kernel', 'general'.

    Returns:
        Dict with adjusted_score, delta, severity_base, severity_adj,
        and a list of active_factors that contributed.
    """
    delta  = 0.0
    active = []

    for factor_key, factor in factors.items():
        if not factor.get("active"):
            continue
        w = factor["weight"]

        # Skip ASLR adjustment for non-kernel/heap findings
        if factor_key == "aslr" and finding_type not in ("kernel", "heap", "general"):
            continue
        # Skip container adjustment for non-capability findings
        if factor_key == "container" and finding_type not in ("caps", "general"):
            continue

        delta += w
        active.append({
            "key":    factor_key,
            "label":  factor["label"],
            "weight": w,
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


# ══════════════════════════════════════════════════════════════════
#  BATCH SCORING
# ══════════════════════════════════════════════════════════════════

def score_findings(findings: list, finding_type: str, factors: dict) -> list:
    """Enrich each finding with context_scoring; sort by adjusted score (desc)."""
    result = []
    for f in findings:
        base = float(f.get("cvss") or f.get("risk_score") or f.get("base_score") or 0.0)
        adj  = adjust_score(base, factors, finding_type)
        enriched = dict(f)
        enriched["context_scoring"] = adj
        result.append(enriched)
    result.sort(key=lambda x: x["context_scoring"]["adjusted_score"], reverse=True)
    return result


def score_all_reports(reports: dict) -> dict:
    """Apply context scoring across all scanner reports.

    Collects context ONCE and reuses it — avoids repeated subprocess calls.

    Returns:
        Enriched reports dict plus a '_context_factors' key.
    """
    # Collect context a single time for the entire run
    factors = collect_context()

    type_map = {
        "caps":     "caps",
        "cron":     "general",
        "kernel":   "kernel",
        "path":     "general",
        "writable": "general",
    }

    scored: dict = {}
    for key, report in reports.items():
        if not report:
            scored[key] = report
            continue

        ftype   = type_map.get(key, "general")
        new_rep = dict(report)

        if "findings" in report:
            new_rep["findings"] = score_findings(report["findings"], ftype, factors)
        if "writable_paths" in report:
            new_rep["writable_paths"] = score_findings(report["writable_paths"], ftype, factors)
        if "path_analysis" in report:
            new_rep["path_analysis"] = score_findings(report["path_analysis"], ftype, factors)

        # Adjust overall summary score
        if "summary" in new_rep:
            old_overall = float(new_rep["summary"].get("overall_cvss", 0))
            new_overall = round(min(max(old_overall + total_weight(factors), 0.0), 10.0), 1)
            new_rep["summary"]["overall_cvss_base"]     = old_overall
            new_rep["summary"]["overall_cvss_adjusted"] = new_overall
            new_rep["summary"]["overall_cvss"]          = new_overall
            new_rep["summary"]["overall_severity"]      = score_to_severity(new_overall)

        scored[key] = new_rep

    scored["_context_factors"] = factors
    return scored


# ══════════════════════════════════════════════════════════════════
#  PRETTY PRINTING
# ══════════════════════════════════════════════════════════════════

def print_banner() -> None:
    _print_banner('Context-Aware Risk Scoring  |  "Conquer Vulnerabilities"')


def print_context_factors(factors: dict) -> None:
    tw     = total_weight(factors)
    tw_col = Color.RED if tw > 0 else (Color.GREEN if tw < 0 else Color.GRAY)

    print(c(Color.CYAN + Color.BOLD,
            "  ╔══ ENVIRONMENT CONTEXT FACTORS ════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, 'Each active factor adjusts all CVSS scores for this run.')}")
    print(f"  {c(Color.CYAN,'║')}")

    for factor in factors.values():
        active = factor.get("active", False)
        weight = factor.get("weight", 0.0)
        label  = factor.get("label", "")

        if active and weight > 0:
            icon = c(Color.RED + Color.BOLD,   f"  ✖  [{'+' if weight > 0 else ''}{weight:.1f}]")
        elif active and weight < 0:
            icon = c(Color.GREEN + Color.BOLD, f"  ✔  [{weight:.1f}]  ")
        else:
            icon = c(Color.GRAY,               f"  ─  [  0.0]")

        print(f"  {c(Color.CYAN,'║')} {icon} {c(Color.WHITE if active else Color.GRAY, label)}")

    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, 'Net Score Adjustment :')} "
          f"{c(tw_col + Color.BOLD, f'{tw:+.1f}')}")
    print(c(Color.CYAN + Color.BOLD,
            "  ╚════════════════════════════════════════════════════════════╝\n"))


def print_top_findings(scored_reports: dict, top_n: int = 10) -> None:
    """Display the top N findings sorted by adjusted score."""
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

    print(c(Color.CYAN + Color.BOLD,
            f"\n  ╔══ TOP {top_n} FINDINGS (Context-Adjusted) ══════════════════════╗"))
    for idx, f in enumerate(all_findings[:top_n], 1):
        cs      = f["context_scoring"]
        scanner = f.get("_scanner", "?")
        name    = (f.get("cve") or f.get("name") or f.get("binary") or f.get("path") or "?")
        adj     = cs["adjusted_score"]
        base    = cs["base_score"]
        delta   = cs["delta"]
        sev     = cs["severity_adj"]

        delta_col  = Color.RED if delta > 0 else (Color.GREEN if delta < 0 else Color.GRAY)
        upgrade    = cs["severity_base"] != sev and delta > 0
        change_str = c(Color.ORANGE + Color.BOLD, f" ▲ UPGRADED → {sev}") if upgrade else ""

        print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY, f'{idx:>2}.')} "
              f"{c(Color.MAGENTA, f'[{scanner}]')} "
              f"{c(Color.WHITE + Color.BOLD, str(name)[:40])}")
        print(f"  {c(Color.CYAN,'║')}       "
              f"Base: {c(Color.GRAY, f'{base:.1f}')}  →  "
              f"Adjusted: {score_bar(adj, width=15)}  "
              f"{c(delta_col, f'({delta:+.1f})')}"
              f"{change_str}")
        print(f"  {c(Color.CYAN,'║')}")

    print(c(Color.CYAN + Color.BOLD,
            "  ╚══════════════════════════════════════════════════════════════╝\n"))


def print_summary(scored_reports: dict) -> None:
    factors  = scored_reports.get("_context_factors", {})
    tw       = total_weight(factors)
    tw_col   = Color.RED if tw > 0 else (Color.GREEN if tw < 0 else Color.GRAY)
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
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Net Context Adjustment :')} "
          f"{c(tw_col + Color.BOLD, f'{tw:+.1f} applied to all scores')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Findings Upgraded      :')} "
          f"{c(Color.ORANGE + Color.BOLD if upgraded else Color.GREEN, str(upgraded))}")
    print(f"  {c(Color.CYAN,'║')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW, 'ℹ  Scores reflect actual exploitability in this environment.')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW, '   Base CVSS from NVD; adjustments are COSVINTE-specific.')}")
    print(c(Color.CYAN + Color.BOLD,
            '  ╚════════════════════════════════════════════════════════════╝\n'))
