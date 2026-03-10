#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Unified Linux Privilege-Escalation Scanner
  "Conquer Vulnerabilities"

  Integrates: Capabilities · Cron · Kernel · PATH Hijack · Writable Paths
              + Attack Chain Analysis · Context-Aware Risk Scoring
              + Remediation Roadmap · Automatic PDF Report Generation

  Usage:
    python3 cosvinte.py                  # interactive menu
    python3 cosvinte.py --caps           # capabilities only
    python3 cosvinte.py --cron           # cron only
    python3 cosvinte.py --kernel         # kernel only
    python3 cosvinte.py --path           # PATH hijack only
    python3 cosvinte.py --writable       # writable paths only
    python3 cosvinte.py --all            # run all 5 scanners + combined PDF
    python3 cosvinte.py --analyze        # run all + attack chain + remediation
    python3 cosvinte.py --all --no-pdf   # skip PDF generation
"""

import os
import sys
import json
import platform
import importlib.util
import argparse
from datetime import datetime
from typing import Optional
from typing import List, Dict, Tuple
from __future__ import annotations

from core.utils import (
    Color as _C, c as cc, system_info as _system_info,
    score_to_severity as _sev_from_score,
    separator as _separator_fn,
)

# ── Shorthand color constants ──────────────────────────────────────
R      = _C.RESET
B      = _C.BOLD
CY     = _C.CYAN
GR     = _C.GREEN
YE     = _C.YELLOW
RE     = _C.RED
GY     = _C.GRAY
MA     = _C.MAGENTA
WH     = _C.WHITE
BG_RED = _C.BG_RED

# ── Resolve the directory this script lives in ────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))

# ══════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════
BANNER = f"""\n{CY}{B}\
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝{R}
{GY}  Unified Scanner Suite  |  "Conquer Vulnerabilities"{R}
"""


# ══════════════════════════════════════════════════════════════════
#  MODULE LOADER
# ══════════════════════════════════════════════════════════════════

def _load_module(filename: str, alias: str):
    """Load a Python module by filename or absolute path.

    Returns the module object, or None if the file does not exist.
    Raises ImportError if the file exists but cannot be imported.
    """
    path = filename if os.path.isabs(filename) else os.path.join(_HERE, filename)
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location(alias, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _find_scanner(name: str, alias: str):
    """Locate and load a scanner module by searching known path conventions.

    Search order:
      1. <HERE>/<name>.py
      2. <HERE>/scanners/<name>.py
      3. <HERE>/scanners_<name>.py

    Raises:
        FileNotFoundError: if no matching file is found.
    """
    candidates = [
        os.path.join(_HERE, "scanners", f"{name}.py"),   # primary: scanners/ subfolder
        os.path.join(_HERE, f"{name}.py"),                # fallback: flat layout
        os.path.join(_HERE, f"scanners_{name}.py"),       # legacy flat layout
    ]
    for path in candidates:
        if os.path.exists(path):
            return _load_module(path, alias)
    raise FileNotFoundError(
        f"Scanner module '{name}' not found. Checked:\n"
        + "\n".join(f"  • {p}" for p in candidates)
    )



# ══════════════════════════════════════════════════════════════════
#  STARTUP HEALTH CHECK
# ══════════════════════════════════════════════════════════════════

_REQUIRED_SCANNERS = {
    "Capabilities_cve": "caps",
    "cron_cve":          "cron",
    "kernel_cve":        "kernel",
    "PATH_hijack":       "path",
    "Writable_paths_cve": "writable",
}


def _health_check(silent: bool = False) -> bool:
    """Verify all required scanner modules are present.

    Args:
        silent: If True, suppress output (useful for --help).

    Returns:
        True if all modules found, False otherwise.
    """
    missing = []
    for name in _REQUIRED_SCANNERS:
        candidates = [
            os.path.join(_HERE, "scanners", f"{name}.py"),
            os.path.join(_HERE, f"{name}.py"),
            os.path.join(_HERE, f"scanners_{name}.py"),
        ]
        if not any(os.path.exists(p) for p in candidates):
            missing.append(name)

    if missing and not silent:
        print(cc(RE + B, "\n  ✖  Missing required scanner modules:"))
        for m in missing:
            print(cc(RE, f"       • {m}.py"))
        print(cc(YE, "\n  Place the missing files in the same directory as cosvinte.py\n"))

    return len(missing) == 0


# ══════════════════════════════════════════════════════════════════
#  OPTIONAL MODULE LOADERS
# ══════════════════════════════════════════════════════════════════

def _load_pdf():
    """Load the PDF report module.

    Search order:
      1. <HERE>/core/pdf_report.py     (primary — matches project structure)
      2. <HERE>/pdf_report.py          (fallback flat layout)
      3. <HERE>/cosvinte_pdf_report.py (legacy name)
    """
    import importlib.util as _ilu
    candidates = [
        os.path.join(_HERE, "core", "pdf_report.py"),
        os.path.join(_HERE, "pdf_report.py"),
        os.path.join(_HERE, "cosvinte_pdf_report.py"),
    ]
    for path in candidates:
        if os.path.exists(path):
            spec = _ilu.spec_from_file_location("cosvinte_pdf", path)
            mod  = _ilu.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                return mod
            except Exception as exc:
                print(cc(RE, f"  ✖  Failed to load {os.path.basename(path)}: {exc}"))
                return None

    print(cc(YE,
        "  ⚠  PDF generation disabled: pdf_report.py not found.\n"
        f"     Expected: {os.path.join(_HERE, 'pdf_report.py')}"
    ))
    return None


def _load_optional_module(filename: str, alias: str, label: str):
    """Load a support module by direct filename from _HERE. Silent on missing."""
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        print(cc(YE, f"  ⚠  {label} disabled ({filename} not found next to cosvinte.py)."))
        return None
    return _load_module(path, alias)


def _load_attack_chain():
    for path in [
        os.path.join(_HERE, "core",     "attack_chain.py"),
        os.path.join(_HERE, "attack_chain.py"),
    ]:
        if os.path.exists(path):
            return _load_module(path, "attack_chain")
    print(cc(YE, "  ⚠  Attack Chain analysis disabled (core/attack_chain.py not found)."))
    return None


def _load_risk_scoring():
    for path in [
        os.path.join(_HERE, "core",     "risk_scoring.py"),
        os.path.join(_HERE, "risk_scoring.py"),
    ]:
        if os.path.exists(path):
            return _load_module(path, "risk_scoring")
    print(cc(YE, "  ⚠  Context-Aware Risk Scoring disabled (core/risk_scoring.py not found)."))
    return None


def _load_remediation():
    for path in [
        os.path.join(_HERE, "scanners", "remediation.py"),
        os.path.join(_HERE, "core",     "remediation.py"),
        os.path.join(_HERE, "remediation.py"),
    ]:
        if os.path.exists(path):
            return _load_module(path, "remediation")
    print(cc(YE, "  ⚠  Remediation Roadmap disabled (scanners/remediation.py not found)."))
    return None


# ══════════════════════════════════════════════════════════════════
#  PDF GENERATION HELPER  (single definition — no duplication)
# ══════════════════════════════════════════════════════════════════

def _generate_pdf(pdf_mod, report: dict, prefix: str) -> Optional[str]:
    """Generate a PDF from *report* and save it under reports/<prefix>_<ts>.pdf.

    Returns the output path on success, or None on failure.
    """
    if pdf_mod is None:
        return None
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.join(_HERE, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, f"{prefix}_{ts}.pdf")
    try:
        out = pdf_mod.generate_pdf(report, path)
        print(cc(GR, f"  ✔  PDF report → {cc(WH + B, out)}"))
        return out
    except Exception as exc:
        print(cc(RE, f"  ✖  PDF generation failed: {exc}"))
        return None


def _build_combined_pdf(pdf_mod, reports: list, prefix: str = "cosvinte_combined") -> None:
    """Merge *reports* into a combined report dict and generate one PDF."""
    combined = _merge_reports(reports)
    print(cc(CY + B, "\n  ▸  Generating combined PDF report …"))
    _generate_pdf(pdf_mod, combined, prefix)


# ══════════════════════════════════════════════════════════════════
#  REPORT MERGE HELPER
# ══════════════════════════════════════════════════════════════════

def _merge_reports(reports: list) -> dict:
    """Merge multiple scanner report dicts into one combined report."""
    all_findings  = []
    all_cve_corr  = []
    all_writable  = []
    all_checks    = {}
    all_path      = []
    all_env       = []
    all_suid      = []
    max_cvss      = 0.0
    summary_acc   = {}
    scanner_names = []

    for r in reports:
        if not r:
            continue
        tool = r.get("tool", "")
        scanner_names.append(tool.replace("COSVINTE — ", ""))
        max_cvss = max(max_cvss, float(r.get("summary", {}).get("overall_cvss", 0)))

        for key, target in [
            ("findings",         all_findings),
            ("cve_correlations", all_cve_corr),
            ("writable_paths",   all_writable),
            ("path_analysis",    all_path),
            ("env_var_findings", all_env),
            ("suid_binaries",    all_suid),
        ]:
            target.extend(r.get(key, []))

        if "checks" in r:
            all_checks.update(r["checks"])

        for k, v in r.get("summary", {}).items():
            if k in ("overall_cvss", "overall_severity", "overall_score"):
                continue
            try:
                summary_acc[k] = summary_acc.get(k, 0) + int(v)
            except (TypeError, ValueError):
                pass

    summary_acc["overall_cvss"]     = max_cvss
    summary_acc["overall_severity"] = _sev_from_score(max_cvss)

    combined: dict = {
        "tool":      f"COSVINTE — Combined Scan: {' · '.join(scanner_names)}",
        "timestamp": datetime.now().isoformat(),
        "system":    _system_info(),
        "summary":   summary_acc,
    }
    if all_findings:  combined["findings"]         = all_findings
    if all_checks:    combined["checks"]           = all_checks
    if all_writable:  combined["writable_paths"]   = all_writable
    if all_cve_corr:  combined["cve_correlations"] = all_cve_corr
    if all_path:      combined["path_analysis"]    = all_path
    if all_env:       combined["env_var_findings"] = all_env
    if all_suid:      combined["suid_binaries"]    = all_suid
    return combined


# ══════════════════════════════════════════════════════════════════
#  INDIVIDUAL SCANNER RUNNERS
# ══════════════════════════════════════════════════════════════════

def run_capabilities(pdf_mod=None) -> Optional[dict]:
    try:
        caps = _find_scanner("Capabilities_cve", "caps")
    except FileNotFoundError as exc:
        print(cc(RE, f"  ✖  {exc}")); return None

    caps.print_banner()
    # When called from CLI (--caps / --all), always use Real Scan (no interactive prompt)
    import sys as _sys
    if _sys.stdin.isatty():
        print(cc(CY + B, "  Select Mode:"))
        print(f"  {cc(WH, '1')} {cc(GY, '─')} Real Scan (getcap -r /)")
        print(f"  {cc(WH, '2')} {cc(GY, '─')} Lab Simulation (safe demo)\n")
        choice = input(cc(CY, "  Enter choice [1/2]: ")).strip() or "1"
    else:
        choice = "1"  # non-interactive (Docker / pipe) → always Real Scan

    if choice == "2":
        lines      = caps.setup_lab()
        mode_label = "Lab Simulation"
    else:
        mode_label = "Real Scan"
        print(cc(CY, "\n  [*] Running getcap -r / …"), end="", flush=True)
        lines = caps.get_capabilities()
        print(cc(GR, f" {len(lines)} entries found\n"))

    caps.print_sysinfo(mode_label)
    print(cc(CY, "  [*] Analysing capabilities …"), end="", flush=True)
    findings = caps.analyze_capabilities(lines)
    print(cc(GR, f" {len(findings)} findings\n"))

    caps.print_findings(findings)
    caps.print_summary(findings)

    max_score = max((f["risk_score"] for f in findings), default=0)
    report = {
        "tool":      "COSVINTE — Linux Capability Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    _system_info(),
        "summary": {
            "total_findings":   len(findings),
            "critical":         sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":             sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":           sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":              sum(1 for f in findings if f["severity"] == "LOW"),
            "interpreters":     sum(1 for f in findings if f.get("is_interpreter")),
            "world_writable":   sum(1 for f in findings if f.get("world_writable")),
            "overall_score":    max_score,
            "overall_cvss":     max_score,
            "overall_severity": _sev_from_score(max_score),
        },
        "findings": findings,
    }
    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_caps")
    return report


def run_cron(pdf_mod=None) -> Optional[dict]:
    try:
        cron = _find_scanner("cron_cve", "cron")
    except FileNotFoundError as exc:
        print(cc(RE, f"  ✖  {exc}")); return None

    cron.print_banner()
    import sys as _sys
    if _sys.stdin.isatty():
        print(cc(CY + B, "  Select Mode:"))
        print(f"  {cc(WH, '1')} {cc(GY, '─')} Real Scan (auto-detect or manual)")
        print(f"  {cc(WH, '2')} {cc(GY, '─')} Lab Simulation (safe test environment)")
        print(f"  {cc(WH, '3')} {cc(GY, '─')} Manual Input\n")
        choice = input(cc(CY, "  Enter choice [1/2/3]: ")).strip() or "1"
    else:
        choice = "1"  # non-interactive → Real Scan

    if choice == "2":
        base         = cron.setup_lab_environment()
        cron_type    = "cronie"
        cron_version = "1.4.0"
        mode_label   = "Lab Simulation"
    elif choice == "3":
        base         = "/"
        print()
        cron_type    = input(cc(CY, "  Cron type (cronie/vixie/dcron/debian cron): ")).strip()
        cron_version = input(cc(CY, "  Cron version (e.g. 1.4.0): ")).strip()
        mode_label   = "Manual Input"
    else:
        base       = "/"
        mode_label = "Auto-Detect"
        print(cc(CY, "\n  [*] Auto-detecting cron software …"), end="", flush=True)
        cron_type, cron_version = cron.detect_cron()
        if cron_type and cron_version:
            print(cc(GR, f" found: {cron_type} v{cron_version}\n"))
        else:
            print(cc(YE, " not detected\n"))
            if _sys.stdin.isatty():
                cron_type    = input(cc(CY, "  Cron type (cronie/vixie/dcron/debian cron): ")).strip()
                cron_version = input(cc(CY, "  Cron version (e.g. 1.4.0): ")).strip()
            else:
                cron_type    = "debian cron"
                cron_version = "3.0"
            mode_label = "Manual Input"

    print()
    cron.print_sysinfo(cron_type, cron_version, mode_label, base)
    print(cc(CY, "  [*] Running detection checks …"), end="", flush=True)
    findings, checks = cron.run_scan(cron_type, cron_version, base)
    print(cc(GR, " done\n"))

    cron.print_checks(checks)
    cron.print_findings(findings)
    cron.print_summary(cron_type, cron_version, findings, checks)

    max_cvss          = max((f["cvss"] for f in findings), default=0)
    checks_triggered  = sum(1 for v, _ in checks.values() if v) if checks else 0
    report = {
        "tool":      "COSVINTE — Cron CVE Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    _system_info(),
        "scan": {
            "cron_type":    cron_type,
            "cron_version": cron_version,
            "base_path":    base,
        },
        "checks": {
            k: {"vulnerable": bool(v), "detail": str(d) if d else None}
            for k, (v, d) in checks.items()
        },
        "summary": {
            "total_cve_db":     len(cron.CVE_DB),
            "total_findings":   len(findings),
            "checks_triggered": checks_triggered,
            "overall_cvss":     max_cvss,
            "overall_severity": _sev_from_score(max_cvss),
        },
        "findings": [{k: v for k, v in f.items() if k != "detail"} for f in findings],
    }
    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_cron")
    return report


def run_kernel(pdf_mod=None) -> Optional[dict]:
    try:
        kern = _find_scanner("kernel_cve", "kernel")
    except FileNotFoundError as exc:
        print(cc(RE, f"  ✖  {exc}")); return None

    kern.print_banner()
    kernel_ver, kernel_full = kern.get_kernel_version()
    distro   = kern.get_distro()
    hostname = kern.get_hostname()
    arch     = kern.get_arch()

    kern.print_sysinfo(kernel_full, distro, hostname, arch)
    print(cc(CY, "  [*] Scanning against CVE database …"), end="", flush=True)
    findings = kern.scan_kernel(kernel_ver)
    print(cc(GR, " done\n"))

    kern.print_findings(findings)
    kern.print_summary(findings, kernel_ver)

    max_cvss = max((f["cvss"] for f in findings), default=0)
    report = {
        "tool":      "COSVINTE — Kernel CVE Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname":       hostname,
            "distro":         distro,
            "arch":           arch,
            "kernel_version": kernel_ver,
            "kernel_full":    kernel_full,
        },
        "summary": {
            "total_cve_db":     len(kern.CVE_DB),
            "total_matches":    len(findings),
            "vulnerable":       sum(1 for f in findings if f["status"] == "VULNERABLE"),
            "unverified":       sum(1 for f in findings if f["status"] == "UNKNOWN"),
            "patched":          sum(1 for f in findings if f["status"] == "PATCHED"),
            "overall_cvss":     max_cvss,
            "overall_severity": _sev_from_score(max_cvss),
        },
        "findings": findings,
    }
    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_kernel")
    return report


def run_path(pdf_mod=None) -> Optional[dict]:
    try:
        path_mod = _find_scanner("PATH_hijack", "path_hijack")
    except FileNotFoundError as exc:
        print(cc(RE, f"  ✖  {exc}")); return None

    path_mod.print_banner()
    path_mod.print_sysinfo()

    print(cc(CY, "  [*] Analysing PATH variable …"), end="", flush=True)
    path_f = path_mod.scan_path()
    print(cc(GR, f" {len(path_f)} entries\n"))

    print(cc(CY, "  [*] Scanning environment variables …"), end="", flush=True)
    env_f = path_mod.scan_env_vars()
    print(cc(GR, f" {len(env_f)} suspicious\n"))

    print(cc(CY, "  [*] Scanning SUID binaries (may take a moment) …"), end="", flush=True)
    suid_f = path_mod.scan_suid_binaries()
    print(cc(GR, f" {len(suid_f)} found\n"))

    print(cc(CY, "  [*] Correlating CVEs …"), end="", flush=True)
    cve_f = path_mod.correlate_cve(path_f, env_f, suid_f)
    print(cc(GR, f" {len(cve_f)} matched\n"))

    path_mod.print_path_analysis(path_f)
    path_mod.print_env_analysis(env_f)
    path_mod.print_suid_analysis(suid_f)
    path_mod.print_cve(cve_f)
    path_mod.print_summary(path_f, env_f, suid_f, cve_f)

    max_cvss = max((f["cvss"] for f in cve_f), default=0)
    report = {
        "tool":      "COSVINTE — PATH Hijack Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            **_system_info(),
            "user": path_mod.get_current_user(),
            "uid":  os.getuid(),
        },
        "summary": {
            "path_entries":           len(path_f),
            "writable_path_dirs":     sum(1 for f in path_f if f.get("world_writable")),
            "relative_path_dirs":     sum(1 for f in path_f if f.get("relative")),
            "phantom_path_dirs":      sum(1 for f in path_f if not f.get("exists")),
            "dangerous_env_vars":     len(env_f),
            "suid_binaries":          len(suid_f),
            "dangerous_suid":         sum(1 for f in suid_f if f.get("dangerous")),
            "total_cve_correlations": len(cve_f),
            "overall_cvss":           max_cvss,
            "overall_severity":       _sev_from_score(max_cvss),
        },
        "path_analysis":    path_f,
        "env_var_findings": env_f,
        "suid_binaries":    suid_f,
        "cve_correlations": [
            {k: v for k, v in e.items() if k != "trigger"} for e in cve_f
        ],
    }
    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_path")
    return report


def run_writable(pdf_mod=None) -> Optional[dict]:
    try:
        wp = _find_scanner("Writable_paths_cve", "writable")
    except FileNotFoundError as exc:
        print(cc(RE, f"  ✖  {exc}")); return None

    wp.print_banner()
    wp.print_sysinfo()

    print(cc(CY, "  [*] Scanning world-writable paths …"), end="", flush=True)
    writable = wp.scan_writable_paths()
    print(cc(GR, f" found {len(writable)}\n"))

    print(cc(CY, "  [*] Correlating CVEs …"), end="", flush=True)
    cve_hits = wp.correlate_cve(writable)
    print(cc(GR, f" {len(cve_hits)} matched\n"))

    wp.print_writable(writable)
    wp.print_cve(cve_hits)
    wp.print_summary(writable, cve_hits)

    max_cvss = max((f["cvss"] for f in cve_hits), default=0)
    report = {
        "tool":      "COSVINTE — Writable Path Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    _system_info(),
        "summary": {
            "total_writable_paths":   len(writable),
            "total_cve_correlations": len(cve_hits),
            "overall_cvss":           max_cvss,
            "overall_severity":       _sev_from_score(max_cvss),
        },
        "writable_paths":  writable,
        "cve_correlations": [
            {k: v for k, v in e.items() if k != "path_patterns"} for e in cve_hits
        ],
    }
    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_writable")
    return report


# ══════════════════════════════════════════════════════════════════
#  SCANNER REGISTRY
# ══════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("1", "Linux Capability Scanner",          "caps"),
    ("2", "Cron CVE Scanner",                  "cron"),
    ("3", "Kernel CVE Scanner",                "kernel"),
    ("4", "PATH Hijack Scanner",               "path"),
    ("5", "Writable Path Scanner",             "writable"),
    ("6", "Run ALL Scanners",                  "all"),
    ("7", "ALL + Attack Chain + Remediation",  "all_plus"),
    ("0", "Exit",                              "exit"),
]

RUNNER_MAP = {
    "caps":     run_capabilities,
    "cron":     run_cron,
    "kernel":   run_kernel,
    "path":     run_path,
    "writable": run_writable,
}


# ══════════════════════════════════════════════════════════════════
#  RUN ALL + ANALYSIS
# ══════════════════════════════════════════════════════════════════

def run_all_scanners(pdf_mod=None) -> Tuple[List[dict], Dict[str, dict]]:
    """Run all five scanners; return (reports_list, reports_dict)."""
    reports_list: List[dict] = []
    reports_dict: Dict[str, dict] = {}
    for _, _, key in MENU_ITEMS:
        if key not in RUNNER_MAP:
            continue
        _separator()
        print(cc(MA + B, f"\n  ▸  Running {key.upper()} scanner …\n"))
        r = RUNNER_MAP[key](None)   # PDF generated later if needed
        reports_list.append(r)
        if r:
            reports_dict[key] = r
    return reports_list, reports_dict


def run_all_plus(pdf_mod=None) -> dict:
    """Run all scanners then Attack Chain → Risk Scoring → Remediation → PDF."""
    ac_mod  = _load_attack_chain()
    rs_mod  = _load_risk_scoring()
    rem_mod = _load_remediation()

    reports_list, reports_dict = run_all_scanners(pdf_mod=None)
    _separator()

    # ── Context-Aware Risk Scoring ─────────────────────────────
    scored_reports = reports_dict
    if rs_mod and reports_dict:
        print(cc(CY + B, "\n  ▸  Context-Aware Risk Scoring …\n"))
        rs_mod.print_banner()
        factors = rs_mod.collect_context()
        rs_mod.print_context_factors(factors)
        scored_reports = rs_mod.score_all_reports(reports_dict)
        rs_mod.print_top_findings(scored_reports, top_n=10)
        rs_mod.print_summary(scored_reports)
        _separator()

    # ── Attack Chain Analysis ──────────────────────────────────
    chains = []
    if ac_mod and reports_dict:
        print(cc(CY + B, "\n  ▸  Attack Chain Analysis …\n"))
        ac_mod.print_banner()
        mem = ac_mod.check_memory_protections()
        ac_mod.print_mem_protections(mem)
        chains = ac_mod.build_chains(scored_reports)
        ac_mod.print_chains(chains)
        ac_mod.print_summary(chains)
        _separator()

    # ── Remediation Roadmap ────────────────────────────────────
    actions = []
    if rem_mod and reports_dict:
        print(cc(CY + B, "\n  ▸  Remediation Roadmap …\n"))
        rem_mod.print_banner()
        actions = rem_mod.build_roadmap(scored_reports, chains)
        rem_mod.print_roadmap(actions)
        rem_mod.print_summary(actions, chains)
        _separator()

    # ── Build combined report ──────────────────────────────────
    combined = _merge_reports(reports_list)
    if ac_mod and chains:
        combined["attack_chains"] = ac_mod.chains_to_report_dict(chains)
    if rem_mod and actions:
        combined["remediation_roadmap"] = rem_mod.roadmap_to_report_dict(actions)
    if rs_mod and "_context_factors" in scored_reports:
        combined["context_factors"] = {
            k: {"active": v.get("active"), "weight": v.get("weight"), "label_th": v.get("label_th", "")}
            for k, v in scored_reports["_context_factors"].items()
        }

    if pdf_mod and any(reports_list):
        print(cc(CY + B, "\n  ▸  Generating combined PDF report …"))
        _generate_pdf(pdf_mod, combined, "cosvinte_full")

    print(cc(GR + B, "\n  ✔  Full analysis complete.\n"))
    return combined


# ══════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════════

def _separator() -> None:
    _separator_fn()


def _print_menu() -> None:
    print(f"\n{CY}{B}  ╔══ SCANNER MENU ══════════════════════════════════════╗{R}")
    for num, label, _ in MENU_ITEMS:
        col  = CY if num not in ("0",) else GY
        icon = ("●" if num not in ("0", "6", "7")
                else ("◆◆" if num == "7" else ("◆" if num == "6" else "✖")))
        print(f"  {cc(GY, chr(8214))}  {cc(col, icon)} {cc(WH, num)}  {cc(col if num != '0' else GY, label)}")
    print(f"{CY}{B}  ╚═══════════════════════════════════════════════════════╝{R}\n")


def _ask_pdf(pdf_mod) -> bool:
    """Prompt the user for PDF generation; returns False if pdf_mod is None."""
    if not pdf_mod:
        return False
    import sys as _sys
    if not _sys.stdin.isatty():
        return True  # non-interactive (Docker / pipe) → always generate PDF
    ans = input(cc(CY, "\n  Generate PDF report? [Y/n]: ")).strip().lower()
    return ans not in ("n", "no")


def interactive_menu() -> None:
    print(BANNER)
    if not _health_check():
        sys.exit(1)

    pdf_mod = _load_pdf()

    while True:
        _print_menu()
        choice = input(cc(CY + B, "  Select scanner [0-7]: ")).strip()

        if choice == "0":
            print(cc(GY, "\n  Goodbye.\n"))
            sys.exit(0)

        if choice == "7":
            want_pdf = _ask_pdf(pdf_mod)
            _separator()
            run_all_plus(pdf_mod if want_pdf else None)
            continue

        if choice == "6":
            want_pdf  = _ask_pdf(pdf_mod)
            reports_list, _ = run_all_scanners(pdf_mod=None)
            if want_pdf and pdf_mod and any(reports_list):
                _separator()
                _build_combined_pdf(pdf_mod, reports_list, "cosvinte_combined")
            continue

        key_map = {num: key for num, _, key in MENU_ITEMS}
        key     = key_map.get(choice)
        if key not in RUNNER_MAP:
            print(cc(YE, "  Invalid choice. Please enter a number from 0 to 7.\n"))
            continue

        want_pdf = _ask_pdf(pdf_mod)
        _separator()
        RUNNER_MAP[key](pdf_mod if want_pdf else None)


# ══════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="cosvinte",
        description="COSVINTE — Unified Linux Privilege-Escalation Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 cosvinte.py                   # interactive menu
  python3 cosvinte.py --caps            # capabilities scan
  python3 cosvinte.py --kernel --no-pdf # kernel scan, no PDF
  python3 cosvinte.py --all             # run all 5 scanners + combined PDF
  python3 cosvinte.py --analyze         # run all + attack chain + remediation
  python3 cosvinte.py --all --no-pdf    # run all, skip PDF
        """,
    )
    ap.add_argument("--caps",     action="store_true", help="Run capability scanner")
    ap.add_argument("--cron",     action="store_true", help="Run cron CVE scanner")
    ap.add_argument("--kernel",   action="store_true", help="Run kernel CVE scanner")
    ap.add_argument("--path",     action="store_true", help="Run PATH hijack scanner")
    ap.add_argument("--writable", action="store_true", help="Run writable path scanner")
    ap.add_argument("--all",      action="store_true", help="Run all five scanners")
    ap.add_argument("--analyze",  action="store_true",
                    help="Run all scanners + Attack Chain + Risk Scoring + Remediation")
    ap.add_argument("--no-pdf",   action="store_true", help="Skip PDF generation")
    ap.add_argument("--pdf",      action="store_true", help="Force PDF generation (default: on)")
    args = ap.parse_args()

    # No flags → interactive mode
    cli_flags = [args.caps, args.cron, args.kernel, args.path,
                 args.writable, args.all, args.analyze]
    if not any(cli_flags):
        interactive_menu()
        return

    # Health check before any scan
    if not _health_check():
        sys.exit(1)

    print(BANNER)
    pdf_mod  = None if args.no_pdf else _load_pdf()
    want_pdf = pdf_mod is not None

    if args.analyze:
        run_all_plus(pdf_mod)
        return

    # Determine which scanners to run
    if args.all:
        to_run = list(RUNNER_MAP.keys())
    else:
        to_run = []
        if args.caps:     to_run.append("caps")
        if args.cron:     to_run.append("cron")
        if args.kernel:   to_run.append("kernel")
        if args.path:     to_run.append("path")
        if args.writable: to_run.append("writable")

    # Single scanner → PDF inline; multiple → combined PDF at end
    single = len(to_run) == 1
    reports: list = []
    for key in to_run:
        _separator()
        print(cc(MA + B, f"\n  ▸  {key.upper()} SCANNER\n"))
        r = RUNNER_MAP[key](pdf_mod if (want_pdf and single) else None)
        reports.append(r)

    if want_pdf and not single and pdf_mod and any(reports):
        _separator()
        _build_combined_pdf(pdf_mod, reports, "cosvinte_combined")

    _separator()
    print(cc(GR + B, "\n  ✔  All scans complete.\n"))


if __name__ == "__main__":
    main()