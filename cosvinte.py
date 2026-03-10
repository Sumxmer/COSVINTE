#!/usr/bin/env python3
"""
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

  COSVINTE — Unified Scanner  |  "Conquer Vulnerabilities"
  Integrates: Capabilities · Cron · Kernel · PATH Hijack · Writable Paths
              + Automatic PDF Report Generation

  Usage:
    python3 cosvinte.py                  # interactive menu (all scanners)
    python3 cosvinte.py --caps           # capabilities only
    python3 cosvinte.py --cron           # cron only
    python3 cosvinte.py --kernel         # kernel only
    python3 cosvinte.py --path           # PATH hijack only
    python3 cosvinte.py --writable       # writable paths only
    python3 cosvinte.py --all            # run all scanners sequentially
    python3 cosvinte.py --all --pdf      # run all + generate combined PDF
    python3 cosvinte.py --no-pdf         # skip PDF generation
"""

import os
import sys
import json
import platform
import importlib.util
import argparse
from datetime import datetime

# ─────────────────────────────────────────────────────
# Resolve sibling module paths
# ─────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))

def _load(filename, alias):
    """Dynamically load a scanner module by filename."""
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location(alias, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# ─────────────────────────────────────────────────────
# ANSI helpers (self-contained so we don't depend on
# any specific scanner's Color class)
# ─────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
CY = "\033[96m"
GR = "\033[92m"
YE = "\033[93m"
RE = "\033[91m"
GY = "\033[90m"
MA = "\033[95m"
WH = "\033[97m"
BG_RED = "\033[41m"

def cc(col, text): return f"{col}{text}{R}"

BANNER = f"""
{CY}{B}
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝{R}
{GY}  Unified Scanner Suite  |  "Conquer Vulnerabilities"{R}
"""

# ─────────────────────────────────────────────────────
# PDF generator import
# ─────────────────────────────────────────────────────
def _load_pdf():
    # Try new filename first, then legacy name
    for filename in ("pdf_report.py", "cosvinte_pdf_report.py"):
        mod = _load(filename, "cosvinte_pdf")
        if mod is not None:
            return mod
    print(cc(YE, "  ⚠  pdf_report.py not found — PDF generation disabled."))
    return None

# ─────────────────────────────────────────────────────

def _load_attack_chain():
    mod = _load("attack_chain.py", "attack_chain")
    if mod is None:
        print(cc(YE, "  Attack Chain analysis disabled."))
    return mod

def _load_risk_scoring():
    mod = _load("risk_scoring.py", "risk_scoring")
    if mod is None:
        print(cc(YE, "  Context-Aware Scoring disabled."))
    return mod

def _load_remediation():
    mod = _load("remediation.py", "remediation")
    if mod is None:
        print(cc(YE, "  Remediation Roadmap disabled."))
    return mod

# Shared report-building helpers
# ─────────────────────────────────────────────────────
def _sev_from_score(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"

def _system_info():
    def _distro():
        import subprocess
        try:
            r = subprocess.run(["lsb_release", "-d"], capture_output=True, text=True)
            return r.stdout.replace("Description:", "").strip()
        except:
            pass
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        return line.split("=", 1)[1].strip().strip('"')
        except:
            pass
        return "Unknown"
    return {
        "hostname": platform.node(),
        "distro":   _distro(),
        "arch":     platform.machine(),
    }

def _output_dir() -> str:
    """Return (and create) the output folder next to this script."""
    out = os.path.join(_HERE, "output")
    os.makedirs(out, exist_ok=True)
    return out

def _generate_pdf(pdf_mod, report, prefix):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(_output_dir(), f"{prefix}_{ts}.pdf")
    try:
        out = pdf_mod.generate_pdf(report, path)
        print(cc(GR, f"  ✔  PDF report → {cc(WH+B, out)}"))
        return out
    except Exception as e:
        print(cc(RE, f"  ✖  PDF generation failed: {e}"))
        import traceback; traceback.print_exc()
        return None

# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  SCANNER 1 — CAPABILITIES
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def run_capabilities(pdf_mod=None):
    caps = _load("Capabilities_cve.py", "caps")
    if caps is None:
        print(cc(RE, "  ✖  Capabilities_cve.py not found.")); return None

    caps.print_banner()

    print(cc(CY+B, "  Select Mode:"))
    print(f"  {cc(WH,'1')} {cc(GY,'─')} Real Scan (getcap -r /)")
    print(f"  {cc(WH,'2')} {cc(GY,'─')} Lab Simulation (safe demo)\n")
    mode = input(cc(CY, "  Enter choice [1/2]: ")).strip()

    if mode == "2":
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

    # ── build report dict ──
    max_score = max((f["risk_score"] for f in findings), default=0)
    report = {
        "tool":      "COSVINTE — Linux Capability Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    _system_info(),
        "summary": {
            "total_findings":  len(findings),
            "critical":        sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":            sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":          sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":             sum(1 for f in findings if f["severity"] == "LOW"),
            "interpreters":    sum(1 for f in findings if f.get("is_interpreter")),
            "world_writable":  sum(1 for f in findings if f.get("world_writable")),
            "overall_score":   max_score,
            "overall_cvss":    max_score,
            "overall_severity": _sev_from_score(max_score),
        },
        "findings": findings,
    }


    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_caps")

    return report


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  SCANNER 2 — CRON
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def run_cron(pdf_mod=None):
    cron = _load("cron_cve.py", "cron")
    if cron is None:
        print(cc(RE, "  ✖  cron_cve.py not found.")); return None

    cron.print_banner()

    print(cc(CY+B, "  Select Mode:"))
    print(f"  {cc(WH,'1')} {cc(GY,'─')} Real Scan (auto-detect or manual)")
    print(f"  {cc(WH,'2')} {cc(GY,'─')} Lab Simulation (safe test environment)")
    print(f"  {cc(WH,'3')} {cc(GY,'─')} Manual Input\n")
    mode = input(cc(CY, "  Enter choice [1/2/3]: ")).strip()

    if mode == "2":
        base         = cron.setup_lab_environment()
        cron_type    = "cronie"
        cron_version = "1.4.0"
        mode_label   = "Lab Simulation"
    elif mode == "3":
        base = "/"
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
            cron_type    = input(cc(CY, "  Cron type (cronie/vixie/dcron/debian cron): ")).strip()
            cron_version = input(cc(CY, "  Cron version (e.g. 1.4.0): ")).strip()
            mode_label   = "Manual Input"

    print()
    cron.print_sysinfo(cron_type, cron_version, mode_label, base)

    print(cc(CY, "  [*] Running detection checks …"), end="", flush=True)
    findings, checks = cron.run_scan(cron_type, cron_version, base)
    print(cc(GR, " done\n"))

    cron.print_checks(checks)
    cron.print_findings(findings)
    cron.print_summary(cron_type, cron_version, findings, checks)

    # ── build report dict ──
    max_cvss = max((f["cvss"] for f in findings), default=0)
    checks_triggered = sum(1 for v, _ in checks.values() if v) if checks else 0
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
            "total_cve_db":    len(cron.CVE_DB),
            "total_findings":  len(findings),
            "checks_triggered": checks_triggered,
            "overall_cvss":    max_cvss,
            "overall_severity": _sev_from_score(max_cvss),
        },
        "findings": [{k: v for k, v in f.items() if k != "detail"} for f in findings],
    }


    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_cron")

    return report


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  SCANNER 3 — KERNEL
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def run_kernel(pdf_mod=None):
    kern = _load("kernel_cve.py", "kernel")
    if kern is None:
        print(cc(RE, "  ✖  kernel_cve.py not found.")); return None

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

    # ── build report dict ──
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
            "total_cve_db":    len(kern.CVE_DB),
            "total_matches":   len(findings),
            "vulnerable":      sum(1 for f in findings if f["status"] == "VULNERABLE"),
            "unverified":      sum(1 for f in findings if f["status"] == "UNKNOWN"),
            "patched":         sum(1 for f in findings if f["status"] == "PATCHED"),
            "overall_cvss":    max_cvss,
            "overall_severity": _sev_from_score(max_cvss),
        },
        "findings": findings,
    }


    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_kernel")

    return report


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  SCANNER 4 — PATH HIJACK
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def run_path(pdf_mod=None):
    path = _load("PATH_hijack.py", "path_hijack")
    if path is None:
        print(cc(RE, "  ✖  PATH_hijack.py not found.")); return None

    path.print_banner()
    path.print_sysinfo()

    print(cc(CY, "  [*] Analysing PATH variable …"), end="", flush=True)
    path_f = path.scan_path()
    print(cc(GR, f" {len(path_f)} entries\n"))

    print(cc(CY, "  [*] Scanning environment variables …"), end="", flush=True)
    env_f = path.scan_env_vars()
    print(cc(GR, f" {len(env_f)} suspicious\n"))

    print(cc(CY, "  [*] Scanning SUID binaries (may take a moment) …"), end="", flush=True)
    suid_f = path.scan_suid_binaries()
    print(cc(GR, f" {len(suid_f)} found\n"))

    print(cc(CY, "  [*] Correlating CVEs …"), end="", flush=True)
    cve_f = path.correlate_cve(path_f, env_f, suid_f)
    print(cc(GR, f" {len(cve_f)} matched\n"))

    path.print_path_analysis(path_f)
    path.print_env_analysis(env_f)
    path.print_suid_analysis(suid_f)
    path.print_cve(cve_f)
    path.print_summary(path_f, env_f, suid_f, cve_f)

    # ── build report dict ──
    max_cvss = max((f["cvss"] for f in cve_f), default=0)
    report = {
        "tool":      "COSVINTE — PATH Hijack Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            **_system_info(),
            "user": path.get_current_user(),
            "uid":  os.getuid(),
        },
        "summary": {
            "path_entries":       len(path_f),
            "writable_path_dirs": sum(1 for f in path_f if f.get("world_writable")),
            "relative_path_dirs": sum(1 for f in path_f if f.get("relative")),
            "phantom_path_dirs":  sum(1 for f in path_f if not f.get("exists")),
            "dangerous_env_vars": len(env_f),
            "suid_binaries":      len(suid_f),
            "dangerous_suid":     sum(1 for f in suid_f if f.get("dangerous")),
            "total_cve_correlations": len(cve_f),
            "overall_cvss":       max_cvss,
            "overall_severity":   _sev_from_score(max_cvss),
        },
        "path_analysis":    path_f,
        "env_var_findings": env_f,
        "suid_binaries":    suid_f,
        "cve_correlations": [
            {k: v for k, v in e.items() if k != "trigger"}
            for e in cve_f
        ],
    }


    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_path")

    return report


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  SCANNER 5 — WRITABLE PATHS
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def run_writable(pdf_mod=None):
    wp = _load("Writable_paths_cve.py", "writable")
    if wp is None:
        print(cc(RE, "  ✖  Writable_paths_cve.py not found.")); return None

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

    # ── build report dict ──
    max_cvss = max((f["cvss"] for f in cve_hits), default=0)
    report = {
        "tool":      "COSVINTE — Writable Path Scanner",
        "timestamp": datetime.now().isoformat(),
        "system":    _system_info(),
        "summary": {
            "total_writable_paths":  len(writable),
            "total_cve_correlations": len(cve_hits),
            "overall_cvss":          max_cvss,
            "overall_severity":      _sev_from_score(max_cvss),
        },
        "writable_paths": writable,
        "cve_correlations": [
            {k: v for k, v in e.items() if k != "path_patterns"}
            for e in cve_hits
        ],
    }


    if pdf_mod:
        _generate_pdf(pdf_mod, report, "cosvinte_writable")

    return report


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  COMBINED PDF — merge all results into one report
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def _combined_report(reports: list) -> dict:
    """Merge multiple scanner reports into one combined PDF report.

    Per-scanner findings are stored under `scanner_reports` so the PDF
    generator can render a distinct section for each scanner without
    duplicating data.
    """
    all_findings     = []
    all_cve_corr     = []
    all_writable     = []
    all_checks       = {}
    all_path         = []
    all_env          = []
    all_suid         = []
    max_cvss         = 0.0
    combined_summary = {}
    scanner_reports  = {}   # key → individual report dict

    # Map tool-name keywords to scanner keys
    _tool_keys = {
        "capability": "caps",
        "cron":       "cron",
        "kernel":     "kernel",
        "path":       "path",
        "writable":   "writable",
    }

    scanner_names = []
    for r in reports:
        if not r: continue
        tool = r.get("tool", "")
        scanner_names.append(tool.replace("COSVINTE — ", ""))
        max_cvss = max(max_cvss, float(r.get("summary", {}).get("overall_cvss", 0)))

        # Tag which scanner this report belongs to
        tool_lower = tool.lower()
        for keyword, key in _tool_keys.items():
            if keyword in tool_lower:
                scanner_reports[key] = r
                break

        if "findings" in r:
            all_findings.extend(r["findings"])
        if "cve_correlations" in r:
            all_cve_corr.extend(r["cve_correlations"])
        if "writable_paths" in r:
            all_writable.extend(r["writable_paths"])
        if "checks" in r:
            all_checks.update(r["checks"])
        if "path_analysis" in r:
            all_path.extend(r["path_analysis"])
        if "env_var_findings" in r:
            all_env.extend(r["env_var_findings"])
        if "suid_binaries" in r:
            all_suid.extend(r["suid_binaries"])

        # Merge summary metrics
        for k, v in r.get("summary", {}).items():
            if k in ("overall_cvss", "overall_severity", "overall_score"): continue
            try:
                combined_summary[k] = combined_summary.get(k, 0) + int(v)
            except (TypeError, ValueError):
                pass

    combined_summary["overall_cvss"]    = max_cvss
    combined_summary["overall_severity"] = _sev_from_score(max_cvss)

    report = {
        "tool":            f"COSVINTE — Combined Scan: {' · '.join(scanner_names)}",
        "timestamp":       datetime.now().isoformat(),
        "system":          _system_info(),
        "summary":         combined_summary,
        "scanner_reports": scanner_reports,   # per-scanner data for PDF sections
    }
    if all_findings:   report["findings"]         = all_findings
    if all_checks:     report["checks"]           = all_checks
    if all_writable:   report["writable_paths"]   = all_writable
    if all_cve_corr:   report["cve_correlations"] = all_cve_corr
    if all_path:       report["path_analysis"]    = all_path
    if all_env:        report["env_var_findings"] = all_env
    if all_suid:       report["suid_binaries"]    = all_suid

    return report



# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  ALL SCANNERS + ATTACK CHAIN + RISK SCORING + ROADMAP
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def run_all_plus(pdf_mod=None):
    """Run all scanners then Attack Chain, Risk Scoring, and Remediation Roadmap."""

    # Load analysis modules
    ac_mod   = _load_attack_chain()
    rs_mod   = _load_risk_scoring()
    rem_mod  = _load_remediation()

    # Run each scanner and collect reports
    reports_list = []
    reports_dict = {}
    for _, _, key in MENU_ITEMS:
        if key in RUNNER_MAP:
            _separator()
            print(cc(MA+B, f"\n  ▸  Running {key.upper()} scanner ...\n"))
            r = RUNNER_MAP[key](None)   # no PDF yet
            reports_list.append(r)
            if r:
                reports_dict[key] = r

    _separator()

    # ── Context-Aware Risk Scoring ──
    scored_reports = reports_dict
    if rs_mod and reports_dict:
        print(cc(CY+B, "\n  ▸  Context-Aware Risk Scoring ...\n"))
        rs_mod.print_banner()
        factors = rs_mod.collect_context()
        rs_mod.print_context_factors(factors)
        scored_reports = rs_mod.score_all_reports(reports_dict)
        rs_mod.print_top_findings(scored_reports, top_n=10)
        rs_mod.print_summary(scored_reports)
        _separator()

    # ── Attack Chain Builder ──
    chains = []
    if ac_mod and reports_dict:
        print(cc(CY+B, "\n  ▸  Attack Chain Analysis ...\n"))
        ac_mod.print_banner()
        mem = ac_mod.check_memory_protections()
        ac_mod.print_mem_protections(mem)
        chains = ac_mod.build_chains(scored_reports)
        ac_mod.print_chains(chains)
        ac_mod.print_summary(chains)
        _separator()

    # ── Remediation Roadmap ──
    actions = []
    if rem_mod and reports_dict:
        print(cc(CY+B, "\n  ▸  Remediation Roadmap ...\n"))
        rem_mod.print_banner()
        actions = rem_mod.build_roadmap(scored_reports, chains)
        rem_mod.print_roadmap(actions)
        rem_mod.print_summary(actions, chains)
        _separator()

    # ── Combined Report ──
    combined = _combined_report(reports_list)

    # Attach analysis results to combined report
    if ac_mod and chains:
        combined["attack_chains"] = ac_mod.chains_to_report_dict(chains)
    if rem_mod and actions:
        combined["remediation_roadmap"] = rem_mod.roadmap_to_report_dict(actions)
    if rs_mod and "_context_factors" in scored_reports:
        combined["context_factors"] = {
            k: {"active": v.get("active"), "weight": v.get("weight"), "label": v.get("label", v.get("label_th", ""))}
            for k, v in scored_reports["_context_factors"].items()
        }

    # Save JSON

    # Generate combined PDF
    if pdf_mod and any(reports_list):
        print(cc(CY+B, "\n  ▸  Generating combined PDF report ..."))
        _generate_pdf(pdf_mod, combined, "cosvinte_full")

    print(cc(GR+B, "\n  ✔  Full analysis complete.\n"))
    return combined


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
MENU_ITEMS = [
    ("1", "Linux Capability Scanner",       "caps"),
    ("2", "Cron CVE Scanner",               "cron"),
    ("3", "Kernel CVE Scanner",             "kernel"),
    ("4", "PATH Hijack Scanner",            "path"),
    ("5", "Writable Path Scanner",          "writable"),
    ("6", "Run ALL Scanners",               "all"),
    ("7", "ALL + Attack Chain + Remediation", "all_plus"),
    ("0", "Exit",                           "exit"),
]

RUNNER_MAP = {
    "caps":     run_capabilities,
    "cron":     run_cron,
    "kernel":   run_kernel,
    "path":     run_path,
    "writable": run_writable,
}

# all_plus is handled separately (not in RUNNER_MAP to avoid recursion)

def _separator():
    print(cc(GY, "  " + "─" * 58))

def _menu_header():
    print(f"\n{CY}{B}  ╔══ SCANNER MENU ══════════════════════════════════════╗{R}")
    for num, label, _ in MENU_ITEMS:
        col  = CY if num not in ("0",) else GY
        icon = "●" if num not in ("0","6","7") else ("◆◆" if num == "7" else ("◆" if num == "6" else "✖"))
        print(f"  {cc(GY,chr(8214))}  {cc(col,icon)} {cc(WH, num)}  {cc(col if num!='0' else GY, label)}")
    print(f"{CY}{B}  ╚═══════════════════════════════════════════════════════╝{R}\n")

def _pdf_prompt():
    ans = input(cc(CY, "\n  Generate PDF report? [Y/n]: ")).strip().lower()
    return ans not in ("n", "no")

def interactive_menu():
    print(BANNER)
    pdf_mod = _load_pdf()

    while True:
        _menu_header()
        choice = input(cc(CY+B, "  Select scanner [0-6]: ")).strip()

        if choice == "0":
            print(cc(GY, "\n  Goodbye.\n"))
            sys.exit(0)

        if choice == "7":
            want_pdf = _pdf_prompt() if pdf_mod else False
            _separator()
            run_all_plus(pdf_mod if want_pdf else None)
            continue

        if choice == "6":
            want_pdf = _pdf_prompt() if pdf_mod else False
            reports  = []
            for _, _, key in MENU_ITEMS:
                if key in RUNNER_MAP:
                    _separator()
                    print(cc(MA+B, f"\n  ▸  Running {key.upper()} scanner ...\n"))
                    r = RUNNER_MAP[key](pdf_mod if want_pdf else None)
                    reports.append(r)
            if want_pdf and pdf_mod and any(reports):
                _separator()
                print(cc(CY+B, "\n  ▸  Generating combined PDF report ..."))
                combined = _combined_report(reports)
                _generate_pdf(pdf_mod, combined, "cosvinte_combined")
            continue

        key_map = {num: key for num, _, key in MENU_ITEMS}
        key = key_map.get(choice)
        if key not in RUNNER_MAP:
            print(cc(YE, "  Invalid choice.\n"))
            continue

        want_pdf = _pdf_prompt() if pdf_mod else False
        _separator()
        RUNNER_MAP[key](pdf_mod if want_pdf else None)


# ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog="cosvinte",
        description="COSVINTE — Unified Linux Privilege-Escalation Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cosvinte.py                   # interactive menu
  python3 cosvinte.py --caps            # capabilities scan + PDF
  python3 cosvinte.py --kernel --no-pdf # kernel scan, no PDF
  python3 cosvinte.py --all             # run all 5 scanners + PDF
  python3 cosvinte.py --all --no-pdf    # run all, JSON only
        """
    )
    ap.add_argument("--caps",     action="store_true", help="Run capability scanner")
    ap.add_argument("--cron",     action="store_true", help="Run cron CVE scanner")
    ap.add_argument("--kernel",   action="store_true", help="Run kernel CVE scanner")
    ap.add_argument("--path",     action="store_true", help="Run PATH hijack scanner")
    ap.add_argument("--writable", action="store_true", help="Run writable path scanner")
    ap.add_argument("--all",      action="store_true", help="Run all scanners")
    ap.add_argument("--analyze",  action="store_true", help="Run all + Attack Chain + Risk Scoring + Remediation")
    ap.add_argument("--no-pdf",   action="store_true", help="Skip PDF generation")
    ap.add_argument("--pdf",      action="store_true", help="Force PDF generation (default on)")
    args = ap.parse_args()

    # No flags → interactive
    flags = [args.caps, args.cron, args.kernel, args.path, args.writable, args.all, args.analyze]
    if not any(flags):
        interactive_menu()
        return

    if args.analyze:
        print(BANNER)
        pdf_mod = None if args.no_pdf else _load_pdf()
        run_all_plus(pdf_mod)
        return

    print(BANNER)
    pdf_mod   = None if args.no_pdf else _load_pdf()
    want_pdf  = (pdf_mod is not None)

    to_run = []
    if args.all:
        to_run = list(RUNNER_MAP.keys())
    else:
        if args.caps:     to_run.append("caps")
        if args.cron:     to_run.append("cron")
        if args.kernel:   to_run.append("kernel")
        if args.path:     to_run.append("path")
        if args.writable: to_run.append("writable")

    reports = []
    for key in to_run:
        _separator()
        print(cc(MA+B, f"\n  ▸  {key.upper()} SCANNER\n"))
        r = RUNNER_MAP[key](pdf_mod if (want_pdf and len(to_run) == 1) else None)
        reports.append(r)

    # For multi-scanner runs generate a combined PDF at the end
    if want_pdf and len(to_run) > 1 and pdf_mod and any(reports):
        _separator()
        print(cc(CY+B, "\n  ▸  Generating combined PDF report …"))
        combined = _combined_report(reports)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out  = pdf_mod.generate_pdf(combined, f"cosvinte_combined_{ts}.pdf")
        print(cc(GR, f"  ✔  Combined PDF → {cc(WH+B, out)}\n"))

    _separator()
    print(cc(GR+B, "\n  ✔  All scans complete.\n"))


if __name__ == "__main__":
    main()