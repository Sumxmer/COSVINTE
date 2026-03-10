#!/usr/bin/env python3
"""
  COSVINTE — Shared Utilities
  Common colors, helpers, and system-info used by all scanner modules.

  Import with:
    from utils import Color, c, severity_badge, cvss_bar, system_info, ...
"""

import os
import json
import warnings
import platform
import subprocess
from datetime import datetime


# ══════════════════════════════════════════════════════
#  ANSI COLORS
# ══════════════════════════════════════════════════════
class Color:
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    RED       = "\033[91m"
    YELLOW    = "\033[93m"
    GREEN     = "\033[92m"
    CYAN      = "\033[96m"
    MAGENTA   = "\033[95m"
    WHITE     = "\033[97m"
    GRAY      = "\033[90m"
    ORANGE    = "\033[38;5;208m"
    BLUE      = "\033[94m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_DARK   = "\033[40m"
    BG_YELLOW = "\033[43m"


def c(color: str, text: str) -> str:
    """Wrap text with an ANSI color code and reset."""
    return f"{color}{text}{Color.RESET}"


# ══════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ══════════════════════════════════════════════════════
def severity_badge(sev: str) -> str:
    """Return a colored severity badge string."""
    colors = {
        "CRITICAL": Color.BG_RED   + Color.BOLD,
        "HIGH":     Color.RED      + Color.BOLD,
        "MEDIUM":   Color.YELLOW   + Color.BOLD,
        "LOW":      Color.GREEN,
    }
    return f"{colors.get(sev, Color.GRAY)} {sev} {Color.RESET}"


def cvss_bar(score: float, width: int = 20) -> str:
    """Return a colored ASCII progress bar for a CVSS score (0–10)."""
    score  = max(0.0, min(float(score), 10.0))
    filled = int((score / 10.0) * width)
    bar    = "█" * filled + "░" * (width - filled)
    if score >= 9.0:   col = Color.BG_RED + Color.BOLD
    elif score >= 7.0: col = Color.RED
    elif score >= 4.0: col = Color.YELLOW
    else:              col = Color.GREEN
    return f"{col}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"


# Alias used by risk_scoring
score_bar = cvss_bar


# ══════════════════════════════════════════════════════
#  SEVERITY HELPERS
# ══════════════════════════════════════════════════════
def score_to_severity(score: float) -> str:
    """Convert a numeric CVSS score to a severity label string."""
    score = float(score)
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"


# Backward-compatible aliases
sev_from_score     = score_to_severity
severity_from_cvss = score_to_severity


# ══════════════════════════════════════════════════════
#  SYSTEM INFORMATION
# ══════════════════════════════════════════════════════
def get_distro() -> str:
    """Return a human-readable OS/distro string."""
    try:
        r = subprocess.run(
            ["lsb_release", "-d"], capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0:
            return r.stdout.replace("Description:", "").strip()
    except Exception:
        pass
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME"):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.platform()


def system_info() -> dict:
    """Return a dict with hostname, distro, and architecture."""
    return {
        "hostname": platform.node(),
        "distro":   get_distro(),
        "arch":     platform.machine(),
    }


def print_sysinfo_box(fields: dict, title: str = "SYSTEM INFORMATION") -> None:
    """Print a bordered system-info box.

    Args:
        fields: Ordered dict of label → value pairs to display.
        title:  Box header text.
    """
    width = 58
    print(c(Color.CYAN + Color.BOLD,
            f"  ╔══ {title} {'═' * (width - len(title) - 5)}╗"))
    for label, value in fields.items():
        label_str = c(Color.GRAY,  f"{label:<12}:")
        value_str = c(Color.WHITE, str(value))
        print(f"  {c(Color.CYAN, '║')}  {label_str} {value_str}")
    print(c(Color.CYAN + Color.BOLD, f"  ╚{'═' * (width + 2)}╝\n"))


# ══════════════════════════════════════════════════════
#  SHARED ASCII BANNER
# ══════════════════════════════════════════════════════
BANNER_TEXT = """\
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝"""


def print_banner(subtitle: str = 'Unified Scanner  |  "Conquer Vulnerabilities"') -> None:
    """Print the shared COSVINTE ASCII banner with an optional subtitle."""
    print(f"\n{c(Color.CYAN + Color.BOLD, BANNER_TEXT)}")
    print(c(Color.GRAY, f"  {subtitle}\n"))


# ══════════════════════════════════════════════════════
#  REPORT I/O
# ══════════════════════════════════════════════════════
def save_json(report: dict, prefix: str) -> str:
    """Serialize *report* to a timestamped JSON file; return filename.

    .. deprecated::
        cosvinte.py no longer calls this directly.
        Kept for backward compatibility with standalone scanner modules.
    """
    warnings.warn(
        "save_json() is deprecated. Use cosvinte.py's built-in report pipeline instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    fname = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4, ensure_ascii=False)
    return fname


def separator(width: int = 58) -> None:
    """Print a grey horizontal separator line."""
    print(c(Color.GRAY, "  " + "─" * width))
