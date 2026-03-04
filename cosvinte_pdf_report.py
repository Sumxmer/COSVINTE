#!/usr/bin/env python3
"""
  COSVINTE — PDF Report Generator
  สร้าง PDF report แบบ professional จาก scan results ทั้งหมด
  รองรับ: Capabilities, Cron, Kernel, PATH Hijack, Writable Paths,
          Attack Chains, Context-Aware Risk Scoring, Remediation Roadmap
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as rl_canvas

def _safe(text: str) -> str:
    """Sanitize text for ReportLab Paragraph — escape XML special chars"""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ──────────────────────────────────────────────
# Color Palette
# ──────────────────────────────────────────────
C_BG        = colors.HexColor("#FFFFFF")
C_SURFACE   = colors.HexColor("#161b22")
C_BORDER    = colors.HexColor("#30363d")
C_CRITICAL  = colors.HexColor("#ff4444")
C_HIGH      = colors.HexColor("#ff8c00")
C_MEDIUM    = colors.HexColor("#ffd700")
C_LOW       = colors.HexColor("#3fb950")
C_INFO      = colors.HexColor("#58a6ff")
C_CYAN      = colors.HexColor("#39d0d8")
C_WHITE     = colors.HexColor("#e6edf3")
C_GRAY      = colors.HexColor("#8b949e")
C_DARK_GRAY = colors.HexColor("#21262d")
C_ACCENT    = colors.HexColor("#7c3aed")
C_CHAIN_HDR = colors.HexColor("#1f2937")

SEV_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "NONE":     C_GRAY,
    "PATCHED":  C_LOW,
    "UNKNOWN":  C_MEDIUM,
    "VULNERABLE": C_CRITICAL,
}

PAGE_W, PAGE_H = A4
MARGIN = 1.8 * cm


# ──────────────────────────────────────────────
# Custom Flowables
# ──────────────────────────────────────────────
class ColorBar(Flowable):
    """Horizontal color bar สำหรับ severity indicators"""
    def __init__(self, width, height, color, label="", label_color=colors.white):
        super().__init__()
        self.bar_w   = width
        self.bar_h   = height
        self.color   = color
        self.label   = label
        self.lcolor  = label_color

    def wrap(self, *args):
        return self.bar_w, self.bar_h

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.bar_w, self.bar_h, 3, fill=1, stroke=0)
        if self.label:
            self.canv.setFillColor(self.lcolor)
            self.canv.setFont("Helvetica-Bold", 8)
            self.canv.drawCentredString(self.bar_w / 2, self.bar_h / 2 - 3, self.label)


class ScoreBar(Flowable):
    """Visual CVSS score bar"""
    def __init__(self, score, max_score=10.0, width=120, height=12):
        super().__init__()
        self.score     = float(score)
        self.max_score = float(max_score)
        self.bar_w     = width
        self.bar_h     = height

    def wrap(self, *args):
        return self.bar_w + 50, self.bar_h + 4

    def draw(self):
        # Background track
        self.canv.setFillColor(C_DARK_GRAY)
        self.canv.roundRect(0, 2, self.bar_w, self.bar_h, 3, fill=1, stroke=0)
        # Filled portion
        ratio  = min(self.score / self.max_score, 1.0)
        filled = int(self.bar_w * ratio)
        if self.score >= 9:   col = C_CRITICAL
        elif self.score >= 7: col = C_HIGH
        elif self.score >= 4: col = C_MEDIUM
        else:                 col = C_LOW
        if filled > 0:
            self.canv.setFillColor(col)
            self.canv.roundRect(0, 2, filled, self.bar_h, 3, fill=1, stroke=0)
        # Score label
        self.canv.setFillColor(C_WHITE)
        self.canv.setFont("Helvetica-Bold", 8)
        self.canv.drawString(self.bar_w + 5, 3, f"{self.score:.1f}")


class SectionDivider(Flowable):
    """Fancy section header with colored left border"""
    def __init__(self, title, color=C_CYAN, width=None):
        super().__init__()
        self.title    = title
        self.color    = color
        self.div_w    = width or (PAGE_W - MARGIN * 2)
        self.div_h    = 28

    def wrap(self, *args):
        return self.div_w, self.div_h + 8

    def draw(self):
        # Background
        self.canv.setFillColor(C_SURFACE)
        self.canv.roundRect(0, 4, self.div_w, self.div_h, 4, fill=1, stroke=0)
        # Left accent bar
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 4, 4, self.div_h, fill=1, stroke=0)
        # Title
        self.canv.setFillColor(self.color)
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawString(14, 13, self.title)


class PageBackground(object):
    """Dark background + header/footer on every page"""
    def __init__(self, report_title, timestamp):
        self.report_title = report_title
        self.timestamp    = timestamp

    def __call__(self, canv, doc):
        canv.saveState()
        w, h = A4

        # Full page dark background
        canv.setFillColor(C_BG)
        canv.rect(0, 0, w, h, fill=1, stroke=0)

        # Top header bar
        canv.setFillColor(C_SURFACE)
        canv.rect(0, h - 40, w, 40, fill=1, stroke=0)
        canv.setFillColor(C_CYAN)
        canv.rect(0, h - 42, w, 2, fill=1, stroke=0)

        # Header text
        canv.setFillColor(C_CYAN)
        canv.setFont("Helvetica-Bold", 9)
        canv.drawString(MARGIN, h - 26, "COSVINTE")
        canv.setFillColor(C_GRAY)
        canv.setFont("Helvetica", 8)
        canv.drawString(MARGIN + 70, h - 26, "Linux Privilege Escalation Scanner")
        canv.setFillColor(C_GRAY)
        canv.setFont("Helvetica", 7)
        canv.drawRightString(w - MARGIN, h - 26, self.timestamp)

        # Bottom footer
        canv.setFillColor(C_SURFACE)
        canv.rect(0, 0, w, 28, fill=1, stroke=0)
        canv.setFillColor(C_BORDER)
        canv.rect(0, 28, w, 1, fill=1, stroke=0)

        # Footer text
        canv.setFillColor(C_GRAY)
        canv.setFont("Helvetica", 7)
        canv.drawString(MARGIN, 10, "CONFIDENTIAL — For authorized security testing only")
        canv.drawRightString(w - MARGIN, 10, f"Page {doc.page}")

        canv.restoreState()


# ──────────────────────────────────────────────
# Style Registry
# ──────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    S    = {}

    def ps(name, **kw):
        S[name] = ParagraphStyle(name, **kw)

    ps("title",       fontName="Helvetica-Bold",  fontSize=22, textColor=C_WHITE,    spaceAfter=4,  leading=28)
    ps("subtitle",    fontName="Helvetica",        fontSize=11, textColor=C_GRAY,     spaceAfter=2)
    ps("h1",          fontName="Helvetica-Bold",   fontSize=13, textColor=C_CYAN,     spaceBefore=8, spaceAfter=4)
    ps("h2",          fontName="Helvetica-Bold",   fontSize=11, textColor=C_WHITE,    spaceBefore=6, spaceAfter=3)
    ps("body",        fontName="Helvetica",        fontSize=8,  textColor=C_WHITE,    leading=13,    spaceAfter=2)
    ps("body_gray",   fontName="Helvetica",        fontSize=8,  textColor=C_GRAY,     leading=12,    spaceAfter=2)
    ps("code",        fontName="Courier",          fontSize=7,  textColor=C_LOW,      leading=10,    backColor=C_DARK_GRAY, leftIndent=6, rightIndent=6, spaceBefore=2, spaceAfter=2)
    ps("label",       fontName="Helvetica-Bold",   fontSize=7,  textColor=C_GRAY)
    ps("value",       fontName="Helvetica",        fontSize=8,  textColor=C_WHITE)
    ps("badge_crit",  fontName="Helvetica-Bold",   fontSize=7,  textColor=colors.white, backColor=C_CRITICAL)
    ps("badge_high",  fontName="Helvetica-Bold",   fontSize=7,  textColor=colors.white, backColor=C_HIGH)
    ps("badge_med",   fontName="Helvetica-Bold",   fontSize=7,  textColor=C_BG,         backColor=C_MEDIUM)
    ps("badge_low",   fontName="Helvetica-Bold",   fontSize=7,  textColor=C_BG,         backColor=C_LOW)
    ps("step",        fontName="Helvetica",        fontSize=8,  textColor=C_GRAY,     leading=12,    leftIndent=12)
    ps("step_num",    fontName="Helvetica-Bold",   fontSize=8,  textColor=C_CYAN)
    ps("toc_item",    fontName="Helvetica",        fontSize=9,  textColor=C_WHITE,    leading=16)
    ps("toc_page",    fontName="Helvetica",        fontSize=9,  textColor=C_GRAY,     leading=16)
    ps("chain_name",  fontName="Helvetica-Bold",   fontSize=10, textColor=C_WHITE,    spaceAfter=2)
    ps("chain_th",    fontName="Helvetica",        fontSize=8,  textColor=C_CYAN,     spaceAfter=3)
    ps("evidence",    fontName="Courier",          fontSize=7,  textColor=C_MEDIUM,   leading=10)
    ps("rem_title",   fontName="Helvetica-Bold",   fontSize=9,  textColor=C_WHITE,    spaceBefore=4, spaceAfter=2)
    ps("cmd",         fontName="Courier",          fontSize=7,  textColor=C_LOW,      leading=10,    backColor=C_DARK_GRAY, leftIndent=8, rightIndent=4)
    ps("cmd_comment", fontName="Courier",          fontSize=7,  textColor=C_GRAY,     leading=10,    backColor=C_DARK_GRAY, leftIndent=8)
    ps("verify",      fontName="Courier",          fontSize=7,  textColor=C_INFO,     leading=10)

    return S


# ──────────────────────────────────────────────
# Helper builders
# ──────────────────────────────────────────────
def _sp(n=1):
    return Spacer(1, n * 4)

def _hr(color=C_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=4, spaceBefore=4)

def _sev_color(sev: str):
    return SEV_COLORS.get(str(sev).upper(), C_GRAY)

def _badge_style(sev: str, S: dict):
    mapping = {
        "CRITICAL": "badge_crit",
        "HIGH":     "badge_high",
        "MEDIUM":   "badge_med",
        "LOW":      "badge_low",
    }
    return S.get(mapping.get(str(sev).upper(), "label"), S["label"])

def _kv_table(rows: list, col_widths=None) -> Table:
    """Build a two-column key-value table"""
    if col_widths is None:
        col_widths = [4 * cm, PAGE_W - MARGIN * 2 - 4 * cm]
    style = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
        ("TEXTCOLOR",   (0, 0), (0, -1),  C_GRAY),
        ("TEXTCOLOR",   (1, 0), (1, -1),  C_WHITE),
        ("FONTNAME",    (0, 0), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1),  "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0),(-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",(0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_SURFACE, C_DARK_GRAY]),
        ("LINEBELOW",   (0, -1), (-1, -1), 0.5, C_BORDER),
    ])
    return Table(rows, colWidths=col_widths, style=style, hAlign="LEFT")


def _finding_card(finding: dict, scanner: str, S: dict, idx: int) -> list:
    """Build a finding card flowable list"""
    story = []
    sev   = str(finding.get("severity", finding.get("status", "UNKNOWN"))).upper()
    score = finding.get("cvss") or finding.get("risk_score") or finding.get("base_score") or 0
    score = float(score)
    name  = (finding.get("cve") or finding.get("name") or
             finding.get("binary") or finding.get("path") or f"Finding #{idx}")
    desc  = (finding.get("description") or finding.get("description_th") or "")[:200]

    # Card header row
    sev_col   = _sev_color(sev)
    hdr_data  = [[
        Paragraph(f"<b>{_safe(name)}</b>", S["h2"]),
        Paragraph(f" {sev} ", _badge_style(sev, S)),
        ScoreBar(score),
    ]]
    hdr_style = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",(0, 0), (-1, -1), 8),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0,0), (-1, -1), 6),
        ("LINEABOVE",   (0, 0), (-1, 0),  1.5, sev_col),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ])
    content_w = PAGE_W - MARGIN * 2
    hdr_table = Table(hdr_data, colWidths=[content_w * 0.52, content_w * 0.14, content_w * 0.34],
                      style=hdr_style, hAlign="LEFT")
    story.append(KeepTogether([hdr_table]))

    # Body rows
    body_rows = []
    if finding.get("category"):
        body_rows.append(["Category", str(finding["category"])])
    if finding.get("cves"):
        cve_str = "  ".join(str(c) for c in finding["cves"][:5])
        body_rows.append(["CVEs", cve_str])
    if finding.get("capability"):
        body_rows.append(["Capability", str(finding["capability"])])
    if finding.get("binary"):
        body_rows.append(["Binary", str(finding["binary"])])
    if finding.get("path"):
        body_rows.append(["Path", str(finding["path"])])
    if finding.get("status"):
        body_rows.append(["Status", str(finding["status"])])

    if desc:
        body_rows.append(["Description", desc])

    # Thai description/impact
    if finding.get("description_th"):
        body_rows.append(["ช่องโหว่", str(finding["description_th"])[:200]])
    if finding.get("impact_th"):
        body_rows.append(["ผลกระทบ", str(finding["impact_th"])[:200]])

    if finding.get("exploit_hint"):
        body_rows.append(["Exploit", str(finding["exploit_hint"])[:120]])

    # Context scoring adjustment
    cs = finding.get("context_scoring", {})
    if cs and cs.get("delta", 0) != 0:
        body_rows.append(["Context Adj.", f"Base {cs['base_score']:.1f} → Adjusted {cs['adjusted_score']:.1f} ({cs['delta']:+.1f})"])

    if body_rows:
        col_w = [3.5 * cm, PAGE_W - MARGIN * 2 - 3.5 * cm]
        t = _kv_table([[Paragraph(_safe(str(k)), S["label"]), Paragraph(_safe(str(v)), S["body"])]
                       for k, v in body_rows], col_widths=col_w)
        story.append(t)

    # Prevention tips Thai
    prev = finding.get("prevention_th", [])
    if prev:
        story.append(_sp(1))
        story.append(Paragraph("🛡  การป้องกัน", S["h2"]))
        for i, tip in enumerate(prev[:4], 1):
            story.append(Paragraph(f"{i}. {tip}", S["step"]))

    story.append(_sp(2))
    return story


# ──────────────────────────────────────────────
# Section Builders
# ──────────────────────────────────────────────
def _build_cover(report: dict, S: dict) -> list:
    story = []
    story.append(Spacer(1, 3.5 * cm))

    # Logo / Title block
    title_data = [[
        Paragraph("COSVINTE", ParagraphStyle("logo", fontName="Helvetica-Bold",
                  fontSize=36, textColor=C_CYAN, leading=44)),
    ]]
    title_table = Table(title_data, colWidths=[PAGE_W - MARGIN * 2],
                        style=TableStyle([
                            ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
                            ("TOPPADDING",  (0, 0), (-1, -1), 18),
                            ("BOTTOMPADDING",(0,0), (-1, -1), 18),
                            ("LEFTPADDING", (0, 0), (-1, -1), 22),
                            ("LINEABOVE",   (0, 0), (-1, 0),  3, C_CYAN),
                            ("LINEBELOW",   (0, -1),(-1, -1), 1, C_BORDER),
                        ]))
    story.append(title_table)
    story.append(_sp(2))
    story.append(Paragraph("Linux Privilege Escalation Scanner", S["subtitle"]))
    story.append(Paragraph("Security Assessment Report", S["subtitle"]))
    story.append(_sp(4))

    # System info table
    sys_info = report.get("system", {})
    ts       = report.get("timestamp", datetime.now().isoformat())
    try:
        ts_fmt = datetime.fromisoformat(ts).strftime("%d %B %Y  %H:%M:%S")
    except Exception:
        ts_fmt = ts

    info_rows = [
        ["Hostname",   sys_info.get("hostname", "-")],
        ["OS / Distro", sys_info.get("distro",  "-")],
        ["Architecture", sys_info.get("arch",   "-")],
        ["Scan Date",  ts_fmt],
        ["Report By",  "COSVINTE Unified Scanner"],
    ]
    if sys_info.get("kernel_version"):
        info_rows.insert(3, ["Kernel", sys_info["kernel_version"]])

    story.append(_kv_table(
        [[Paragraph(k, S["label"]), Paragraph(str(v), S["value"])] for k, v in info_rows]
    ))

    # Overall risk badge
    summary = report.get("summary", {})
    overall_sev   = summary.get("overall_severity", "UNKNOWN")
    overall_score = float(summary.get("overall_cvss") or summary.get("overall_cvss_adjusted") or 0)
    sev_col       = _sev_color(overall_sev)

    story.append(_sp(4))
    risk_data = [[
        Paragraph("OVERALL RISK", ParagraphStyle("or_lbl", fontName="Helvetica-Bold",
                  fontSize=9, textColor=C_GRAY)),
        Paragraph(f" {overall_sev} ", ParagraphStyle("or_sev", fontName="Helvetica-Bold",
                  fontSize=18, textColor=colors.white, backColor=sev_col, leading=24)),
        Paragraph(f"CVSS {overall_score:.1f}", ParagraphStyle("or_score", fontName="Helvetica-Bold",
                  fontSize=18, textColor=sev_col, leading=24)),
    ]]
    risk_table = Table(risk_data, colWidths=[4*cm, 6*cm, 4*cm],
                       style=TableStyle([
                           ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
                           ("TOPPADDING",  (0, 0), (-1, -1), 14),
                           ("BOTTOMPADDING",(0,0), (-1, -1), 14),
                           ("LEFTPADDING", (0, 0), (-1, -1), 14),
                           ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
                           ("LINEABOVE",   (0, 0), (-1, 0),  2, sev_col),
                       ]))
    story.append(risk_table)
    story.append(PageBreak())
    return story


def _build_executive_summary(report: dict, chains: list, S: dict) -> list:
    story = []
    story.append(SectionDivider("EXECUTIVE SUMMARY", C_CYAN))
    story.append(_sp(2))

    summary = report.get("summary", {})

    # Stats grid
    stats = [
        ("Total Findings",  str(summary.get("total_findings", 0) or
                                summary.get("total_matches", 0) or
                                summary.get("total_cve_db", 0) or "-")),
        ("Critical",        str(summary.get("critical", 0) or
                                summary.get("vulnerable", 0) or "0")),
        ("High",            str(summary.get("high", 0) or "0")),
        ("Medium",          str(summary.get("medium", 0) or "0")),
        ("Attack Chains",   str(len(chains))),
        ("Immediate Fixes", str(sum(1 for a in report.get("remediation_roadmap", [])
                                   if a.get("timeline") == "immediate"))),
    ]

    stat_data = []
    row = []
    for i, (label, val) in enumerate(stats):
        cell = Table(
            [[Paragraph(val,   ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=22,
                                               textColor=C_CYAN, alignment=TA_CENTER))],
             [Paragraph(label, ParagraphStyle("sl", fontName="Helvetica", fontSize=7,
                                               textColor=C_GRAY, alignment=TA_CENTER))]],
            style=TableStyle([
                ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
                ("TOPPADDING",  (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING",(0,0), (-1, -1), 8),
                ("LINEABOVE",   (0, 0), (-1, 0),  2, C_CYAN),
            ]))
        row.append(cell)
        if len(row) == 3:
            stat_data.append(row)
            row = []
    if row:
        while len(row) < 3:
            row.append(Spacer(1, 1))
        stat_data.append(row)

    col_w = (PAGE_W - MARGIN * 2) / 3
    stats_table = Table(stat_data, colWidths=[col_w]*3,
                        style=TableStyle([
                            ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                            ("TOPPADDING",   (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                        ]))
    story.append(stats_table)
    story.append(_sp(3))

    # Attack chains quick list
    if chains:
        story.append(Paragraph("Attack Chains Detected", S["h1"]))
        chain_rows = [
            [Paragraph("ID", S["label"]), Paragraph("Chain", S["label"]),
             Paragraph("Severity", S["label"]), Paragraph("Confidence", S["label"])]
        ]
        for ch in chains[:8]:
            chain_rows.append([
                Paragraph(str(ch.get("id", "-")), S["body"]),
                Paragraph(_safe(str(ch.get("name_th", ch.get("name", "-")))[:55]), S["body"]),
                Paragraph(f' {ch.get("severity","?")} ', _badge_style(ch.get("severity","?"), S)),
                Paragraph(f'{ch.get("confidence","?")}%', S["body"]),
            ])
        cw = PAGE_W - MARGIN * 2
        chain_tbl = Table(chain_rows, colWidths=[2.2*cm, cw-2.2*cm-2.5*cm-2.5*cm, 2.5*cm, 2.5*cm],
                          style=TableStyle([
                              ("BACKGROUND",  (0, 0), (-1, 0),  C_DARK_GRAY),
                              ("BACKGROUND",  (0, 1), (-1, -1), C_SURFACE),
                              ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_SURFACE, C_DARK_GRAY]),
                              ("TEXTCOLOR",   (0, 0), (-1, 0),  C_GRAY),
                              ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
                              ("FONTSIZE",    (0, 0), (-1, -1), 8),
                              ("TOPPADDING",  (0, 0), (-1, -1), 5),
                              ("BOTTOMPADDING",(0,0), (-1, -1), 5),
                              ("LEFTPADDING", (0, 0), (-1, -1), 8),
                              ("LINEBELOW",   (0, 0), (-1, 0),  0.5, C_BORDER),
                          ]))
        story.append(chain_tbl)

    story.append(PageBreak())
    return story


def _build_scanner_section(scanner_key: str, report: dict, S: dict) -> list:
    SCANNER_TITLES = {
        "caps":     ("CAPABILITIES SCANNER", C_CRITICAL),
        "cron":     ("CRON CVE SCANNER",     C_HIGH),
        "kernel":   ("KERNEL CVE SCANNER",   C_MEDIUM),
        "path":     ("PATH HIJACK SCANNER",  C_HIGH),
        "writable": ("WRITABLE PATH SCANNER",C_MEDIUM),
    }
    title, color = SCANNER_TITLES.get(scanner_key, (scanner_key.upper(), C_CYAN))

    story = []
    story.append(SectionDivider(title, color))
    story.append(_sp(2))

    # System info
    sys_info = report.get("system", {})
    summary  = report.get("summary", {})

    if sys_info:
        info_rows = [(k.replace("_", " ").title(), str(v))
                     for k, v in sys_info.items() if v and k not in ("hostname",)]
        if info_rows:
            story.append(_kv_table(
                [[Paragraph(k, S["label"]), Paragraph(v, S["body"])]
                 for k, v in info_rows[:5]]
            ))
            story.append(_sp(2))

    # Summary stats
    if summary:
        sum_rows = [(k.replace("_", " ").title(), str(v))
                    for k, v in summary.items()
                    if not isinstance(v, dict) and str(v) not in ("", "None")]
        if sum_rows:
            story.append(Paragraph("Scan Summary", S["h2"]))
            story.append(_kv_table(
                [[Paragraph(k, S["label"]), Paragraph(_safe(str(v)), S["body"])]
                 for k, v in sum_rows]
            ))
            story.append(_sp(2))

    # Findings
    findings = (report.get("findings") or
                report.get("writable_paths") or
                report.get("path_analysis") or [])

    if findings:
        story.append(Paragraph(f"Findings ({len(findings)})", S["h1"]))
        for idx, f in enumerate(findings, 1):
            story.extend(_finding_card(f, scanner_key, S, idx))

    # CVE correlations
    cve_corr = report.get("cve_correlations", [])
    if cve_corr:
        story.append(Paragraph(f"CVE Correlations ({len(cve_corr)})", S["h1"]))
        for idx, f in enumerate(cve_corr, 1):
            story.extend(_finding_card(f, scanner_key, S, idx))

    # Checks (cron)
    checks = report.get("checks", {})
    if checks:
        story.append(Paragraph("Detection Checks", S["h2"]))
        chk_rows = [
            [Paragraph("Check", S["label"]), Paragraph("Result", S["label"]),
             Paragraph("Detail", S["label"])]
        ]
        for k, v in checks.items():
            vuln   = v.get("vulnerable", False)
            detail = str(v.get("detail", "") or "")[:80]
            result = Paragraph(" FOUND " if vuln else " OK ",
                               S["badge_crit"] if vuln else S["badge_low"])
            chk_rows.append([
                Paragraph(k.replace("_", " ").title(), S["body"]),
                result,
                Paragraph(detail, S["body_gray"]),
            ])
        cw = PAGE_W - MARGIN * 2
        chk_tbl = Table(chk_rows, colWidths=[4*cm, 2*cm, cw-6*cm],
                        style=TableStyle([
                            ("BACKGROUND",  (0, 0), (-1, 0),  C_DARK_GRAY),
                            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_DARK_GRAY]),
                            ("FONTSIZE",    (0, 0), (-1, -1), 8),
                            ("TOPPADDING",  (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8),
                            ("LINEBELOW",   (0, 0), (-1, 0),  0.5, C_BORDER),
                        ]))
        story.append(chk_tbl)

    story.append(PageBreak())
    return story


def _build_attack_chains(chains: list, S: dict) -> list:
    if not chains:
        return []

    story = []
    story.append(SectionDivider("ATTACK CHAIN ANALYSIS", C_CRITICAL))
    story.append(_sp(1))
    story.append(Paragraph(
        "ส่วนนี้แสดง attack path ที่ exploit ได้จริง โดยเชื่อมโยง findings จากหลาย scanner เข้าด้วยกัน "
        "แต่ละ chain มี confidence score และขั้นตอนการโจมตีแบบ step-by-step",
        S["body_gray"]
    ))
    story.append(_sp(2))

    for idx, chain in enumerate(chains, 1):
        sev      = chain.get("severity", "HIGH")
        conf     = chain.get("confidence", 0)
        sev_col  = _sev_color(sev)

        # Chain header
        hdr_data = [[
            Paragraph(f'{chain.get("id","?")}', S["label"]),
            Paragraph(f'{chain.get("name","?")}', S["chain_name"]),
            Paragraph(f' {sev} ', _badge_style(sev, S)),
            Paragraph(f'Confidence: {conf}%', S["body_gray"]),
        ]]
        cw = PAGE_W - MARGIN * 2
        hdr_t = Table(hdr_data, colWidths=[2*cm, cw-2*cm-2.5*cm-3*cm, 2.5*cm, 3*cm],
                      style=TableStyle([
                          ("BACKGROUND",  (0, 0), (-1, -1), C_CHAIN_HDR),
                          ("LINEABOVE",   (0, 0), (-1, 0),  2, sev_col),
                          ("TOPPADDING",  (0, 0), (-1, -1), 8),
                          ("BOTTOMPADDING",(0,0), (-1, -1), 8),
                          ("LEFTPADDING", (0, 0), (-1, -1), 8),
                          ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
                      ]))

        # Body
        body_elements = [hdr_t]

        if chain.get("name_th"):
            body_elements.append(
                Table([[Paragraph(_safe(chain["name_th"]), S["chain_th"])]],
                      colWidths=[cw],
                      style=TableStyle([
                          ("BACKGROUND",  (0,0),(-1,-1), C_SURFACE),
                          ("LEFTPADDING", (0,0),(-1,-1), 10),
                          ("TOPPADDING",  (0,0),(-1,-1), 4),
                          ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                      ]))
            )

        if chain.get("description_th"):
            body_elements.append(
                Table([[Paragraph(_safe(chain["description_th"]), S["body_gray"])]],
                      colWidths=[cw],
                      style=TableStyle([
                          ("BACKGROUND",  (0,0),(-1,-1), C_SURFACE),
                          ("LEFTPADDING", (0,0),(-1,-1), 10),
                          ("BOTTOMPADDING",(0,0),(-1,-1), 6),
                      ]))
            )

        # MITRE + Sources
        mitre_sources = f"MITRE: {chain.get('mitre','?')}   |   Sources: {', '.join(chain.get('sources_used',[]))}"
        body_elements.append(
            Table([[Paragraph(_safe(mitre_sources), S["body_gray"])]],
                  colWidths=[cw],
                  style=TableStyle([
                      ("BACKGROUND", (0,0),(-1,-1), C_SURFACE),
                      ("LEFTPADDING",(0,0),(-1,-1), 10),
                      ("BOTTOMPADDING",(0,0),(-1,-1),4),
                  ]))
        )

        # Steps
        steps = chain.get("steps_th", [])
        if steps:
            step_rows = [[Paragraph("ขั้นตอนการโจมตี", S["h2"])]]
            for si, step in enumerate(steps, 1):
                for li, line in enumerate(step.split("\n")):
                    safe_line = line.strip().replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                    if li == 0:
                        step_rows.append([Paragraph(f"{si}. {safe_line}", S["step"])])
                    else:
                        step_rows.append([Paragraph(safe_line, S["cmd"])])

            steps_t = Table(step_rows, colWidths=[cw],
                            style=TableStyle([
                                ("BACKGROUND",  (0,0),(-1,-1), C_SURFACE),
                                ("LEFTPADDING", (0,0),(-1,-1), 12),
                                ("TOPPADDING",  (0,0),(-1,-1), 1),
                                ("BOTTOMPADDING",(0,0),(-1,-1),1),
                                ("LINEBELOW",   (0,-1),(-1,-1), 0.5, C_BORDER),
                            ]))
            body_elements.append(steps_t)

        # Evidence
        ev_summary = chain.get("evidence_summary", {})
        if ev_summary:
            ev_rows = [[Paragraph("Evidence", S["h2"])]]
            for src, items in ev_summary.items():
                for item in items:
                    ev_rows.append([Paragraph(f"[{src}] {item}", S["evidence"])])
            ev_t = Table(ev_rows, colWidths=[cw],
                         style=TableStyle([
                             ("BACKGROUND",  (0,0),(-1,-1), C_DARK_GRAY),
                             ("LEFTPADDING", (0,0),(-1,-1), 12),
                             ("TOPPADDING",  (0,0),(-1,-1), 2),
                             ("BOTTOMPADDING",(0,0),(-1,-1),2),
                         ]))
            body_elements.append(ev_t)

        story.append(KeepTogether(body_elements[:4]))
        for el in body_elements[4:]:
            story.append(el)
        story.append(_sp(3))

    story.append(PageBreak())
    return story


def _build_remediation(actions: list, S: dict) -> list:
    if not actions:
        return []

    TIMELINE_LABELS = {
        "immediate": ("ทำทันที (วันนี้)",    C_CRITICAL),
        "week1":     ("ภายใน 1 สัปดาห์",    C_HIGH),
        "week2":     ("ภายใน 2 สัปดาห์",    C_MEDIUM),
        "month1":    ("ภายใน 1 เดือน",      C_LOW),
    }
    EFFORT_COLS = {"LOW": C_LOW, "MEDIUM": C_MEDIUM, "HIGH": C_HIGH}

    story = []
    story.append(SectionDivider("REMEDIATION ROADMAP", C_LOW))
    story.append(_sp(1))
    story.append(Paragraph(
        "แผนการแก้ไขเรียงตาม priority: timeline → impact → effort  "
        "แต่ละ action มี command พร้อมรันและ verify step",
        S["body_gray"]
    ))
    story.append(_sp(2))

    # Group by timeline
    grouped = {}
    for a in actions:
        grouped.setdefault(a["timeline"], []).append(a)

    global_idx = 1
    for tl_key in ("immediate", "week1", "week2", "month1"):
        group = grouped.get(tl_key, [])
        if not group:
            continue

        tl_label, tl_col = TIMELINE_LABELS.get(tl_key, (tl_key, C_GRAY))
        story.append(ColorBar(PAGE_W - MARGIN * 2, 20, tl_col,
                              label=f"  {tl_label}  ({len(group)} actions)"))
        story.append(_sp(1))

        for action in group:
            imp_col  = _sev_color(action.get("impact", "MEDIUM"))
            eff_col  = EFFORT_COLS.get(action.get("effort", "MEDIUM"), C_GRAY)
            chains_broken = action.get("breaks_chains", [])

            # Action header
            hdr = [[
                Paragraph(f'[{global_idx:02d}] {action["title"]}', S["rem_title"]),
                Paragraph(f' {action.get("impact","?")} ',
                          ParagraphStyle("imp_b", fontName="Helvetica-Bold", fontSize=7,
                                         textColor=colors.white, backColor=imp_col)),
                Paragraph(f'Effort: {action.get("effort","?")}',
                          ParagraphStyle("eff_l", fontName="Helvetica", fontSize=7,
                                         textColor=eff_col)),
            ]]
            cw = PAGE_W - MARGIN * 2
            hdr_t = Table(hdr, colWidths=[cw - 3*cm - 2.5*cm, 3*cm, 2.5*cm],
                          style=TableStyle([
                              ("BACKGROUND",  (0,0),(-1,-1), C_SURFACE),
                              ("TOPPADDING",  (0,0),(-1,-1), 6),
                              ("BOTTOMPADDING",(0,0),(-1,-1),6),
                              ("LEFTPADDING", (0,0),(-1,-1), 8),
                              ("LINEABOVE",   (0,0),(-1,0),  1.5, imp_col),
                              ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
                          ]))
            story.append(hdr_t)

            # Details
            details = []
            if action.get("description_th"):
                details.append(Paragraph(_safe(action["description_th"]), S["body_gray"]))

            if chains_broken:
                details.append(Paragraph(
                    f"Breaks Attack Chains: {', '.join(chains_broken)}",
                    ParagraphStyle("chain_ref", fontName="Helvetica-Bold", fontSize=7,
                                   textColor=C_MEDIUM)
                ))

            trigger = action.get("trigger_finding", "")
            if trigger:
                details.append(Paragraph(f"Triggered by: {_safe(trigger)}", S["body_gray"]))

            if details:
                det_rows = [[el] for el in details]
                det_t = Table(det_rows, colWidths=[cw],
                              style=TableStyle([
                                  ("BACKGROUND", (0,0),(-1,-1), C_SURFACE),
                                  ("LEFTPADDING",(0,0),(-1,-1), 10),
                                  ("TOPPADDING", (0,0),(-1,-1), 2),
                                  ("BOTTOMPADDING",(0,0),(-1,-1),2),
                              ]))
                story.append(det_t)

            # Commands
            cmds = action.get("commands", [])
            if cmds:
                cmd_rows = []
                for cmd in cmds:
                    style_key = "cmd_comment" if cmd.startswith("#") else "cmd"
                    cmd_rows.append([Paragraph(_safe(cmd), S[style_key])])
                cmd_t = Table(cmd_rows, colWidths=[cw],
                              style=TableStyle([
                                  ("BACKGROUND",  (0,0),(-1,-1), C_DARK_GRAY),
                                  ("LEFTPADDING", (0,0),(-1,-1), 8),
                                  ("TOPPADDING",  (0,0),(-1,-1), 1),
                                  ("BOTTOMPADDING",(0,0),(-1,-1),1),
                                  ("LINEBELOW",   (0,-1),(-1,-1), 0.5, C_BORDER),
                              ]))
                story.append(cmd_t)

            # Verify
            if action.get("verify"):
                ver_t = Table(
                    [[Paragraph(f"Verify: {_safe(action['verify'])}", S["verify"])]],
                    colWidths=[cw],
                    style=TableStyle([
                        ("BACKGROUND",  (0,0),(-1,-1), C_SURFACE),
                        ("LEFTPADDING", (0,0),(-1,-1), 10),
                        ("TOPPADDING",  (0,0),(-1,-1), 3),
                        ("BOTTOMPADDING",(0,0),(-1,-1),5),
                    ])
                )
                story.append(ver_t)

            story.append(_sp(2))
            global_idx += 1

    story.append(PageBreak())
    return story


def _build_context_factors(factors: dict, S: dict) -> list:
    if not factors:
        return []

    story = []
    story.append(SectionDivider("CONTEXT-AWARE RISK FACTORS", C_CYAN))
    story.append(_sp(1))
    story.append(Paragraph(
        "ปัจจัย environment เหล่านี้ถูกนำมาปรับ CVSS base score ให้สะท้อนความเสี่ยงจริงของระบบนี้",
        S["body_gray"]
    ))
    story.append(_sp(2))

    rows = [[
        Paragraph("Factor", S["label"]),
        Paragraph("Status", S["label"]),
        Paragraph("Weight", S["label"]),
        Paragraph("Description", S["label"]),
    ]]
    for key, factor in factors.items():
        active = factor.get("active", False)
        weight = factor.get("weight", 0.0)
        label  = factor.get("label_th", factor.get("label", key))
        w_col  = C_CRITICAL if weight > 0.5 else (C_LOW if weight < 0 else C_GRAY)
        s_col  = C_CRITICAL if (active and weight > 0) else (C_LOW if not active else C_GRAY)
        status = "RISK" if (active and weight > 0) else ("SAFE" if not active else "MITIGATING")
        rows.append([
            Paragraph(key.replace("_", " ").title(), S["body"]),
            Paragraph(status, ParagraphStyle("fs", fontName="Helvetica-Bold",
                                              fontSize=7, textColor=s_col)),
            Paragraph(f"{weight:+.1f}", ParagraphStyle("fw", fontName="Helvetica-Bold",
                                                         fontSize=8, textColor=w_col)),
            Paragraph(_safe(label[:80]), S["body_gray"]),
        ])

    cw = PAGE_W - MARGIN * 2
    tbl = Table(rows, colWidths=[3.5*cm, 2*cm, 1.5*cm, cw-7*cm],
                style=TableStyle([
                    ("BACKGROUND",  (0,0),(-1,0),  C_DARK_GRAY),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_SURFACE, C_DARK_GRAY]),
                    ("FONTSIZE",    (0,0),(-1,-1), 8),
                    ("TOPPADDING",  (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING",(0,0),(-1,-1),5),
                    ("LEFTPADDING", (0,0),(-1,-1), 8),
                    ("LINEBELOW",   (0,0),(-1,0),  0.5, C_BORDER),
                ]))
    story.append(tbl)
    story.append(PageBreak())
    return story


# ──────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────
def generate_pdf(report: dict, output_path: str) -> str:
    """
    สร้าง PDF report จาก combined report dict
    คืน path ของไฟล์ที่สร้าง
    """
    S = _build_styles()

    ts = report.get("timestamp", datetime.now().isoformat())
    try:
        ts_fmt = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        ts_fmt = ts

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN + 30,
        bottomMargin=MARGIN + 20,
        title="COSVINTE Security Report",
        author="COSVINTE Scanner",
        subject="Linux Privilege Escalation Assessment",
    )

    bg = PageBackground(report.get("tool", "COSVINTE"), ts_fmt)
    story = []

    # ── Cover Page ──
    story.extend(_build_cover(report, S))

    # ── Executive Summary ──
    chains = report.get("attack_chains", [])
    story.extend(_build_executive_summary(report, chains, S))

    # ── Scanner Sections ──
    # จาก combined report ดึงข้อมูลแต่ละ scanner
    scanner_keys = ["caps", "cron", "kernel", "path", "writable"]
    for key in scanner_keys:
        # หา findings ที่ตรงกับ scanner นี้จาก combined data
        scanner_report = _extract_scanner_data(report, key)
        if scanner_report:
            story.extend(_build_scanner_section(key, scanner_report, S))

    # ── Attack Chains ──
    if chains:
        story.extend(_build_attack_chains(chains, S))

    # ── Context Factors ──
    context_factors = report.get("context_factors", {})
    if context_factors:
        story.extend(_build_context_factors(context_factors, S))

    # ── Remediation Roadmap ──
    roadmap = report.get("remediation_roadmap", [])
    if roadmap:
        story.extend(_build_remediation(roadmap, S))

    doc.build(story, onFirstPage=bg, onLaterPages=bg)
    return output_path


def _extract_scanner_data(combined: dict, scanner_key: str) -> dict:
    """
    พยายามดึงข้อมูลของ scanner จาก combined report
    ทั้ง combined format และ single-scanner format
    """
    tool_map = {
        "caps":     "Capability",
        "cron":     "Cron",
        "kernel":   "Kernel",
        "path":     "PATH",
        "writable": "Writable",
    }
    keyword = tool_map.get(scanner_key, "")

    # ถ้า report มี tool field ตรงกับ scanner นี้ (single scanner mode)
    if keyword and keyword.lower() in str(combined.get("tool", "")).lower():
        return combined

    # สำหรับ combined report: สร้าง sub-report จาก findings ที่เกี่ยวข้อง
    findings = combined.get("findings", [])
    relevant = []

    if scanner_key == "caps":
        relevant = [f for f in findings if "capability" in f or "cap_" in str(f.get("capability",""))]
    elif scanner_key == "cron":
        relevant = [f for f in findings if f.get("category") in
                    ("File Permission", "Memory Corruption", "Buffer Overflow", "Permission", "Access Control")]
    elif scanner_key == "kernel":
        relevant = [f for f in findings if f.get("category") in
                    ("Race Condition", "Pipe Buffer", "Heap Overflow", "Use-After-Free")]
    elif scanner_key == "path":
        relevant = combined.get("path_analysis", []) + \
                   [f for f in combined.get("suid_binaries", []) if f]
    elif scanner_key == "writable":
        relevant = combined.get("writable_paths", [])

    if not relevant:
        return None

    return {
        "tool":     f"COSVINTE — {scanner_key.title()} Scanner",
        "system":   combined.get("system", {}),
        "summary":  {},
        "findings": relevant,
        "writable_paths": combined.get("writable_paths", []) if scanner_key == "writable" else [],
        "cve_correlations": combined.get("cve_correlations", []) if scanner_key == "writable" else [],
        "checks":   combined.get("checks", {}) if scanner_key == "cron" else {},
        "path_analysis": combined.get("path_analysis", []) if scanner_key == "path" else [],
    }


# ──────────────────────────────────────────────
# Standalone runner (test)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json, sys

    if len(sys.argv) < 2:
        print("Usage: python3 cosvinte_pdf_report.py <report.json> [output.pdf]")
        sys.exit(1)

    json_path = sys.argv[1]
    out_path  = sys.argv[2] if len(sys.argv) > 2 else json_path.replace(".json", ".pdf")

    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    result = generate_pdf(data, out_path)
    print(f"PDF generated: {result}")
