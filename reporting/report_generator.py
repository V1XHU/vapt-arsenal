#!/usr/bin/env python3
"""
report_generator.py - turn a findings JSON file into a polished PDF pentest report.

    python3 report_generator.py findings.example.json [output.pdf]

The JSON shape (see findings.example.json):
    {
      "org": "Your Security Co.",
      "client": "Example Corp",
      "title": "Web Application Penetration Test Report",
      "project_id": "PT-2026-001",
      "scope": [{"host": "app.example.com", "desc": "Primary web app (HTTPS)"}],
      "findings": [
        {
          "title": "...", "severity": "High", "cvss": "8.1",
          "description": ["para", "para"],
          "poc": ["step or code line", "..."],
          "recommendations": ["fix", "fix"]
        }
      ]
    }

Severity is one of: Critical, High, Medium, Low, Informational.
Fonts fall back to built-ins if no TTFs are found, so it runs anywhere reportlab does.
"""
import json
import os
import sys

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
                                Spacer, Table, TableStyle, PageBreak, NextPageTemplate)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ---------- palette (neutral, print-friendly) ----------
NAVY  = colors.HexColor("#15314B")
ACCENT = colors.HexColor("#1F6FEB")
INK   = colors.HexColor("#1b1f24")
MUTE  = colors.HexColor("#5b6670")
PANEL = colors.HexColor("#F4F6F8")
LINE  = colors.HexColor("#D5DCE3")
SEV = {
    "Critical":      colors.HexColor("#B00020"),
    "High":          colors.HexColor("#D9541E"),
    "Medium":        colors.HexColor("#B98900"),
    "Low":           colors.HexColor("#3B7A2A"),
    "Informational": colors.HexColor("#4A6572"),
}
SEVRANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# ---------- fonts: use TTFs if present, else built-ins ----------
BODY, BOLD, MONO = "Helvetica", "Helvetica-Bold", "Courier"
_FONT_DIRS = ["/mnt/c/Windows/Fonts", "/usr/share/fonts", os.path.expanduser("~/.fonts")]


def _find(name):
    for d in _FONT_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def _try_register():
    global BODY, BOLD, MONO
    reg = _find("calibri.ttf"); regb = _find("calibrib.ttf")
    monof = _find("consola.ttf") or _find("DejaVuSansMono.ttf")
    try:
        if reg and regb:
            pdfmetrics.registerFont(TTFont("Body", reg))
            pdfmetrics.registerFont(TTFont("Body-Bold", regb))
            BODY, BOLD = "Body", "Body-Bold"
        if monof:
            pdfmetrics.registerFont(TTFont("Mono", monof))
            MONO = "Mono"
    except Exception:  # noqa: BLE001
        pass


_try_register()
PW, PH = A4
LM = RM = 2.0 * cm
TM = 2.0 * cm
BM = 1.8 * cm
CW = PW - LM - RM


def st(name, **kw):
    kw.setdefault("fontName", BODY); kw.setdefault("textColor", INK)
    kw.setdefault("fontSize", 10); kw.setdefault("leading", kw["fontSize"] * 1.35)
    return ParagraphStyle(name, **kw)


body   = st("body", alignment=TA_JUSTIFY, spaceAfter=7)
h1     = st("h1", fontName=BOLD, textColor=NAVY, fontSize=17, spaceBefore=4, spaceAfter=10)
h2     = st("h2", fontName=BOLD, textColor=NAVY, fontSize=13, spaceBefore=6, spaceAfter=6)
findt  = st("findt", fontName=BOLD, textColor=NAVY, fontSize=12, spaceBefore=4, spaceAfter=6)
lbl    = st("lbl", fontName=BOLD, textColor=INK, fontSize=10.5, spaceBefore=6, spaceAfter=3)
bullet = st("bullet", leftIndent=14, bulletIndent=2, spaceAfter=3, fontSize=9.5)
codest = st("code", fontName=MONO, fontSize=7.8, leading=10.6, textColor=INK)
cover1 = st("cover1", fontName=BOLD, fontSize=24, alignment=TA_CENTER, textColor=NAVY, leading=30)
cover2 = st("cover2", fontName=BOLD, fontSize=15, alignment=TA_CENTER, textColor=ACCENT)
coversm = st("coversm", fontSize=12, alignment=TA_CENTER, textColor=MUTE)


def esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def code_block(lines):
    if isinstance(lines, str):
        lines = lines.split("\n")
    txt = "<br/>".join(esc(x) if x else "&nbsp;" for x in lines)
    t = Table([[Paragraph(txt, codest)]], colWidths=[CW])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def sev_table(sev, cvss):
    hs = st("th", fontName=BOLD, fontSize=10, textColor=colors.white, alignment=TA_CENTER)
    vs = st("tv", fontName=BODY, fontSize=10, textColor=INK, alignment=TA_CENTER)
    t = Table([[Paragraph("Severity", hs), Paragraph("CVSS v3.1", hs)],
               [Paragraph(f'<font color="white"><b>{esc(sev)}</b></font>', vs),
                Paragraph(esc(cvss), vs)]],
              colWidths=[CW * 0.5, CW * 0.5])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BACKGROUND", (0, 1), (0, 1), SEV.get(sev, MUTE)),
        ("BACKGROUND", (1, 1), (1, 1), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def kv_table(rows):
    data = [[Paragraph(f"<b>{esc(k)}</b>", st("k", textColor=colors.white)),
             Paragraph(esc(v), st("v"))] for k, v in rows]
    t = Table(data, colWidths=[CW * 0.3, CW * 0.7])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), NAVY),
        ("BACKGROUND", (1, 0), (1, -1), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def draw_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE); canvas.setLineWidth(0.5)
    canvas.line(LM, 1.3 * cm, PW - RM, 1.3 * cm)
    canvas.setFont(BODY, 8); canvas.setFillColor(MUTE)
    canvas.drawString(LM, 1.0 * cm, "Confidential")
    canvas.drawRightString(PW - RM, 1.0 * cm, str(canvas.getPageNumber()))
    canvas.restoreState()


def build(data, out):
    doc = BaseDocTemplate(out, pagesize=A4, leftMargin=LM, rightMargin=RM,
                          topMargin=TM, bottomMargin=BM,
                          title=data.get("title", "Penetration Test Report"),
                          author=data.get("org", "Security Assessment"))
    frame = Frame(LM, BM, CW, PH - TM - BM, id="f")
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[frame]),
        PageTemplate(id="Content", frames=[frame], onPage=draw_footer),
    ])
    s = []

    # cover
    s.append(Spacer(1, 5 * cm))
    s.append(Paragraph(esc(data.get("org", "Your Security Co.")), cover2))
    s.append(Spacer(1, 1.2 * cm))
    s.append(Paragraph(esc(data.get("title", "Penetration Test Report")), cover1))
    s.append(Spacer(1, 0.5 * cm))
    s.append(Paragraph(esc(data.get("client", "")), coversm))
    s.append(Spacer(1, 2.0 * cm))
    if data.get("project_id"):
        s.append(Paragraph("Project ID: " + esc(data["project_id"]), coversm))
    s.append(Paragraph("Report Date: ______________", coversm))
    s.append(NextPageTemplate("Content"))
    s.append(PageBreak())

    findings = sorted(data.get("findings", []),
                      key=lambda f: (SEVRANK.get(f.get("severity", "Low"), 3),
                                     -float(f.get("cvss", 0) or 0)))

    # executive summary
    s.append(Paragraph("Executive Summary", h1))
    counts = {k: 0 for k in SEVRANK}
    for f in findings:
        counts[f.get("severity", "Low")] = counts.get(f.get("severity", "Low"), 0) + 1
    s.append(Paragraph(
        f"This report documents {len(findings)} finding(s) identified during the assessment. "
        "Each finding is rated by severity and CVSS, with a proof of concept and remediation "
        "guidance. Findings are ordered most-severe first.", body))
    s.append(Spacer(1, 0.3 * cm))
    if data.get("scope"):
        s.append(Paragraph("Scope", h2))
        for sc in data["scope"]:
            s.append(Paragraph("&bull; <b>%s</b> &mdash; %s"
                               % (esc(sc.get("host", "")), esc(sc.get("desc", ""))), bullet))
        s.append(Spacer(1, 0.3 * cm))
    s.append(Paragraph("Findings by Severity", h2))
    rows = [[Paragraph("<b>Severity</b>", st("c", textColor=colors.white)),
             Paragraph("<b>Count</b>", st("c", textColor=colors.white))]]
    for sv in ["Critical", "High", "Medium", "Low", "Informational"]:
        if counts.get(sv):
            rows.append([Paragraph(f'<font color="#{SEV[sv].hexval()[2:]}"><b>{sv}</b></font>',
                                   st("c")), Paragraph(str(counts[sv]), st("c"))])
    t = Table(rows, colWidths=[CW * 0.3, CW * 0.2]); t.hAlign = "LEFT"
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    s.append(t)
    s.append(PageBreak())

    # findings
    s.append(Paragraph("Detailed Findings", h1))
    for i, f in enumerate(findings, 1):
        s.append(Paragraph("%d. %s" % (i, esc(f.get("title", "Untitled"))), findt))
        s.append(sev_table(f.get("severity", "Low"), f.get("cvss", "N/A")))
        s.append(Spacer(1, 0.2 * cm))
        s.append(Paragraph("Description", lbl))
        for d in f.get("description", []):
            s.append(Paragraph(esc(d), body))
        if f.get("poc"):
            s.append(Paragraph("Proof of Concept", lbl))
            s.append(code_block(f["poc"]))
        if f.get("recommendations"):
            s.append(Paragraph("Recommendations", lbl))
            for r in f["recommendations"]:
                s.append(Paragraph(esc(r), bullet, bulletText=u"•"))
        s.append(PageBreak())

    doc.build(s)
    print("[+] wrote", out)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: report_generator.py findings.json [out.pdf]")
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".pdf"
    with open(src, encoding="utf-8") as fh:
        data = json.load(fh)
    build(data, out)


if __name__ == "__main__":
    main()
