import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports_output')
os.makedirs(OUTPUT_DIR, exist_ok=True)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#d32f2f"),
    "High":     colors.HexColor("#f57c00"),
    "Medium":   colors.HexColor("#fbc02d"),
    "Low":      colors.HexColor("#388e3c"),
}

RISK_SCORES = {"Critical": 95, "High": 80, "Medium": 55, "Low": 20}


def _overall_risk_score(vulns):
    if not vulns:
        return 0
    weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    total = sum(weights.get(v.get("severity", "Low"), 1) for v in vulns)
    max_possible = len(vulns) * 4
    return min(100, int((total / max_possible) * 100)) if max_possible else 0


def generate_report(target_url: str, vulnerabilities: list,
                    waf_stats: dict = None, report_type: str = "technical") -> str:
    """
    Generate a PDF security report.

    Args:
        target_url: The scanned target URL
        vulnerabilities: List of vulnerability dicts
        waf_stats: Optional WAF statistics dict
        report_type: 'technical' | 'executive' | 'waf'

    Returns:
        Absolute path to the generated PDF
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"bensec_{report_type}_report_{timestamp}.pdf"
    filepath = os.path.join(OUTPUT_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontSize=20, textColor=colors.HexColor("#1a1a2e"),
                                 spaceAfter=6)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"],
                              fontSize=14, textColor=colors.HexColor("#16213e"),
                              spaceBefore=12, spaceAfter=4)
    body_style = styles["Normal"]

    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("Bensec Security Platform", title_style))
    story.append(Paragraph(f"{report_type.capitalize()} Security Report", h2_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#7c3aed")))
    story.append(Spacer(1, 0.4*cm))

    meta = [
        ["Target URL", target_url],
        ["Report Type", report_type.capitalize()],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Total Findings", str(len(vulnerabilities))],
        ["Overall Risk Score", f"{_overall_risk_score(vulnerabilities)} / 100"],
    ]
    meta_table = Table(meta, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Severity Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Vulnerability Summary", h2_style))
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_data = [["Severity", "Count", "Risk Level"]]
    for sev in ["Critical", "High", "Medium", "Low"]:
        summary_data.append([sev, str(severity_counts[sev]),
                              "Immediate Action" if sev == "Critical"
                              else "High Priority" if sev == "High"
                              else "Moderate" if sev == "Medium"
                              else "Informational"])

    summary_table = Table(summary_data, colWidths=[5*cm, 3*cm, 9*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
    ]))
    # Color severity cells
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"], start=1):
        c = SEVERITY_COLORS.get(sev, colors.grey)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, i), (0, i), c),
            ("TEXTCOLOR", (0, i), (0, i), colors.white),
        ]))

    story.append(summary_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Detailed Findings ─────────────────────────────────────────────────────
    if report_type in ("technical", "executive"):
        story.append(Paragraph("Detailed Findings", h2_style))

        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities detected.", body_style))
        else:
            for idx, v in enumerate(vulnerabilities, 1):
                sev = v.get("severity", "Low")
                sev_color = SEVERITY_COLORS.get(sev, colors.grey)

                finding_data = [
                    [f"Finding #{idx}", f"[{sev}] {v.get('vuln_type', 'Unknown')}"],
                    ["Affected URL", v.get("affected_url", "N/A")],
                    ["Parameter", v.get("parameter") or "N/A"],
                    ["Payload", v.get("payload") or "N/A"],
                    ["Description", v.get("description", "")],
                ]

                t = Table(finding_data, colWidths=[4*cm, 13*cm])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), sev_color),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f0f0f0")),
                    ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                story.append(t)
                story.append(Spacer(1, 0.3*cm))

    # ── WAF Section ───────────────────────────────────────────────────────────
    if report_type in ("waf", "technical") and waf_stats:
        story.append(Paragraph("WAF Statistics", h2_style))
        waf_data = [
            ["Total Blocked Requests", str(waf_stats.get("total", 0))],
        ]
        for row in waf_stats.get("by_type", []):
            waf_data.append([f"  {row['attack_type']}", str(row['count'])])

        wt = Table(waf_data, colWidths=[8*cm, 9*cm])
        wt.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
        ]))
        story.append(wt)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Paragraph(
        "Generated by Bensec Security Platform | For authorized testing only",
        ParagraphStyle("footer", parent=styles["Normal"],
                       fontSize=8, textColor=colors.grey, alignment=1)
    ))

    doc.build(story)
    return filepath
