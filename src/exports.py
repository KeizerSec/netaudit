"""
Exports alternatifs du rapport de scan : JSON brut et PDF structuré.

Le PDF est généré directement avec reportlab (pas de HTML→PDF via xhtml2pdf/
WeasyPrint), pour deux raisons :
- reportlab est un unique paquet pip sans dépendances transitives lourdes,
  ce qui garde l'image Docker slim.
- La conversion HTML→PDF produit souvent un rendu dégradé du dark-mode et
  du kill chain visuel. Un PDF reconstruit directement depuis la data
  donne un document d'audit net, imprimable, sans dépendre du template HTML.
"""
from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

_RISK_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH":     colors.HexColor("#F97316"),
    "MEDIUM":   colors.HexColor("#EAB308"),
    "LOW":      colors.HexColor("#22C55E"),
}


def _style_for_risk(risk: str) -> colors.Color:
    return _RISK_COLORS.get((risk or "").upper(), colors.HexColor("#64748B"))


def _build_header(data: dict, styles) -> list:
    title = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0F172A"),
        spaceAfter=4,
    )
    subtitle = ParagraphStyle(
        "Subtitle", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor("#475569"), spaceAfter=12,
    )
    flow = [
        Paragraph(f"Rapport NetAudit — {data.get('ip', '?')}", title),
        Paragraph(
            f"Scan du {data.get('scan_date', '?')} "
            f"— hôte {'actif' if data.get('host_up') else 'inactif'}",
            subtitle,
        ),
    ]

    hostname = data.get("hostname") or ""
    os_guess = data.get("os_guess") or ""
    if hostname or os_guess:
        details = []
        if hostname:
            details.append(f"<b>Nom DNS :</b> {hostname}")
        if os_guess:
            details.append(f"<b>OS supposé :</b> {os_guess}")
        flow.append(Paragraph(" &nbsp;•&nbsp; ".join(details), styles["Normal"]))
        flow.append(Spacer(1, 6))
    return flow


def _build_attack_summary(data: dict, styles) -> list:
    summary = data.get("attack_summary") or {}
    if not summary:
        return []

    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor("#0F172A"), spaceBefore=12, spaceAfter=6,
    )
    risk = summary.get("risk_level", "?")
    risk_color = _style_for_risk(risk)

    flow = [
        Paragraph("Synthèse MITRE ATT&amp;CK", h2),
        Paragraph(
            f'<b>Niveau de risque :</b> '
            f'<font color="{risk_color.hexval()}"><b>{risk}</b></font> &nbsp;•&nbsp; '
            f'Phases kill chain actives : <b>{summary.get("phases_count", 0)}</b> &nbsp;•&nbsp; '
            f'Total vulnérabilités : <b>{data.get("total_vulns", 0)}</b>',
            styles["Normal"],
        ),
        Spacer(1, 4),
    ]

    priorities = summary.get("detection_priorities") or []
    if priorities:
        flow.append(Paragraph("<b>Priorités de détection :</b>", styles["Normal"]))
        for p in priorities[:5]:
            flow.append(Paragraph(f"• {p}", styles["Normal"]))
        flow.append(Spacer(1, 6))

    phases = summary.get("phases") or []
    if phases:
        rows = [["Tactique", "Techniques"]]
        for phase in phases:
            techs = ", ".join(t.get("id", "?") for t in phase.get("techniques", []))
            rows.append([phase.get("tactic", "?"), techs or "—"])
        tbl = Table(rows, colWidths=[55 * mm, 110 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        flow.append(tbl)
    return flow


def _build_ports_table(data: dict, styles) -> list:
    ports = data.get("ports") or []
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor("#0F172A"), spaceBefore=12, spaceAfter=6,
    )
    flow = [Paragraph(f"Ports et vulnérabilités ({len(ports)})", h2)]
    if not ports:
        flow.append(Paragraph("<i>Aucun port détecté.</i>", styles["Normal"]))
        return flow

    cell = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8, leading=10)
    rows = [["Port", "Service", "Version", "CVEs (id / CVSS)"]]
    for port in ports:
        vulns = port.get("vulns") or []
        if vulns:
            lines = []
            for v in vulns[:10]:
                try:
                    score = float(v.get("score", 0) or 0)
                except (TypeError, ValueError):
                    score = 0.0
                color = _score_color(score).hexval()
                lines.append(f'{v.get("id", "?")} (<font color="{color}">{score:.1f}</font>)')
            vuln_lines = "<br/>".join(lines)
            if len(vulns) > 10:
                vuln_lines += f"<br/><i>+ {len(vulns) - 10} autres</i>"
        else:
            vuln_lines = "—"
        rows.append([
            Paragraph(f"{port.get('port', '?')}/{port.get('protocol', '')}", cell),
            Paragraph(port.get("service", "") or "—", cell),
            Paragraph(port.get("version", "") or "—", cell),
            Paragraph(vuln_lines, cell),
        ])

    tbl = Table(rows, colWidths=[20 * mm, 25 * mm, 50 * mm, 70 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 9),
        ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    flow.append(tbl)
    return flow


def _score_color(score: float) -> colors.Color:
    try:
        s = float(score)
    except (TypeError, ValueError):
        s = 0.0
    if s >= 9.0:
        return colors.HexColor("#DC2626")
    if s >= 7.0:
        return colors.HexColor("#F97316")
    if s >= 4.0:
        return colors.HexColor("#EAB308")
    return colors.HexColor("#22C55E")


def render_pdf(data: dict) -> bytes:
    """Rend le rapport en PDF A4 et retourne les octets.

    Structure : en-tête (IP, date, hôte) → synthèse ATT&CK (risk level,
    priorités de détection, phases kill chain) → tableau détaillé des ports
    avec CVEs colorisées selon le score CVSS.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"NetAudit — {data.get('ip', '?')}",
        author="NetAudit",
    )
    styles = getSampleStyleSheet()

    story: list[Any] = []
    story.extend(_build_header(data, styles))
    story.extend(_build_attack_summary(data, styles))
    story.extend(_build_ports_table(data, styles))

    doc.build(story)
    return buffer.getvalue()
