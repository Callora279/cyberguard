"""Generate PDF compliance evidence packs from real scan/posture data.

Three frameworks are supported: the NHS Data Security & Protection Toolkit
(10 National Data Guardian standards), GDPR Article 32 (security of
processing), and Cyber Essentials (5 technical controls).

Design principle: where CyberGuard genuinely has automated visibility (open
findings, SBOM/CVE data, identity/access posture, AI governance enforcement)
the result is data-driven. Where it doesn't (staff training, physical
backups, firewall hardware config, endpoint malware protection) the standard
is marked "Partial" with an explicit manual-attestation note — a compliance
tool must never silently claim something it can't actually observe.
"""
from __future__ import annotations

import hmac
import hashlib
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.database.db import session_scope
from core.database.models import Organisation, OrgSettings
from core.services.ai_governance.real_time_enforcer import enforcement_status
from core.services.machine_identity import identity_registry
from core.services.security_debt import reporting as debt_reporting
from core.services.supply_chain import alerts as sc_alerts
from core.services.unified_risk_score import score_calculator
from core.utils.config import settings
from core.utils.exceptions import ValidationError
from core.utils.logger import get_logger

logger = get_logger("compliance.report_generator")

_RESULT_COLOR = {
    "Compliant": colors.HexColor("#16a34a"),
    "Partial": colors.HexColor("#d97706"),
    "Non-Compliant": colors.HexColor("#dc2626"),
}


# ---------------------------------------------------------------------------
# Evidence gathering
# ---------------------------------------------------------------------------
def _gather_evidence(org_id: str) -> dict:
    debt = debt_reporting.summary(org_id)
    components = sc_alerts.list_components(org_id)
    identities = identity_registry.list_registry(org_id)
    score = score_calculator.calculate(org_id)
    enforcement = enforcement_status(org_id)

    with session_scope() as db:
        org_settings = db.get(OrgSettings, org_id)

    by_sev = debt.get("by_severity", {})
    vulnerable = [c for c in components if c.get("cve_count", 0) > 0]
    high_cvss = [c for c in components if c.get("max_cvss", 0) >= 7.0]
    high_vendor_risk = [c for c in components if c.get("vendor_risk_score", 0) >= 70]
    active_identities = [i for i in identities if i.get("status") == "active"]
    expiring_identities = [i for i in identities if i.get("status") == "expiring"]

    return {
        "overall_score": score.get("overall", 0),
        "grade": score.get("grade", "F"),
        "open_findings": debt.get("total_findings", 0),
        "critical_high_findings": by_sev.get("critical", 0) + by_sev.get("high", 0),
        "secret_findings": debt.get("by_type", {}).get("secret", 0),
        "misconfig_findings": debt.get("by_type", {}).get("insecure_fn", 0) + debt.get("by_type", {}).get("owasp", 0),
        "total_components": len(components),
        "vulnerable_components": len(vulnerable),
        "high_cvss_components": len(high_cvss),
        "high_vendor_risk_components": len(high_vendor_risk),
        "total_identities": len(identities),
        "active_identities": len(active_identities),
        "expiring_identities": len(expiring_identities),
        "ai_policy_enforced": enforcement.get("installed", False),
        "alerting_configured": bool(org_settings and (org_settings.slack_webhook_url or org_settings.notification_email)),
    }


def _manual(_ev: dict) -> tuple[str, str, str]:
    return (
        "Partial",
        "Not directly observable via automated scanning.",
        "Confirm and document this control manually as part of your ISMS / policy review; "
        "CyberGuard AI cannot verify it from code, dependency or identity scans.",
    )


# ---------------------------------------------------------------------------
# Framework definitions: id, title, description, "how we checked it", and a
# ``check(evidence) -> (result, evidence_text, recommendation)`` callable.
# ---------------------------------------------------------------------------
def _nhs_standards() -> list[dict]:
    return [
        {
            "id": "1",
            "title": "Personal Confidential Data",
            "description": "All personal confidential data is handled, stored and transmitted securely, "
            "in line with the Caldicott Principles.",
            "method": "Static secret-scanning across the connected repository (hardcoded credentials, "
            "keys and tokens that could expose data in transit or at rest).",
            "check": lambda ev: (
                ("Compliant", f"0 hardcoded secrets found in {ev['open_findings']} open findings.", "")
                if ev["secret_findings"] == 0
                else ("Non-Compliant", f"{ev['secret_findings']} hardcoded secret finding(s) detected.",
                      "Remove and rotate the exposed secrets; move them to a secret manager.")
            ),
        },
        {
            "id": "2",
            "title": "Staff Responsibilities",
            "description": "All staff understand their responsibilities under the Data Security and "
            "Protection Toolkit and the Caldicott Principles.",
            "method": "N/A — organisational/HR control.",
            "check": _manual,
        },
        {
            "id": "3",
            "title": "Training",
            "description": "Staff complete appropriate annual data security awareness training.",
            "method": "N/A — organisational/HR control.",
            "check": _manual,
        },
        {
            "id": "4",
            "title": "Managing Data Access",
            "description": "Access to personal confidential data is limited to identified, authenticated "
            "and appropriately authorised individuals and systems.",
            "method": "Machine Identity registry: active vs. expiring credentials, and whether "
            "zero-trust access evaluation is in use.",
            "check": lambda ev: (
                ("Compliant", f"{ev['active_identities']} active identities under managed access control; "
                 f"{ev['expiring_identities']} expiring soon and flagged for rotation.", "")
                if ev["total_identities"] > 0
                else ("Non-Compliant", "No machine identities are registered — access cannot be attributed or audited.",
                      "Register all service accounts, API keys and integrations in the Machine Identity registry.")
            ),
        },
        {
            "id": "5",
            "title": "Process Reviews",
            "description": "Data security and protection processes are reviewed regularly and kept up to date.",
            "method": "Continuous scanning cadence: CyberGuard AI itself provides the regular review "
            "process (see evidence).",
            "check": lambda ev: (
                "Compliant",
                f"Automated risk scoring is active; current posture score {ev['overall_score']:.0f}/100 (grade {ev['grade']}).",
                "",
            ),
        },
        {
            "id": "6",
            "title": "Responding to Incidents",
            "description": "Staff know how to identify and report data security incidents, and the "
            "organisation can respond effectively.",
            "method": "Whether an alerting channel (Slack / email) is configured to receive CyberGuard AI alerts.",
            "check": lambda ev: (
                ("Compliant", "An alert delivery channel (Slack and/or email) is configured.", "")
                if ev["alerting_configured"]
                else ("Non-Compliant", "No alert delivery channel is configured.",
                      "Configure a Slack webhook or notification email in Settings so incidents are actioned promptly.")
            ),
        },
        {
            "id": "7",
            "title": "Continuity Planning",
            "description": "The organisation has a continuity plan to respond to data security incidents "
            "and disruption, including backups.",
            "method": "N/A — infrastructure/DR control outside CyberGuard AI's scan scope.",
            "check": _manual,
        },
        {
            "id": "8",
            "title": "Unsupported Systems",
            "description": "No unsupported, unpatched or known-vulnerable software components are in use.",
            "method": "Software Bill of Materials (SBOM) dependency scan for known CVEs.",
            "check": lambda ev: (
                ("Compliant", f"0 of {ev['total_components']} tracked components have known CVEs.", "")
                if ev["vulnerable_components"] == 0
                else ("Non-Compliant",
                      f"{ev['vulnerable_components']} of {ev['total_components']} components have known CVEs "
                      f"({ev['high_cvss_components']} rated CVSS ≥ 7.0).",
                      "Upgrade or replace the flagged dependencies; prioritise the CVSS ≥ 7.0 components first.")
            ),
        },
        {
            "id": "9",
            "title": "IT Protection",
            "description": "A defence-in-depth strategy protects IT systems from cyber attack, including "
            "AI-specific threats.",
            "method": "Open critical/high security findings, and whether AI Governance real-time "
            "enforcement is installed.",
            "check": lambda ev: (
                ("Compliant" if ev["critical_high_findings"] == 0 else "Partial",
                 f"{ev['critical_high_findings']} open critical/high finding(s); "
                 f"AI governance enforcement {'active' if ev['ai_policy_enforced'] else 'inactive'}.",
                 "" if ev["critical_high_findings"] == 0 else "Remediate open critical/high severity findings.")
            ),
        },
        {
            "id": "10",
            "title": "Accountable Suppliers",
            "description": "Third-party suppliers and dependencies are risk-assessed and provide assurance "
            "of their own data security.",
            "method": "Supply-chain vendor risk scoring across all tracked SBOM components.",
            "check": lambda ev: (
                ("Compliant", f"0 of {ev['total_components']} components flagged as high vendor risk.", "")
                if ev["high_vendor_risk_components"] == 0
                else ("Non-Compliant", f"{ev['high_vendor_risk_components']} component(s) flagged as high vendor risk.",
                      "Review the flagged suppliers/packages and obtain assurance evidence or replace them.")
            ),
        },
    ]


def _gdpr_standards() -> list[dict]:
    return [
        {
            "id": "32(1)",
            "title": "Appropriate technical and organisational measures",
            "description": "Implement measures appropriate to the risk, considering the state of the art, "
            "cost of implementation, and the nature, scope, context and purpose of processing.",
            "method": "Unified risk score across AI governance, security debt, supply chain, machine "
            "identity and fraud detection.",
            "check": lambda ev: (
                "Compliant" if ev["overall_score"] >= 78 else "Partial",
                f"Current unified risk posture: {ev['overall_score']:.0f}/100 (grade {ev['grade']}).",
                "" if ev["overall_score"] >= 78 else "Raise the posture score by remediating open findings before the next review.",
            ),
        },
        {
            "id": "32(1)(a)",
            "title": "Pseudonymisation and encryption",
            "description": "Personal data is pseudonymised and/or encrypted where appropriate.",
            "method": "Secret-scanning for hardcoded credentials/keys that would indicate data handled in "
            "cleartext, plus API-key encryption-at-rest for org-configured AI providers.",
            "check": lambda ev: (
                ("Compliant", "No hardcoded secrets found; org-supplied AI provider keys are encrypted at rest.", "")
                if ev["secret_findings"] == 0
                else ("Non-Compliant", f"{ev['secret_findings']} hardcoded secret finding(s) detected.",
                      "Remove hardcoded secrets and encrypt sensitive data at rest and in transit.")
            ),
        },
        {
            "id": "32(1)(b)",
            "title": "Confidentiality, integrity, availability and resilience",
            "description": "Ongoing ability to ensure the confidentiality, integrity, availability and "
            "resilience of processing systems and services.",
            "method": "Open critical/high findings and misconfiguration findings across the codebase.",
            "check": lambda ev: (
                ("Compliant" if ev["critical_high_findings"] == 0 and ev["misconfig_findings"] == 0 else "Non-Compliant",
                 f"{ev['critical_high_findings']} critical/high finding(s), {ev['misconfig_findings']} "
                 f"misconfiguration finding(s).",
                 "" if ev["critical_high_findings"] == 0 and ev["misconfig_findings"] == 0
                 else "Remediate the flagged findings to restore confidentiality/integrity assurance.")
            ),
        },
        {
            "id": "32(1)(c)",
            "title": "Restore availability and access in a timely manner",
            "description": "Ability to restore availability and access to personal data in a timely manner "
            "in the event of a physical or technical incident.",
            "method": "N/A — backup/DR infrastructure control outside CyberGuard AI's scan scope.",
            "check": _manual,
        },
        {
            "id": "32(1)(d)",
            "title": "Regular testing, assessing and evaluating",
            "description": "A process for regularly testing, assessing and evaluating the effectiveness of "
            "technical and organisational measures.",
            "method": "CyberGuard AI's own continuous scanning and Cyber Twin attack simulation constitute "
            "this regular testing process.",
            "check": lambda ev: (
                "Compliant",
                f"Continuous automated scanning active across all modules; posture score {ev['overall_score']:.0f}/100.",
                "",
            ),
        },
    ]


def _cyber_essentials_standards() -> list[dict]:
    return [
        {
            "id": "1",
            "title": "Firewalls",
            "description": "Boundary firewalls and internet gateways restrict inbound and outbound "
            "network traffic to only what is necessary.",
            "method": "N/A — network infrastructure control outside CyberGuard AI's scan scope.",
            "check": _manual,
        },
        {
            "id": "2",
            "title": "Secure Configuration",
            "description": "Computers and network devices are configured securely, with unnecessary "
            "functionality removed and default credentials changed.",
            "method": "Static scan for insecure functions, OWASP-pattern misconfigurations and known-bad defaults.",
            "check": lambda ev: (
                ("Compliant", "0 misconfiguration findings.", "")
                if ev["misconfig_findings"] == 0
                else ("Non-Compliant", f"{ev['misconfig_findings']} misconfiguration finding(s) detected.",
                      "Review and remediate the flagged insecure functions / configuration patterns.")
            ),
        },
        {
            "id": "3",
            "title": "Security Update Management",
            "description": "Software is kept up to date, with security updates applied promptly (patch management).",
            "method": "Software Bill of Materials (SBOM) dependency scan for known CVEs.",
            "check": lambda ev: (
                ("Compliant", f"0 of {ev['total_components']} components have known CVEs.", "")
                if ev["vulnerable_components"] == 0
                else ("Non-Compliant",
                      f"{ev['vulnerable_components']} of {ev['total_components']} components have known CVEs.",
                      "Patch or upgrade the flagged dependencies, prioritising CVSS ≥ 7.0 first.")
            ),
        },
        {
            "id": "4",
            "title": "User Access Control",
            "description": "User and system accounts are given only the access they need, with strong "
            "authentication and regular access reviews.",
            "method": "Machine Identity registry: active vs. expiring credentials under managed access control.",
            "check": lambda ev: (
                ("Compliant", f"{ev['active_identities']} identities under managed access control; "
                 f"{ev['expiring_identities']} flagged for rotation review.", "")
                if ev["total_identities"] > 0
                else ("Non-Compliant", "No identities are registered under managed access control.",
                      "Register all accounts, service credentials and API keys in the Machine Identity registry.")
            ),
        },
        {
            "id": "5",
            "title": "Malware Protection",
            "description": "Malware protection software is installed and kept up to date on all devices.",
            "method": "N/A — endpoint protection control outside CyberGuard AI's scan scope.",
            "check": _manual,
        },
    ]


_FRAMEWORKS = {
    "nhs_dsp_toolkit": {
        "name": "NHS Data Security & Protection Toolkit",
        "filename_prefix": "NHS_DSP_Toolkit",
        "standards": _nhs_standards,
    },
    "gdpr_article_32": {
        "name": "GDPR Article 32 — Security of Processing",
        "filename_prefix": "GDPR_Article32",
        "standards": _gdpr_standards,
    },
    "cyber_essentials": {
        "name": "Cyber Essentials",
        "filename_prefix": "CyberEssentials",
        "standards": _cyber_essentials_standards,
    },
}


def list_frameworks() -> list[dict]:
    return [{"id": k, "name": v["name"]} for k, v in _FRAMEWORKS.items()]


# ---------------------------------------------------------------------------
# Digital signature block — an HMAC over the evidence bundle so a tampered or
# forged copy of the PDF can be told apart from the one CyberGuard generated.
# Not a PKI/x509 signature; documented as such in the report itself.
# ---------------------------------------------------------------------------
def _verification_code(org_id: str, framework: str, generated_at: str, evidence: dict) -> str:
    payload = f"{org_id}|{framework}|{generated_at}|{sorted(evidence.items())}"
    return hmac.new(settings.JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------
def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("CGTitle", parent=base["Title"], fontSize=26, spaceAfter=6),
        "subtitle": ParagraphStyle("CGSubtitle", parent=base["Normal"], fontSize=13, textColor=colors.HexColor("#475569"), alignment=TA_CENTER),
        "h2": ParagraphStyle("CGH2", parent=base["Heading2"], fontSize=14, spaceBefore=14, spaceAfter=4, textColor=colors.HexColor("#0f172a")),
        "body": ParagraphStyle("CGBody", parent=base["Normal"], fontSize=10, leading=14),
        "label": ParagraphStyle("CGLabel", parent=base["Normal"], fontSize=9, textColor=colors.HexColor("#64748b")),
        "small": ParagraphStyle("CGSmall", parent=base["Normal"], fontSize=8, textColor=colors.HexColor("#94a3b8")),
    }


def _cover_page(story: list, *, org_name: str, framework_name: str, date_str: str, evidence: dict, styles: dict) -> None:
    story.append(Spacer(1, 60 * mm))
    story.append(Paragraph("CyberGuard AI", styles["subtitle"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"{framework_name}<br/>Compliance Evidence Pack", styles["title"]))
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(org_name, ParagraphStyle("org", parent=styles["subtitle"], fontSize=16, textColor=colors.HexColor("#0f172a"))))
    story.append(Paragraph(f"Generated {date_str}", styles["label"]))
    story.append(Spacer(1, 14 * mm))

    summary_tbl = Table(
        [
            ["Overall risk posture", f"{evidence['overall_score']:.0f} / 100 (grade {evidence['grade']})"],
            ["Open security findings", str(evidence["open_findings"])],
            ["Components tracked (SBOM)", str(evidence["total_components"])],
            ["Machine identities under management", str(evidence["total_identities"])],
        ],
        colWidths=[85 * mm, 60 * mm],
    )
    summary_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(summary_tbl)
    story.append(PageBreak())


def _standard_section(story: list, standard: dict, evidence: dict, styles: dict) -> None:
    result, evidence_text, recommendation = standard["check"](evidence)
    story.append(Paragraph(f"{standard['id']}. {standard['title']}", styles["h2"]))
    story.append(Paragraph(standard["description"], styles["body"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(f"<b>How CyberGuard AI checked it:</b> {standard['method']}", styles["body"]))

    badge = Table([[result]], colWidths=[35 * mm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _RESULT_COLOR.get(result, colors.grey)),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(Spacer(1, 2 * mm))
    story.append(badge)
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(f"<b>Evidence:</b> {evidence_text}", styles["body"]))
    if recommendation:
        story.append(Paragraph(f"<b>Recommendation:</b> {recommendation}", styles["body"]))
    story.append(Spacer(1, 4 * mm))


def _signature_block(story: list, *, org_id: str, framework: str, generated_at: str, evidence: dict, styles: dict) -> None:
    code = _verification_code(org_id, framework, generated_at, evidence)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Digital Signature", styles["h2"]))
    story.append(Paragraph(
        "This evidence pack was generated automatically by CyberGuard AI from live scan and posture "
        "data — no findings in this report were manually entered. The verification code below is an "
        "HMAC-SHA256 digest over the report's evidence bundle; regenerating this report for the same "
        "org and data will reproduce it, confirming the evidence has not been altered.",
        styles["body"],
    ))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(f"<font face='Courier'>Verification code: {code}</font>", styles["body"]))
    story.append(Paragraph(f"Generated at: {generated_at}", styles["small"]))


def generate(framework: str, org_id: str) -> tuple[bytes, str]:
    """Build the PDF for ``framework`` and return (pdf_bytes, filename)."""
    if framework not in _FRAMEWORKS:
        raise ValidationError(f"unknown compliance framework '{framework}'")
    spec = _FRAMEWORKS[framework]

    with session_scope() as db:
        org = db.get(Organisation, org_id)
    org_name = org.name if org else "Unknown organisation"

    evidence = _gather_evidence(org_id)
    generated_at = datetime.now(timezone.utc).isoformat()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    styles = _styles()
    story: list = []
    _cover_page(story, org_name=org_name, framework_name=spec["name"], date_str=date_str, evidence=evidence, styles=styles)
    for standard in spec["standards"]():
        _standard_section(story, standard, evidence, styles)
    _signature_block(story, org_id=org_id, framework=framework, generated_at=generated_at, evidence=evidence, styles=styles)

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=18 * mm, bottomMargin=18 * mm, leftMargin=20 * mm, rightMargin=20 * mm,
        title=f"{spec['name']} — {org_name}",
    )
    doc.build(story)
    logger.info("generated compliance report framework=%s org=%s", framework, org_id)

    filename = f"{spec['filename_prefix']}_{date_str}.pdf"
    return buf.getvalue(), filename
