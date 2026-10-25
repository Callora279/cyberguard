"""Rendered content for each notification type — email (subject/html/text) and
Slack (Block Kit). Kept pure so they are trivially testable."""
from __future__ import annotations

from core.utils.config import settings

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}


def _link(path: str = "") -> str:
    return f"{settings.FRONTEND_URL.rstrip('/')}/{path.lstrip('/')}"


# --------------------------------------------------------------------------- #
# EMAIL
# --------------------------------------------------------------------------- #
def critical_alert_email(finding: dict) -> dict:
    title = finding.get("title") or finding.get("description") or "Security finding"
    file_ref = finding.get("file_path") or finding.get("file") or "—"
    line = finding.get("line")
    where = f"{file_ref}:{line}" if line else file_ref
    rec = finding.get("recommendation") or finding.get("remediation") or "Review and remediate."
    html = (
        f"<h2>🔴 Critical Security Alert</h2>"
        f"<p><strong>Finding:</strong> {title}</p>"
        f"<p><strong>Severity:</strong> Critical<br>"
        f"<strong>Location:</strong> {where}</p>"
        f"<p><strong>Recommended action:</strong><br>{rec}</p>"
        f'<p><a href="{_link("security-debt")}">View in CyberGuard AI</a></p>'
    )
    text = (
        f"CRITICAL SECURITY ALERT\n\nFinding: {title}\nSeverity: Critical\n"
        f"Location: {where}\n\nRecommended action:\n{rec}\n\n{_link('security-debt')}"
    )
    return {"subject": "🔴 Critical Security Alert — CyberGuard AI", "html": html, "text": text}


def fraud_alert_email(fraud: dict) -> dict:
    score = fraud.get("fraud_score", fraud.get("score", 0.0))
    verdict = fraud.get("verdict", "review")
    reasons = fraud.get("reasons", []) or []
    subject_ref = fraud.get("subject") or fraud.get("document") or "document"
    reasons_html = "".join(f"<li>{r}</li>" for r in reasons[:12]) or "<li>—</li>"
    html = (
        f"<h2>⚠️ Fraud Risk Detected</h2>"
        f"<p><strong>Score:</strong> {score:.2f} &nbsp; <strong>Verdict:</strong> {verdict}</p>"
        f"<p><strong>Document:</strong> {subject_ref}</p>"
        f"<p><strong>Reasons:</strong></p><ul>{reasons_html}</ul>"
        f'<p><a href="{_link("fraud-detection")}">Review in CyberGuard AI</a></p>'
    )
    text = (
        f"FRAUD RISK DETECTED\n\nScore: {score:.2f}\nVerdict: {verdict}\n"
        f"Document: {subject_ref}\n\nReasons:\n"
        + "\n".join(f"- {r}" for r in reasons[:12])
        + f"\n\n{_link('fraud-detection')}"
    )
    return {"subject": f"⚠️ Fraud Risk Detected — Score: {score:.2f}", "html": html, "text": text}


def credential_expiring_email(cred: dict) -> dict:
    name = cred.get("name", "credential")
    days = cred.get("days_left", cred.get("days", "?"))
    html = (
        f"<h2>🔑 Credential Expiring Soon</h2>"
        f"<p><strong>{name}</strong> ({cred.get('type', 'credential')}) expires in "
        f"<strong>{days} day(s)</strong>.</p>"
        f"<p>Rotate it before it lapses to avoid an outage.</p>"
        f'<p><a href="{_link("machine-identity")}">Manage machine identities</a></p>'
    )
    text = (
        f"CREDENTIAL EXPIRING\n\n{name} ({cred.get('type', 'credential')}) expires in "
        f"{days} day(s). Rotate it now.\n\n{_link('machine-identity')}"
    )
    return {"subject": f"🔑 Credential expiring in {days} days — CyberGuard AI", "html": html, "text": text}


def risk_drop_email(before: float, after: float, org_name: str) -> dict:
    delta = round(after - before, 1)
    html = (
        f"<h2>📉 Security Score Dropped</h2>"
        f"<p>{org_name}'s unified risk score moved from <strong>{before}</strong> to "
        f"<strong>{after}</strong> ({delta:+}).</p>"
        f'<p><a href="{_link()}">Open the dashboard</a></p>'
    )
    text = (
        f"SECURITY SCORE DROPPED\n\n{org_name}: {before} -> {after} ({delta:+})\n\n{_link()}"
    )
    return {"subject": f"📉 Security score dropped {delta:+} — {org_name}", "html": html, "text": text}


def weekly_digest_email(digest: dict) -> dict:
    org_name = digest.get("org_name", "your organisation")
    score = digest.get("score", "—")
    grade = digest.get("grade", "—")
    findings = digest.get("top_findings", []) or []
    improvements = digest.get("improvements", []) or []
    f_html = "".join(
        f"<li>{_SEV_EMOJI.get(f.get('severity'), '•')} {f.get('title')} "
        f"<em>({f.get('file_path', '')})</em></li>"
        for f in findings[:8]
    ) or "<li>No open findings 🎉</li>"
    i_html = "".join(f"<li>{i}</li>" for i in improvements[:8]) or "<li>—</li>"
    html = (
        f"<h2>📊 Weekly Security Report — {org_name}</h2>"
        f"<p><strong>Score:</strong> {score}/100 (grade {grade})</p>"
        f"<h3>Top findings</h3><ul>{f_html}</ul>"
        f"<h3>Improvements this week</h3><ul>{i_html}</ul>"
        f'<p><a href="{_link()}">Open the dashboard</a></p>'
    )
    text = (
        f"WEEKLY SECURITY REPORT — {org_name}\n\nScore: {score}/100 (grade {grade})\n\n"
        "Top findings:\n"
        + "\n".join(f"- {f.get('title')} ({f.get('file_path', '')})" for f in findings[:8])
        + "\n\nImprovements:\n"
        + "\n".join(f"- {i}" for i in improvements[:8])
        + f"\n\n{_link()}"
    )
    return {"subject": f"📊 Weekly Security Report — {org_name}", "html": html, "text": text}


# --------------------------------------------------------------------------- #
# SLACK (Block Kit)
# --------------------------------------------------------------------------- #
def _btn(text: str, url: str) -> dict:
    return {"type": "button", "text": {"type": "plain_text", "text": text}, "url": url}


def _blocks(header: str, section_md: str, button_text: str, button_path: str = "") -> list[dict]:
    return [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
        {"type": "section", "text": {"type": "mrkdwn", "text": section_md}},
        {"type": "actions", "elements": [_btn(button_text, _link(button_path))]},
    ]


def critical_finding_blocks(finding: dict) -> list[dict]:
    desc = finding.get("title") or finding.get("description") or "Security finding"
    file_ref = finding.get("file_path") or finding.get("file") or "—"
    line = finding.get("line")
    where = f"{file_ref}:{line}" if line else file_ref
    rec = finding.get("recommendation") or finding.get("remediation") or "Review and remediate."
    return _blocks(
        "🔴 Critical Security Alert",
        f"*Finding:* {desc}\n*Severity:* Critical\n*File:* {where}\n*Action:* {rec}",
        "View in CyberGuard",
        "security-debt",
    )


def fraud_blocked_blocks(fraud: dict) -> list[dict]:
    score = fraud.get("fraud_score", fraud.get("score", 0.0))
    reasons = ", ".join((fraud.get("reasons") or [])[:5]) or "—"
    return _blocks(
        "🚫 Fraud Blocked",
        f"*Score:* {score:.2f}\n*Verdict:* {fraud.get('verdict', 'block')}\n*Reasons:* {reasons}",
        "Review case",
        "fraud-detection",
    )


def credential_expiring_blocks(cred: dict) -> list[dict]:
    return _blocks(
        "🔑 Credential Expiring",
        f"*{cred.get('name', 'credential')}* ({cred.get('type', 'credential')}) expires in "
        f"*{cred.get('days_left', cred.get('days', '?'))} day(s)*.",
        "Manage identities",
        "machine-identity",
    )


def risk_change_blocks(before: float, after: float, org_name: str) -> list[dict]:
    delta = round(after - before, 1)
    arrow = "📉" if delta < 0 else "📈"
    return _blocks(
        f"{arrow} Risk score changed {delta:+}",
        f"*{org_name}*: {before} → {after}",
        "Open dashboard",
    )


def daily_summary_blocks(summary: dict) -> list[dict]:
    lines = "\n".join(
        f"• {_SEV_EMOJI.get(a.get('severity'), '•')} [{a.get('module')}] {a.get('title')}"
        for a in (summary.get("open_alerts") or [])[:10]
    ) or "_No open alerts_"
    return _blocks(
        f"🌅 Daily summary — {summary.get('org_name', '')}",
        f"*Risk score:* {summary.get('score', '—')} ({summary.get('grade', '—')})\n"
        f"*Open alerts:* {summary.get('open_count', 0)}\n{lines}",
        "Open dashboard",
    )
