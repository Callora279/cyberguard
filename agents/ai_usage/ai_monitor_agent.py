"""AI-usage agent: monitor AI API usage, detect policy violations, track cost.

Runs as a periodic job (or on demand) and produces usage analytics that feed
the AI Governance dashboard and Slack digest.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from core.database.db import session_scope
from core.database.models import AIInteraction, Alert
from core.services.ai_governance import monitor
from core.services.ai_governance.ai_behavior_fingerprinting import fingerprint_analyzer
from core.utils.logger import get_logger

logger = get_logger("agents.ai_usage")

_COST_ALERT_THRESHOLD_USD = 50.0
_VIOLATION_RATE_THRESHOLD = 0.05


class AIMonitorAgent:
    def usage_analytics(self, org_id: str, *, days: int = 7) -> dict:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        with session_scope() as db:
            rows = db.scalars(
                select(AIInteraction).where(
                    AIInteraction.org_id == org_id, AIInteraction.timestamp >= since
                )
            ).all()
            daily = db.execute(
                select(
                    func.date(AIInteraction.timestamp),
                    func.count(AIInteraction.id),
                    func.sum(AIInteraction.total_tokens),
                    func.sum(AIInteraction.cost_usd),
                )
                .where(AIInteraction.org_id == org_id, AIInteraction.timestamp >= since)
                .group_by(func.date(AIInteraction.timestamp))
            ).all()

        blocked = sum(1 for r in rows if r.policy_decision == "block")
        flagged = sum(1 for r in rows if r.policy_decision == "flag")
        high_risk = sum(1 for r in rows if r.risk_score >= 60)
        total = len(rows) or 1
        return {
            "org_id": org_id,
            "window_days": days,
            "total_calls": len(rows),
            "total_tokens": sum(r.total_tokens for r in rows),
            "total_cost_usd": round(sum(r.cost_usd for r in rows), 4),
            "blocked": blocked,
            "flagged": flagged,
            "high_risk_interactions": high_risk,
            "violation_rate": round((blocked + flagged) / total, 4),
            "avg_risk_score": round(sum(r.risk_score for r in rows) / total, 2),
            "daily": [
                {"date": str(d), "calls": c, "tokens": int(t or 0), "cost_usd": round(float(cost or 0), 4)}
                for d, c, t, cost in daily
            ],
            "top_models": monitor.usage_summary(org_id, days=days)["by_model"],
        }

    def check_violations(self, org_id: str) -> dict:
        analytics = self.usage_analytics(org_id, days=1)
        issues = []
        if analytics["total_cost_usd"] > _COST_ALERT_THRESHOLD_USD:
            issues.append(f"daily AI spend ${analytics['total_cost_usd']} exceeds ${_COST_ALERT_THRESHOLD_USD}")
        if analytics["violation_rate"] > _VIOLATION_RATE_THRESHOLD:
            issues.append(f"policy violation rate {analytics['violation_rate']:.1%} is elevated")
        drift = fingerprint_analyzer.drift_report(org_id)
        if drift.get("drift"):
            issues.append(f"AI behaviour drift detected: {list(drift['changes'])}")

        if issues:
            with session_scope() as db:
                db.add(
                    Alert(
                        org_id=org_id,
                        module="ai_governance",
                        severity="high",
                        title="AI usage policy / cost concern",
                        body="; ".join(issues),
                        context=analytics,
                    )
                )
        return {"issues": issues, "analytics": analytics}

    def run(self, org_id: str) -> dict:
        logger.info("ai-usage agent run for %s", org_id)
        return self.check_violations(org_id)
