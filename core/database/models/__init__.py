"""ORM models for CyberGuard AI.

Tables:
    organisations, users, ai_interactions, security_findings, sbom_components,
    machine_identities, fraud_alerts, risk_scores, alerts, ai_policies.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan: Mapped[str] = mapped_column(String(32), default="trial")  # trial|free|pro|enterprise
    license_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    chakra_org_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    users: Mapped[list["User"]] = relationship(back_populates="org", cascade="all, delete-orphan")
    settings: Mapped["OrgSettings"] = relationship(
        back_populates="org", cascade="all, delete-orphan", uselist=False
    )


class OrgSettings(Base):
    """One row per organisation: onboarding progress + integration config."""

    __tablename__ = "org_settings"

    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), primary_key=True)

    # onboarding
    onboarding_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    onboarding_step: Mapped[int] = mapped_column(Integer, default=1)  # 1..4
    scan_count: Mapped[int] = mapped_column(Integer, default=0)

    # step 1 — GitHub
    github_repo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    github_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_webhook_secret: Mapped[str | None] = mapped_column(String(128), nullable=True)
    github_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    github_last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # step 2 — website
    website_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    website_last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    website_last_result: Mapped[dict] = mapped_column(JSON, default=dict)

    # step 4 — alerts / Slack
    slack_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    slack_daily_digest: Mapped[bool] = mapped_column(Boolean, default=False)
    report_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    alert_threshold: Mapped[str] = mapped_column(String(16), default="high")  # critical|high|medium|low

    # email notifications
    notification_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notify_types: Mapped[list] = mapped_column(JSON, default=list)  # [] = all types
    weekly_digest: Mapped[bool] = mapped_column(Boolean, default=True)
    last_notified_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Jira integration
    jira_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    jira_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    jira_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    jira_project_key: Mapped[str | None] = mapped_column(String(32), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    org: Mapped[Organisation] = relationship(back_populates="settings")


class OrgAISettings(Base):
    """Per-org bring-your-own-AI-provider configuration.

    ``api_key_encrypted`` holds ciphertext from ``core.utils.crypto.encrypt_secret``
    — never the plaintext key. A missing row (or a row with no key) means the
    org uses the system default (Groq, via ``core.utils.config.settings``).
    """

    __tablename__ = "org_ai_settings"

    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), default="groq")  # groq|openai|anthropic|gemini|custom
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(String(128), default="qwen/qwen3.8-27b")
    base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)  # custom/self-hosted only
    max_tokens: Mapped[int] = mapped_column(Integer, default=1024)
    temperature: Mapped[float] = mapped_column(Float, default=0.2)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class RiskPrediction(Base):
    """A single AI- or heuristic-generated risk prediction, persisted so the
    forecast is auditable and doesn't require re-calling the model on every
    page load."""

    __tablename__ = "risk_predictions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    horizon_days: Mapped[int] = mapped_column(Integer, default=30)
    risk_name: Mapped[str] = mapped_column(String(255))
    probability: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    impact: Mapped[str] = mapped_column(Text, default="")
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="heuristic")  # ai|heuristic
    model: Mapped[str] = mapped_column(String(128), default="")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class ApiToken(Base):
    """Long-lived tokens for CLI / CI access (only the hash is stored)."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    created_by: Mapped[str] = mapped_column(String(36))
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organisations.id"))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    org: Mapped[Organisation] = relationship(back_populates="users")


class AIInteraction(Base):
    __tablename__ = "ai_interactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    model: Mapped[str] = mapped_column(String(128))
    prompt_hash: Mapped[str] = mapped_column(String(64), index=True)
    prompt_preview: Mapped[str] = mapped_column(Text, default="")
    response_preview: Mapped[str] = mapped_column(Text, default="")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_decision: Mapped[str] = mapped_column(String(16), default="allow")  # allow|block|flag
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class AIPolicy(Base):
    __tablename__ = "ai_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(128))
    max_tokens: Mapped[int] = mapped_column(Integer, default=4096)
    allowed_models: Mapped[list] = mapped_column(JSON, default=list)
    prohibited_patterns: Mapped[list] = mapped_column(JSON, default=list)
    data_classification_rules: Mapped[dict] = mapped_column(JSON, default=dict)
    block_on_violation: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(64))  # secret|dependency|insecure_fn|owasp|debt
    title: Mapped[str] = mapped_column(String(255), default="")
    file_path: Mapped[str] = mapped_column(String(512), default="")
    line: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|triaged|fixed|accepted|suppressed
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability: Mapped[float] = mapped_column(Float, default=0.0)
    business_impact: Mapped[float] = mapped_column(Float, default=0.0)
    fix_effort: Mapped[float] = mapped_column(Float, default=0.0)
    remediation: Mapped[str] = mapped_column(Text, default="")
    jira_key: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class SBOMComponent(Base):
    __tablename__ = "sbom_components"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(64), default="")
    ecosystem: Mapped[str] = mapped_column(String(32), default="")
    license: Mapped[str] = mapped_column(String(128), default="UNKNOWN")
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    max_cvss: Mapped[float] = mapped_column(Float, default=0.0)
    vendor_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class MachineIdentity(Base):
    __tablename__ = "machine_identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(32))  # api_key|service_account|cert|oauth|ssh_key
    name: Mapped[str] = mapped_column(String(255))
    fingerprint: Mapped[str] = mapped_column(String(64), default="")
    owner: Mapped[str] = mapped_column(String(255), default="")
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_rotated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|expiring|revoked
    dna: Mapped[dict] = mapped_column(JSON, default=dict)


class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(32))  # deepfake|invoice|synthetic_identity|fusion
    subject: Mapped[str] = mapped_column(String(255), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    signals: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|investigating|confirmed|dismissed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    overall: Mapped[float] = mapped_column(Float, default=0.0)
    grade: Mapped[str] = mapped_column(String(2), default="C")
    breakdown_json: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    module: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    # dedupe key: at most one open (unacknowledged) alert per (org, module, kind)
    kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
    count: Mapped[int | None] = mapped_column(Integer, nullable=True, default=1)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class GatePolicyModel(Base):
    """Security-gate policy. ``org_id`` NULL = the global default policy."""

    __tablename__ = "gate_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    fail_on: Mapped[str] = mapped_column(String(16), default="critical")  # critical|high|medium|low|info
    scanners: Mapped[list] = mapped_column(JSON, default=lambda: ["supply_chain", "security_debt", "iac"])
    fail_open: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GateRunModel(Base):
    """One security-gate evaluation triggered by an SCM webhook."""

    __tablename__ = "gate_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    provider: Mapped[str] = mapped_column(String(16))  # github|gitlab
    repo: Mapped[str] = mapped_column(String(512), default="")
    ref: Mapped[str] = mapped_column(String(255), default="")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    event: Mapped[str] = mapped_column(String(32))  # push|pull_request|merge_request
    decision: Mapped[str] = mapped_column(String(16))  # passed|blocked|error
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class IacScanModel(Base):
    """One IaC config scan (a source tree) or container image scan."""

    __tablename__ = "iac_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    target: Mapped[str] = mapped_column(String(512), default="")  # path / repo or image ref
    kind: Mapped[str] = mapped_column(String(16), default="config")  # config|image
    counts: Mapped[dict] = mapped_column(JSON, default=dict)  # by severity
    findings: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class AuthorizedTargetModel(Base):
    """A live host an org has attested it is authorised to scan (LiveScan)."""

    __tablename__ = "livescan_authorized_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)  # lower-cased hostname, no port
    scheme: Mapped[str] = mapped_column(String(8), default="https")  # http|https
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    attested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class LiveScanModel(Base):
    """One read-only LiveScan of an authorised target."""

    __tablename__ = "livescan_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    target: Mapped[str] = mapped_column(String(512), default="")
    fingerprint: Mapped[dict] = mapped_column(JSON, default=dict)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)  # by severity
    findings: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


__all__ = [
    "AuthorizedTargetModel",
    "LiveScanModel",
    "IacScanModel",
    "GatePolicyModel",
    "GateRunModel",
    "Organisation",
    "OrgSettings",
    "OrgAISettings",
    "RiskPrediction",
    "ApiToken",
    "User",
    "AIInteraction",
    "AIPolicy",
    "SecurityFinding",
    "SBOMComponent",
    "MachineIdentity",
    "FraudAlert",
    "RiskScore",
    "Alert",
]
