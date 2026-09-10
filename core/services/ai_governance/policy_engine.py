"""AI usage policy definition and real-time enforcement."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import select

from core.database.db import session_scope
from core.database.models import AIPolicy
from core.utils.exceptions import PolicyViolation

# Data-classification detectors used by ``data_classification_rules``.
_CLASSIFIERS = {
    "pii": [
        r"\b\d{3}-\d{2}-\d{4}\b",                     # US SSN
        r"\b[A-Z]{2}\d{6}[A-Z]\b",                     # UK NI number-ish
        r"\b\d{16}\b",                                 # PAN
        r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",               # email
    ],
    "secret": [
        r"gsk_[A-Za-z0-9]{20,}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"(?i)aws_secret_access_key\s*=",
    ],
}


@dataclass
class PolicyDecision:
    allowed: bool
    action: str  # allow | block | flag
    violations: list[str] = field(default_factory=list)

    def raise_if_blocked(self) -> None:
        if not self.allowed:
            raise PolicyViolation(
                "AI request blocked by governance policy",
                details={"violations": self.violations},
            )


@dataclass
class ResolvedPolicy:
    id: str
    name: str
    max_tokens: int
    allowed_models: list[str]
    prohibited_patterns: list[str]
    data_classification_rules: dict[str, str]
    block_on_violation: bool


# Spec-mandated built-in default, used when an org has no enabled policy row.
_DEFAULT = ResolvedPolicy(
    id="default",
    name="Built-in default",
    max_tokens=4000,
    allowed_models=["qwen/qwen3.8-27b"],
    prohibited_patterns=[
        r"\bpassword\b",
        r"\bsecret\b",
        r"\bapi[_ -]?key\b",
        r"ignore (all|previous) instructions",
    ],
    data_classification_rules={"secret": "block", "pii": "flag"},
    block_on_violation=True,
)


def load_policy(org_id: str) -> ResolvedPolicy:
    with session_scope() as db:
        row = db.scalar(
            select(AIPolicy)
            .where(AIPolicy.org_id == org_id, AIPolicy.enabled.is_(True))
            .order_by(AIPolicy.created_at.desc())
        )
        if not row:
            return _DEFAULT
        return ResolvedPolicy(
            id=row.id,
            name=row.name,
            max_tokens=row.max_tokens,
            allowed_models=list(row.allowed_models or []),
            prohibited_patterns=list(row.prohibited_patterns or []),
            data_classification_rules=dict(row.data_classification_rules or {}),
            block_on_violation=row.block_on_violation,
        )


def _classify(text: str) -> set[str]:
    found: set[str] = set()
    for label, patterns in _CLASSIFIERS.items():
        if any(re.search(p, text) for p in patterns):
            found.add(label)
    return found


def evaluate(
    org_id: str,
    *,
    prompt: str,
    model: str,
    max_tokens: int,
) -> PolicyDecision:
    policy = load_policy(org_id)
    violations: list[str] = []
    action = "allow"

    if policy.allowed_models and model not in policy.allowed_models:
        violations.append(f"model '{model}' is not in the allowed list")
        action = "block"

    if max_tokens > policy.max_tokens:
        violations.append(
            f"requested max_tokens {max_tokens} exceeds limit {policy.max_tokens}"
        )
        action = "block"

    for pattern in policy.prohibited_patterns:
        try:
            if re.search(pattern, prompt, re.IGNORECASE):
                violations.append(f"prompt matches prohibited pattern: {pattern}")
                action = "block"
        except re.error:
            continue

    for label in _classify(prompt):
        rule = policy.data_classification_rules.get(label, "allow")
        if rule == "block":
            violations.append(f"prompt contains {label} data (rule: block)")
            action = "block"
        elif rule == "flag" and action == "allow":
            violations.append(f"prompt contains {label} data (rule: flag)")
            action = "flag"

    allowed = not (action == "block" and policy.block_on_violation)
    return PolicyDecision(allowed=allowed, action=action, violations=violations)
