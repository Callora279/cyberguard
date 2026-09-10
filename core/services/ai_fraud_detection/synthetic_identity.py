"""Detect synthetic (fabricated) identities."""
from __future__ import annotations

import re
from datetime import datetime

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "trashmail.com", "yopmail.com", "sharklasers.com",
}
_ROLE_LOCALPARTS = {"admin", "info", "sales", "test", "noreply", "user", "contact"}


def _email_signals(email: str) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""):
        return 40.0, ["malformed email"]
    local, domain = email.lower().split("@", 1)
    if domain in _DISPOSABLE_DOMAINS:
        score += 45
        reasons.append("disposable email domain")
    if local in _ROLE_LOCALPARTS:
        score += 15
        reasons.append("role-based local part")
    if re.search(r"\d{4,}", local):
        score += 15
        reasons.append("long digit run in local part")
    if re.fullmatch(r"[a-z]{7,}\d{2,}", local):
        score += 10
        reasons.append("random-looking local part")
    return score, reasons


def _phone_signals(phone: str, country: str = "GB") -> tuple[float, list[str]]:
    reasons: list[str] = []
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) < 8:
        return 30.0, ["phone number too short"]
    if len(set(digits)) <= 2:
        return 50.0, ["phone number has no entropy (repeated digits)"]
    if digits in ("1234567890", "0000000000") or digits.endswith("1234567"):
        return 45.0, ["sequential / placeholder phone number"]
    return 0.0, reasons


def _address_signals(address: dict) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    line1 = (address.get("line1") or "").strip()
    postcode = (address.get("postcode") or "").strip()
    if not line1 or not postcode:
        return 25.0, ["incomplete address"]
    if re.fullmatch(r"\d+ (test|fake|main) (st|street|road)", line1.lower()):
        score += 30
        reasons.append("placeholder street address")
    if address.get("country") == "GB" and not re.match(
        r"^[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}$", postcode.upper()
    ):
        score += 20
        reasons.append("postcode fails UK format")
    return score, reasons


def _consistency_signals(identity: dict) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    name = (identity.get("full_name") or "").lower().replace(" ", "")
    email_local = (identity.get("email") or "").split("@")[0].lower()
    if name and email_local and name[:4] not in email_local and email_local[:4] not in name:
        score += 10
        reasons.append("name and email appear unrelated")
    dob = identity.get("dob")
    try:
        if dob:
            age = (datetime.utcnow() - datetime.fromisoformat(dob)).days / 365.25
            if age < 18 or age > 110:
                score += 25
                reasons.append(f"implausible age {age:.0f}")
    except ValueError:
        score += 10
        reasons.append("unparseable date of birth")
    if identity.get("created_at") and identity.get("first_transaction_at"):
        try:
            gap = (
                datetime.fromisoformat(identity["first_transaction_at"])
                - datetime.fromisoformat(identity["created_at"])
            ).total_seconds()
            if gap < 120:
                score += 20
                reasons.append("transacted within 2 minutes of account creation")
        except ValueError:
            pass
    return score, reasons


def analyze(identity: dict) -> dict:
    total = 0.0
    all_reasons: list[str] = []
    for fn, arg in (
        (_email_signals, identity.get("email", "")),
        (_phone_signals, identity.get("phone", "")),
        (_address_signals, identity.get("address", {})),
        (_consistency_signals, identity),
    ):
        s, r = fn(arg)
        total += s
        all_reasons += r
    score = min(100.0, total)
    return {
        "identity_ref": identity.get("id") or identity.get("email"),
        "synthetic_score": round(score, 1),
        "verdict": "synthetic" if score >= 65 else ("suspicious" if score >= 35 else "genuine"),
        "reasons": all_reasons,
    }
