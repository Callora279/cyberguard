"""Detect synthetic (fabricated) identities."""
from __future__ import annotations

import re
from datetime import datetime

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "trashmail.com", "yopmail.com", "sharklasers.com",
}
_FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "mail.com", "icloud.com",
}
# TLDs disproportionately used by throw-away / recently-registered domains
_SUSPICIOUS_TLDS = {"xyz", "top", "click", "buzz", "live", "online", "site", "monster", "rest"}
_ROLE_LOCALPARTS = {"admin", "info", "sales", "test", "noreply", "user", "contact"}


def _email_signals(email: str) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    if not email:
        return 0.0, []  # nothing supplied — not the same as "malformed"
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return 40.0, ["malformed email"]
    local, domain = email.lower().split("@", 1)
    tld = domain.rsplit(".", 1)[-1]
    if domain in _DISPOSABLE_DOMAINS:
        score += 45
        reasons.append("disposable email domain")
    elif tld in _SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"domain on a high-abuse TLD (.{tld}) — often newly registered")
    elif domain in _FREEMAIL_DOMAINS:
        score += 8
        reasons.append("consumer freemail domain for a business identity")
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
    if not phone:
        return 0.0, []
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 8:
        return 30.0, ["phone number too short"]
    if len(set(digits)) <= 2:
        return 50.0, ["phone number has no entropy (repeated digits)"]
    if digits in ("1234567890", "0000000000") or digits.endswith("1234567"):
        return 45.0, ["sequential / placeholder phone number"]
    if not re.fullmatch(r"\+?[1-9]\d{6,14}", (phone or "").strip().replace(" ", "")):
        return 15.0, ["phone number format is not valid E.164"]
    return 0.0, []


def _address_signals(address: dict) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    address = address if isinstance(address, dict) else {}
    if not address:
        return 0.0, []  # no address supplied — nothing to assess
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


# --------------------------------------------------------------------------- #
# text-content analysis (free-text vendor / customer details, no dict fields)
# --------------------------------------------------------------------------- #
_REG_RE = re.compile(
    r"\b(?:company\s*(?:number|no\.?|reg(?:istration)?)|registration\s*(?:number|no\.?)"
    r"|companies\s*house|vat\s*(?:number|no\.?|reg)|crn\b|co\.?\s*reg)\b",
    re.IGNORECASE,
)
_GENERIC_COMPANY_RE = re.compile(
    r"\bnew\s+company\b|\bglobal\s+(?:services|solutions|trading|holdings)\b"
    r"|\b(?:acme|test|example|generic|sample|demo)\s+(?:ltd|limited|inc|llc|corp|co)\b"
    r"|\b[a-z]+\s+(?:services|solutions|holdings|trading|consulting|ventures|group)\s+"
    r"(?:ltd|limited|llc|inc)\b|\bcompany\s+(?:ltd|limited)\b",
    re.IGNORECASE,
)
_CONTACT_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]{2,}")
_CONTACT_PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
_CONTACT_ADDR_RE = re.compile(
    r"\b(?:street|st\.?|road|rd\.?|avenue|ave\.?|lane|ln\.?|drive|suite|floor|unit|"
    r"postcode|post\s*code|zip\s*code)\b",
    re.IGNORECASE,
)


def analyze_content(content: str | None) -> dict:
    """Score free-text party/vendor details for synthetic-identity signals (0.0-1.0)."""
    text = content or ""
    if not text.strip():
        return {"score": 0.0, "reasons": [], "verdict": "genuine"}
    low = text.lower()
    reasons: list[str] = []
    score = 0.0

    # 1. suspicious bank details — repeated-digit sort code / account number
    bank_hit = False
    for m in re.finditer(
        r"(?:sort\s*code|account\s*(?:number|no\.?)?|acc\s*no\.?|iban)\D{0,8}"
        r"([0-9][0-9\-\s]{3,}[0-9])",
        low,
    ):
        digits = re.sub(r"\D", "", m.group(1))
        if digits and len(set(digits)) <= 2:
            reasons.append(f"bank details use repeated digits ({m.group(1).strip()})")
            score += 0.30
            bank_hit = True
            break
    if not bank_hit and re.search(r"\b(\d)\1[-\s]?\1\1[-\s]?\1\1\b|\b(\d\d)-\2-\2\b", text):
        reasons.append("repeated-digit sort-code / account pattern (e.g. 99-99-99)")
        score += 0.25

    # 2. missing company registration
    if not _REG_RE.search(text):
        reasons.append("no company registration / VAT number quoted")
        score += 0.20

    # 3. generic / placeholder company name
    if _GENERIC_COMPANY_RE.search(text):
        reasons.append("generic or placeholder company name")
        score += 0.25

    # 4. no contact details at all
    has_email = bool(_CONTACT_EMAIL_RE.search(text))
    has_phone = bool(_CONTACT_PHONE_RE.search(text))
    has_addr = bool(_CONTACT_ADDR_RE.search(text))
    if not (has_email or has_phone or has_addr):
        reasons.append("no contact details (email, phone or address)")
        score += 0.20

    score = min(1.0, round(score, 3))
    return {
        "score": score,
        "reasons": reasons,
        "verdict": "synthetic" if score >= 0.6 else ("suspicious" if score >= 0.3 else "genuine"),
    }


def analyze(identity: dict | None) -> dict:
    identity = identity if isinstance(identity, dict) else {}
    total = 0.0
    all_reasons: list[str] = []
    for fn, arg in (
        (_email_signals, identity.get("email") or ""),
        (_phone_signals, identity.get("phone") or ""),
        (_address_signals, identity.get("address") if isinstance(identity.get("address"), dict) else {}),
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
