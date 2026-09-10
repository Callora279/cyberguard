"""Detect anomalous invoices from a historical baseline or from raw text."""
from __future__ import annotations

import re
from collections import Counter
from datetime import date, datetime
from statistics import mean, pstdev

# invoice: {id, vendor, amount, currency, date (iso), line_items:[{desc, qty, unit_price}], iban?}

# Fixed public holidays (month, day) treated as "holiday submission" regardless
# of year, plus a small set of movable UK bank holidays by exact date.
_FIXED_HOLIDAYS = {(1, 1), (12, 25), (12, 26), (7, 4), (11, 11)}
_MOVABLE_HOLIDAYS = {
    date(2026, 4, 3), date(2026, 4, 6), date(2026, 5, 4), date(2026, 5, 25),
    date(2026, 8, 31), date(2027, 3, 26), date(2027, 3, 29), date(2027, 5, 3),
    date(2027, 5, 31), date(2027, 8, 30),
}


def _is_holiday(d: datetime) -> bool:
    return (d.month, d.day) in _FIXED_HOLIDAYS or d.date() in _MOVABLE_HOLIDAYS


def _is_round(amount: float) -> bool:
    return amount >= 100 and (amount % 100 == 0 or amount % 1000 == 0)


def analyze(invoice: dict | None, history: list[dict] | None = None) -> dict:
    invoice = invoice if isinstance(invoice, dict) else {}
    history = [h for h in (history or []) if isinstance(h, dict)]
    reasons: list[str] = []
    amount = float(invoice.get("amount", 0) or 0)
    vendor = invoice.get("vendor") or ""

    vendor_hist = [
        float(h.get("amount") or 0)
        for h in history
        if h.get("vendor") == vendor and h.get("amount") is not None
    ]
    all_vendors = {h.get("vendor") for h in history}

    # 1. new vendor
    if vendor and vendor not in all_vendors and history:
        reasons.append("first invoice from this vendor")

    # 2. unusual amount vs vendor baseline
    if len(vendor_hist) >= 4:
        mu, sd = mean(vendor_hist), pstdev(vendor_hist) or 1.0
        if amount > mu + 3 * sd:
            reasons.append(f"amount {amount:.2f} far above vendor mean {mu:.2f}")
        if amount > mu * 3:
            reasons.append("amount is 3x the vendor's typical invoice")

    # 3. duplicate detection
    for h in history:
        if (
            h.get("vendor") == vendor
            and abs(float(h.get("amount") or 0) - amount) < 0.01
            and h.get("id") != invoice.get("id")
        ):
            reasons.append(f"possible duplicate of invoice {h.get('id')}")
            break

    # 4. round-number pattern
    if _is_round(amount):
        reasons.append("suspiciously round amount")

    # 5. timing anomalies (weekend / end-of-quarter / rapid re-submission)
    try:
        d = datetime.fromisoformat(invoice["date"])
        if d.weekday() >= 5:
            reasons.append("invoice dated on a weekend")
        if _is_holiday(d):
            reasons.append("invoice dated on a public holiday")
        if d.month in (3, 6, 9, 12) and d.day >= 27:
            reasons.append("submitted at quarter-end")
    except (KeyError, ValueError):
        pass

    # 6. line-item math doesn't add up
    li_total = sum(
        float(li.get("qty", 1)) * float(li.get("unit_price", 0))
        for li in invoice.get("line_items", [])
    )
    if invoice.get("line_items") and abs(li_total - amount) > max(1.0, amount * 0.02):
        reasons.append(f"line items sum to {li_total:.2f}, not {amount:.2f}")

    # 7. changed bank details
    ibans = Counter(h.get("iban") for h in history if h.get("vendor") == vendor and h.get("iban"))
    if invoice.get("iban") and ibans and invoice["iban"] not in ibans:
        reasons.append("bank account (IBAN) differs from vendor history")

    score = min(100.0, len(reasons) * 22.0)
    return {
        "invoice_id": invoice.get("id"),
        "vendor": vendor,
        "anomaly_score": round(score, 1),
        "verdict": "high_risk" if score >= 60 else ("review" if score >= 30 else "ok"),
        "reasons": reasons,
    }


# --------------------------------------------------------------------------- #
# text-content analysis (free-text invoice / email body, no structured fields)
# --------------------------------------------------------------------------- #
_AMOUNT_LABEL_RE = re.compile(
    r"(?:amount|total|sum|invoice\s+value|balance\s+due|pay(?:able)?)\D{0,12}"
    r"([£$€]?\s?\d[\d,]*(?:\.\d{1,2})?)(\s?k\b)?",
    re.IGNORECASE,
)
_TIME_RE = re.compile(r"\b([01]?\d|2[0-3]):([0-5]\d)\b")

# keyword -> (friendly label, weight 0-1)
_INVOICE_KEYWORDS = {
    "bypass": ("process-bypass language ('bypass')", 0.30),
    "ceo approved": ("claims CEO approval", 0.30),
    "ceo-approved": ("claims CEO approval", 0.30),
    "approved by the ceo": ("claims CEO approval", 0.30),
    "pay immediately": ("demands immediate payment", 0.30),
    "within 24 hours": ("artificial 24-hour deadline", 0.25),
    "within 24hrs": ("artificial 24-hour deadline", 0.25),
    "same day": ("same-day payment pressure", 0.15),
    "urgent": ("urgency language ('urgent')", 0.20),
    "do not tell": ("secrecy request", 0.25),
    "don't tell": ("secrecy request", 0.25),
    "confidential": ("secrecy language ('confidential')", 0.15),
    "gift card": ("gift-card payment request", 0.35),
    "wire transfer": ("wire-transfer request", 0.10),
    "new bank": ("new/changed bank details", 0.25),
    "changed our bank": ("new/changed bank details", 0.25),
    "updated bank details": ("new/changed bank details", 0.25),
}
_NEW_VENDOR_RE = re.compile(
    r"\bnew (?:company|vendor|supplier|payee|account)\b|\bfirst invoice\b|"
    r"\bnew to (?:you|your system)\b",
    re.IGNORECASE,
)


def _extract_amounts(text: str) -> list[float]:
    amounts: list[float] = []
    for m in re.finditer(r"[£$€]\s?(\d[\d,]*(?:\.\d{1,2})?)(\s?k\b)?", text, re.IGNORECASE):
        val = float(m.group(1).replace(",", ""))
        if m.group(2):
            val *= 1000
        amounts.append(val)
    for m in re.finditer(
        r"\b(\d[\d,]*(?:\.\d{1,2})?)\s?(k\b|gbp|usd|eur|pounds|dollars|euros)\b", text, re.IGNORECASE
    ):
        val = float(m.group(1).replace(",", ""))
        if m.group(2).lower() == "k":
            val *= 1000
        amounts.append(val)
    for m in _AMOUNT_LABEL_RE.finditer(text):
        raw = re.sub(r"[£$€,\s]", "", m.group(1))
        if raw.replace(".", "").isdigit():
            val = float(raw)
            if m.group(2):
                val *= 1000
            amounts.append(val)
    return amounts


def analyze_content(content: str | None) -> dict:
    """Score a free-text invoice / payment request on a 0.0-1.0 scale."""
    text = content or ""
    if not text.strip():
        return {"score": 0.0, "reasons": [], "verdict": "ok", "max_amount": 0.0}
    low = text.lower()
    reasons: list[str] = []
    score = 0.0

    amounts = _extract_amounts(text)
    max_amount = max(amounts, default=0.0)

    # round amounts (£1,000 / £5,000 / £50,000 ...)
    if any(a >= 1000 and a % 1000 == 0 for a in amounts):
        rnd = next(a for a in amounts if a >= 1000 and a % 1000 == 0)
        reasons.append(f"suspiciously round amount ({rnd:,.0f})")
        score += 0.15

    # high-value payment
    if max_amount > 10_000:
        reasons.append(f"high-value amount over 10,000 ({max_amount:,.0f})")
        score += 0.25
    elif max_amount > 5_000:
        score += 0.10

    # pressure / social-engineering keywords
    seen_labels: set[str] = set()
    for kw, (label, weight) in _INVOICE_KEYWORDS.items():
        if kw in low and label not in seen_labels:
            seen_labels.add(label)
            reasons.append(label)
            score += weight

    # late-night / out-of-hours timestamp
    for m in _TIME_RE.finditer(text):
        hh = int(m.group(1))
        if hh >= 22 or hh < 6:
            reasons.append(f"submitted out-of-hours ({m.group(0)})")
            score += 0.15
            break

    # first invoice from a brand-new vendor
    if _NEW_VENDOR_RE.search(text):
        reasons.append("first invoice from a new/unknown vendor")
        score += 0.15

    score = min(1.0, round(score, 3))
    return {
        "score": score,
        "reasons": reasons,
        "verdict": "high_risk" if score >= 0.7 else ("review" if score >= 0.4 else "ok"),
        "max_amount": max_amount,
    }
