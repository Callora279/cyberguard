"""Detect anomalous invoices from a historical baseline."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from statistics import mean, pstdev

# invoice: {id, vendor, amount, currency, date (iso), line_items:[{desc, qty, unit_price}], iban?}


def _is_round(amount: float) -> bool:
    return amount >= 100 and (amount % 100 == 0 or amount % 1000 == 0)


def analyze(invoice: dict, history: list[dict] | None = None) -> dict:
    history = history or []
    reasons: list[str] = []
    amount = float(invoice.get("amount", 0))
    vendor = invoice.get("vendor", "")

    vendor_hist = [float(h["amount"]) for h in history if h.get("vendor") == vendor]
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
            and abs(float(h.get("amount", 0)) - amount) < 0.01
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
