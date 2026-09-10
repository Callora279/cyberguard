"""Risk scoring for a single AI interaction (0-100, higher = riskier).

Combines five sub-scores:
    * prompt injection attempts
    * data exfiltration risk
    * PII / sensitive-data exposure   (email, phone, credit card, SSN, secrets)
    * bias / toxicity
    * hallucination risk

``prompt_risk`` returns a normalised 0-1 figure used by the real-time enforcer
as a pre-call block gate (block when >= 0.8).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

_INJECTION_PATTERNS = [
    r"ignore (all |the )?(previous|prior|above) instructions",
    r"disregard (your|the) (system|previous) (prompt|instructions)",
    r"you are now (?:in )?(?:dev|developer|jailbreak|dan) mode",
    r"reveal (your |the )?(system prompt|instructions|hidden)",
    r"pretend (you|to be)",
    r"</?(system|assistant)>",
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
]
_EXFIL_PATTERNS = [
    r"\b(list|dump|export|show me all)\b.{0,20}\b(users|customers|passwords|secrets|tokens|api keys)\b",
    r"\bselect\b.+\bfrom\b.+\b(users|accounts|credentials)\b",
    r"send (this|it|the data) to (https?://|[\w.-]+@)",
    r"base64|hex encode|exfiltrate",
]
_BIAS_TERMS = [
    "always", "never", "obviously", "everyone knows", "inferior", "superior race",
    "men are", "women are", "those people",
]
_HEDGE_TERMS = [
    "i think", "probably", "might be", "as far as i know", "i'm not sure",
    "cannot verify", "no information",
]

# --- PII / sensitive-data detectors ---------------------------------------- #
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?!\d)"
)
_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SECRET_RE = re.compile(
    r"gsk_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|aws_secret_access_key\s*=",
    re.IGNORECASE,
)


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_pii(text: str) -> dict[str, list[str]]:
    """Return the PII categories found in ``text`` and a redacted sample of each."""
    found: dict[str, list[str]] = {}
    if not text:
        return found

    emails = _EMAIL_RE.findall(text)
    if emails:
        found["email"] = [_redact(e) for e in dict.fromkeys(emails)][:5]

    ccs = [m.group(0) for m in _CC_RE.finditer(text) if _luhn_ok(m.group(0))]
    if ccs:
        found["credit_card"] = [_redact(c) for c in dict.fromkeys(ccs)][:5]

    if _SSN_RE.search(text):
        found["ssn"] = ["***-**-****"]

    # phones: only count matches with >= 10 digits to cut false positives
    phones = [
        m.group(0).strip()
        for m in _PHONE_RE.finditer(text)
        if sum(c.isdigit() for c in m.group(0)) >= 10
    ]
    # drop anything already claimed as a credit-card / ssn
    phones = [p for p in phones if not _CC_RE.fullmatch(p.replace(" ", ""))]
    if phones:
        found["phone"] = [_redact(p) for p in dict.fromkeys(phones)][:5]

    if _SECRET_RE.search(text):
        found["secret"] = ["***REDACTED***"]

    return found


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 4:
        return "****"
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


@dataclass
class RiskBreakdown:
    prompt_injection: float
    data_exfiltration: float
    pii_exposure: float
    bias: float
    hallucination: float

    @property
    def score(self) -> float:
        # weighted, capped at 100
        total = (
            self.prompt_injection * 0.34
            + self.data_exfiltration * 0.28
            + self.pii_exposure * 0.16
            + self.bias * 0.10
            + self.hallucination * 0.12
        )
        return round(min(total, 100.0), 2)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        return d


def _pattern_hits(text: str, patterns: list[str]) -> float:
    text_l = text.lower()
    hits = sum(1 for p in patterns if re.search(p, text_l))
    if not hits:
        return 0.0
    return min(100.0, 35.0 + hits * 25.0)


def _bias_score(text: str) -> float:
    text_l = text.lower()
    hits = sum(1 for t in _BIAS_TERMS if t in text_l)
    return min(100.0, hits * 20.0)


def _pii_score(text: str) -> float:
    cats = detect_pii(text)
    if not cats:
        return 0.0
    weight = {"credit_card": 55.0, "ssn": 55.0, "secret": 60.0, "email": 20.0, "phone": 25.0}
    return min(100.0, sum(weight.get(c, 20.0) for c in cats))


def _hallucination_score(prompt: str, response: str) -> float:
    """Heuristic: confident, specific claims with numbers/dates and no hedging."""
    if not response:
        return 0.0
    resp_l = response.lower()
    hedges = sum(1 for h in _HEDGE_TERMS if h in resp_l)
    specifics = len(re.findall(r"\b\d{4}\b|\b\d+(\.\d+)?%|\bv?\d+\.\d+\.\d+\b", response))
    fabricated_refs = len(re.findall(r"\[\d+\]|https?://\S+", response))
    raw = specifics * 6 + fabricated_refs * 8 - hedges * 15
    return float(max(0.0, min(100.0, raw)))


def score_interaction(prompt: str, response: str = "") -> RiskBreakdown:
    return RiskBreakdown(
        prompt_injection=_pattern_hits(prompt, _INJECTION_PATTERNS),
        data_exfiltration=_pattern_hits(f"{prompt}\n{response}", _EXFIL_PATTERNS),
        pii_exposure=max(_pii_score(prompt), _pii_score(response)),
        bias=max(_bias_score(prompt), _bias_score(response)),
        hallucination=_hallucination_score(prompt, response),
    )


def prompt_risk(prompt: str) -> float:
    """Normalised 0-1 risk for the request *before* it is sent upstream.

    Only the prompt is available at this point, so hallucination (a property of
    the response) is excluded and the injection / exfil / PII signals are
    weighted to dominate.
    """
    b = score_interaction(prompt)
    raw = (
        b.prompt_injection * 0.45
        + b.data_exfiltration * 0.35
        + b.pii_exposure * 0.20
    )
    return round(min(raw, 100.0) / 100.0, 4)
