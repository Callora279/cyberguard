"""Risk scoring for a single AI interaction (0-100, higher = riskier).

Combines four sub-scores:
    * prompt injection attempts
    * data exfiltration risk
    * bias / toxicity
    * hallucination risk
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


@dataclass
class RiskBreakdown:
    prompt_injection: float
    data_exfiltration: float
    bias: float
    hallucination: float

    @property
    def score(self) -> float:
        # weighted, capped at 100
        total = (
            self.prompt_injection * 0.40
            + self.data_exfiltration * 0.35
            + self.bias * 0.10
            + self.hallucination * 0.15
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
        bias=max(_bias_score(prompt), _bias_score(response)),
        hallucination=_hallucination_score(prompt, response),
    )
