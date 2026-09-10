"""Detect AI-generated / manipulated documents and images.

Works on text (LLM-generated document detection), and on file metadata /
structural signals for images and PDFs. No heavy ML dependency: uses
statistical text signals, metadata inspection and an optional LLM adjudication.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from core.services.ai_governance.real_time_enforcer import guarded_chat
from core.utils.exceptions import CyberGuardError
from core.utils.logger import get_logger

logger = get_logger("fraud.deepfake")

_AI_TEXT_MARKERS = [
    "as an ai language model", "i cannot", "however, it is important to note",
    "in conclusion", "furthermore", "delve into", "tapestry", "it's worth noting",
]


def _burstiness(text: str) -> float:
    sents = [s for s in re.split(r"[.!?]+", text) if s.strip()]
    if len(sents) < 3:
        return 0.0
    lengths = [len(s.split()) for s in sents]
    mean = sum(lengths) / len(lengths)
    var = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    # human writing is "bursty" (high variance); LLM text is smooth
    return round(var / (mean or 1), 3)


def _repetition(text: str) -> float:
    words = re.findall(r"[a-z']+", text.lower())
    if not words:
        return 0.0
    counts = Counter(words)
    top = sum(c for _, c in counts.most_common(10))
    return round(top / len(words), 3)


def analyze_text(text: str, *, org_id: str = "unknown", use_ai: bool = True) -> dict:
    lower = text.lower()
    marker_hits = [m for m in _AI_TEXT_MARKERS if m in lower]
    burst = _burstiness(text)
    rep = _repetition(text)

    score = 0.0
    score += len(marker_hits) * 15
    score += 25 if burst < 4.0 and len(text) > 400 else 0
    score += 20 if rep > 0.35 else 0
    score = min(100.0, score)

    signals = {
        "ai_phrase_markers": marker_hits,
        "burstiness": burst,
        "lexical_repetition": rep,
    }

    if use_ai and len(text) > 120:
        try:
            record = guarded_chat(
                "Classify whether the following document was most likely written by "
                "a large language model. Reply with JSON {\"ai_generated\": bool, "
                "\"confidence\": 0-1, \"indicators\": [str]}.\n\n" + text[:3000],
                org_id=org_id,
                system="Return only JSON.",
                purpose="deepfake_text_detection",
                max_tokens=300,
            )
            import json

            verdict = json.loads(record.response[record.response.find("{"): record.response.rfind("}") + 1])
            signals["llm_adjudication"] = verdict
            if verdict.get("ai_generated"):
                score = max(score, verdict.get("confidence", 0.5) * 100)
        except (CyberGuardError, ValueError) as exc:
            logger.warning("deepfake LLM adjudication failed: %s", exc)

    return {
        "authenticity_score": round(100.0 - score, 1),  # higher = more authentic
        "ai_generated_likelihood": round(score, 1),
        "verdict": "likely_ai_generated" if score >= 60 else ("uncertain" if score >= 35 else "likely_human"),
        "signals": signals,
    }


def analyze_document_metadata(meta: dict) -> dict:
    """meta: {producer, creator, creation_date, mod_date, software, xmp}"""
    flags: list[str] = []
    producer = (meta.get("producer") or "").lower()
    creator = (meta.get("creator") or "").lower()
    for tool in ("chatgpt", "gpt", "dall", "midjourney", "stable diffusion", "canva ai", "gemini"):
        if tool in producer or tool in creator:
            flags.append(f"generator tool in metadata: {tool}")
    if meta.get("creation_date") and meta.get("mod_date"):
        if meta["creation_date"] == meta["mod_date"]:
            flags.append("creation and modification timestamps identical")
    if not producer and not creator:
        flags.append("stripped document metadata")
    score = min(100.0, len(flags) * 30.0)
    return {
        "authenticity_score": round(100.0 - score, 1),
        "tampering_likelihood": round(score, 1),
        "flags": flags,
    }


def score_invoice_document(text: str, meta: dict | None = None, *, org_id: str = "unknown") -> dict:
    t = analyze_text(text, org_id=org_id, use_ai=False)
    m = analyze_document_metadata(meta or {})
    combined = round((t["ai_generated_likelihood"] * 0.5 + m["tampering_likelihood"] * 0.5), 1)
    return {
        "document_risk_score": combined,
        "text_analysis": t,
        "metadata_analysis": m,
    }
