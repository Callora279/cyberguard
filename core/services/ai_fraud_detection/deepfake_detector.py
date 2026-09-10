"""Detect AI-generated / manipulated documents and images.

Works on text (LLM-generated document detection), and on file metadata /
structural signals for images and PDFs. No heavy ML dependency: uses
statistical text signals, metadata inspection and an optional LLM adjudication.
"""
from __future__ import annotations

import json
import re
from collections import Counter

from core.services.ai_governance.real_time_enforcer import guarded_chat
from core.utils.exceptions import CyberGuardError
from core.utils.logger import get_logger

logger = get_logger("fraud.deepfake")


def _extract_json(text: str) -> str:
    start, end = text.find("{"), text.rfind("}")
    return text[start : end + 1] if 0 <= start < end else text

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


def detect_falsified_document(text: str, *, org_id: str = "unknown") -> dict:
    """Ask Groq directly whether a document looks AI-generated or falsified.

    Returns ``{confidence: 0-1, verdict, reasoning, indicators}``. Falls back to
    the statistical text signals if the model call is unavailable.
    """
    stats = analyze_text(text, org_id=org_id, use_ai=False)
    try:
        record = guarded_chat(
            "Does this document show signs of being AI-generated or falsified "
            "(inconsistent formatting, fabricated figures, template language, "
            "impossible dates/totals)? Reply ONLY with JSON: "
            '{"ai_generated_or_falsified": bool, "confidence": 0-1, '
            '"reasoning": str, "indicators": [str]}.\n\n' + text[:3500],
            org_id=org_id,
            system="You are a forensic document examiner. Return only JSON.",
            purpose="falsified_document_detection",
            max_tokens=400,
        )
        import json

        verdict = json.loads(
            record.response[record.response.find("{"): record.response.rfind("}") + 1]
        )
        confidence = float(verdict.get("confidence", 0.0))
        flagged = bool(verdict.get("ai_generated_or_falsified"))
        return {
            "confidence": round(confidence, 2),
            "verdict": "likely_falsified" if flagged and confidence >= 0.5 else (
                "uncertain" if confidence >= 0.35 else "likely_authentic"
            ),
            "reasoning": verdict.get("reasoning", ""),
            "indicators": verdict.get("indicators", []),
            "statistical_signals": stats["signals"],
            "source": "groq",
        }
    except (CyberGuardError, ValueError, KeyError) as exc:
        logger.warning("falsified-document LLM check failed, using heuristics: %s", exc)
        conf = stats["ai_generated_likelihood"] / 100.0
        return {
            "confidence": round(conf, 2),
            "verdict": stats["verdict"],
            "reasoning": "LLM unavailable; scored from statistical text signals only.",
            "indicators": stats["signals"].get("ai_phrase_markers", []),
            "statistical_signals": stats["signals"],
            "source": "heuristic",
        }


def analyze_content(content: str | None, *, org_id: str = "unknown") -> dict:
    """Ask Groq to score a document for fraud / AI generation on a 0.0-1.0 scale.

    Returns ``{"fraud_score": 0.0-1.0, "is_suspicious": bool, "reasons": [...]}``.
    Falls back to statistical text signals if the model is unavailable.
    """
    text = (content or "").strip()
    if not text:
        return {"fraud_score": 0.0, "is_suspicious": False, "reasons": [], "source": "empty"}

    prompt = (
        "Analyse this document for signs of fraud or AI generation:\n"
        f"{text[:4000]}\n\n"
        "Return JSON:\n"
        "{\n"
        '  "fraud_score": 0.0-1.0,\n'
        '  "is_suspicious": true/false,\n'
        '  "reasons": ["reason1", "reason2"]\n'
        "}"
    )
    try:
        record = guarded_chat(
            prompt,
            org_id=org_id,
            system="You are a fraud analyst. Return only valid JSON.",
            purpose="fraud_document_analysis",
            max_tokens=400,
        )
        data = json.loads(_extract_json(record.response))
        fraud_score = max(0.0, min(1.0, float(data.get("fraud_score", 0.0))))
        reasons = [str(r) for r in (data.get("reasons") or [])][:10]
        return {
            "fraud_score": round(fraud_score, 3),
            "is_suspicious": bool(data.get("is_suspicious", fraud_score >= 0.5)),
            "reasons": reasons,
            "source": "groq",
        }
    except (CyberGuardError, ValueError, TypeError, KeyError) as exc:
        logger.warning("fraud document LLM analysis failed, using heuristics: %s", exc)
        stats = analyze_text(text, org_id=org_id, use_ai=False)
        fraud_score = round(stats["ai_generated_likelihood"] / 100.0, 3)
        reasons = list(stats["signals"].get("ai_phrase_markers", []))
        if not reasons and fraud_score > 0:
            reasons = ["template-like / low-variance text"]
        return {
            "fraud_score": fraud_score,
            "is_suspicious": fraud_score >= 0.5,
            "reasons": reasons,
            "source": "heuristic",
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
