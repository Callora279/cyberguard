"""Thin wrapper around the Groq OpenAI-compatible chat completions API.

Every AI call in CyberGuard flows through here so the AI Governance module can
observe prompts, responses, token usage and latency in one place.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from core.utils.config import settings
from core.utils.crypto import sha256_hex
from core.utils.exceptions import UpstreamError
from core.utils.logger import get_logger

logger = get_logger("ai_client")

# Observers are called after every completion (used by ai_governance.monitor).
_observers: list[Callable[["AICallRecord"], None]] = []


def register_observer(fn: Callable[["AICallRecord"], None]) -> None:
    _observers.append(fn)


@dataclass
class AICallRecord:
    model: str
    prompt: str
    prompt_hash: str
    response: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: float
    cost_usd: float
    metadata: dict[str, Any] = field(default_factory=dict)


# Rough Groq pricing (USD per 1M tokens) for cost estimation only.
_PRICE_PER_MTOK = {"prompt": 0.20, "completion": 0.60}


def _estimate_cost(prompt_tokens: int, completion_tokens: int) -> float:
    return round(
        prompt_tokens / 1_000_000 * _PRICE_PER_MTOK["prompt"]
        + completion_tokens / 1_000_000 * _PRICE_PER_MTOK["completion"],
        6,
    )


def chat(
    prompt: str,
    *,
    system: str | None = None,
    model: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 1024,
    json_mode: bool = False,
    metadata: dict[str, Any] | None = None,
) -> AICallRecord:
    """Run a single-turn chat completion and emit an :class:`AICallRecord`."""
    model = model or settings.GROQ_MODEL
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}

    started = time.perf_counter()
    try:
        resp = httpx.post(
            f"{settings.GROQ_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json=body,
            timeout=45.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("groq call failed: %s", exc)
        raise UpstreamError(f"groq request failed: {exc}") from exc

    latency_ms = (time.perf_counter() - started) * 1000
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    pt = int(usage.get("prompt_tokens", 0))
    ct = int(usage.get("completion_tokens", 0))

    record = AICallRecord(
        model=model,
        prompt=prompt,
        prompt_hash=sha256_hex(prompt),
        response=content,
        prompt_tokens=pt,
        completion_tokens=ct,
        total_tokens=int(usage.get("total_tokens", pt + ct)),
        latency_ms=round(latency_ms, 2),
        cost_usd=_estimate_cost(pt, ct),
        metadata=metadata or {},
    )
    for observer in _observers:
        try:
            observer(record)
        except Exception:  # noqa: BLE001
            logger.exception("ai observer failed")
    return record


def chat_json(prompt: str, **kwargs: Any) -> dict[str, Any]:
    """Convenience helper that parses a JSON object response."""
    record = chat(prompt, json_mode=True, **kwargs)
    try:
        return json.loads(record.response)
    except json.JSONDecodeError:
        start, end = record.response.find("{"), record.response.rfind("}")
        if 0 <= start < end:
            return json.loads(record.response[start : end + 1])
        raise
