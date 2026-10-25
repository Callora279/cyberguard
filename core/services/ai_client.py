"""Universal, org-aware AI client.

Every module that needs an AI call (AI Governance, Security Debt remediation,
Fraud Detection, Predictive Risk, Cyber Twin simulation, ...) should call
:func:`chat_for_org` / :func:`chat_json_for_org` here instead of hitting a
provider SDK directly.

Routing:
    * No ``org_ai_settings`` row, or a row with no API key configured →
      falls back to the system default (Groq via ``core.utils.ai_client``,
      routed through the full AI Governance policy/risk gate exactly as
      before this module existed).
    * A row with a configured provider + key → calls that provider directly
      with the org's own key/model/limits, still recorded through AI
      Governance (``ai_interactions`` + anomaly alerts) so monitoring stays
      uniform regardless of which provider answered the call.

All five providers speak either an OpenAI-compatible chat/completions shape
(Groq, OpenAI, Custom/self-hosted — Ollama, LM Studio, Azure OpenAI's
compatibility endpoint, ...) or their own REST shape (Anthropic, Gemini) —
handled directly over httpx so this stays dependency-light.
"""
from __future__ import annotations

import json
import time
from typing import Any

import httpx

from core.database.db import session_scope
from core.database.models import OrgAISettings
from core.utils.ai_client import AICallRecord
from core.utils.config import settings
from core.utils.crypto import decrypt_secret, encrypt_secret, mask_secret, sha256_hex
from core.utils.exceptions import UpstreamError, ValidationError
from core.utils.logger import get_logger

logger = get_logger("services.ai_client")

# ---------------------------------------------------------------------------
# Provider / model catalogue — drives the Settings page dropdowns.
# ---------------------------------------------------------------------------
PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "groq": {
        "label": "Groq (default — fast, free tier)",
        "requires_key": False,  # system default key is used if the org leaves this blank
        "requires_base_url": False,
        "default_model": "qwen/qwen3.8-27b",
        "models": [
            {"id": "qwen/qwen3.8-27b", "label": "Qwen 3.8 27B (default)"},
            {"id": "openai/gpt-oss-120b", "label": "GPT-OSS 120B (powerful)"},
            {"id": "meta-llama/llama-4-scout", "label": "Llama 4 Scout"},
        ],
    },
    "openai": {
        "label": "OpenAI",
        "requires_key": True,
        "requires_base_url": False,
        "default_model": "gpt-4o-mini",
        "models": [
            {"id": "gpt-4o", "label": "GPT-4o (most capable)"},
            {"id": "gpt-4o-mini", "label": "GPT-4o mini (faster/cheaper)"},
            {"id": "gpt-3.5-turbo", "label": "GPT-3.5 Turbo (cheapest)"},
        ],
    },
    "anthropic": {
        "label": "Anthropic Claude",
        "requires_key": True,
        "requires_base_url": False,
        "default_model": "claude-sonnet-5",
        "models": [
            {"id": "claude-sonnet-5", "label": "Claude Sonnet 5 (best reasoning)"},
            {"id": "claude-haiku-4-5", "label": "Claude Haiku 4.5 (fastest)"},
        ],
    },
    "gemini": {
        "label": "Google Gemini",
        "requires_key": True,
        "requires_base_url": False,
        "default_model": "gemini-3.6-flash",
        "models": [
            {"id": "gemini-3.6-flash", "label": "Gemini 3.6 Flash (fast)"},
            {"id": "gemini-2.5-flash", "label": "Gemini 2.5 Flash (powerful)"},
        ],
    },
    "custom": {
        "label": "Custom / self-hosted (OpenAI-compatible)",
        "requires_key": False,  # many local servers (Ollama, LM Studio) need no key
        "requires_base_url": True,
        "default_model": "",
        "models": [],  # free-text — Ollama/LM Studio/Azure model names vary
        "hint": "Any OpenAI-compatible /chat/completions endpoint — Ollama, LM Studio, Azure OpenAI, vLLM, ...",
    },
}

_PRICE_PER_MTOK: dict[str, dict[str, float]] = {
    # rough USD-per-million-token estimates, for dashboard cost tracking only
    "groq": {"prompt": 0.20, "completion": 0.60},
    "openai": {"prompt": 2.50, "completion": 10.00},
    "anthropic": {"prompt": 3.00, "completion": 15.00},
    "gemini": {"prompt": 0.35, "completion": 1.05},
    "custom": {"prompt": 0.0, "completion": 0.0},
}


def _estimate_cost(provider: str, prompt_tokens: int, completion_tokens: int) -> float:
    price = _PRICE_PER_MTOK.get(provider, _PRICE_PER_MTOK["custom"])
    return round(
        prompt_tokens / 1_000_000 * price["prompt"] + completion_tokens / 1_000_000 * price["completion"], 6
    )


# ---------------------------------------------------------------------------
# Settings persistence
# ---------------------------------------------------------------------------
def get_org_settings_row(org_id: str) -> OrgAISettings | None:
    with session_scope() as db:
        row = db.get(OrgAISettings, org_id)
        if row is None:
            return None
        db.expunge(row)
        return row


def describe_org_settings(org_id: str) -> dict:
    """Masked view for API responses — never returns the plaintext key."""
    row = get_org_settings_row(org_id)
    if row is None:
        default = PROVIDER_CATALOG["groq"]
        return {
            "provider": "groq",
            "model": default["default_model"],
            "base_url": None,
            "max_tokens": 1024,
            "temperature": 0.2,
            "api_key_configured": False,
            "api_key_masked": "",
            "using_system_default": True,
            "updated_at": None,
        }
    plaintext = decrypt_secret(row.api_key_encrypted) if row.api_key_encrypted else ""
    return {
        "provider": row.provider,
        "model": row.model,
        "base_url": row.base_url,
        "max_tokens": row.max_tokens,
        "temperature": row.temperature,
        "api_key_configured": bool(plaintext),
        "api_key_masked": mask_secret(plaintext),
        "using_system_default": row.provider == "groq" and not plaintext,
        "updated_at": row.updated_at,
    }


def save_org_settings(
    org_id: str,
    *,
    provider: str,
    model: str,
    api_key: str | None = None,
    base_url: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.2,
) -> dict:
    if provider not in PROVIDER_CATALOG:
        raise ValidationError(f"unknown provider '{provider}'")
    catalog = PROVIDER_CATALOG[provider]
    if catalog["requires_base_url"] and not base_url:
        raise ValidationError(f"provider '{provider}' requires a base_url")

    with session_scope() as db:
        row = db.get(OrgAISettings, org_id)
        if row is None:
            row = OrgAISettings(org_id=org_id)
            db.add(row)
        row.provider = provider
        row.model = model or catalog["default_model"]
        row.base_url = base_url if provider == "custom" else None
        row.max_tokens = max_tokens
        row.temperature = temperature
        if api_key:  # blank/omitted = keep the existing key ("leave blank to keep current")
            row.api_key_encrypted = encrypt_secret(api_key)
    return describe_org_settings(org_id)


# ---------------------------------------------------------------------------
# Low-level provider callers — each returns (content, prompt_tokens, completion_tokens)
# ---------------------------------------------------------------------------
def _openai_compatible(
    base_url: str, api_key: str | None, model: str, messages: list[dict], *,
    temperature: float, max_tokens: int, json_mode: bool,
) -> tuple[str, int, int]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body: dict[str, Any] = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    try:
        resp = httpx.post(f"{base_url.rstrip('/')}/chat/completions", headers=headers, json=body, timeout=45.0)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise UpstreamError(f"AI provider request failed: {exc}") from exc
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    return content, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))


def _anthropic(api_key: str, model: str, system: str | None, prompt: str, *, temperature: float, max_tokens: int) -> tuple[str, int, int]:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system
    try:
        resp = httpx.post("https://api.anthropic.com/v1/messages", headers=headers, json=body, timeout=45.0)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise UpstreamError(f"Anthropic request failed: {exc}") from exc
    content = "".join(block.get("text", "") for block in data.get("content", []))
    usage = data.get("usage", {})
    return content, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))


def _gemini(api_key: str, model: str, system: str | None, prompt: str, *, temperature: float, max_tokens: int) -> tuple[str, int, int]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    body: dict[str, Any] = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
    }
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}
    try:
        resp = httpx.post(url, json=body, timeout=45.0)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise UpstreamError(f"Gemini request failed: {exc}") from exc
    candidates = data.get("candidates", [])
    content = ""
    if candidates:
        content = "".join(p.get("text", "") for p in candidates[0].get("content", {}).get("parts", []))
    usage = data.get("usageMetadata", {})
    return content, int(usage.get("promptTokenCount", 0)), int(usage.get("candidatesTokenCount", 0))


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def chat_for_org(
    org_id: str,
    prompt: str,
    *,
    system: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    json_mode: bool = False,
    purpose: str = "generic",
    metadata: dict[str, Any] | None = None,
) -> AICallRecord:
    """Route a chat completion through the org's configured AI provider,
    falling back to the system default (Groq, fully governed) when the org
    has none configured."""
    row = get_org_settings_row(org_id)
    api_key = decrypt_secret(row.api_key_encrypted) if row and row.api_key_encrypted else ""

    if row is None or not api_key:
        # System default — reuse the existing, fully-governed Groq path
        # (policy engine, pre-call risk gate, fingerprinting, monitor observer).
        from core.services.ai_governance.real_time_enforcer import guarded_chat

        # Note: guarded_chat has no json_mode passthrough (matches the existing
        # core.utils.ai_client.chat_json contract) — chat_json_for_org's
        # find-the-braces repair step is the safety net for this path, same as
        # it is for the existing system-default JSON callers.
        return guarded_chat(
            prompt,
            org_id=org_id,
            system=system,
            model=model,
            max_tokens=max_tokens or 1024,
            temperature=temperature if temperature is not None else 0.2,
            purpose=purpose,
        )

    provider = row.provider
    model = model or row.model
    temperature = row.temperature if temperature is None else temperature
    max_tokens = row.max_tokens if max_tokens is None else max_tokens

    # Same pre-call governance gate the system-default path gets, applied
    # uniformly regardless of provider.
    from core.services.ai_governance import policy_engine, risk_scoring

    decision = policy_engine.evaluate(org_id, prompt=prompt, model=model, max_tokens=max_tokens)
    if not decision.allowed:
        from core.utils.exceptions import PolicyViolation

        raise PolicyViolation("AI request blocked by governance policy", details={"violations": decision.violations})
    pre_risk = risk_scoring.prompt_risk(prompt)

    messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
    started = time.perf_counter()

    if provider == "groq":
        content, pt, ct = _openai_compatible(
            settings.GROQ_BASE_URL, api_key, model, messages,
            temperature=temperature, max_tokens=max_tokens, json_mode=json_mode,
        )
    elif provider == "openai":
        content, pt, ct = _openai_compatible(
            "https://api.openai.com/v1", api_key, model, messages,
            temperature=temperature, max_tokens=max_tokens, json_mode=json_mode,
        )
    elif provider == "anthropic":
        content, pt, ct = _anthropic(api_key, model, system, prompt, temperature=temperature, max_tokens=max_tokens)
    elif provider == "gemini":
        content, pt, ct = _gemini(api_key, model, system, prompt, temperature=temperature, max_tokens=max_tokens)
    elif provider == "custom":
        content, pt, ct = _openai_compatible(
            row.base_url or "", api_key or None, model, messages,
            temperature=temperature, max_tokens=max_tokens, json_mode=json_mode,
        )
    else:  # pragma: no cover — guarded by save_org_settings' validation
        raise ValidationError(f"unknown provider '{provider}'")

    record = AICallRecord(
        model=model,
        prompt=prompt,
        prompt_hash=sha256_hex(prompt),
        response=content,
        prompt_tokens=pt,
        completion_tokens=ct,
        total_tokens=pt + ct,
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
        cost_usd=_estimate_cost(provider, pt, ct),
        metadata={
            "org_id": org_id,
            "purpose": purpose,
            "provider": provider,
            "policy_decision": decision.action,
            "pre_call_risk": pre_risk,
            **(metadata or {}),
        },
    )

    # Keep AI Governance monitoring uniform across providers.
    from core.services.ai_governance.monitor import record_interaction

    try:
        record_interaction(record)
    except Exception:  # noqa: BLE001
        logger.exception("failed to record ai interaction for provider=%s", provider)

    return record


def chat_json_for_org(org_id: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper that parses a JSON object response, matching
    ``core.utils.ai_client.chat_json``'s repair-on-parse-failure behaviour."""
    record = chat_for_org(org_id, prompt, json_mode=True, **kwargs)
    try:
        return json.loads(record.response)
    except json.JSONDecodeError:
        start, end = record.response.find("{"), record.response.rfind("}")
        if 0 <= start < end:
            return json.loads(record.response[start : end + 1])
        raise


def test_connection(org_id: str) -> dict:
    """Fire a minimal real request against the org's configured provider (or
    the system default) and report whether it's reachable."""
    started = time.perf_counter()
    try:
        record = chat_for_org(
            org_id,
            "Reply with exactly one word: ok",
            max_tokens=8,
            temperature=0.0,
            purpose="settings_test_connection",
        )
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "ok": True,
            "provider": record.metadata.get("provider", "groq"),
            "model": record.model,
            "latency_ms": latency_ms,
            "response_preview": record.response[:80],
        }
    except Exception as exc:  # noqa: BLE001 — surface every failure mode to the UI
        cfg = describe_org_settings(org_id)
        logger.warning("ai test_connection failed for org=%s: %s", org_id, exc)
        return {"ok": False, "provider": cfg["provider"], "model": cfg["model"], "error": str(exc)}
