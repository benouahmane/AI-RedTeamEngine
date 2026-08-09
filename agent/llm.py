"""LLM client abstraction.

Supports two providers — Anthropic (default, with prompt caching on the
system prompt + tool catalogue) and Ollama (local, for air-gapped labs).

The agent only uses the `propose_action(context)` method which always
returns a typed `AgentDecision`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from config import settings


# Approximate USD per 1M tokens (input, output). Used for benchmark cost
# accounting only — keep in sync with current Anthropic pricing as needed.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-fable-5":            (5.00, 25.00),
    "claude-opus-4-8":           (15.00, 75.00),
    "claude-sonnet-4-6":         (3.00, 15.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
}


def estimate_cost_usd(model: str | None, input_tokens: int | None, output_tokens: int | None) -> float:
    """Best-effort cost estimate; returns 0.0 for unknown models / missing usage."""
    if not model:
        return 0.0
    price = MODEL_PRICING.get(model)
    if price is None:
        # match on prefix (handles dated model ids)
        price = next((v for k, v in MODEL_PRICING.items() if model.startswith(k)), None)
    if price is None:
        return 0.0
    in_rate, out_rate = price
    return round(
        (in_rate * (input_tokens or 0) + out_rate * (output_tokens or 0)) / 1_000_000,
        6,
    )


@dataclass
class LLMResponse:
    decision: dict[str, Any]            # parsed JSON action
    raw_text: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    model: str | None = None

    @property
    def cost_usd(self) -> float:
        return estimate_cost_usd(self.model, self.input_tokens, self.output_tokens)


class LLMClient(Protocol):
    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse: ...


# ────────────────────────────────────────────────────────────────────────────
# Anthropic (Claude API) with prompt caching on system prompt
# ────────────────────────────────────────────────────────────────────────────


class AnthropicClient:
    def __init__(self, model: str | None = None) -> None:
        from anthropic import Anthropic
        if not settings.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set in .env")
        self._client = Anthropic(api_key=settings.anthropic_api_key)
        self.model = model or settings.anthropic_model

    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        # Cache the system prompt — it's huge (catalogue, MITRE refs, RoE)
        # and stable across the entire session.
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=[{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return LLMResponse(
            decision=_parse_json_action(text),
            raw_text=text,
            input_tokens=getattr(resp.usage, "input_tokens", None),
            output_tokens=getattr(resp.usage, "output_tokens", None),
            model=self.model,
        )


# ────────────────────────────────────────────────────────────────────────────
# Ollama (local)
# ────────────────────────────────────────────────────────────────────────────


class OllamaClient:
    def __init__(self, model: str | None = None, host: str | None = None) -> None:
        self.host = host or settings.ollama_host
        self.model = model or settings.ollama_model

    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        resp = httpx.post(
            f"{self.host}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=300,
        )
        resp.raise_for_status()
        body = resp.json()
        text = body.get("message", {}).get("content", "")
        return LLMResponse(
            decision=_parse_json_action(text),
            raw_text=text,
            input_tokens=body.get("prompt_eval_count"),
            output_tokens=body.get("eval_count"),
            model=self.model,
        )


# ────────────────────────────────────────────────────────────────────────────
# Factory + JSON extractor
# ────────────────────────────────────────────────────────────────────────────


def get_llm_client(role: str = "planner") -> LLMClient:
    """Return an LLM client for the given role.

    `role="planner"` uses the stronger reasoning model (tool selection, attack
    planning); `role="parser"` uses the cheaper model for high-volume output
    interpretation. Both fall back to a single configured model when the
    role-specific overrides aren't set, and Ollama ignores the distinction.
    """
    provider = settings.llm_provider.lower()
    if provider == "anthropic":
        model = settings.parser_model if role == "parser" else settings.planner_model
        return AnthropicClient(model=model)
    if provider == "ollama":
        return OllamaClient()
    raise ValueError(f"Unknown LLM_PROVIDER: {settings.llm_provider}")


def _parse_json_action(text: str) -> dict[str, Any]:
    """Extract the JSON object the model returned. Tolerant of fenced code blocks."""
    text = text.strip()
    if text.startswith("```"):
        # strip ```json ... ```
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fallback: find the first { ... } balanced block
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM returned malformed JSON: {exc}\n---\n{text}") from exc
    raise ValueError(f"LLM response contained no JSON action:\n{text}")
