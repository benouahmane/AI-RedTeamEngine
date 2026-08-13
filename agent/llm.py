"""LLM client abstraction.

Supports two providers — Anthropic (default, with prompt caching on the
system prompt + tool catalogue) and OpenRouter (gateway to many vendors,
used for cross-model benchmark runs).

Every client implements `complete(system_prompt, user_prompt)` and returns a
typed `LLMResponse` carrying the parsed JSON action and token usage.
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
    # OpenRouter-routed models (ids carry a `vendor/` prefix).
    "qwen/qwen3.8-max":          (2.00, 6.00),
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
# OpenRouter (gateway — one key, many vendors; OpenAI-compatible API)
# ────────────────────────────────────────────────────────────────────────────


class OpenRouterClient:
    """OpenRouter gateway, for benchmarking the agent across vendors (FYP D5).

    Keep `LLM_PROVIDER=anthropic` for the runs that produce assessment reports —
    the Claude API is the orchestration stack named in the brief. This client
    exists so the same target can be re-run under a different model and scored
    with `python main.py benchmark`.

    Two behaviours are opt-in because provider support varies:

    * `OPENROUTER_CACHE_SYSTEM` — sends the system prompt as a content block
      with a `cache_control` breakpoint. Needed by vendors that require an
      explicit marker (Anthropic models routed through OpenRouter); others cache
      automatically. The system prompt carries the ~35k-char tool catalogue and
      is stable for a whole session, so getting this right dominates cost.
    * `OPENROUTER_JSON_MODE` — asks for a guaranteed-JSON response. Not every
      model/provider honours `response_format`; enable it if
      `_parse_json_action` starts raising on malformed output.
    """

    def __init__(self, model: str | None = None, host: str | None = None) -> None:
        if not settings.openrouter_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not set in .env")
        self.host = (host or settings.openrouter_url).rstrip("/")
        self.model = model or settings.openrouter_model

    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        system_content: Any = system_prompt
        if settings.openrouter_cache_system:
            system_content = [{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }]

        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": settings.openrouter_max_tokens,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_prompt},
            ],
        }
        if settings.openrouter_json_mode:
            body["response_format"] = {"type": "json_object"}

        resp = httpx.post(
            f"{self.host}/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openrouter_api_key}",
                "Content-Type": "application/json",
                # Attribution headers OpenRouter shows on its activity dashboard.
                "HTTP-Referer": settings.openrouter_referer,
                "X-Title": "AI Red Team Engine",
            },
            json=body,
            timeout=300,
        )
        resp.raise_for_status()
        payload = resp.json()

        choices = payload.get("choices") or []
        message = choices[0].get("message") or {} if choices else {}
        # `content` is regularly present-but-null rather than absent, so a
        # dict.get default never fires. Reasoning models put their output in
        # `reasoning` instead, so try that before treating the reply as empty.
        text = message.get("content") or message.get("reasoning") or ""
        if not text.strip():
            finish = choices[0].get("finish_reason") if choices else None
            raise RuntimeError(
                f"{payload.get('model') or self.model} returned an empty response "
                f"(finish_reason={finish!r}). 'length' means it hit max_tokens "
                f"({body['max_tokens']}) before emitting an action — raise it or "
                f"pick a less verbose model. Otherwise the model may be unsuited "
                f"to the agent loop; try OPENROUTER_JSON_MODE=true first."
            )
        usage = payload.get("usage") or {}
        return LLMResponse(
            decision=_parse_json_action(text),
            raw_text=text,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            # Echo back the id the gateway actually served, so cost accounting
            # and the benchmark record the real model, not the requested one.
            model=payload.get("model") or self.model,
        )


# ────────────────────────────────────────────────────────────────────────────
# Factory + JSON extractor
# ────────────────────────────────────────────────────────────────────────────


def get_llm_client(role: str = "planner") -> LLMClient:
    """Return an LLM client for the given role.

    `role="planner"` uses the stronger reasoning model (tool selection, attack
    planning); `role="parser"` uses the cheaper model for high-volume output
    interpretation. Both fall back to a single configured model when the
    role-specific overrides aren't set.
    """
    provider = settings.llm_provider.lower()
    if provider == "anthropic":
        model = settings.parser_model if role == "parser" else settings.planner_model
        return AnthropicClient(model=model)
    if provider == "openrouter":
        # Single model for both roles — benchmark comparisons are only
        # meaningful when one model handles the whole session.
        return OpenRouterClient()
    raise ValueError(
        f"Unknown LLM_PROVIDER: {settings.llm_provider!r} — expected "
        f"'anthropic' or 'openrouter'"
    )


def _parse_json_action(text: str | None) -> dict[str, Any]:
    """Extract the JSON object the model returned. Tolerant of fenced code blocks."""
    text = (text or "").strip()
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
