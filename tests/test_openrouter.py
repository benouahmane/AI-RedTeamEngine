"""OpenRouter client — request shape, response parsing, cost accounting.

No network: `httpx.post` is patched, the same way the tool tests patch `_run`.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from agent.llm import MODEL_PRICING, OpenRouterClient, estimate_cost_usd, get_llm_client
from config import settings


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


def _payload(content: str = '{"action": "complete_session"}') -> dict[str, Any]:
    return {
        "model": "qwen/qwen3.8-max",
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 12000, "completion_tokens": 400},
    }


@pytest.fixture()
def api_key(monkeypatch):
    monkeypatch.setattr(settings, "openrouter_api_key", "sk-or-test", raising=False)
    return "sk-or-test"


def test_requires_api_key(monkeypatch):
    monkeypatch.setattr(settings, "openrouter_api_key", None, raising=False)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        OpenRouterClient()


def test_parses_action_and_usage(api_key):
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload())) as post:
        resp = OpenRouterClient().complete("SYSTEM", "USER")

    assert resp.decision == {"action": "complete_session"}
    assert resp.input_tokens == 12000
    assert resp.output_tokens == 400
    assert resp.model == "qwen/qwen3.8-max"
    assert post.call_count == 1


def test_request_shape(api_key):
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload())) as post:
        OpenRouterClient(model="qwen/qwen3.8-max").complete("SYSTEM", "USER")

    kwargs = post.call_args.kwargs
    body = kwargs["json"]
    assert body["model"] == "qwen/qwen3.8-max"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert body["messages"][0]["content"] == "SYSTEM"      # plain string by default
    assert body["messages"][1]["content"] == "USER"
    assert kwargs["headers"]["Authorization"] == "Bearer sk-or-test"
    assert post.call_args.args[0].endswith("/chat/completions")


def test_cache_breakpoint_is_opt_in(api_key, monkeypatch):
    monkeypatch.setattr(settings, "openrouter_cache_system", True, raising=False)
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload())) as post:
        OpenRouterClient().complete("SYSTEM", "USER")

    system = post.call_args.kwargs["json"]["messages"][0]["content"]
    assert isinstance(system, list)
    assert system[0]["cache_control"] == {"type": "ephemeral"}
    assert system[0]["text"] == "SYSTEM"


def test_json_mode_is_opt_in(api_key, monkeypatch):
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload())) as post:
        OpenRouterClient().complete("SYSTEM", "USER")
    assert "response_format" not in post.call_args.kwargs["json"]

    monkeypatch.setattr(settings, "openrouter_json_mode", True, raising=False)
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload())) as post:
        OpenRouterClient().complete("SYSTEM", "USER")
    assert post.call_args.kwargs["json"]["response_format"] == {"type": "json_object"}


def test_tolerates_fenced_json(api_key):
    fenced = '```json\n{"action": "execute_tool", "node_id": "abc"}\n```'
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload(fenced))):
        resp = OpenRouterClient().complete("SYSTEM", "USER")
    assert resp.decision["action"] == "execute_tool"


def test_empty_choices_raises(api_key):
    payload = {"model": "qwen/qwen3.8-max", "choices": [], "usage": {}}
    with (
        patch("agent.llm.httpx.post", return_value=_FakeResponse(payload)),
        pytest.raises(ValueError),
    ):
        OpenRouterClient().complete("SYSTEM", "USER")


def test_cost_accounting_recognises_openrouter_id():
    assert "qwen/qwen3.8-max" in MODEL_PRICING
    # 12k in @ $2/M + 400 out @ $6/M
    assert estimate_cost_usd("qwen/qwen3.8-max", 12000, 400) == pytest.approx(0.0264)


def test_response_cost_uses_served_model(api_key):
    with patch("agent.llm.httpx.post", return_value=_FakeResponse(_payload())):
        resp = OpenRouterClient().complete("SYSTEM", "USER")
    assert resp.cost_usd == pytest.approx(0.0264)


def test_factory_dispatches_to_openrouter(api_key, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "openrouter", raising=False)
    assert isinstance(get_llm_client(role="planner"), OpenRouterClient)
    assert isinstance(get_llm_client(role="parser"), OpenRouterClient)