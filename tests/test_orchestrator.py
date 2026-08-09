"""Tests for target expansion, LLM cost estimation, and model-routing config."""
from __future__ import annotations

from agent.llm import estimate_cost_usd
from agent.orchestrator import expand_targets
from config import Settings


def test_expand_cidr_excludes_network_and_broadcast():
    hosts = expand_targets("10.0.0.0/30")
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_single_ip():
    assert expand_targets("192.168.56.101") == ["192.168.56.101"]


def test_expand_comma_list():
    assert expand_targets("10.0.0.1, 10.0.0.2 ,10.0.0.3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_expand_hostname_passthrough():
    assert expand_targets("dc01.lab.local") == ["dc01.lab.local"]


def test_expand_from_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.5\n# comment\n\n10.0.0.6\n")
    assert expand_targets(str(f)) == ["10.0.0.5", "10.0.0.6"]


def test_cost_estimation_known_model():
    # 1M input tokens on sonnet = $3.00
    assert estimate_cost_usd("claude-sonnet-4-6", 1_000_000, 0) == 3.0
    assert estimate_cost_usd("claude-sonnet-4-6", 0, 1_000_000) == 15.0


def test_cost_estimation_unknown_or_missing():
    assert estimate_cost_usd("some-future-model", 1000, 1000) == 0.0
    assert estimate_cost_usd(None, 1000, 1000) == 0.0


def test_model_routing_falls_back_to_base_model():
    s = Settings(anthropic_model="base-model",
                 anthropic_planner_model=None, anthropic_parser_model=None)
    assert s.planner_model == "base-model"
    assert s.parser_model == "base-model"


def test_model_routing_overrides():
    s = Settings(anthropic_model="base-model",
                 anthropic_planner_model="strong", anthropic_parser_model="cheap")
    assert s.planner_model == "strong"
    assert s.parser_model == "cheap"
