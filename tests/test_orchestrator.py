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


# ─── environment wiring ───────────────────────────────────────────────────
#
# `--env` used to be a label: only the key reached the session, while the
# spec's description, notes and default objective were never read by anything.


def test_environment_description_and_notes_reach_the_prompt():
    """env3's "roast before brute force" is the steer that makes the label
    worth passing; the model previously saw only the bare key."""
    from agent.prompts import build_step_prompt
    from environments.config import ENVIRONMENTS

    spec = ENVIRONMENTS["env3"]
    prompt = build_step_prompt(
        session_id="s", target="10.20.0.10", environment="env3",
        environment_description=spec.description,
        environment_notes=spec.notes,
        mode="autonomous", objective=spec.default_objective,
        allowed_targets=["10.20.0.0/16"], tree_ascii="", tree_context={},
        previous_result=None,
    )
    assert "Game of Active Directory" in prompt
    assert "Kerberoast" in prompt
    assert "Domain Admin" in prompt


def test_prompt_omits_the_guidance_line_when_there_is_none():
    from agent.prompts import build_step_prompt

    prompt = build_step_prompt(
        session_id="s", target="10.0.0.1", environment="env9",
        mode="autonomous", objective="", allowed_targets=[],
        tree_ascii="", tree_context={}, previous_result=None,
    )
    assert "guidance:" not in prompt
    assert "(no description)" in prompt


def test_every_environment_declares_an_objective_and_description():
    """Both now feed the agent, so a blank one silently degrades a run."""
    from environments.config import ENVIRONMENTS

    for key, spec in ENVIRONMENTS.items():
        assert spec.default_objective.strip(), f"{key} has no default objective"
        assert spec.description.strip(), f"{key} has no description"


def test_target_outside_declared_network_warns_but_does_not_block(capsys):
    """Labs get rebuilt on new subnets; a mismatch is a note, not a refusal."""
    from environments.config import ENVIRONMENTS
    from main import warn_if_outside_environment

    env1 = ENVIRONMENTS["env1"]
    warn_if_outside_environment("192.168.56.30", env1)
    assert "outside env1's declared network" in capsys.readouterr().err

    warn_if_outside_environment("192.168.163.131", env1)
    assert capsys.readouterr().err == ""

    # A CIDR or hostname target is not something this check can judge.
    warn_if_outside_environment("10.0.0.0/24", env1)
    warn_if_outside_environment("dc01.lab.local", env1)
    assert capsys.readouterr().err == ""
