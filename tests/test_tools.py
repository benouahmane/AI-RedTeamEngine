"""Tests for the tool registry + base contract.

Per-wrapper execution tests live in `test_tool_execution.py` — those mock
the subprocess (or RPC) layer to verify each parser produces the expected
findings shape without needing the real binary installed.
"""
from __future__ import annotations

import pytest

import tools  # noqa: F401  (registers wrappers)
from tools import registry
from tools.base import OffensiveTool, ToolResult, ToolStatus


def test_registry_contains_expected_tools() -> None:
    names = registry.names()
    for expected in ["nmap", "gobuster", "nuclei", "metasploit", "hydra", "impacket"]:
        assert expected in names, f"{expected} should be registered"


def test_each_tool_exposes_required_metadata() -> None:
    for entry in registry.all_tools():
        assert entry["name"]
        assert entry["phase"] in {
            "recon", "enumeration", "vuln_id", "exploitation",
            "post_exploit", "lateral_movement", "objective",
        }
        assert isinstance(entry["mitre_techniques"], list)


def test_param_schemas_are_well_formed() -> None:
    for name in registry.names():
        schema = registry.get(name).param_schema()
        assert schema["type"] == "object"
        assert "properties" in schema


def test_unknown_tool_raises() -> None:
    with pytest.raises(KeyError):
        registry.get("definitely-not-a-real-tool")


def test_nmap_xml_parser_extracts_hosts() -> None:
    """Verify the nmap XML parser without actually running nmap."""
    from tools.recon.nmap import NmapTool
    sample = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addrtype="ipv4" addr="10.0.0.5"/>
        <hostnames><hostname name="metasploitable"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="4.7"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    parsed = NmapTool._parse_xml(sample)
    assert parsed["host_count"] == 1
    host = parsed["hosts"][0]
    assert host["ip"] == "10.0.0.5"
    assert "metasploitable" in host["hostnames"]
    assert {p["port"] for p in host["ports"]} == {22, 80}


def test_tool_result_dict_round_trip() -> None:
    r = ToolResult(
        status=ToolStatus.SUCCESS,
        command="nmap -sV target",
        raw_output="...",
        findings={"hosts": []},
        duration_sec=1.234,
    )
    d = r.to_dict()
    assert d["status"] == "success"
    assert d["duration_sec"] == 1.23
    assert d["findings"] == {"hosts": []}


def test_offensive_tool_is_abstract() -> None:
    with pytest.raises(TypeError):
        OffensiveTool()        # type: ignore[abstract]
