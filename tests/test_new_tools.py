"""Execution/parser tests for the newly added wrappers, mocking the binary
or REST layer (same approach as test_tool_execution.py)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import tools  # noqa: F401  — registers wrappers
from tools import registry
from tools.base import ToolStatus


def _mock_run(stdout="", stderr="", rc=0, duration=0.1):
    return MagicMock(return_value=(rc, stdout, stderr, duration))


# ── sqlmap ──────────────────────────────────────────────────────────────────

_SQLMAP_OUTPUT = """\
sqlmap identified the following injection point(s) with a total of 120 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
back-end DBMS: MySQL >= 5.0.12
"""


def test_sqlmap_detects_injection():
    tool = registry.get("sqlmap")
    with patch.object(tool, "_run", new=_mock_run(stdout=_SQLMAP_OUTPUT)):
        result = tool.execute(url="http://10.0.0.5/item.php?id=1")
    assert result.status == ToolStatus.SUCCESS
    f = result.findings
    assert f["injectable"] is True
    assert "id" in f["parameters"]
    assert f["dbms"].startswith("MySQL")
    assert "boolean-based blind" in f["techniques"][0]
    assert f["vulnerabilities"][0]["name"] == "SQL injection"


def test_sqlmap_no_injection_is_no_findings():
    tool = registry.get("sqlmap")
    out = "all tested parameters do not appear to be injectable.\n"
    with patch.object(tool, "_run", new=_mock_run(stdout=out)):
        result = tool.execute(url="http://10.0.0.5/item.php?id=1")
    assert result.status == ToolStatus.NO_FINDINGS
    assert result.findings["injectable"] is False


def test_sqlmap_requires_url():
    tool = registry.get("sqlmap")
    result = tool.execute(action="test")
    assert result.status == ToolStatus.ERROR


# ── enum4linux-ng ───────────────────────────────────────────────────────────

def test_enum4linux_parses_json(tmp_path):
    tool = registry.get("enum4linux")
    payload = {
        "users": {"1000": {"username": "msfadmin"}, "1001": {"username": "user"}},
        "groups": {"100": {"groupname": "users"}},
        "shares": {"tmp": {"access": "READ, WRITE"}, "print$": {"access": "NO ACCESS"}},
        "os_info": {"OS": "Unix"},
        "domain": "WORKGROUP",
    }

    def fake_run(argv, **kwargs):
        prefix = argv[argv.index("-oJ") + 1]
        Path(prefix + ".json").write_text(json.dumps(payload))
        return 0, "done", "", 0.3

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(target="10.0.0.5")

    assert result.status == ToolStatus.SUCCESS
    f = result.findings
    assert "msfadmin" in f["users"]
    assert {s["name"] for s in f["shares"]} == {"tmp", "print$"}
    assert f["os"] == "Unix"


def test_enum4linux_requires_target():
    tool = registry.get("enum4linux")
    result = tool.execute()
    assert result.status == ToolStatus.ERROR


# ── linpeas ─────────────────────────────────────────────────────────────────

_LINPEAS_OUTPUT = """\
[+] Linux Exploit Suggester
Vulnerable to CVE-2009-2692

[+] Checking sudo -l
(root) NOPASSWD: /usr/bin/python

SUID Files found:
/usr/bin/passwd
/bin/mount

leaked password = secret123
"""


def test_linpeas_parses_privesc_vectors(tmp_path):
    tool = registry.get("linpeas")
    script = tmp_path / "linpeas.sh"
    script.write_text("#!/bin/bash\necho fake\n")

    with patch.object(tool, "_run", new=_mock_run(stdout=_LINPEAS_OUTPUT)):
        result = tool.execute(
            target="10.0.0.5", username="msfadmin", password="msfadmin",
            script_path=str(script),
        )

    assert result.status == ToolStatus.SUCCESS
    f = result.findings
    assert "CVE-2009-2692" in f["kernel_cves"]
    assert "/usr/bin/python" in f["sudo_nopasswd"]
    assert "/usr/bin/passwd" in f["suid_binaries"]
    assert "secret123" in f["passwords"]


def test_linpeas_requires_auth():
    tool = registry.get("linpeas")
    result = tool.execute(target="10.0.0.5", username="root")
    assert result.status == ToolStatus.ERROR


def test_linpeas_missing_script_errors():
    tool = registry.get("linpeas")
    result = tool.execute(target="10.0.0.5", username="root", password="x",
                          script_path="/nonexistent/linpeas.sh")
    assert result.status == ToolStatus.ERROR
    assert "linpeas" in (result.error or "").lower()


# ── CALDERA ─────────────────────────────────────────────────────────────────

def test_caldera_list_adversaries():
    tool = registry.get("caldera")
    data = [{"adversary_id": "abc", "name": "Hunter", "atomic_ordering": ["a", "b"]}]
    with patch.object(tool, "_request", return_value=data):
        result = tool.execute(action="list_adversaries")
    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 1
    assert result.findings["adversaries"][0]["abilities"] == 2


def test_caldera_start_operation_requires_adversary():
    tool = registry.get("caldera")
    result = tool.execute(action="start_operation")
    assert result.status == ToolStatus.ERROR


def test_caldera_operation_report_summarises_links():
    tool = registry.get("caldera")
    report = {"links": [
        {"ability": {"name": "Whoami", "technique_id": "T1033"}, "status": 0, "paw": "xyz"},
        {"ability": {"name": "Discovery", "technique_id": "T1057"}, "status": 1, "paw": "xyz"},
    ]}
    with patch.object(tool, "_request", return_value=report):
        result = tool.execute(action="operation_report", operation_id="op-1")
    assert result.status == ToolStatus.SUCCESS
    assert result.findings["executed"] == 2
    assert result.findings["succeeded"] == 1


# ── Atomic Red Team ─────────────────────────────────────────────────────────

_ATOMIC_OUTPUT = """\
PathToAtomicsFolder = /opt/atomics
Executing test: T1059.001-1 Mimikatz
Done executing test: T1059.001-1 Mimikatz
"""


def test_atomic_red_team_runs_test():
    tool = registry.get("atomic_red_team")
    with patch.object(tool, "_run", new=_mock_run(stdout=_ATOMIC_OUTPUT)):
        result = tool.execute(technique="T1059.001")
    assert result.status == ToolStatus.SUCCESS
    assert "T1059.001-1 Mimikatz" in result.findings["executed_tests"]
    assert result.findings["completed_tests"]


def test_atomic_red_team_rejects_bad_technique():
    tool = registry.get("atomic_red_team")
    result = tool.execute(technique="not-a-technique")
    assert result.status == ToolStatus.ERROR


# ── registry sanity ─────────────────────────────────────────────────────────

def test_new_tools_are_registered():
    names = set(registry.names())
    for t in ("sqlmap", "enum4linux", "linpeas", "caldera", "atomic_red_team"):
        assert t in names
