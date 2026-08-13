"""Per-tool execution tests with mocked subprocess / RPC.

Each test fakes the subprocess invocation by patching `OffensiveTool._run`
(or, for metasploit, the MSFRPC client) so we can verify the parser
contract without needing the real binary installed.

Failure of any of these tests means a tool parser broke its contract —
the agent depends on the structured findings shape to feed the entity
tables (hosts/vulns/creds).
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import tools  # noqa: F401  — registers wrappers
from tools import registry
from tools.base import ToolStatus


def _mock_run(stdout: str = "", stderr: str = "", rc: int = 0, duration: float = 0.1):
    """Make a MagicMock suitable for `patch.object(tool, '_run', new=...)`.

    Returns the 4-tuple `(returncode, stdout, stderr, duration)` that the
    real `_run` produces.
    """
    return MagicMock(return_value=(rc, stdout, stderr, duration))


# ────────────────────────────────────────────────────────────────────────────
# Recon
# ────────────────────────────────────────────────────────────────────────────


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="ipv4" addr="192.168.56.101"/>
    <hostnames><hostname name="metasploitable"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="4.7"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_execute_parses_xml() -> None:
    tool = registry.get("nmap")
    with patch.object(tool, "_run", new=_mock_run(stdout=NMAP_XML)):
        result = tool.execute(target="192.168.56.101", scan_type="service")

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["host_count"] == 1
    host = result.findings["hosts"][0]
    assert host["ip"] == "192.168.56.101"
    assert "metasploitable" in host["hostnames"]
    assert {p["port"] for p in host["ports"]} == {22, 80}


def test_nmap_no_findings_when_no_hosts() -> None:
    tool = registry.get("nmap")
    empty_xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    with patch.object(tool, "_run", new=_mock_run(stdout=empty_xml)):
        result = tool.execute(target="10.99.99.99")
    assert result.status == ToolStatus.NO_FINDINGS


def test_nmap_timeout_returns_timeout_status() -> None:
    tool = registry.get("nmap")
    with patch.object(tool, "_run", new=_mock_run(rc=-1, stderr="Timeout after 900s")):
        result = tool.execute(target="192.168.56.101")
    assert result.status == ToolStatus.TIMEOUT


def test_rustscan_parses_greppable() -> None:
    tool = registry.get("rustscan")
    sample = "Open 192.168.56.101:22\n192.168.56.101 -> [22,80,445,3306,3632]\n"
    with patch.object(tool, "_run", new=_mock_run(stdout=sample)):
        result = tool.execute(target="192.168.56.101")

    assert result.status == ToolStatus.SUCCESS
    h = result.findings["hosts"][0]
    assert h["ip"] == "192.168.56.101"
    assert h["open_ports"] == [22, 80, 445, 3306, 3632]
    assert all(p["protocol"] == "tcp" for p in h["ports"])


def test_rustscan_no_findings_on_empty_output() -> None:
    tool = registry.get("rustscan")
    with patch.object(tool, "_run", new=_mock_run(stdout="")):
        result = tool.execute(target="10.99.99.99")
    assert result.status == ToolStatus.NO_FINDINGS


def test_theharvester_parses_json_output(tmp_path: Path) -> None:
    tool = registry.get("theharvester")
    sample = {
        "emails": ["admin@example.com", "support@example.com"],
        "hosts": ["mail.example.com", "www.example.com"],
        "ips": ["198.51.100.1"],
        "asns": [],
        "urls": [],
    }

    def fake_run(argv, **kwargs):
        # `-f <prefix>` — theHarvester writes <prefix>.json
        prefix = argv[argv.index("-f") + 1]
        Path(prefix + ".json").write_text(json.dumps(sample))
        return 0, "ok", "", 0.1

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(domain="example.com")

    assert result.status == ToolStatus.SUCCESS
    assert "admin@example.com" in result.findings["emails"]
    assert result.findings["total"] == 5  # 2 emails + 2 hosts + 1 ip


# ────────────────────────────────────────────────────────────────────────────
# Vulnerability scanning
# ────────────────────────────────────────────────────────────────────────────


def test_nuclei_parses_jsonl() -> None:
    tool = registry.get("nuclei")
    sample = (
        '{"template-id":"apache-default","host":"http://10.0.0.1",'
        '"matched-at":"http://10.0.0.1/","type":"http",'
        '"info":{"name":"Apache default page","severity":"info","classification":{}}}\n'
        '{"template-id":"cve-2017-9841","host":"http://10.0.0.1",'
        '"matched-at":"http://10.0.0.1/util.php","type":"http",'
        '"info":{"name":"PHPUnit RCE","severity":"critical",'
        '"classification":{"cve-id":"CVE-2017-9841","cvss-score":9.8}}}\n'
    )
    with patch.object(tool, "_run", new=_mock_run(stdout=sample)):
        result = tool.execute(target="http://10.0.0.1")

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["total"] == 2
    cves = [v["cve"] for v in result.findings["vulnerabilities"] if v["cve"]]
    assert "CVE-2017-9841" in cves
    assert result.findings["severity_counts"]["critical"] == 1


def test_nuclei_skips_malformed_lines() -> None:
    tool = registry.get("nuclei")
    sample = '{"template-id":"x","host":"h","info":{"name":"n","severity":"low"}}\n<<<not-json>>>\n'
    with patch.object(tool, "_run", new=_mock_run(stdout=sample)):
        result = tool.execute(target="http://10.0.0.1")
    assert result.findings["total"] == 1


# ────────────────────────────────────────────────────────────────────────────
# Web enumeration
# ────────────────────────────────────────────────────────────────────────────


def test_gobuster_parses_status_size_lines() -> None:
    tool = registry.get("gobuster")
    sample = (
        "/admin                (Status: 301) [Size: 312]\n"
        "/login.php            (Status: 200) [Size: 1024]\n"
        "/robots.txt           (Status: 200) [Size: 56]\n"
    )
    with patch.object(tool, "_run", new=_mock_run(stdout=sample)):
        result = tool.execute(url="http://10.0.0.1")

    assert result.status == ToolStatus.SUCCESS
    paths = result.findings["paths"]
    assert len(paths) == 3
    assert {p["path"] for p in paths} == {"/admin", "/login.php", "/robots.txt"}
    admin = next(p for p in paths if p["path"] == "/admin")
    assert admin["status"] == 301
    assert admin["size"] == 312


def test_ffuf_parses_json_results() -> None:
    tool = registry.get("ffuf")
    sample_results = {
        "results": [
            {
                "url": "http://10.0.0.1/admin",
                "input": {"FUZZ": "admin"},
                "status": 200,
                "length": 100,
                "words": 10,
                "lines": 5,
                "content-type": "text/html",
            },
            {
                "url": "http://10.0.0.1/backup.zip",
                "input": {"FUZZ": "backup.zip"},
                "status": 200,
                "length": 50000,
                "words": 1,
                "lines": 1,
                "content-type": "application/zip",
            },
        ]
    }

    def fake_run(argv, **kwargs):
        outfile = argv[argv.index("-o") + 1]
        Path(outfile).write_text(json.dumps(sample_results))
        return 0, "", "", 0.1

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(url="http://10.0.0.1/FUZZ")

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 2
    statuses = {r["status"] for r in result.findings["results"]}
    assert statuses == {200}


def test_ffuf_rejects_url_without_FUZZ() -> None:
    tool = registry.get("ffuf")
    result = tool.execute(url="http://10.0.0.1/admin")
    assert result.status == ToolStatus.ERROR
    assert "FUZZ" in (result.error or "")


def test_nikto_parses_json_output() -> None:
    tool = registry.get("nikto")
    sample = {
        "host": "10.0.0.1",
        "ip": "10.0.0.1",
        "port": "80",
        "banner": "Apache/2.2.8",
        "vulnerabilities": [
            {"id": "999100", "OSVDB": "877", "method": "GET",
             "url": "/icons/", "msg": "Directory indexing found."},
            {"id": "999101", "method": "GET",
             "url": "/admin.cgi", "msg": "Admin interface exposed."},
        ],
    }

    def fake_run(argv, **kwargs):
        outfile = argv[argv.index("-output") + 1]
        Path(outfile).write_text(json.dumps(sample))
        return 0, "", "", 0.1

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(host="10.0.0.1")

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 2
    titles = [v["name"] for v in result.findings["vulnerabilities"]]
    assert any("Directory indexing" in t for t in titles)


# ────────────────────────────────────────────────────────────────────────────
# Credentials
# ────────────────────────────────────────────────────────────────────────────


def test_hydra_parses_credential_hits() -> None:
    tool = registry.get("hydra")
    sample = (
        "[DATA] attacking ssh://192.168.56.101:22/\n"
        "[22][ssh] host: 192.168.56.101   login: msfadmin   password: msfadmin\n"
        "1 of 1 target successfully completed, 1 valid password found\n"
    )
    with patch.object(tool, "_run", new=_mock_run(stdout=sample)):
        result = tool.execute(
            target="192.168.56.101",
            service="ssh",
            username="msfadmin",
            password="msfadmin",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 1
    cred = result.findings["credentials"][0]
    assert cred["host"] == "192.168.56.101"
    assert cred["port"] == 22
    assert cred["service"] == "ssh"
    assert cred["username"] == "msfadmin"
    assert cred["password"] == "msfadmin"
    assert result.findings["reported_valid"] == 1


def test_hydra_requires_credentials_input() -> None:
    tool = registry.get("hydra")
    result = tool.execute(target="192.168.56.101", service="ssh")
    assert result.status == ToolStatus.ERROR
    assert "userlist" in (result.error or "") or "username" in (result.error or "")


def test_hashcat_extracts_show_pairs() -> None:
    tool = registry.get("hashcat")
    show_output = (
        "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
        "098f6bcd4621d373cade4e832627b4f6:test\n"
    )
    # First call (the crack) returns rc=0; second call (--show) returns the pairs.
    run_outputs = iter([
        (0, "Cracking…", "", 1.0),    # initial crack
        (0, show_output, "", 0.1),     # --show
    ])
    with patch.object(tool, "_run", side_effect=lambda *a, **kw: next(run_outputs)):
        result = tool.execute(hash_file="/tmp/hashes", mode=0)

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 2
    plains = [c["plaintext"] for c in result.findings["credentials"]]
    assert "password" in plains
    assert "test" in plains


def test_john_extracts_show_credentials() -> None:
    tool = registry.get("john")
    show_output = (
        "msfadmin:msfadmin:::\n"
        "service:service:::\n"
        "2 password hashes cracked, 0 left\n"
    )
    run_outputs = iter([
        (0, "Cracking…", "", 1.0),
        (0, show_output, "", 0.1),
    ])
    with patch.object(tool, "_run", side_effect=lambda *a, **kw: next(run_outputs)):
        result = tool.execute(hash_file="/tmp/hashes")

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 2
    users = {c["username"] for c in result.findings["credentials"]}
    assert {"msfadmin", "service"} == users


# ────────────────────────────────────────────────────────────────────────────
# Exploitation — Metasploit (RPC, not subprocess)
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def fake_msfrpc(monkeypatch):
    """Inject a fake `pymetasploit3.msfrpc` module so the wrapper imports it."""
    fake_msfrpc_mod = types.ModuleType("pymetasploit3.msfrpc")

    class FakeMod:
        def __init__(self):
            self._opts: dict = {}

        def __setitem__(self, k, v):
            self._opts[k] = v

        def execute(self, **kwargs):
            return {"job_id": 42, "uuid": "abc-123"}

    class FakeModules:
        def search(self, query):
            return [{
                "fullname": f"exploit/unix/ftp/{query}_backdoor",
                "type": "exploit",
                "rank": "great",
                "disclosure_date": "2011-07-04",
                "description": f"{query} backdoor RCE",
            }]

        def use(self, mod_type, mod_name):
            return FakeMod()

    class FakeSessions:
        # Sessions msfrpcd already holds. Defined inside the fixture, so each
        # test gets a fresh class and cannot leak state into the next.
        preset: dict = {}

        def __init__(self):
            self.list = dict(FakeSessions.preset)

        def session(self, sid):
            mock = MagicMock()
            mock.write = MagicMock()
            mock.read = MagicMock(return_value="uid=0(root)\n")
            return mock

    class FakeMsfRpcClient:
        Sessions = FakeSessions          # so tests can preset the session map

        def __init__(self, *a, **kw):
            self.modules = FakeModules()
            self.sessions = FakeSessions()

    fake_msfrpc_mod.MsfRpcClient = FakeMsfRpcClient
    fake_pkg = types.ModuleType("pymetasploit3")
    fake_pkg.msfrpc = fake_msfrpc_mod

    monkeypatch.setitem(sys.modules, "pymetasploit3", fake_pkg)
    monkeypatch.setitem(sys.modules, "pymetasploit3.msfrpc", fake_msfrpc_mod)
    # The inherited-session snapshot is process-global and taken once; without
    # this reset it would leak between tests.
    monkeypatch.setattr("tools.exploitation.metasploit._INHERITED_SESSIONS", None)
    yield FakeMsfRpcClient


def test_metasploit_search(fake_msfrpc) -> None:
    tool = registry.get("metasploit")
    result = tool.execute(action="search", query="vsftpd")
    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 1
    assert "vsftpd" in result.findings["modules"][0]["name"]


def test_metasploit_unknown_action() -> None:
    tool = registry.get("metasploit")
    result = tool.execute(action="not-real")
    assert result.status == ToolStatus.ERROR
    assert "unknown action" in (result.error or "").lower()


def test_metasploit_session_list_empty(fake_msfrpc) -> None:
    tool = registry.get("metasploit")
    result = tool.execute(action="session_list")
    assert result.status == ToolStatus.NO_FINDINGS
    assert result.findings["count"] == 0


def test_metasploit_session_list_flags_inherited_sessions(fake_msfrpc) -> None:
    """A shell left behind by a previous run must not read as this run's win.

    msfrpcd outlives an engine run. The agent found a leftover session, used
    it, and the report described a clean autonomous compromise for a run whose
    every exploit returned session_id=null.
    """
    fake_msfrpc.Sessions.preset = {
        "1": {"type": "shell", "session_port": 139,
              "via_exploit": "exploit/multi/samba/usermap_script"},
    }
    tool = registry.get("metasploit")
    result = tool.execute(action="session_list")

    assert result.status == ToolStatus.SUCCESS
    f = result.findings
    assert f["count"] == 1
    assert f["inherited_count"] == 1
    assert f["opened_this_run"] == 0
    assert f["sessions"][0]["inherited"] is True
    assert "NOT evidence" in f["warning"]


def test_metasploit_session_run_marks_inherited(fake_msfrpc) -> None:
    fake_msfrpc.Sessions.preset = {"1": {"type": "shell"}}
    tool = registry.get("metasploit")
    result = tool.execute(action="session_run", session_id=1, command="id")
    assert result.findings["inherited"] is True
    assert result.findings["session_id"] == "1"


def test_metasploit_exploit_requires_module(fake_msfrpc) -> None:
    tool = registry.get("metasploit")
    result = tool.execute(action="exploit")
    assert result.status == ToolStatus.ERROR
    assert "module" in (result.error or "").lower()


def test_metasploit_module_metadata_pulls_cves() -> None:
    """The vulnerability register needs the CVE, and msf already holds it.

    Shapes copied from a live pymetasploit3 ExploitModule: the info dict is
    exposed as `.info`, NOT `.moduleinfo`. Reading the wrong name yielded {},
    which put the module path in the register's Title column and left CVE null.
    """
    from tools.exploitation.metasploit import _module_metadata

    class Mod:
        info = {
            "type": "exploit",
            "name": 'Samba "username map script" Command Execution',
            "fullname": "exploit/multi/samba/usermap_script",
            "rank": "excellent",
            "disclosuredate": "2007-05-14",
            "description": "  This module exploits a command execution vuln.  ",
            "references": [
                ["CVE", "2007-2447"],
                ["OSVDB", "34700"],
                ["BID", "23972"],
                ["URL", "https://example.test/advisory"],
            ],
        }

    meta = _module_metadata(Mod())
    assert meta["cves"] == ["CVE-2007-2447"]
    assert meta["module_name"].startswith("Samba")
    assert meta["module_rank"] == "excellent"
    assert meta["disclosure_date"] == "2007-05-14"
    assert meta["module_description"] == "This module exploits a command execution vuln."
    assert meta["references"] == ["https://example.test/advisory"]


def test_metasploit_module_metadata_falls_back_to_properties() -> None:
    """Builds without an info dict still expose name/description/references."""
    from tools.exploitation.metasploit import _module_metadata

    class Mod:
        name = "UnrealIRCD 3.2.8.1 Backdoor Command Execution"
        description = "Backdoored source tarball."
        rank = "excellent"
        references = [["CVE", "2010-2075"]]

    meta = _module_metadata(Mod())
    assert meta["cves"] == ["CVE-2010-2075"]
    assert meta["module_name"].startswith("UnrealIRCD")


def test_payload_choice_prefers_exact_interact_then_reverse() -> None:
    """Substring matching picked generic/ssh/interact and bind_awk; both
    launched a job and produced no session."""
    from tools.exploitation.metasploit import _pick_payload

    # vsftpd backdoor: `generic/ssh/interact` also contains "interact".
    vsftpd = ["cmd/unix/interact", "generic/ssh/interact", "cmd/unix/bind_awk"]
    assert _pick_payload(vsftpd) == "cmd/unix/interact"

    # usermap_script: no interact payload — reverse must beat bind.
    samba = ["cmd/unix/bind_awk", "cmd/unix/bind_netcat", "cmd/unix/reverse_netcat"]
    assert _pick_payload(samba) == "cmd/unix/reverse_netcat"

    # The agent supplying LHOST/LPORT means it wants a reverse shell. Handing
    # it `interact` made the wrapper reject its own LPORT as invalid.
    assert _pick_payload(vsftpd, wants_callback=True) != "cmd/unix/interact"

    # Non-unix targets fall through to any reverse payload.
    win = ["windows/shell/bind_tcp", "windows/meterpreter/reverse_tcp"]
    assert _pick_payload(win) == "windows/meterpreter/reverse_tcp"

    # Bind only when nothing reverse exists, and never crash on an empty list.
    assert _pick_payload(["cmd/unix/bind_awk"]) == "cmd/unix/bind_awk"
    assert _pick_payload(["some/odd/payload"]) == "some/odd/payload"
    assert _pick_payload([]) is None


def test_metasploit_module_metadata_survives_missing_moduleinfo() -> None:
    """Older pymetasploit3 builds expose no moduleinfo — must not crash."""
    from tools.exploitation.metasploit import _module_metadata

    meta = _module_metadata(object())
    assert meta["cves"] == []
    assert meta["module_name"] is None


# ────────────────────────────────────────────────────────────────────────────
# OpenVAS / Greenbone — multi-step GMP orchestration over gvm-cli
# ────────────────────────────────────────────────────────────────────────────


_OV_TARGET_OK = '<create_target_response status="201" id="tgt-1"/>'
_OV_TASK_OK = '<create_task_response status="201" id="task-1"/>'
_OV_START_OK = (
    '<start_task_response status="202">'
    '<report_id>rep-1</report_id>'
    '</start_task_response>'
)
_OV_TASK_RUNNING = (
    '<get_tasks_response status="200">'
    '<task id="task-1"><status>Running</status></task>'
    '</get_tasks_response>'
)
_OV_TASK_DONE = (
    '<get_tasks_response status="200">'
    '<task id="task-1"><status>Done</status></task>'
    '</get_tasks_response>'
)
_OV_REPORT = """<get_reports_response status="200">
  <report><report><results>
    <result>
      <name>vsftpd 2.3.4 backdoor</name>
      <host>192.168.56.101</host>
      <port>21/tcp</port>
      <threat>High</threat>
      <severity>10.0</severity>
      <description>The vsftpd 2.3.4 daemon contains a backdoor.</description>
      <refs><ref type="cve" id="CVE-2011-2523"/></refs>
    </result>
    <result>
      <name>SSH Weak MAC Algorithms</name>
      <host>192.168.56.101</host>
      <port>22/tcp</port>
      <threat>Medium</threat>
      <severity>4.3</severity>
      <description>Weak HMAC algorithms enabled.</description>
    </result>
  </results></report></report>
</get_reports_response>"""


def test_openvas_full_scan_parses_results(monkeypatch) -> None:
    tool = registry.get("openvas")
    monkeypatch.setattr("tools.vuln_scan.openvas._sleep", lambda *_: None)

    responses = iter([
        (0, _OV_TARGET_OK,    "", 0.1),
        (0, _OV_TASK_OK,      "", 0.1),
        (0, _OV_START_OK,     "", 0.1),
        (0, _OV_TASK_RUNNING, "", 0.1),
        (0, _OV_TASK_DONE,    "", 0.1),
        (0, _OV_REPORT,       "", 0.1),
    ])
    with patch.object(tool, "_run", side_effect=lambda *a, **kw: next(responses)):
        result = tool.execute(target="192.168.56.101", poll_interval_sec=0)

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["task_id"] == "task-1"
    assert result.findings["report_id"] == "rep-1"
    assert result.findings["total"] == 2
    vulns = result.findings["vulnerabilities"]
    backdoor = next(v for v in vulns if "vsftpd" in v["name"])
    assert backdoor["cve"] == "CVE-2011-2523"
    assert backdoor["severity"] == "critical"          # 10.0 → critical
    assert backdoor["port"] == 21
    weak_mac = next(v for v in vulns if "MAC" in v["name"])
    assert weak_mac["severity"] == "medium"            # 4.3 → medium
    assert result.findings["severity_counts"]["critical"] == 1
    assert result.findings["severity_counts"]["medium"] == 1


def test_openvas_no_findings_when_report_empty(monkeypatch) -> None:
    tool = registry.get("openvas")
    monkeypatch.setattr("tools.vuln_scan.openvas._sleep", lambda *_: None)
    empty_report = '<get_reports_response status="200"><report><report><results/></report></report></get_reports_response>'
    responses = iter([
        (0, _OV_TARGET_OK, "", 0.1),
        (0, _OV_TASK_OK,   "", 0.1),
        (0, _OV_START_OK,  "", 0.1),
        (0, _OV_TASK_DONE, "", 0.1),
        (0, empty_report,  "", 0.1),
    ])
    with patch.object(tool, "_run", side_effect=lambda *a, **kw: next(responses)):
        result = tool.execute(target="10.99.99.99", poll_interval_sec=0)

    assert result.status == ToolStatus.NO_FINDINGS
    assert result.findings["total"] == 0


def test_openvas_times_out_when_task_never_finishes(monkeypatch) -> None:
    tool = registry.get("openvas")
    # Drive the polling clock: 0 (deadline init), 0 (iter 1 enters loop), 9999 (iter 2 exits)
    clock = iter([0.0, 0.0, 9999.0])
    monkeypatch.setattr("tools.vuln_scan.openvas._now", lambda: next(clock))
    monkeypatch.setattr("tools.vuln_scan.openvas._sleep", lambda *_: None)

    responses = iter([
        (0, _OV_TARGET_OK,    "", 0.1),
        (0, _OV_TASK_OK,      "", 0.1),
        (0, _OV_START_OK,     "", 0.1),
        (0, _OV_TASK_RUNNING, "", 0.1),
    ])
    with patch.object(tool, "_run", side_effect=lambda *a, **kw: next(responses)):
        result = tool.execute(
            target="192.168.56.101",
            max_wait_sec=10, poll_interval_sec=1,
        )

    assert result.status == ToolStatus.TIMEOUT
    assert result.findings["task_id"] == "task-1"
    assert "Running" in (result.error or "")


def test_openvas_create_target_failure_surfaces_as_error() -> None:
    tool = registry.get("openvas")
    err_response = '<create_target_response status="400" status_text="Bogus hosts"/>'
    with patch.object(tool, "_run", new=_mock_run(stdout=err_response)):
        result = tool.execute(target="not-an-ip", max_wait_sec=10, poll_interval_sec=0)

    assert result.status == ToolStatus.ERROR
    assert "GMP error 400" in (result.error or "")


def test_openvas_rejects_unknown_scan_config() -> None:
    tool = registry.get("openvas")
    result = tool.execute(target="192.168.56.101", scan_config="bogus")
    assert result.status == ToolStatus.ERROR
    assert "scan_config" in (result.error or "")


# ────────────────────────────────────────────────────────────────────────────
# Post-exploit — pwncat-cs (subprocess driven via stdin script)
# ────────────────────────────────────────────────────────────────────────────


_PWNCAT_ENUMERATE_OUTPUT = """[+] connecting to 192.168.56.101:22
[+] authenticated as msfadmin
[+] starting enumeration
hostname: metasploitable
current user: msfadmin
kernel: Linux 2.6.24-16-server
[+] suid binaries discovered:
  /usr/bin/passwd (suid)
  /usr/bin/sudo (suid)
  /bin/mount (suid)
[+] sudo entries:
  (root) NOPASSWD: /usr/bin/python
  (root) ALL: ALL
[+] enumeration complete
"""

_PWNCAT_PRIVESC_OUTPUT = """[+] running linux.enumerate.privesc
[+] kernel exploitation candidate: CVE-2009-2692
[+] privesc path found: sudo /usr/bin/python -> root shell
[+] escalation candidate via SUID /usr/bin/passwd
"""

_PWNCAT_EXEC_OUTPUT = """[+] connected
(local) pwncat$ id
uid=1000(msfadmin) gid=1000(msfadmin)
(local) pwncat$ uname -a
Linux metasploitable 2.6.24-16-server
(local) pwncat$ exit
"""


def test_pwncat_enumerate_extracts_suid_and_sudo() -> None:
    tool = registry.get("pwncat")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["stdin"] = kwargs.get("input_data", "")
        return 0, _PWNCAT_ENUMERATE_OUTPUT, "", 0.5

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            target="192.168.56.101",
            username="msfadmin", password="msfadmin",
            action="enumerate",
        )

    assert result.status == ToolStatus.SUCCESS
    assert "ssh://msfadmin:msfadmin@192.168.56.101:22" in captured["argv"]
    assert "run enumerate" in captured["stdin"]
    assert captured["stdin"].rstrip().endswith("exit")

    f = result.findings
    assert f["current_user"] == "msfadmin"
    assert f["hostname"] == "metasploitable"
    assert f["kernel"].startswith("Linux 2.6.24")
    assert "/usr/bin/passwd" in f["suid_binaries"]
    assert "/usr/bin/sudo" in f["suid_binaries"]
    nopasswd = next(s for s in f["sudo_entries"] if "NOPASSWD" in s["spec"])
    assert nopasswd["as_user"] == "root"


def test_pwncat_privesc_finds_escalation_paths() -> None:
    tool = registry.get("pwncat")
    with patch.object(tool, "_run", new=_mock_run(stdout=_PWNCAT_PRIVESC_OUTPUT)):
        result = tool.execute(
            target="192.168.56.101",
            username="msfadmin", password="msfadmin",
            action="privesc",
        )

    assert result.status == ToolStatus.SUCCESS
    paths = result.findings["escalation_paths"]
    assert any("CVE-2009-2692" in p for p in paths)
    assert any("python" in p for p in paths)


def test_pwncat_exec_splits_command_blocks() -> None:
    tool = registry.get("pwncat")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["stdin"] = kwargs.get("input_data", "")
        return 0, _PWNCAT_EXEC_OUTPUT, "", 0.2

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            target="192.168.56.101",
            username="msfadmin", password="msfadmin",
            action="exec",
            commands=["id", "uname -a"],
        )

    assert result.status == ToolStatus.SUCCESS
    blocks = result.findings["output_blocks"]
    assert any("uid=1000" in b for b in blocks)
    assert any("metasploitable" in b for b in blocks)
    # The script piped to stdin should be the user-provided commands plus exit.
    script_lines = captured["stdin"].splitlines()
    assert script_lines[0] == "id"
    assert script_lines[1] == "uname -a"
    assert script_lines[-1] == "exit"


def test_pwncat_uses_identity_file_when_provided() -> None:
    tool = registry.get("pwncat")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _PWNCAT_ENUMERATE_OUTPUT, "", 0.1

    with patch.object(tool, "_run", side_effect=fake_run):
        tool.execute(
            target="10.0.0.1",
            username="alice",
            identity_file="/tmp/id_rsa",
            action="enumerate",
        )

    argv = captured["argv"]
    assert "-i" in argv
    assert argv[argv.index("-i") + 1] == "/tmp/id_rsa"
    # No password embedded in the connect URL.
    assert "ssh://alice@10.0.0.1:22" in argv


def test_pwncat_connection_refused_returns_partial() -> None:
    tool = registry.get("pwncat")
    output = "[!] connection refused on 192.168.56.99:22\n"
    with patch.object(tool, "_run", new=_mock_run(stdout=output, rc=0)):
        result = tool.execute(
            target="192.168.56.99",
            username="root", password="root",
            action="enumerate",
        )
    assert result.status == ToolStatus.PARTIAL
    assert "authentication failed" in (result.error or "") or "connection" in (result.error or "")


def test_pwncat_requires_auth() -> None:
    tool = registry.get("pwncat")
    result = tool.execute(target="10.0.0.1", username="root", action="enumerate")
    assert result.status == ToolStatus.ERROR
    assert "auth" in (result.error or "").lower()


def test_pwncat_rejects_both_password_and_identity() -> None:
    tool = registry.get("pwncat")
    result = tool.execute(
        target="10.0.0.1", username="root",
        password="x", identity_file="/tmp/k",
        action="enumerate",
    )
    assert result.status == ToolStatus.ERROR
    assert "either" in (result.error or "").lower()


def test_pwncat_exec_requires_commands() -> None:
    tool = registry.get("pwncat")
    result = tool.execute(
        target="10.0.0.1", username="root", password="x",
        action="exec",
    )
    assert result.status == ToolStatus.ERROR
    assert "commands" in (result.error or "")


def test_pwncat_unknown_action_returns_error() -> None:
    tool = registry.get("pwncat")
    result = tool.execute(
        target="10.0.0.1", username="root", password="x",
        action="not-real",
    )
    assert result.status == ToolStatus.ERROR


def test_pwncat_timeout_returns_timeout_status() -> None:
    tool = registry.get("pwncat")
    with patch.object(tool, "_run", new=_mock_run(rc=-1, stderr="Timeout after 900s")):
        result = tool.execute(
            target="10.0.0.1", username="root", password="x",
            action="enumerate",
        )
    assert result.status == ToolStatus.TIMEOUT


# ────────────────────────────────────────────────────────────────────────────
# Active Directory — CrackMapExec / NetExec
# ────────────────────────────────────────────────────────────────────────────


_CME_AUTH_OUTPUT = """SMB         10.0.0.5        445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:LAB.LOCAL)
SMB         10.0.0.5        445    DC01             [+] LAB.LOCAL\\admin:Password1 (Pwn3d!)
SMB         10.0.0.6        445    WS01             [*] Windows 10.0 Build 19041 (name:WS01) (domain:LAB.LOCAL)
SMB         10.0.0.6        445    WS01             [+] LAB.LOCAL\\admin:Password1
SMB         10.0.0.7        445    WS02             [-] LAB.LOCAL\\admin:Password1 STATUS_LOGON_FAILURE
"""

_CME_NTDS_OUTPUT = """SMB         10.0.0.5        445    DC01             [*] Windows 10.0 Build 17763
SMB         10.0.0.5        445    DC01             [+] Dumping LSA secrets
SMB         10.0.0.5        445    DC01             [+] LAB.LOCAL\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.0.5        445    DC01             [+] LAB.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::
"""


def test_crackmapexec_parses_valid_creds_and_pwn3d() -> None:
    tool = registry.get("crackmapexec")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _CME_AUTH_OUTPUT, "", 0.5

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            protocol="smb", targets="10.0.0.0/24",
            username="admin", password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    f = result.findings
    assert f["host_count"] == 3
    assert f["credential_count"] == 2
    pwn3d = next(c for c in f["valid_credentials"] if c["is_admin"])
    assert pwn3d["host"] == "10.0.0.5"
    assert pwn3d["domain"] == "LAB.LOCAL"
    assert "10.0.0.5" in f["pwned_hosts"]
    assert "10.0.0.7" not in f["pwned_hosts"]
    # Argv carries the credentials.
    assert "-u" in captured["argv"] and "admin" in captured["argv"]
    assert "-p" in captured["argv"] and "Password1" in captured["argv"]


def test_crackmapexec_secretsdump_collects_ntds_hashes() -> None:
    tool = registry.get("crackmapexec")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _CME_NTDS_OUTPUT, "", 1.5

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            protocol="smb", targets="10.0.0.5",
            username="admin", ntlm_hash=":31d6cfe0d16ae931b73c59d7e0c089c0",
            ntds=True,
        )

    assert result.status == ToolStatus.SUCCESS
    secrets = result.findings["dumped_secrets"]
    assert len(secrets) == 2
    krbtgt = next(s for s in secrets if s["username"] == "krbtgt")
    assert krbtgt["secret"].endswith(":::")
    assert "--ntds" in captured["argv"]
    assert "-H" in captured["argv"]


def test_crackmapexec_rejects_password_and_hash_together() -> None:
    tool = registry.get("crackmapexec")
    result = tool.execute(
        protocol="smb", targets="10.0.0.5",
        username="x", password="y", ntlm_hash="z",
    )
    assert result.status == ToolStatus.ERROR
    assert "either" in (result.error or "").lower()


def test_crackmapexec_unknown_protocol_returns_error() -> None:
    tool = registry.get("crackmapexec")
    result = tool.execute(protocol="bogus", targets="10.0.0.5")
    assert result.status == ToolStatus.ERROR


def test_crackmapexec_no_valid_creds_is_no_findings() -> None:
    tool = registry.get("crackmapexec")
    output = ("SMB  10.0.0.5  445  DC01  [*] Windows 10.0\n"
              "SMB  10.0.0.5  445  DC01  [-] LAB.LOCAL\\admin:wrong STATUS_LOGON_FAILURE\n")
    with patch.object(tool, "_run", new=_mock_run(stdout=output)):
        result = tool.execute(
            protocol="smb", targets="10.0.0.5",
            username="admin", password="wrong",
        )
    assert result.status == ToolStatus.NO_FINDINGS
    assert result.findings["credential_count"] == 0
    assert result.findings["host_count"] == 1


# ────────────────────────────────────────────────────────────────────────────
# Active Directory — Impacket
# ────────────────────────────────────────────────────────────────────────────


_IMP_ASREP_OUTPUT = """Impacket v0.12.0
[*] Getting TGT for user
$krb5asrep$23$alice@LAB.LOCAL:abcdef0123456789abcdef$0123456789abcdef
$krb5asrep$23$bob@LAB.LOCAL:fedcba9876543210fedcba$9876543210fedcba
[*] Done
"""

_IMP_KRB_OUTPUT = """Impacket v0.12.0
ServicePrincipalName    Name        MemberOf
MSSQLSvc/sql.lab.local  svc_sql     CN=Domain Users
$krb5tgs$23$*svc_sql$LAB.LOCAL$MSSQLSvc/sql.lab.local*$abcdef0123456789...
"""

_IMP_SECRETS_OUTPUT = """Impacket v0.12.0
[*] Service RemoteRegistry is in stopped state
[*] Target system bootKey: 0x...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
LAB.LOCAL\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
LAB.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::
[*] Cleartext passwords from LSA
DefaultPassword: hunter2
"""


def test_impacket_asreproast_parses_kerberos_hashes() -> None:
    tool = registry.get("impacket")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _IMP_ASREP_OUTPUT, "", 0.4

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="asreproast",
            domain="LAB.LOCAL", target_dc="10.0.0.5",
            userlist="/tmp/users.txt",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 2
    assert result.findings["hash_type"] == "krb5asrep"
    assert all(t.startswith("$krb5asrep$") for t in result.findings["tickets"])
    assert "impacket-GetNPUsers" in captured["argv"][0]
    assert "-no-pass" in captured["argv"]
    assert "-usersfile" in captured["argv"]


def test_impacket_kerberoast_parses_tgs_hashes() -> None:
    tool = registry.get("impacket")
    with patch.object(tool, "_run", new=_mock_run(stdout=_IMP_KRB_OUTPUT)):
        result = tool.execute(
            action="kerberoast",
            domain="LAB.LOCAL", target_dc="10.0.0.5",
            username="alice", password="pw",
        )
    assert result.status == ToolStatus.SUCCESS
    assert result.findings["hash_type"] == "krb5tgs"
    assert result.findings["count"] == 1
    assert result.findings["tickets"][0].startswith("$krb5tgs$")


def test_impacket_secretsdump_extracts_ntds() -> None:
    tool = registry.get("impacket")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _IMP_SECRETS_OUTPUT, "", 1.0

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="secretsdump",
            domain="LAB.LOCAL", target_dc="10.0.0.5",
            username="admin",
            ntlm_hash=":31d6cfe0d16ae931b73c59d7e0c089c0",
        )

    assert result.status == ToolStatus.SUCCESS
    creds = result.findings["credentials"]
    assert len(creds) == 2
    admin = next(c for c in creds if c["username"] == "Administrator")
    assert admin["rid"] == 500
    assert admin["blank_password"] is True       # 31d6… == empty NT hash
    krbtgt = next(c for c in creds if c["username"] == "krbtgt")
    assert krbtgt["blank_password"] is False
    assert any("Cleartext" in s for s in result.findings["cleartext_sections"])
    assert "-hashes" in captured["argv"]


def test_impacket_psexec_runs_one_shot_command() -> None:
    tool = registry.get("impacket")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["stdin"] = kwargs.get("input_data", "")
        return 0, "Impacket v0.12.0\n[*] Connecting...\nuid=0(root)\n", "", 0.3

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="psexec",
            domain="LAB.LOCAL", target_dc="10.0.0.6",
            username="admin", password="pw",
            command="whoami /all",
        )

    assert result.status == ToolStatus.SUCCESS
    assert "uid=0" in result.findings["output"]
    # Connection string DOMAIN/user:password@target with positional principal arg
    assert any(arg.startswith("LAB.LOCAL/admin:pw@10.0.0.6") for arg in captured["argv"])
    assert captured["stdin"].splitlines() == ["whoami /all", "exit"]


def test_impacket_auth_failure_is_partial() -> None:
    tool = registry.get("impacket")
    output = "Impacket v0.12.0\n[-] [Errno Connection error] STATUS_LOGON_FAILURE\n"
    with patch.object(tool, "_run", new=_mock_run(stdout=output, rc=1)):
        result = tool.execute(
            action="kerberoast",
            domain="LAB.LOCAL", target_dc="10.0.0.5",
            username="alice", password="bad",
        )
    assert result.status == ToolStatus.PARTIAL
    assert "auth" in (result.error or "").lower()


def test_impacket_secretsdump_requires_target() -> None:
    tool = registry.get("impacket")
    result = tool.execute(action="secretsdump", domain="LAB.LOCAL", username="x", password="y")
    assert result.status == ToolStatus.ERROR
    assert "target_dc" in (result.error or "")


def test_impacket_kerberoast_requires_password_or_hash() -> None:
    tool = registry.get("impacket")
    result = tool.execute(
        action="kerberoast",
        domain="LAB.LOCAL", target_dc="10.0.0.5", username="alice",
    )
    assert result.status == ToolStatus.ERROR


def test_impacket_rejects_password_and_hash() -> None:
    tool = registry.get("impacket")
    result = tool.execute(
        action="kerberoast",
        domain="LAB.LOCAL", target_dc="10.0.0.5", username="alice",
        password="x", ntlm_hash="y",
    )
    assert result.status == ToolStatus.ERROR
    assert "either" in (result.error or "").lower()


def test_impacket_unknown_action_returns_error() -> None:
    tool = registry.get("impacket")
    result = tool.execute(action="bogus")
    assert result.status == ToolStatus.ERROR


# ────────────────────────────────────────────────────────────────────────────
# BloodHound
# ────────────────────────────────────────────────────────────────────────────

_BH_COLLECT_OUTPUT = """\
INFO: Found AD domain: lab.local
INFO: Connecting to LDAP server: dc01.lab.local
INFO: Found 1 domains
INFO: Found 14 users
INFO: Found 6 groups
INFO: Found 4 computers
INFO: Done in 00M 12S
Compressing output into /tmp/bh_abc/20260507120000_BloodHound.zip
"""


def test_bloodhound_collect_parses_stats() -> None:
    tool = registry.get("bloodhound")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _BH_COLLECT_OUTPUT, "", 12.1

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="collect",
            target_dc="10.0.0.5",
            domain="lab.local",
            username="alice",
            password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    f = result.findings
    assert f["stats"]["users"] == 14
    assert f["stats"]["computers"] == 4
    assert f["completed"] is True
    assert "bloodhound-python" in captured["argv"][0]
    assert "-u" in captured["argv"] and "alice" in captured["argv"]
    assert "--zip" in captured["argv"]


def test_bloodhound_collect_with_hash() -> None:
    tool = registry.get("bloodhound")

    def fake_run(argv, **kwargs):
        return 0, _BH_COLLECT_OUTPUT, "", 10.0

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="collect",
            target_dc="10.0.0.5",
            domain="lab.local",
            username="alice",
            ntlm_hash=":31d6cfe0d16ae931b73c59d7e0c089c0",
        )

    assert result.status == ToolStatus.SUCCESS


def test_bloodhound_collect_missing_args_returns_error() -> None:
    tool = registry.get("bloodhound")
    result = tool.execute(action="collect", domain="lab.local", username="alice")
    assert result.status == ToolStatus.ERROR
    assert "target_dc" in (result.error or "")


def test_bloodhound_collect_no_creds_returns_error() -> None:
    tool = registry.get("bloodhound")
    result = tool.execute(
        action="collect", target_dc="10.0.0.5", domain="lab.local", username="alice"
    )
    assert result.status == ToolStatus.ERROR
    assert "password" in (result.error or "").lower()


def test_bloodhound_query_builtin() -> None:
    tool = registry.get("bloodhound")
    mock_rows = [{"user": "alice@LAB.LOCAL", "computer": "DC01.LAB.LOCAL"}]

    with patch.object(tool, "_neo4j_query", return_value=(mock_rows, None)):
        result = tool.execute(
            action="query",
            query_name="local_admins",
            neo4j_password="neo4j",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["result_count"] == 1
    assert result.findings["results"][0]["user"] == "alice@LAB.LOCAL"
    assert result.findings["query_name"] == "local_admins"


def test_bloodhound_query_custom_cypher() -> None:
    tool = registry.get("bloodhound")
    cypher = "MATCH (u:User) RETURN u.name LIMIT 5"
    mock_rows = [{"u.name": "alice"}, {"u.name": "bob"}]

    with patch.object(tool, "_neo4j_query", return_value=(mock_rows, None)):
        result = tool.execute(action="query", custom_query=cypher, neo4j_password="pw")

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["result_count"] == 2


def test_bloodhound_query_no_results_is_no_findings() -> None:
    tool = registry.get("bloodhound")

    with patch.object(tool, "_neo4j_query", return_value=([], None)):
        result = tool.execute(action="query", query_name="kerberoastable", neo4j_password="pw")

    assert result.status == ToolStatus.NO_FINDINGS


def test_bloodhound_query_missing_query_name_returns_error() -> None:
    tool = registry.get("bloodhound")
    result = tool.execute(action="query", neo4j_password="pw")
    assert result.status == ToolStatus.ERROR
    assert "query_name" in (result.error or "")


def test_bloodhound_unknown_action_returns_error() -> None:
    tool = registry.get("bloodhound")
    result = tool.execute(action="bogus")
    assert result.status == ToolStatus.ERROR


# ────────────────────────────────────────────────────────────────────────────
# Rubeus
# ────────────────────────────────────────────────────────────────────────────

_ASKTGT_OUTPUT = """\
Impacket v0.12.0 - Copyright 2023 Fortra

[*] Using KDC: 10.0.0.5
[*] Saving ticket in alice.ccache
"""

_KERBEROAST_OUTPUT = """\
Impacket v0.12.0 - Copyright 2023 Fortra

$krb5tgs$23$*svc_sql$LAB.LOCAL$LAB.LOCAL/svc_sql*$abcdef0123456789...
$krb5tgs$23$*svc_http$LAB.LOCAL$LAB.LOCAL/svc_http*$deadbeef01234567...
"""

_ASREPROAST_OUTPUT = """\
Impacket v0.12.0 - Copyright 2023 Fortra

$krb5asrep$23$nopreauth@LAB.LOCAL:deadbeef01234567abcdef...
"""

_S4U_OUTPUT = """\
Impacket v0.12.0 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
"""

_TRIAGE_OUTPUT = """\
[*] Action: Triage Kerberos Tickets (All Users)

 -----------------------------------------------------------------------
 | LUID     | UserName                | Service            | EndTime   |
 -----------------------------------------------------------------------
 | 0x3e4    | DC01$ @ LAB.LOCAL       | krbtgt/LAB.LOCAL   | 5/8/2026  |
 | 0x40e770 | alice @ LAB.LOCAL       | krbtgt/LAB.LOCAL   | 5/8/2026  |
 | 0x40e770 | alice @ LAB.LOCAL       | cifs/dc01.lab.local| 5/8/2026  |
 -----------------------------------------------------------------------
"""

_DUMP_OUTPUT = """\
[*] Action: Dump Kerberos Ticket Data (All Users)

  UserName                 : alice
  ServiceName              : krbtgt
  Base64EncodedTicket      :
    doIFijCCBYagAwIBBaEDAgEWooIEpDCCBKBhggSc
    MIIE/TCCBOWgAwIBBaELGwlMQUIuTE9DQUw=

  UserName                 : DC01$
  ServiceName              : krbtgt
  Base64EncodedTicket      :
    doIGDjCCBgqgAwIBBaEDAgEWooIFAjCCBP5hggT6
    MIIE9jCCBO6gAwIBBaELGwlMQUIuTE9DQUw=
"""


def test_rubeus_asktgt_saves_ccache() -> None:
    tool = registry.get("rubeus")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _ASKTGT_OUTPUT, "", 0.8

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="asktgt",
            target_dc="10.0.0.5",
            domain="LAB.LOCAL",
            user="alice",
            password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["ccache"] == "alice.ccache"
    assert "impacket-getTGT" in captured["argv"][0]
    assert "-dc-ip" in captured["argv"]


def test_rubeus_asktgt_with_hash() -> None:
    tool = registry.get("rubeus")

    def fake_run(argv, **kwargs):
        return 0, _ASKTGT_OUTPUT, "", 0.5

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="asktgt",
            target_dc="10.0.0.5",
            domain="LAB.LOCAL",
            user="alice",
            rc4=":aad3b435b51404eeaad3b435b51404ee",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["ccache"] == "alice.ccache"


def test_rubeus_kerberoast_parses_hashes() -> None:
    tool = registry.get("rubeus")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _KERBEROAST_OUTPUT, "", 1.2

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="kerberoast",
            target_dc="10.0.0.5",
            domain="LAB.LOCAL",
            user="alice",
            password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 2
    assert result.findings["hash_type"] == "krb5tgs"
    assert all(t.startswith("$krb5tgs$") for t in result.findings["tickets"])
    assert "impacket-GetUserSPNs" in captured["argv"][0]
    assert "-request" in captured["argv"]


def test_rubeus_asreproast_parses_hashes() -> None:
    tool = registry.get("rubeus")

    def fake_run(argv, **kwargs):
        return 0, _ASREPROAST_OUTPUT, "", 0.9

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="asreproast",
            target_dc="10.0.0.5",
            domain="LAB.LOCAL",
            user="alice",
            password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["count"] == 1
    assert result.findings["hash_type"] == "krb5asrep"


def test_rubeus_s4u_saves_ccache() -> None:
    tool = registry.get("rubeus")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return 0, _S4U_OUTPUT, "", 1.5

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="s4u",
            target_dc="10.0.0.5",
            domain="LAB.LOCAL",
            user="svc_account",
            password="Password1",
            spn="cifs/dc01.lab.local",
            impersonate="Administrator",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["ccache"] == "Administrator.ccache"
    assert "impacket-getST" in captured["argv"][0]
    assert "-impersonate" in captured["argv"]
    assert "Administrator" in captured["argv"]


def test_rubeus_triage_parses_ticket_table() -> None:
    tool = registry.get("rubeus")

    with patch.object(tool, "_winrm_run", return_value=(_TRIAGE_OUTPUT, None)):
        result = tool.execute(
            action="triage",
            winrm_host="10.0.0.10",
            winrm_user="CORP\\admin",
            winrm_password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["ticket_count"] == 3
    users = {t["user"] for t in result.findings["tickets"]}
    assert any("alice" in u for u in users)


def test_rubeus_dump_extracts_b64_tickets() -> None:
    tool = registry.get("rubeus")

    with patch.object(tool, "_winrm_run", return_value=(_DUMP_OUTPUT, None)):
        result = tool.execute(
            action="dump",
            winrm_host="10.0.0.10",
            winrm_user="CORP\\admin",
            winrm_password="Password1",
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.findings["ticket_count"] == 2
    assert "alice" in result.findings["users"]


def test_rubeus_triage_missing_winrm_args() -> None:
    tool = registry.get("rubeus")
    result = tool.execute(action="triage", winrm_host="10.0.0.10")
    assert result.status == ToolStatus.ERROR
    assert "winrm_user" in (result.error or "") or "winrm" in (result.error or "").lower()


def test_rubeus_asktgt_missing_creds() -> None:
    tool = registry.get("rubeus")
    result = tool.execute(action="asktgt", target_dc="10.0.0.5", domain="LAB.LOCAL", user="alice")
    assert result.status == ToolStatus.ERROR
    assert "password" in (result.error or "").lower() or "rc4" in (result.error or "")


def test_rubeus_s4u_missing_spn() -> None:
    tool = registry.get("rubeus")
    result = tool.execute(
        action="s4u",
        target_dc="10.0.0.5", domain="LAB.LOCAL", user="svc",
        password="pw", impersonate="Administrator",
    )
    assert result.status == ToolStatus.ERROR
    assert "spn" in (result.error or "")


def test_rubeus_auth_failure_is_partial() -> None:
    tool = registry.get("rubeus")

    def fake_run(argv, **kwargs):
        return 1, "", "Kerberos SessionError: KDC_ERR_PREAUTH_FAILED", 0.3

    with patch.object(tool, "_run", side_effect=fake_run):
        result = tool.execute(
            action="asktgt",
            target_dc="10.0.0.5", domain="LAB.LOCAL", user="alice", password="wrong",
        )

    assert result.status == ToolStatus.PARTIAL
    assert "authentication" in (result.error or "").lower()


def test_rubeus_unknown_action_returns_error() -> None:
    tool = registry.get("rubeus")
    result = tool.execute(action="bogus")
    assert result.status == ToolStatus.ERROR
