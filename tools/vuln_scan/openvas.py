"""OpenVAS / Greenbone wrapper — heavyweight network vulnerability scanner.

Driven via `gvm-cli` (gvm-tools package), which speaks the Greenbone Management
Protocol (GMP) to a running gvmd. We orchestrate a normal scan lifecycle:

    create_target → create_task → start_task → poll get_tasks → get_reports

Real OpenVAS scans take 30-120+ minutes; bump `max_wait_sec` accordingly. The
default `tool_execution_timeout_sec` only bounds individual gvm-cli calls, not
the overall scan — total wait is governed by `max_wait_sec` here.
"""
from __future__ import annotations

import time
import uuid
from typing import Any
from xml.etree import ElementTree as ET

from config import settings
from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


# Module-private clock + sleep — indirected so tests can drive the polling loop
# without affecting `_run`'s subprocess-duration measurements.
def _now() -> float:
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


# Built-in UUIDs shipped with every Greenbone install. Stable across versions.
SCAN_CONFIGS = {
    "discovery":     "8715c877-47a0-438d-98a3-27c7a6ab2196",
    "host_discovery":"2d3f051c-55ba-11e3-bf43-406186ea4fc5",
    "system_discovery":"bbca7412-a950-11e3-9109-406186ea4fc5",
    "full_fast":     "daba56c8-73ec-11df-a475-002264764cea",
    "full_deep":     "74db13d6-7489-11df-91b9-002264764cea",
}
DEFAULT_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"          # OpenVAS Default
XML_REPORT_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"         # built-in XML

# GMP severity → CVSS v2 cutoffs Greenbone publishes
SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def _band(cvss: float) -> str:
    for cutoff, label in SEVERITY_BANDS:
        if cvss >= cutoff:
            return label
    return "info"


@register
class OpenVASTool(OffensiveTool):
    name = "openvas"
    phase = "vuln_id"
    mitre_techniques = ["T1595.002", "T1190"]
    description = """
    Comprehensive network vulnerability scanner (Greenbone/OpenVAS). Slow but
    thorough — try `nuclei` first; reach for openvas when deeper coverage is
    needed (compliance scans, deep service probing). Returns CVE/CVSS-tagged
    findings keyed by host:port.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, CIDR, or hostname list"},
                "scan_config": {"type": "string", "enum": list(SCAN_CONFIGS),
                                "default": "full_fast"},
                "max_wait_sec": {"type": "integer", "default": 3600,
                                 "description": "Total scan budget (polling stops here)"},
                "poll_interval_sec": {"type": "integer", "default": 30},
            },
            "required": ["target"],
        }

    # ─── execute ────────────────────────────────────────────────────────────

    def execute(self, **params: Any) -> ToolResult:
        target = params["target"]
        scan_config_name = params.get("scan_config", "full_fast")
        max_wait_sec = int(params.get("max_wait_sec", 3600))
        poll_interval_sec = int(params.get("poll_interval_sec", 30))

        if scan_config_name not in SCAN_CONFIGS:
            return ToolResult(ToolStatus.ERROR, "", "",
                              error=f"Unknown scan_config: {scan_config_name}")

        run_id = uuid.uuid4().hex[:8]
        target_name = f"redteam-{run_id}"
        task_name = f"redteam-task-{run_id}"

        try:
            target_id = self._create_target(target_name, target)
            task_id = self._create_task(
                task_name, target_id,
                config_id=SCAN_CONFIGS[scan_config_name],
                scanner_id=DEFAULT_SCANNER,
            )
            report_id = self._start_task(task_id)
            done, status_text = self._wait_for_task(task_id, max_wait_sec, poll_interval_sec)
            if not done:
                return ToolResult(
                    status=ToolStatus.TIMEOUT,
                    command=f"openvas scan target={target} task_id={task_id}",
                    raw_output="",
                    error=f"scan still {status_text!r} after {max_wait_sec}s",
                    findings={"task_id": task_id, "report_id": report_id},
                )
            findings, raw_xml = self._fetch_report(report_id)
        except OpenVASError as exc:
            return ToolResult(ToolStatus.ERROR, exc.command, exc.raw_output,
                              error=str(exc))

        findings.update({"target": target, "task_id": task_id, "report_id": report_id})
        status = ToolStatus.SUCCESS if findings.get("total", 0) > 0 else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=f"openvas scan target={target} config={scan_config_name}",
            raw_output=raw_xml,
            findings=findings,
        )

    # ─── GMP helpers ────────────────────────────────────────────────────────

    def _gmp_argv(self, xml_command: str) -> list[str]:
        if settings.gvm_connection == "socket":
            transport = ["socket", "--socketpath", settings.gvm_socket_path]
        else:
            transport = ["tls", "--hostname", settings.gvm_host,
                         "--port", str(settings.gvm_port)]
        return [
            "gvm-cli",
            "--gmp-username", settings.gvm_username,
            "--gmp-password", settings.gvm_password,
            *transport,
            "--xml", xml_command,
        ]

    def _gmp(self, xml_command: str) -> ET.Element:
        argv = self._gmp_argv(xml_command)
        rc, stdout, stderr, _ = self._run(argv)
        cmd = self.quote(argv)
        if rc == -1:
            raise OpenVASError(f"gvm-cli timed out: {stderr.strip()}", cmd, stdout)
        if rc != 0:
            raise OpenVASError(f"gvm-cli exited {rc}: {stderr.strip()[:300]}",
                               cmd, stdout)
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as exc:
            raise OpenVASError(f"malformed GMP response: {exc}", cmd, stdout) from exc

        # Every GMP response carries a `status` attribute; 2xx == OK.
        status = root.get("status", "")
        if not status.startswith("2"):
            raise OpenVASError(
                f"GMP error {status} {root.get('status_text', '')}", cmd, stdout,
            )
        return root

    def _create_target(self, name: str, hosts: str) -> str:
        # Greenbone rejects duplicate target names — embed the run id.
        cmd = (
            f"<create_target>"
            f"<name>{_xml_escape(name)}</name>"
            f"<hosts>{_xml_escape(hosts)}</hosts>"
            f"</create_target>"
        )
        root = self._gmp(cmd)
        target_id = root.get("id")
        if not target_id:
            raise OpenVASError("create_target returned no id", cmd, ET.tostring(root, encoding="unicode"))
        return target_id

    def _create_task(self, name: str, target_id: str,
                     config_id: str, scanner_id: str) -> str:
        cmd = (
            f"<create_task>"
            f"<name>{_xml_escape(name)}</name>"
            f'<config id="{config_id}"/>'
            f'<target id="{target_id}"/>'
            f'<scanner id="{scanner_id}"/>'
            f"</create_task>"
        )
        root = self._gmp(cmd)
        task_id = root.get("id")
        if not task_id:
            raise OpenVASError("create_task returned no id", cmd, ET.tostring(root, encoding="unicode"))
        return task_id

    def _start_task(self, task_id: str) -> str:
        root = self._gmp(f'<start_task task_id="{task_id}"/>')
        # Response carries <report_id>...</report_id>
        rep = root.find("report_id")
        if rep is None or not rep.text:
            raise OpenVASError("start_task returned no report_id",
                               f"<start_task task_id={task_id}/>",
                               ET.tostring(root, encoding="unicode"))
        return rep.text

    def _wait_for_task(self, task_id: str, max_wait_sec: int,
                       poll_interval_sec: int) -> tuple[bool, str]:
        deadline = _now() + max_wait_sec
        last_status = ""
        while _now() < deadline:
            root = self._gmp(f'<get_tasks task_id="{task_id}"/>')
            task_el = root.find("task")
            status_el = task_el.find("status") if task_el is not None else None
            last_status = status_el.text if (status_el is not None and status_el.text) else ""
            if last_status == "Done":
                return True, last_status
            if last_status in {"Stopped", "Interrupted"}:
                raise OpenVASError(f"task ended unexpectedly: {last_status}",
                                   f"<get_tasks task_id={task_id}/>", "")
            _sleep(poll_interval_sec)
        return False, last_status

    def _fetch_report(self, report_id: str) -> tuple[dict[str, Any], str]:
        cmd = (
            f'<get_reports report_id="{report_id}" '
            f'format_id="{XML_REPORT_FORMAT}" '
            f'details="1" ignore_pagination="1"/>'
        )
        root = self._gmp(cmd)
        return _parse_report(root), ET.tostring(root, encoding="unicode")


# ────────────────────────────────────────────────────────────────────────────
# Parsing
# ────────────────────────────────────────────────────────────────────────────


class OpenVASError(Exception):
    def __init__(self, message: str, command: str = "", raw_output: str = "") -> None:
        super().__init__(message)
        self.command = command
        self.raw_output = raw_output


def _parse_report(root: ET.Element) -> dict[str, Any]:
    vulns: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}

    # GMP nests results: <get_reports_response><report><report><results>...
    for result in root.findall(".//results/result"):
        host = (result.findtext("host") or "").strip()
        port = (result.findtext("port") or "").strip()
        name = (result.findtext("name") or "").strip()
        threat = (result.findtext("threat") or "").strip()
        cvss_text = (result.findtext("severity") or "").strip()
        try:
            cvss = float(cvss_text) if cvss_text else 0.0
        except ValueError:
            cvss = 0.0
        severity = _band(cvss)
        description = (result.findtext("description") or "").strip()

        cves: list[str] = []
        for ref in result.findall(".//refs/ref"):
            if ref.get("type", "").lower() == "cve":
                cve_id = ref.get("id")
                if cve_id:
                    cves.append(cve_id)

        port_num: int | None = None
        if "/" in port:
            try:
                port_num = int(port.split("/", 1)[0])
            except ValueError:
                port_num = None

        vulns.append({
            "host": host,
            "port": port_num,
            "port_spec": port,
            "name": name,
            "threat": threat,
            "severity": severity,
            "cvss_score": cvss,
            "cve": cves[0] if cves else None,
            "cves": cves,
            "description": description[:1000],
        })
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "vulnerabilities": vulns,
        "total": len(vulns),
        "severity_counts": severity_counts,
    }


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
    )
