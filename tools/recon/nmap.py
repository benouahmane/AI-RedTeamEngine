"""Nmap wrapper — host discovery, port scanning, service/version detection.

Uses `-oX -` to emit XML on stdout and parses it into structured findings.
"""
from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class NmapTool(OffensiveTool):
    name = "nmap"
    phase = "recon"
    mitre_techniques = ["T1046", "T1018"]
    description = """
    Network mapper. Use for host discovery, TCP/UDP port scanning, OS fingerprinting,
    and service/version detection. Prefer `scan_type='service'` for unknown hosts —
    it runs `-sV -sC -O` and produces rich service banners.
    """

    SCAN_PROFILES = {
        "ping":     ["-sn"],
        "fast":     ["-T4", "-F"],
        "full_tcp": ["-T4", "-p-", "-sS"],
        "service":  ["-sV", "-sC", "-O", "-T4"],
        "udp_top":  ["-sU", "--top-ports", "50"],
    }

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, CIDR, or hostname"},
                "scan_type": {"type": "string", "enum": list(self.SCAN_PROFILES)},
                "ports": {"type": "string", "description": "e.g. '22,80,443' or '1-1000'"},
                "extra_args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
        }

    def execute(self, **params: Any) -> ToolResult:
        target = params["target"]
        scan_type = params.get("scan_type", "service")
        ports = params.get("ports")
        extra = list(params.get("extra_args") or [])

        if scan_type not in self.SCAN_PROFILES:
            return ToolResult(
                status=ToolStatus.ERROR,
                command="",
                raw_output="",
                error=f"Unknown scan_type: {scan_type}",
            )

        argv = ["nmap", *self.SCAN_PROFILES[scan_type], "-oX", "-"]
        if ports:
            argv += ["-p", ports]
        argv += extra
        argv.append(target)

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                command=cmd,
                raw_output=stdout,
                error=stderr,
                duration_sec=duration,
            )
        if rc != 0 and not stdout.strip().startswith("<?xml"):
            return ToolResult(
                status=ToolStatus.ERROR,
                command=cmd,
                raw_output=stdout + stderr,
                error=f"nmap exited {rc}: {stderr.strip()}",
                duration_sec=duration,
            )

        findings = self._parse_xml(stdout)
        status = ToolStatus.SUCCESS if findings.get("hosts") else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings=findings,
            duration_sec=duration,
        )

    @staticmethod
    def _parse_xml(xml: str) -> dict[str, Any]:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            return {"hosts": [], "parse_error": str(exc)}

        hosts: list[dict[str, Any]] = []
        for host in root.findall("host"):
            state_el = host.find("status")
            if state_el is None or state_el.get("state") != "up":
                continue

            addr_el = host.find("address[@addrtype='ipv4']")
            ip = addr_el.get("addr") if addr_el is not None else None

            hostnames = [hn.get("name") for hn in host.findall(".//hostname") if hn.get("name")]
            os_match = host.find("os/osmatch")
            os_name = os_match.get("name") if os_match is not None else None

            ports: list[dict[str, Any]] = []
            for port in host.findall("ports/port"):
                p_state = port.find("state")
                if p_state is None or p_state.get("state") != "open":
                    continue
                svc = port.find("service")
                ports.append({
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extrainfo": svc.get("extrainfo") if svc is not None else None,
                })

            hosts.append({
                "ip": ip,
                "hostnames": hostnames,
                "os": os_name,
                "ports": ports,
            })

        return {"hosts": hosts, "host_count": len(hosts)}
