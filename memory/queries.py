"""Convenience queries over session entities — used by reports and the API."""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from memory.models import (
    AgentDecision,
    Credential,
    Host,
    PentestSession,
    Vulnerability,
)


def get_session(db: Session, session_id: uuid.UUID) -> PentestSession | None:
    return db.get(PentestSession, session_id)


def list_sessions(db: Session, limit: int = 50) -> list[PentestSession]:
    stmt = select(PentestSession).order_by(PentestSession.started_at.desc()).limit(limit)
    return list(db.scalars(stmt))


def hosts_for(db: Session, session_id: uuid.UUID) -> list[Host]:
    return list(db.scalars(select(Host).where(Host.session_id == session_id)))


def vulns_for(db: Session, session_id: uuid.UUID) -> list[Vulnerability]:
    # Severity first, then proven-over-suspected, and only then CVSS. Ordering
    # by CVSS alone buried the findings that matter most: an exploited RCE
    # carries no CVSS score of its own, so nullslast pushed a confirmed root
    # shell below every informational scanner hit.
    severity_rank = case(
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
        value=Vulnerability.severity,
        else_=5,
    )
    return list(
        db.scalars(
            select(Vulnerability)
            .where(Vulnerability.session_id == session_id)
            .order_by(
                severity_rank,
                Vulnerability.exploited.desc(),
                Vulnerability.cvss.desc().nullslast(),
            )
        )
    )


def creds_for(db: Session, session_id: uuid.UUID) -> list[Credential]:
    return list(db.scalars(select(Credential).where(Credential.session_id == session_id)))


def decisions_for(db: Session, session_id: uuid.UUID) -> list[AgentDecision]:
    return list(
        db.scalars(
            select(AgentDecision)
            .where(AgentDecision.session_id == session_id)
            .order_by(AgentDecision.step_number.asc())
        )
    )


# ─── upserts called from agent / tool result parsers ───────────────────────


def upsert_host(
    db: Session,
    session_id: uuid.UUID,
    ip: str,
    **fields: Any,
) -> Host:
    host = db.scalar(
        select(Host).where(Host.session_id == session_id).where(Host.ip == ip)
    )
    if host is None:
        host = Host(session_id=session_id, ip=ip, **fields)
        db.add(host)
    else:
        for k, v in fields.items():
            setattr(host, k, v)
    db.commit()
    db.refresh(host)
    return host


def record_vulnerability(
    db: Session,
    session_id: uuid.UUID,
    *,
    host_ip: str,
    title: str,
    severity: str,
    **fields: Any,
) -> Vulnerability:
    vuln = Vulnerability(
        session_id=session_id,
        host_ip=host_ip,
        title=title,
        severity=severity,
        **fields,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


def upsert_vulnerability(
    db: Session,
    session_id: uuid.UUID,
    *,
    host_ip: str,
    title: str,
    severity: str,
    **fields: Any,
) -> Vulnerability | None:
    """Insert a vulnerability unless an equivalent row already exists.

    Scanners get re-run and a foothold gets re-verified over several steps, so
    without this the register grows a duplicate on every pass. When the same
    finding comes back proven, the existing row is upgraded to `exploited`
    rather than sitting alongside a second copy of itself.

    Returns the new row, or None if it was a duplicate.
    """
    existing = db.scalar(
        select(Vulnerability)
        .where(Vulnerability.session_id == session_id)
        .where(Vulnerability.host_ip == host_ip)
        .where(Vulnerability.title == title)
        .where(Vulnerability.cve.is_not_distinct_from(fields.get("cve")))
        .where(Vulnerability.port.is_not_distinct_from(fields.get("port")))
    )
    if existing is not None:
        if fields.get("exploited") and not existing.exploited:
            existing.exploited = True
            if fields.get("evidence"):
                existing.evidence = fields["evidence"]
            db.commit()
        return None
    return record_vulnerability(
        db, session_id, host_ip=host_ip, title=title, severity=severity, **fields,
    )


def record_credential(
    db: Session,
    session_id: uuid.UUID,
    *,
    username: str,
    secret: str,
    secret_type: str = "password",
    **fields: Any,
) -> Credential:
    cred = Credential(
        session_id=session_id,
        username=username,
        secret=secret,
        secret_type=secret_type,
        **fields,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


def upsert_credential(
    db: Session,
    session_id: uuid.UUID,
    *,
    username: str,
    secret: str,
    secret_type: str = "password",
    **fields: Any,
) -> Credential | None:
    """Insert a credential unless an identical (username, secret, host) row
    already exists for the session. Returns the row, or None if it was a dup."""
    host_ip = fields.get("host_ip")
    existing = db.scalar(
        select(Credential)
        .where(Credential.session_id == session_id)
        .where(Credential.username == username)
        .where(Credential.secret == secret)
        .where(Credential.host_ip == host_ip)
    )
    if existing is not None:
        return None
    return record_credential(
        db, session_id,
        username=username, secret=secret, secret_type=secret_type, **fields,
    )


def mark_host_compromised(
    db: Session,
    session_id: uuid.UUID,
    ip: str,
    *,
    note: str | None = None,
) -> Host:
    """Flag a host as owned. Creates the host row if recon never saw it."""
    host = db.scalar(
        select(Host).where(Host.session_id == session_id).where(Host.ip == ip)
    )
    if host is None:
        host = Host(session_id=session_id, ip=ip)
        db.add(host)
    host.is_compromised = True
    if note:
        host.notes = (host.notes + "\n" if host.notes else "") + note
    db.commit()
    db.refresh(host)
    return host


def entity_snapshot(db: Session, session_id: uuid.UUID, *, max_items: int = 25) -> dict[str, Any]:
    """Compact, token-budget-conscious view of consolidated findings.

    Fed into the agent prompt alongside the task tree so the agent can reason
    over *what it knows* (open services, harvested creds, unexploited vulns)
    rather than only over *what it has queued*. This is what enables credential
    reuse and cross-host correlation.
    """
    hosts = hosts_for(db, session_id)
    vulns = vulns_for(db, session_id)
    creds = creds_for(db, session_id)

    host_rows = []
    for h in hosts[:max_items]:
        services = [
            {
                "port": p.get("port"),
                "service": p.get("service") or p.get("name"),
                "product": p.get("product"),
                "version": p.get("version"),
            }
            for p in (h.services or h.ports or [])
        ]
        host_rows.append({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os_fingerprint,
            "compromised": h.is_compromised,
            "services": services,
        })

    cred_rows = [
        {
            "username": c.username,
            "secret": (c.secret or "")[:200],
            "type": c.secret_type,
            "host": c.host_ip,
            "service": c.service,
            "domain": c.domain,
            "privilege": c.privilege,
        }
        for c in creds[:max_items]
    ]

    vuln_rows = [
        {
            "host": v.host_ip,
            "title": v.title,
            "severity": v.severity,
            "cve": v.cve,
            "exploited": v.exploited,
        }
        for v in vulns[:max_items]
    ]

    return {
        "hosts": host_rows,
        "credentials": cred_rows,
        "vulnerabilities": vuln_rows,
        "counts": {
            "hosts": len(hosts),
            "compromised_hosts": sum(1 for h in hosts if h.is_compromised),
            "credentials": len(creds),
            "vulnerabilities": len(vulns),
        },
    }
