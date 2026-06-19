"""Exposure scanner — open ports and listening services via Wazuh syscollector."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lureguard_mcp.config import onboard_ssh_password
from lureguard_mcp.ssh_remote import build_sudo_remote_command, run_remote_shell, validate_ip
from lureguard_mcp.db import (
    get_agent_exposure_counts_db,
    get_agent_exposure_findings_db,
    get_agent_exposure_last_scan_db,
    get_fleet_exposure_summary_db,
    get_host_ip_db,
    replace_agent_exposure_findings_db,
)
from lureguard_mcp.wazuh_client import WazuhClient, paginate_affected_items

PORT_PAGE = 500

# Well-known risky services (port -> base risk)
RISKY_PORTS: dict[int, str] = {
    23: "critical",
    21: "high",
    445: "high",
    3389: "high",
    5900: "high",
    6379: "high",
    27017: "high",
    11211: "high",
    9200: "medium",
    9300: "medium",
    5432: "medium",
    3306: "medium",
    1433: "medium",
    8080: "low",
    8443: "low",
    22: "info",
    80: "info",
    443: "info",
}


# Kubernetes / control-plane ports — elevated when bound to all interfaces
K8S_PORTS: dict[int, str] = {
    6443: "medium",
    10250: "medium",
    10255: "low",
    2379: "high",
    2380: "high",
    8443: "low",
    30000: "info",
}


def _bind_scope(local_address: str) -> str:
    addr = (local_address or "").strip()
    if addr in ("0.0.0.0", "::", "*", "any"):
        return "all_interfaces"
    if addr.startswith("127.") or addr == "::1":
        return "localhost"
    return "specific"


def _score_port(port: int, local_address: str, protocol: str) -> str:
    base = RISKY_PORTS.get(port) or K8S_PORTS.get(port, "info")
    scope = _bind_scope(local_address)
    if scope == "all_interfaces":
        if base == "info":
            return "low"
        if base == "low":
            return "medium"
        if base == "medium":
            return "high"
        return base
    if scope == "localhost":
        if base in ("critical", "high"):
            return "medium"
        if port in K8S_PORTS and base != "info":
            return "info"
        return "info" if base in ("info", "low") else "low"
    return base


def _fetch_all_ports(wazuh: WazuhClient, agent_id: str) -> list[dict[str, Any]]:
    return paginate_affected_items(
        lambda limit, offset: wazuh.get_agent_ports(agent_id, limit=limit, offset=offset),
        page_size=PORT_PAGE,
    )


def scan_agent_exposure(
    agent_id: str,
    *,
    wazuh: WazuhClient | None = None,
) -> dict[str, Any]:
    """Scan listening ports for one agent and persist exposure findings."""
    wazuh = wazuh or WazuhClient()
    scanned_at = datetime.utcnow()

    try:
        raw_ports = _fetch_all_ports(wazuh, agent_id)
    except Exception as exc:
        return {"agent_id": agent_id, "error": str(exc), "findings": [], "counts": {}}

    findings: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for item in raw_ports:
        state = str(item.get("state") or "").lower()
        if state and state not in ("listening", "listen", "open"):
            continue
        local = item.get("local") or {}
        if isinstance(local, dict):
            local_address = str(local.get("ip") or "")
            port_raw = local.get("port")
        else:
            local_address = str(item.get("local_ip") or item.get("local_address") or "")
            port_raw = item.get("local_port") or item.get("port")
        try:
            port = int(port_raw or 0)
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        dedupe_key = (port, protocol, local_address)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        process = str(item.get("process") or item.get("name") or "")
        risk = _score_port(port, local_address, protocol)
        bind_scope = _bind_scope(local_address)
        findings.append(
            {
                "port": port,
                "protocol": protocol,
                "process": process or None,
                "local_address": local_address or None,
                "state": state or "listening",
                "risk_level": risk,
                "bind_scope": bind_scope,
            }
        )

    replace_agent_exposure_findings_db(
        agent_id=agent_id, findings=findings, scanned_at=scanned_at
    )
    counts = get_agent_exposure_counts_db(agent_id)
    display_findings = [f for f in findings if int(f.get("port", 0)) > 0]
    risky = [f for f in display_findings if f.get("risk_level") in {"critical", "high", "medium"}]
    return {
        "agent_id": agent_id,
        "ports_scanned": len(raw_ports),
        "listening_count": len(display_findings),
        "risky_listening_count": len(risky),
        "counts": counts,
        "scanned_at": scanned_at.isoformat(),
        "findings": display_findings[:100],
        "truncated": len(display_findings) > 100,
    }


def _fetch_firewall_rules(agent_id: str) -> str | None:
    host_ip = get_host_ip_db(agent_id)
    password = onboard_ssh_password()
    if not host_ip or not password:
        return None
    try:
        host = validate_ip(host_ip, field="host_ip")
    except Exception:
        return None
    inner = (
        "(iptables -L INPUT -n --line-numbers 2>/dev/null | head -40) "
        "|| (ufw status verbose 2>/dev/null | head -40)"
    )
    remote = build_sudo_remote_command(password, inner)
    result = run_remote_shell(host, remote, password=password, timeout=25)
    output = (result.get("stdout") or result.get("stderr") or "").strip()
    return output[:4000] if output else None


def get_agent_exposure(
    agent_id: str,
    *,
    risk_level: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    items = get_agent_exposure_findings_db(agent_id, risk_level=risk_level, limit=limit)
    counts = get_agent_exposure_counts_db(agent_id)
    scanned_at = get_agent_exposure_last_scan_db(agent_id)
    firewall_rules = _fetch_firewall_rules(agent_id)
    return {
        "agent_id": agent_id,
        "source": "postgres+syscollector",
        "scanned_at": scanned_at,
        "counts": counts,
        "total": sum(counts.values()),
        "findings": items,
        "firewall_rules": firewall_rules,
        "hint": "Run trigger_posture_scan if data is stale or empty",
    }


def get_fleet_exposure_summary() -> dict[str, Any]:
    return get_fleet_exposure_summary_db()
