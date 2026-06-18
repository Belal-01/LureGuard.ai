"""Container image CVE scanning via Trivy over SSH."""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime
from typing import Any

from lureguard_mcp.config import onboard_ssh_password
from lureguard_mcp.db import (
    get_container_cve_findings_db,
    get_host_ip_db,
    replace_container_cve_findings_db,
)

logger = logging.getLogger(__name__)


def _parse_trivy_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in payload.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity") or "unknown").lower()
            cvss_data = vuln.get("CVSS") or {}
            cvss = None
            for vendor in ("nvd", "redhat", "ghsa"):
                if vendor in cvss_data and cvss_data[vendor].get("V3Score") is not None:
                    cvss = float(cvss_data[vendor]["V3Score"])
                    break
            findings.append(
                {
                    "cve_id": vuln.get("VulnerabilityID"),
                    "package_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": severity,
                    "cvss": cvss,
                }
            )
    return findings


def scan_container_image(agent_id: str, image_ref: str) -> dict[str, Any]:
    host_ip = get_host_ip_db(agent_id)
    if not host_ip:
        return {"agent_id": agent_id, "error": "host IP not found — enroll agent first"}

    password = onboard_ssh_password()
    if not password:
        return {"agent_id": agent_id, "error": "ONBOARD_SSH_PASSWORD not set"}

    trivy_cmd = (
        f"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "
        f"aquasec/trivy:latest image --format json --quiet {image_ref}"
    )
    ssh_cmd = (
        f"sshpass -p {password!r} ssh -o StrictHostKeyChecking=no -T "
        f"ubuntu@{host_ip} {trivy_cmd!r}"
    )
    try:
        proc = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            return {
                "agent_id": agent_id,
                "image_ref": image_ref,
                "error": (proc.stderr or proc.stdout or "trivy failed")[:1000],
            }
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"agent_id": agent_id, "error": f"invalid trivy JSON: {exc}"}
    except Exception as exc:
        return {"agent_id": agent_id, "error": str(exc)}

    findings = _parse_trivy_json(payload)
    scanned_at = datetime.utcnow()
    replace_container_cve_findings_db(
        agent_id=agent_id,
        image_ref=image_ref,
        findings=findings,
        scanned_at=scanned_at,
    )
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    return {
        "agent_id": agent_id,
        "image_ref": image_ref,
        "scanned_at": scanned_at.isoformat(),
        "total_cves": len(findings),
        "critical": critical,
        "high": high,
        "top_findings": sorted(findings, key=lambda x: -(x.get("cvss") or 0))[:10],
    }


def get_container_vulnerabilities(
    agent_id: str,
    image_ref: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    items = get_container_cve_findings_db(
        agent_id,
        image_ref=image_ref or None,
        limit=limit,
    )
    return {
        "agent_id": agent_id,
        "image_ref": image_ref or "all",
        "count": len(items),
        "findings": items,
        "hint": "Run scan_container_image if empty",
    }
