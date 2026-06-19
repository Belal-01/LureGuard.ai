"""Container image posture — Trivy scans run as part of trigger_posture_scan."""

from __future__ import annotations

import json
import logging
import re
import shlex
from datetime import datetime
from typing import Any

from lureguard_mcp.config import onboard_ssh_password
from lureguard_mcp.db import (
    get_container_cve_counts_db,
    get_container_cve_findings_db,
    get_container_cve_last_scan_db,
    get_container_runtime_db,
    get_host_ip_db,
    replace_container_cve_findings_db,
    upsert_container_runtime_db,
)
from lureguard_mcp.ssh_remote import (
    SSHValidationError,
    build_sudo_remote_command,
    run_remote_shell,
    validate_ip,
)
from lureguard_mcp.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,200}$")


def _validate_image_ref(image_ref: str) -> str:
    ref = image_ref.strip()
    if not ref or not _IMAGE_REF_RE.match(ref):
        raise SSHValidationError(f"invalid image_ref: {image_ref!r}")
    return ref


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


def _trivy_scan_command(image: str) -> str:
    image_q = shlex.quote(_validate_image_ref(image))
    return (
        "docker run --rm --dns 8.8.8.8 --dns 1.1.1.1 "
        "-e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db "
        "-e TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db "
        "-v /var/run/docker.sock:/var/run/docker.sock "
        f"aquasec/trivy:latest image --format json --quiet --timeout 10m {image_q}"
    )


def _ssh_host(agent_id: str) -> tuple[str, str] | dict[str, Any]:
    host_ip = get_host_ip_db(agent_id)
    if not host_ip:
        return {"agent_id": agent_id, "error": "host IP not found — enroll agent first"}
    password = onboard_ssh_password()
    if not password:
        return {"agent_id": agent_id, "error": "ONBOARD_SSH_PASSWORD not set"}
    try:
        return validate_ip(host_ip, field="host_ip"), password
    except SSHValidationError as exc:
        return {"agent_id": agent_id, "error": str(exc)}


def _scan_one_image(agent_id: str, host: str, password: str, image_ref: str) -> dict[str, Any]:
    try:
        image = _validate_image_ref(image_ref)
    except SSHValidationError as exc:
        return {"image_ref": image_ref, "error": str(exc)}

    remote = build_sudo_remote_command(password, _trivy_scan_command(image))
    try:
        result = run_remote_shell(host, remote, password=password, timeout=900)
        if not result.get("ok"):
            return {
                "image_ref": image,
                "error": (result.get("stderr") or result.get("stdout") or "trivy failed")[:1000],
            }
        payload = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError as exc:
        return {"image_ref": image, "error": f"invalid trivy JSON: {exc}"}
    except Exception as exc:
        return {"image_ref": image, "error": str(exc)}

    findings = _parse_trivy_json(payload)
    scanned_at = datetime.utcnow()
    replace_container_cve_findings_db(
        agent_id=agent_id,
        image_ref=image,
        findings=findings,
        scanned_at=scanned_at,
    )
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    return {
        "image_ref": image,
        "scanned_at": scanned_at.isoformat(),
        "total_cves": len(findings),
        "critical": critical,
        "high": high,
    }


def _list_running_containers(host: str, password: str) -> tuple[list[dict[str, str]], list[str]]:
    remote = build_sudo_remote_command(
        password,
        "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null || true",
    )
    result = run_remote_shell(host, remote, password=password, timeout=60)
    containers: list[dict[str, str]] = []
    images: set[str] = set()
    if not result.get("ok"):
        return containers, []
    for line in (result.get("stdout") or "").splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) < 2:
            continue
        name, image = parts[0], parts[1]
        status = parts[2] if len(parts) > 2 else ""
        containers.append({"name": name, "image": image, "status": status})
        if image:
            images.add(image)
    return containers, sorted(images)


def scan_agent_containers(
    agent_id: str,
    *,
    wazuh: WazuhClient | None = None,
) -> dict[str, Any]:
    """Trivy-scan all running container images on a host (posture scan pillar)."""
    _ = wazuh  # signature matches other scan_agent_* hooks; containers use SSH not Wazuh API
    host_auth = _ssh_host(agent_id)
    if isinstance(host_auth, dict):
        return host_auth
    host, password = host_auth

    containers, images = _list_running_containers(host, password)
    upsert_container_runtime_db(agent_id, containers)

    if not images:
        return {
            "agent_id": agent_id,
            "containers": containers,
            "images_scanned": 0,
            "message": "no running container images",
        }

    results: list[dict[str, Any]] = []
    for image in images:
        results.append(_scan_one_image(agent_id, host, password, image))

    total_cves = sum(r.get("total_cves", 0) for r in results if "total_cves" in r)
    return {
        "agent_id": agent_id,
        "containers": containers,
        "images_scanned": sum(1 for r in results if "total_cves" in r),
        "images_failed": sum(1 for r in results if r.get("error")),
        "total_cves": total_cves,
        "results": results,
    }


def get_agent_container_posture(
    agent_id: str,
    *,
    image_ref: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    """Cached container runtime + image CVE findings (posture read path)."""
    runtime = get_container_runtime_db(agent_id)
    counts = get_container_cve_counts_db(agent_id)
    items = get_container_cve_findings_db(
        agent_id,
        image_ref=image_ref or None,
        limit=limit,
    )
    return {
        "agent_id": agent_id,
        "scanned_at": get_container_cve_last_scan_db(agent_id),
        "containers": runtime.get("containers", []),
        "runtime_updated_at": runtime.get("updated_at"),
        "counts": counts,
        "total_cves": sum(counts.values()),
        "findings": items,
        "hint": "Run trigger_posture_scan if empty or stale",
    }
