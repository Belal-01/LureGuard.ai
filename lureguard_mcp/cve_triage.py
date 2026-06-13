"""CVE triage — filter OSV noise, score actionable findings."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Packages where OSV returns many historical/meta CVEs — deprioritize unless service runs
METADATA_PACKAGES = frozenset(
    {
        "linux-firmware",
        "linux-modules-extra",
        "firmware-sof-signed",
        "linux-image-generic",
        "linux-headers-generic",
    }
)

PACKAGE_PROCESS_HINTS: dict[str, tuple[str, ...]] = {
    "apache2": ("apache2", "httpd"),
    "nginx": ("nginx",),
    "snapd": ("snapd",),
    "openssl": ("openssl",),
    "openssh-server": ("sshd", "ssh"),
    "ssh": ("sshd",),
    "mysql-server": ("mysqld", "mariadbd"),
    "postgresql": ("postgres",),
    "redis-server": ("redis-server",),
    "docker.io": ("dockerd", "containerd"),
    "containerd": ("containerd",),
    "git": ("git",),
    "perl": ("perl",),
    "python3.12": ("python3", "python3.12"),
}


def _version_key(version: str) -> list[Any]:
    v = version.strip()
    if ":" in v:
        v = v.split(":", 1)[1]
    parts = re.split(r"[.+\-~]", v)
    out: list[Any] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            out.append(int(part))
        else:
            out.append(part)
    return out


def version_gte(installed: str, fixed: str) -> bool:
    """Best-effort Debian/Ubuntu version compare (installed >= fixed)."""
    if not installed or not fixed:
        return False
    a, b = _version_key(installed), _version_key(fixed)
    for left, right in zip(a, b):
        if left == right:
            continue
        if isinstance(left, int) and isinstance(right, int):
            return left > right
        return str(left) > str(right)
    return len(a) >= len(b)


@lru_cache(maxsize=1)
def _kev_cve_ids() -> frozenset[str]:
    try:
        resp = httpx.get(KEV_URL, timeout=20.0, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        return frozenset(
            str(v.get("cveID", "")).upper()
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        )
    except Exception:
        return frozenset()


def is_on_kev(cve_id: str) -> bool:
    return cve_id.upper() in _kev_cve_ids()


def _is_patched(package_version: str, vuln: dict[str, Any], package_name: str, ecosystem: str) -> bool:
    db_spec = vuln.get("database_specific") or {}
    if str(db_spec.get("status", "")).lower() in {"not-affected", "fixed", "ignored"}:
        return True

    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") and pkg.get("name") != package_name:
            continue
        if pkg.get("ecosystem") and pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed and version_gte(package_version, str(fixed)):
                    return True
    return False


def process_names_from_packages(processes: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for proc in processes:
        name = str(proc.get("name") or proc.get("process") or "").lower()
        if name:
            names.add(name)
    return names


def package_service_running(package_name: str, running: set[str]) -> bool:
    hints = PACKAGE_PROCESS_HINTS.get(package_name.lower(), (package_name.lower(),))
    return any(h in running for h in hints)


def triage_finding(
    *,
    vuln: dict[str, Any],
    package_name: str,
    package_version: str,
    ecosystem: str,
    cve_id: str,
    severity: str,
    cvss: float | None,
    running_processes: set[str],
) -> dict[str, Any] | None:
    """Return enriched finding dict or None if filtered as noise."""
    if _is_patched(package_version, vuln, package_name, ecosystem):
        return None

    svc_running = package_service_running(package_name, running_processes)
    on_kev = is_on_kev(cve_id)
    meta_pkg = package_name.lower() in METADATA_PACKAGES

    priority = 0
    if on_kev:
        priority += 100
    if svc_running:
        priority += 40
    if severity == "critical":
        priority += 30
    elif severity == "high":
        priority += 20
    elif severity == "medium":
        priority += 10
    if cvss:
        priority += int(min(cvss, 10))
    if meta_pkg and not svc_running and not on_kev:
        priority -= 50

    actionable = priority >= 15 or on_kev or (svc_running and severity in {"critical", "high"})
    if meta_pkg and not svc_running and not on_kev:
        actionable = False
    if severity == "unknown" and not on_kev and not svc_running:
        actionable = False

    return {
        "actionable": actionable,
        "service_running": svc_running,
        "on_kev": on_kev,
        "priority_score": priority,
    }
