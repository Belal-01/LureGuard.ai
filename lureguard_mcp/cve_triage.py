"""CVE triage — filter OSV noise, score actionable findings."""

from __future__ import annotations

import re
from datetime import date, datetime
from functools import lru_cache
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# (platform substring, version substring) -> EOL date (standard support)
_EOL_OS_RULES: list[tuple[tuple[str, str], date]] = [
    (("ubuntu", "18.04"), date(2023, 4, 30)),
    (("ubuntu", "20.04"), date(2025, 4, 30)),
    (("ubuntu", "22.04"), date(2027, 4, 30)),
    (("debian", "10"), date(2024, 6, 30)),
    (("debian", "11"), date(2026, 8, 14)),
    (("centos", "7"), date(2024, 6, 30)),
    (("rhel", "7"), date(2024, 6, 30)),
    (("rocky", "8"), date(2029, 5, 31)),
]

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


def is_eol_os(platform: str, version: str = "", name: str = "") -> bool:
    """Return True if OS appears end-of-life per hardcoded support dates."""
    text = f"{platform} {version} {name}".lower()
    today = datetime.utcnow().date()
    for (plat, ver), eol in _EOL_OS_RULES:
        if plat in text and ver in text and today > eol:
            return True
    return False


def normalize_cve_id(raw: str) -> str:
    """Map distro-prefixed IDs (e.g. UBUNTU-CVE-2024-1234) to canonical CVE- form."""
    value = (raw or "").strip().upper()
    if value.startswith("UBUNTU-CVE-"):
        return "CVE-" + value[len("UBUNTU-CVE-") :]
    if value.startswith("DEBIAN-CVE-"):
        return "CVE-" + value[len("DEBIAN-CVE-") :]
    return value


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for CVE IDs (FIRST.org public API, no key)."""
    scores: dict[str, float] = {}
    unique = sorted(
        {
            normalize_cve_id(c)
            for c in cve_ids
            if normalize_cve_id(c).startswith("CVE-")
        }
    )
    if not unique:
        return scores
    chunk_size = 100
    with httpx.Client(timeout=30.0) as client:
        for start in range(0, len(unique), chunk_size):
            chunk = unique[start : start + chunk_size]
            try:
                resp = client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                resp.raise_for_status()
                for row in resp.json().get("data") or []:
                    cve = str(row.get("cve") or "").upper()
                    try:
                        scores[cve] = float(row.get("epss") or 0)
                    except (TypeError, ValueError):
                        continue
            except Exception:
                continue
    return scores


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
    epss_score: float | None = None,
    eol_os: bool = False,
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
    if epss_score is not None and epss_score > 0.5:
        priority += 25
    elif epss_score is not None and epss_score > 0.1:
        priority += 10
    if eol_os and severity == "critical":
        priority += 50
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
        "epss_score": epss_score,
        "eol_os_boost": eol_os,
    }
