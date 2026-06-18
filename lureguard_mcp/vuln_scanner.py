"""OSV.dev-backed vulnerability scanner using Wazuh syscollector inventory."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from lureguard_mcp.cve_triage import (
    fetch_epss_batch,
    is_eol_os,
    normalize_cve_id,
    process_names_from_packages,
    triage_finding,
)
from lureguard_mcp.db import (
    get_agent_cve_counts_db,
    get_agent_cve_findings_db,
    get_agent_cve_last_scan_db,
    get_fleet_cve_summary_db,
    replace_agent_cve_findings_db,
    set_host_eol_os_db,
)
from lureguard_mcp.wazuh_client import WazuhClient

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
BATCH_SIZE = 500
PACKAGE_PAGE = 500

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _parse_cvss(vuln: dict[str, Any]) -> tuple[float | None, str]:
    best: float | None = None
    ubuntu_sev: str | None = None
    for entry in vuln.get("severity") or []:
        sev_type = str(entry.get("type") or "")
        raw = entry.get("score")
        if raw is None:
            continue
        if sev_type == "Ubuntu":
            ubuntu_sev = str(raw).lower()
            continue
        raw_str = str(raw)
        if raw_str.startswith("CVSS:"):
            if "/C:H/" in raw_str and "/I:H/" in raw_str:
                best = max(best or 0, 9.0)
            elif "/C:H/" in raw_str or "/I:H/" in raw_str:
                best = max(best or 0, 7.5)
            elif "/A:H/" in raw_str:
                best = max(best or 0, 6.0)
            elif "/C:L/" in raw_str:
                best = max(best or 0, 5.0)
            continue
        try:
            val = float(raw_str.split()[0])
        except (TypeError, ValueError):
            continue
        if best is None or val > best:
            best = val
    if best is not None:
        return best, _cvss_to_severity(best)
    if ubuntu_sev in {"critical", "high", "medium", "low"}:
        return None, ubuntu_sev
    return None, "unknown"


def _extract_fix_version(vuln: dict[str, Any], ecosystem: str, package_name: str) -> str | None:
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") and pkg.get("name") != package_name:
            continue
        if pkg.get("ecosystem") and pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


def _osv_ecosystem(os_item: dict[str, Any]) -> str:
    platform = str(os_item.get("platform") or "").lower()
    name = str(os_item.get("name") or "").lower()
    if "ubuntu" in platform or "ubuntu" in name:
        return "Ubuntu"
    if "debian" in platform or "debian" in name:
        return "Debian"
    if "almalinux" in name or "rocky" in name or "centos" in name or "rhel" in name:
        return "Red Hat"
    return "Ubuntu"


def _fetch_all_processes(wazuh: WazuhClient, agent_id: str) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    offset = 0
    while True:
        resp = wazuh.get_agent_processes(agent_id, limit=PACKAGE_PAGE, offset=offset)
        items = resp.get("data", {}).get("affected_items") or []
        if not items:
            break
        processes.extend(items)
        total = resp.get("data", {}).get("total_affected_items")
        offset += len(items)
        if total is not None and offset >= int(total):
            break
        if len(items) < PACKAGE_PAGE:
            break
    return processes


def _fetch_all_packages(wazuh: WazuhClient, agent_id: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    offset = 0
    while True:
        resp = wazuh.get_agent_packages(agent_id, limit=PACKAGE_PAGE, offset=offset)
        items = resp.get("data", {}).get("affected_items") or []
        if not items:
            break
        packages.extend(items)
        total = resp.get("data", {}).get("total_affected_items")
        offset += len(items)
        if total is not None and offset >= int(total):
            break
        if len(items) < PACKAGE_PAGE:
            break
    return packages


def _query_osv_batch(
    queries: list[dict[str, Any]],
    *,
    client: httpx.Client,
) -> list[dict[str, Any] | None]:
    if not queries:
        return []
    resp = client.post(OSV_BATCH_URL, json={"queries": queries}, timeout=120.0)
    resp.raise_for_status()
    results = resp.json().get("results") or []
    return results


def _ensure_vuln_detail(
    vuln: dict[str, Any],
    *,
    client: httpx.Client,
    cache: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if vuln.get("severity"):
        return vuln
    vuln_id = str(vuln.get("id") or "")
    if not vuln_id:
        return vuln
    if vuln_id in cache:
        return cache[vuln_id]
    try:
        resp = client.get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout=30.0)
        if resp.status_code == 200:
            full = resp.json()
            cache[vuln_id] = full
            return full
    except Exception:
        pass
    cache[vuln_id] = vuln
    return vuln


def scan_agent_vulnerabilities(
    agent_id: str,
    *,
    wazuh: WazuhClient | None = None,
) -> dict[str, Any]:
    """Scan one agent via OSV.dev and persist findings to Postgres."""
    wazuh = wazuh or WazuhClient()
    scanned_at = datetime.utcnow()

    try:
        agents_resp = wazuh.list_agents(limit=500)
        agent_meta = None
        for a in agents_resp.get("data", {}).get("affected_items") or []:
            if str(a.get("id")) == str(agent_id):
                agent_meta = a
                break
        if not agent_meta:
            return {"agent_id": agent_id, "error": "agent not found", "findings": [], "counts": {}}
    except Exception as exc:
        return {"agent_id": agent_id, "error": str(exc), "findings": [], "counts": {}}

    try:
        os_resp = wazuh.get_agent_os(agent_id)
        os_items = os_resp.get("data", {}).get("affected_items") or []
        os_item = (os_items[0].get("os") if os_items else {}) or {}
    except Exception:
        os_item = {}

    ecosystem = _osv_ecosystem(os_item)
    os_platform = str(os_item.get("platform") or os_item.get("name") or "")
    os_version = str(os_item.get("version") or os_item.get("major") or "")
    os_name = str(os_item.get("name") or "")
    eol_os = is_eol_os(os_platform, os_version, os_name)
    set_host_eol_os_db(agent_id, eol_os)
    packages = _fetch_all_packages(wazuh, agent_id)
    try:
        running = process_names_from_packages(_fetch_all_processes(wazuh, agent_id))
    except Exception:
        running = set()

    if not packages:
        replace_agent_cve_findings_db(agent_id=agent_id, findings=[], scanned_at=scanned_at)
        return {
            "agent_id": agent_id,
            "name": agent_meta.get("name", ""),
            "ip": agent_meta.get("ip", ""),
            "ecosystem": ecosystem,
            "packages_scanned": 0,
            "findings": [],
            "counts": {s: 0 for s in _SEVERITY_ORDER},
            "scanned_at": scanned_at.isoformat(),
        }

    findings: list[dict[str, Any]] = []
    vuln_cache: dict[str, dict[str, Any]] = {}
    pending: list[dict[str, Any]] = []
    with httpx.Client(timeout=120.0) as client:
        for start in range(0, len(packages), BATCH_SIZE):
            batch_pkgs = packages[start : start + BATCH_SIZE]
            queries = [
                {
                    "package": {"name": pkg.get("name", ""), "ecosystem": ecosystem},
                    "version": str(pkg.get("version") or ""),
                }
                for pkg in batch_pkgs
                if pkg.get("name") and pkg.get("version")
            ]
            if not queries:
                continue
            try:
                results = _query_osv_batch(queries, client=client)
            except Exception as exc:
                return {
                    "agent_id": agent_id,
                    "error": f"OSV query failed: {exc}",
                    "findings": findings,
                    "counts": _count_findings(findings),
                }

            for pkg, result in zip(batch_pkgs, results):
                if not result:
                    continue
                pkg_name = str(pkg.get("name", ""))
                pkg_version = str(pkg.get("version", ""))
                for vuln in result.get("vulns") or []:
                    detail = _ensure_vuln_detail(vuln, client=client, cache=vuln_cache)
                    cve_id = str(detail.get("id") or vuln.get("id") or "")
                    for alias in detail.get("aliases") or vuln.get("aliases") or []:
                        if str(alias).upper().startswith("CVE-"):
                            cve_id = str(alias)
                            break
                    if not cve_id:
                        continue
                    cve_id = normalize_cve_id(cve_id)
                    cvss, severity = _parse_cvss(detail)
                    fix_version = _extract_fix_version(detail, ecosystem, pkg_name)
                    triage = triage_finding(
                        vuln=detail,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        ecosystem=ecosystem,
                        cve_id=cve_id,
                        severity=severity,
                        cvss=cvss,
                        running_processes=running,
                        eol_os=eol_os,
                    )
                    if triage is None:
                        continue
                    pending.append(
                        {
                            "package_name": pkg_name,
                            "package_version": pkg_version,
                            "cve_id": cve_id,
                            "severity": severity,
                            "cvss": cvss,
                            "fix_version": fix_version,
                            "summary": (detail.get("summary") or "")[:2000] or None,
                            "source": "osv",
                            **triage,
                        }
                    )

    epss_scores = fetch_epss_batch([p["cve_id"] for p in pending])
    for item in pending:
        epss = epss_scores.get(normalize_cve_id(item["cve_id"]))
        if epss is not None:
            item["epss_score"] = epss
            priority = int(item.get("priority_score") or 0)
            if epss > 0.5:
                priority += 25
            elif epss > 0.1:
                priority += 10
            item["priority_score"] = priority
        findings.append(item)

    replace_agent_cve_findings_db(agent_id=agent_id, findings=findings, scanned_at=scanned_at)
    backfill_agent_epss_scores(agent_id)
    counts = _count_findings(findings)
    actionable_counts = _count_findings(findings, actionable_only=True)
    return {
        "agent_id": agent_id,
        "name": agent_meta.get("name", ""),
        "ip": agent_meta.get("ip", ""),
        "ecosystem": ecosystem,
        "eol_os": eol_os,
        "packages_scanned": len(packages),
        "findings_count": len(findings),
        "actionable_count": sum(actionable_counts.values()),
        "counts": counts,
        "actionable_counts": actionable_counts,
        "scanned_at": scanned_at.isoformat(),
        "findings": sorted(
            findings,
            key=lambda f: (f.get("priority_score") or 0, f.get("cvss") or 0),
            reverse=True,
        )[:100],
        "truncated": len(findings) > 100,
    }


def backfill_agent_epss_scores(agent_id: str) -> int:
    """Fill epss_score on cached CVE rows (handles UBUNTU-CVE-* IDs)."""
    from lureguard_mcp.db import get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT cve_id FROM cve_findings WHERE agent_id = %s AND epss_score IS NULL",
                (agent_id,),
            )
            raw_ids = [row[0] for row in cur.fetchall()]
    if not raw_ids:
        return 0

    scores = fetch_epss_batch(raw_ids)
    updated = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for raw in raw_ids:
                epss = scores.get(normalize_cve_id(raw))
                if epss is None:
                    continue
                cur.execute(
                    "UPDATE cve_findings SET epss_score = %s WHERE agent_id = %s AND cve_id = %s",
                    (epss, agent_id, raw),
                )
                updated += cur.rowcount
    return updated


def _count_findings(
    findings: list[dict[str, Any]],
    *,
    actionable_only: bool = False,
) -> dict[str, int]:
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        if actionable_only and not f.get("actionable", True):
            continue
        sev = str(f.get("severity", "unknown")).lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] += 1
    return counts


def get_agent_vulnerabilities(
    agent_id: str,
    *,
    severity: str | None = None,
    actionable_only: bool = True,
    limit: int = 500,
) -> dict[str, Any]:
    """Return cached CVE findings from Postgres for one agent."""
    items = get_agent_cve_findings_db(
        agent_id,
        severity=severity,
        actionable_only=actionable_only,
        limit=limit,
    )
    counts = get_agent_cve_counts_db(agent_id, actionable_only=actionable_only)
    raw_counts = get_agent_cve_counts_db(agent_id, actionable_only=False) if actionable_only else counts
    scanned_at = get_agent_cve_last_scan_db(agent_id)
    total = sum(counts.values())
    return {
        "agent_id": agent_id,
        "source": "postgres+osv",
        "actionable_only": actionable_only,
        "scanned_at": scanned_at,
        "counts": counts,
        "raw_counts": raw_counts if actionable_only else None,
        "total": total,
        "findings": items,
        "hint": "Run scan_agent_vulnerabilities if data is stale or empty",
    }


def get_fleet_vulnerability_summary() -> dict[str, Any]:
    """Fleet CVE summary from Postgres cache."""
    return get_fleet_cve_summary_db()
