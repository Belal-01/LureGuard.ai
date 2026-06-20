"""LureGuard MCP server — FastMCP stdio with audit logging."""

from __future__ import annotations

import functools
import inspect
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TypeVar

from mcp.server.fastmcp import FastMCP

from lureguard_mcp import context as inv_ctx
from lureguard_mcp.db import (
    add_timeline_event as db_add_timeline_event,
    close_investigation_db,
    get_alerts_for_ip as db_get_alerts_for_ip,
    get_attack_summary as db_get_attack_summary,
    get_event_timeline as db_get_event_timeline,
    get_investigation_findings_db,
    get_investigation_iocs_db,
    get_investigation_timeline_db,
    get_recent_alerts as db_get_recent_alerts,
    get_soc_health_db,
    list_hosts_db,
    log_agent_action,
    open_investigation as db_open_investigation,
    record_finding as db_record_finding,
    save_report_db,
    search_events as db_search_events,
    set_host_criticality_db,
)
from lureguard_mcp.config import REPORTS_DIR, REPO_ROOT
from lureguard_mcp.enrichment import (
    analyze_web_attack as enrich_analyze_web_attack,
    check_domain_virustotal as enrich_domain_vt,
    check_hash_virustotal,
    check_ip_reputation as enrich_abuseipdb,
    check_ip_virustotal as enrich_vt_ip,
    check_tls as enrich_check_tls,
    check_url_urlhaus as enrich_urlhaus,
    check_url_virustotal as enrich_url_vt,
    defang_indicator,
    get_ip_context as enrich_get_ip_context,
)
from lureguard_mcp.blocklist import (
    confirm_block_ip as blocklist_confirm,
    list_blocklist as blocklist_list,
    recommend_block_ip as blocklist_recommend,
)
from lureguard_mcp.whitelist import (
    confirm_whitelist_ip as whitelist_confirm,
    list_whitelist as whitelist_list,
    recommend_whitelist_ip as whitelist_recommend,
    remove_whitelist_ip as whitelist_remove,
)
from lureguard_mcp.container_posture import get_agent_container_posture
from lureguard_mcp.onboarding import onboard_host
from lureguard_mcp.detection_scanner import (
    get_agent_detection_coverage as detection_get_agent,
    get_fleet_detection_coverage as detection_fleet_summary,
)
from lureguard_mcp.exposure_scanner import (
    get_agent_exposure as exposure_get_agent,
    get_fleet_exposure_summary as exposure_fleet_summary,
)
from lureguard_mcp.posture_snapshot import (
    get_fleet_posture_summary as posture_fleet_summary,
    get_posture_snapshot as posture_get_snapshot,
)
from lureguard_mcp.sca_scanner import (
    get_agent_sca_summary as sca_get_agent,
    get_fleet_sca_summary as sca_fleet_summary,
)
from lureguard_mcp.user_scanner import get_agent_users as users_get_agent
from lureguard_mcp.report_charts import (
    enrich_report_markdown,
    generate_chart_from_preset,
    generate_chart_png,
    report_stem_from_title,
)
from lureguard_mcp.report_pdf import convert_markdown_to_pdf, pdf_available, resolve_report_pdf_path
from lureguard_mcp.scan_scheduler import (
    get_scan_job_status,
    start_scan_scheduler,
    trigger_posture_scan as scheduler_trigger_scan,
)
from lureguard_mcp.vuln_scanner import (
    get_agent_vulnerabilities as vuln_get_agent,
    get_fleet_vulnerability_summary as vuln_fleet_summary,
    scan_agent_vulnerabilities as vuln_scan_agent,
)
from lureguard_mcp.correlator import correlate_alerts as correlate_alerts_db
from lureguard_mcp.mcp_json import mcp_json
from lureguard_mcp.rag import rag_lookup_json
from lureguard_mcp.secrets import redact_mapping
from lureguard_mcp.system_update import (
    apply_system_update as _apply_system_update,
    check_system_update as _check_system_update,
    dismiss_system_update as _dismiss_system_update,
    rollback_system_update as _rollback_system_update,
)
from lureguard_mcp.wazuh_client import WazuhClient, compact_json

mcp = FastMCP("LureGuard")
_wazuh = WazuhClient()

F = TypeVar("F", bound=Callable[..., Any])


def _log_tool_call(name: str, args: tuple[Any, ...], kwargs: dict[str, Any], summary: str, start: float) -> None:
    elapsed = int((time.perf_counter() - start) * 1000)
    try:
        log_agent_action(
            tool_name=name,
            args={"args": list(args), "kwargs": redact_mapping(kwargs)},
            result_summary=summary,
            duration_ms=elapsed,
            investigation_id=inv_ctx.get_investigation_id(),
        )
    except Exception:
        pass


def audited(tool_fn: F) -> F:
    """Log every tool call to agent_actions in Postgres."""

    if inspect.iscoroutinefunction(tool_fn):

        @functools.wraps(tool_fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> str:
            start = time.perf_counter()
            name = tool_fn.__name__
            summary = "ok"
            try:
                result = await tool_fn(*args, **kwargs)
                summary = result[:500] + "..." if len(result) > 500 else result
                return result
            except Exception as exc:
                summary = f"ERROR: {exc}"
                raise
            finally:
                _log_tool_call(name, args, kwargs, summary, start)

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(tool_fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> str:
        start = time.perf_counter()
        name = tool_fn.__name__
        summary = "ok"
        try:
            result = tool_fn(*args, **kwargs)
            summary = result[:500] + "..." if len(result) > 500 else result
            return result
        except Exception as exc:
            summary = f"ERROR: {exc}"
            raise
        finally:
            _log_tool_call(name, args, kwargs, summary, start)

    return sync_wrapper  # type: ignore[return-value]


@mcp.tool()
@audited
def get_recent_alerts(limit: int = 50, min_level: int = 3, channel: str = "") -> str:
    """Return recent security events from LureGuard Postgres (Wazuh-ingested alerts)."""
    rows = db_get_recent_alerts(
        limit=min(limit, 200),
        min_level=min_level if min_level > 0 else None,
        channel=channel or None,
    )
    return mcp_json({"count": len(rows), "alerts": rows})


@mcp.tool()
@audited
def get_alerts_for_ip(ip: str, limit: int = 100) -> str:
    """Return all events for a source IP address."""
    rows = db_get_alerts_for_ip(ip, limit=min(limit, 500))
    return mcp_json({"ip": ip, "count": len(rows), "events": rows})


@mcp.tool()
@audited
def get_event_timeline(ip: str, window_hours: int = 24) -> str:
    """Chronological attack timeline for an IP with geo, duration, ML scores, and phases."""
    timeline = db_get_event_timeline(ip, window_hours=min(window_hours, 168))
    return mcp_json(timeline)


@mcp.tool()
@audited
def get_attack_summary(ip: str, window_hours: int = 48) -> str:
    """Aggregate attack summary for an IP — duration, channels, top rules, honeypot contact."""
    summary = db_get_attack_summary(ip, window_hours=min(window_hours, 168))
    return mcp_json(summary)


@mcp.tool()
@audited
def get_ip_context(ip: str) -> str:
    """Mandatory compound enrichment: geo + AbuseIPDB + VirusTotal + verdict in one call."""
    return enrich_get_ip_context(ip)


@mcp.tool()
@audited
def check_tls(host: str, port: int = 443) -> str:
    """Check TLS certificate expiry and negotiated cipher for host:port."""
    return enrich_check_tls(host, port=port)


@mcp.tool()
@audited
def recommend_block_ip(ip: str, reason: str, investigation_id: str = "") -> str:
    """Recommend blocking an IP after investigation. Requires human confirm_block_ip to execute."""
    result = blocklist_recommend(ip, reason, investigation_id)
    return mcp_json(result)


@mcp.tool()
@audited
def confirm_block_ip(block_id: str, notes: str = "") -> str:
    """Human-confirmed: apply iptables DROP for a pending blocklist entry across active hosts."""
    result = blocklist_confirm(block_id, notes=notes, caller="agent")
    return mcp_json(result)


@mcp.tool()
@audited
def list_blocklist(pending_only: bool = False) -> str:
    """List blocklist entries (pending and executed)."""
    return blocklist_list(pending_only=pending_only)


@mcp.tool()
@audited
def recommend_whitelist_ip(ip: str, reason: str, investigation_id: str = "") -> str:
    """Recommend whitelisting an IP for SSH ML (skips alert/redirect). Requires human confirm_whitelist_ip."""
    result = whitelist_recommend(ip, reason, investigation_id)
    return mcp_json(result)


@mcp.tool()
@audited
def confirm_whitelist_ip(whitelist_id: str, notes: str = "") -> str:
    """Human-confirmed: activate a pending whitelist entry for Core SSH ML."""
    result = whitelist_confirm(whitelist_id, notes=notes, caller="agent")
    return mcp_json(result)


@mcp.tool()
@audited
def list_whitelist(pending_only: bool = False) -> str:
    """List whitelist entries (pending and active)."""
    return whitelist_list(pending_only=pending_only)


@mcp.tool()
@audited
def remove_whitelist_ip(whitelist_id: str = "", ip: str = "") -> str:
    """Remove an active or pending whitelist entry (provide whitelist_id or ip)."""
    result = whitelist_remove(whitelist_id=whitelist_id, ip=ip)
    return mcp_json(result)


@mcp.tool()
@audited
def set_host_criticality(agent_id: str, criticality: str) -> str:
    """Set persistent asset criticality: critical | high | medium | low."""
    return mcp_json(set_host_criticality_db(agent_id, criticality))


@mcp.tool()
@audited
def search_events(
    ip: str = "",
    channel: str = "",
    min_level: int = 0,
    username: str = "",
    limit: int = 100,
) -> str:
    """Search stored events with optional filters (no raw SQL)."""
    rows = db_search_events(
        ip=ip or None,
        channel=channel or None,
        min_level=min_level if min_level > 0 else None,
        username=username or None,
        limit=min(limit, 500),
    )
    return mcp_json({"count": len(rows), "events": rows})


@mcp.tool()
@audited
def list_agents(status: str = "") -> str:
    """List Wazuh agents and their connection status."""
    return compact_json(_wazuh.list_agents(status=status or None))


@mcp.tool()
@audited
def get_agent_detail(agent_id: str) -> str:
    """Get Wazuh agent details including OS, processes, ports, and packages."""
    agent = _wazuh.get_agent(agent_id)
    os_info = _wazuh.get_agent_os(agent_id)
    processes = _wazuh.get_agent_processes(agent_id, limit=20)
    ports = _wazuh.get_agent_ports(agent_id, limit=20)
    packages = _wazuh.get_agent_packages(agent_id, limit=20)
    payload = {
        "agent": agent.get("data", agent),
        "os": os_info.get("data", os_info),
        "processes_sample": processes.get("data", processes),
        "ports_sample": ports.get("data", ports),
        "packages_sample": packages.get("data", packages),
    }
    return compact_json(payload)


@mcp.tool()
@audited
def get_rules_summary(limit: int = 20) -> str:
    """Summarize Wazuh detection rules (highest level first)."""
    return compact_json(_wazuh.get_rules_summary(limit=min(limit, 100)))


@mcp.tool()
@audited
def get_manager_status() -> str:
    """Return Wazuh manager health and component status."""
    return compact_json(_wazuh.get_manager_status())


@mcp.tool()
@audited
def scan_agent_vulnerabilities(agent_id: str) -> str:
    """Scan one agent: Wazuh syscollector packages + OSV.dev CVE lookup, saved to Postgres."""
    return compact_json(vuln_scan_agent(agent_id, wazuh=_wazuh))


@mcp.tool()
@audited
def get_agent_vulnerabilities(agent_id: str, severity: str = "", include_noise: bool = False) -> str:
    """List cached CVE findings for an agent (actionable-only by default; set include_noise=true for all OSV matches)."""
    sev = severity.strip().lower() or None
    if sev and sev not in {"critical", "high", "medium", "low"}:
        return mcp_json({"error": "severity must be critical, high, medium, or low"})
    return compact_json(
        vuln_get_agent(agent_id, severity=sev, actionable_only=not include_noise)
    )


@mcp.tool()
@audited
def get_soc_health() -> str:
    """Ingestion health: event volume, last event time, per-agent activity (for daily summary)."""
    return compact_json(get_soc_health_db())


@mcp.tool()
@audited
def get_fleet_vulnerability_summary() -> str:
    """CVE summary across fleet from Postgres cache (counts by severity per host)."""
    return compact_json(vuln_fleet_summary())


@mcp.tool()
@audited
def get_agent_exposure(agent_id: str, risk_level: str = "") -> str:
    """Cached open-port exposure for an agent from Postgres (run trigger_posture_scan first)."""
    level = risk_level.strip().lower() or None
    if level and level not in {"critical", "high", "medium", "low", "info"}:
        return mcp_json({"error": "risk_level must be critical, high, medium, low, or info"})
    return compact_json(exposure_get_agent(agent_id, risk_level=level))


@mcp.tool()
@audited
def get_fleet_exposure_summary() -> str:
    """Fleet-wide open port / service exposure summary from Postgres cache."""
    return compact_json(exposure_fleet_summary())


@mcp.tool()
@audited
def get_agent_detection_coverage(agent_id: str) -> str:
    """Cached detection coverage (FIM, rootcheck, alert volume) for one agent."""
    return compact_json(detection_get_agent(agent_id))


@mcp.tool()
@audited
def get_fleet_detection_coverage() -> str:
    """Fleet-wide detection coverage summary from Postgres cache."""
    return compact_json(detection_fleet_summary())


@mcp.tool()
@audited
def get_agent_sca_summary(agent_id: str) -> str:
    """Cached SCA/CIS compliance summary for an agent (score, failed checks)."""
    return compact_json(sca_get_agent(agent_id))


@mcp.tool()
@audited
def get_fleet_sca_summary() -> str:
    """Fleet-wide SCA/CIS compliance scores from Postgres cache."""
    return compact_json(sca_fleet_summary())


@mcp.tool()
@audited
def get_agent_users(agent_id: str, risk_level: str = "") -> str:
    """Cached local user inventory with risk levels for an agent."""
    level = risk_level.strip().lower() or None
    if level and level not in {"critical", "high", "medium", "low", "info"}:
        return mcp_json({"error": "risk_level must be critical, high, medium, low, or info"})
    return compact_json(users_get_agent(agent_id, risk_level=level))


@mcp.tool()
@audited
def get_posture_snapshot(agent_id: str) -> str:
    """Instant posture read from Postgres — host CVE, exposure, detection, SCA, users, and container image CVE caches."""
    return compact_json(posture_get_snapshot(agent_id))


@mcp.tool()
@audited
def get_agent_container_posture(agent_id: str, image_ref: str = "", limit: int = 200) -> str:
    """Cached Docker runtime inventory + Trivy image CVE findings for an agent (posture pillar)."""
    return compact_json(
        get_agent_container_posture(agent_id, image_ref=image_ref, limit=limit)
    )


@mcp.tool()
@audited
def get_fleet_posture_summary() -> str:
    """Fleet posture overview from Postgres caches (no live scan)."""
    return compact_json(posture_fleet_summary())


@mcp.tool()
@audited
def trigger_posture_scan(agent_id: str = "", force: bool = False) -> str:
    """Start background posture scan (host CVE + exposure + detection + SCA + users + container Trivy). force=true rescans even if cache is fresh."""
    return compact_json(scheduler_trigger_scan(agent_id=agent_id, force=force))


@mcp.tool()
@audited
def get_posture_scan_status(job_id: str) -> str:
    """Check status of a background posture scan job."""
    return compact_json(get_scan_job_status(job_id))


@mcp.tool()
@audited
def restart_agent(agent_id: str) -> str:
    """Request restart of a Wazuh agent (advisory — confirm with human first)."""
    return compact_json(_wazuh.restart_agent(agent_id))


@mcp.tool()
@audited
def check_ip_reputation(ip: str) -> str:
    """Check IP reputation via AbuseIPDB."""
    return enrich_abuseipdb(ip)


@mcp.tool()
@audited
def check_ip_virustotal(ip: str) -> str:
    """Check IP reputation via VirusTotal."""
    return enrich_vt_ip(ip)


@mcp.tool()
@audited
def check_hash(file_hash: str) -> str:
    """Check file hash reputation via VirusTotal."""
    return check_hash_virustotal(file_hash)


@mcp.tool()
@audited
def check_url_virustotal(url: str) -> str:
    """Check URL reputation via VirusTotal v3."""
    return enrich_url_vt(url)


@mcp.tool()
@audited
def check_domain_virustotal(domain: str) -> str:
    """Check domain reputation via VirusTotal v3."""
    return enrich_domain_vt(domain)


@mcp.tool()
@audited
def check_url_urlhaus(url: str) -> str:
    """Check URL against URLhaus (abuse.ch). No API key required."""
    return enrich_urlhaus(url)


@mcp.tool()
@audited
def defang_ioc(value: str, ioc_type: str = "") -> str:
    """Defang an IOC (IP, URL, domain, email) for safe report sharing."""
    return mcp_json(
        {"original": value, "defanged": defang_indicator(value, ioc_type or None)},
    )


@mcp.tool()
@audited
def analyze_web_attack(event_payload: str) -> str:
    """Classify web attack patterns (SQLi, XSS, LFI, RCE, scanner UA) from event text/JSON."""
    return enrich_analyze_web_attack(event_payload)


@mcp.tool()
@audited
def open_investigation(
    subject: str,
    trigger: str = "human",
    severity: str = "",
    detection_source: str = "",
    asset_criticality: str = "",
) -> str:
    """Open a new investigation. Always call this before triage or deep investigation."""
    inv = db_open_investigation(
        trigger=trigger,
        subject=subject,
        severity=severity or None,
        detection_source=detection_source or None,
        asset_criticality=asset_criticality or None,
    )
    inv_ctx.set_investigation_id(inv["id"])
    return mcp_json(inv)


@mcp.tool()
@audited
def record_finding(
    finding: str,
    citation: str,
    investigation_id: str = "",
    mitre_technique: str = "",
    mitre_tactic: str = "",
    severity: str = "",
    verdict: str = "",
    confidence: str = "",
    ioc_type: str = "",
    ioc_value: str = "",
) -> str:
    """Record a grounded finding with mandatory citation. Optional MITRE, severity, IOC fields."""
    inv_id = investigation_id or inv_ctx.get_investigation_id()
    if not inv_id:
        return mcp_json({"error": "No investigation open. Call open_investigation first."})
    return mcp_json(
        db_record_finding(
            inv_id,
            finding,
            citation,
            mitre_technique=mitre_technique or None,
            mitre_tactic=mitre_tactic or None,
            severity=severity or None,
            verdict=verdict or None,
            confidence=confidence or None,
            ioc_type=ioc_type or None,
            ioc_value=ioc_value or None,
        ),
    )


@mcp.tool()
@audited
def add_timeline_event(
    description: str,
    ts_event: str,
    phase: str = "",
    source: str = "",
    investigation_id: str = "",
) -> str:
    """Add a cited timeline event (ISO8601 ts_event). Phase: identification|containment|eradication|recovery|lessons."""
    inv_id = investigation_id or inv_ctx.get_investigation_id()
    if not inv_id:
        return mcp_json({"error": "No investigation open. Call open_investigation first."})
    try:
        event_ts = datetime.fromisoformat(ts_event.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return mcp_json({"error": "ts_event must be ISO8601 (e.g. 2026-06-16T12:00:00Z)"})
    return mcp_json(
        db_add_timeline_event(
            inv_id,
            ts_event=event_ts,
            description=description,
            phase=phase or None,
            source=source or None,
        ),
    )


@mcp.tool()
@audited
def get_investigation_artifacts(investigation_id: str = "") -> str:
    """Return structured findings, timeline events, and IOCs for an investigation."""
    inv_id = investigation_id or inv_ctx.get_investigation_id()
    if not inv_id:
        return mcp_json({"error": "No investigation id provided."})
    return mcp_json(
        {
            "investigation_id": inv_id,
            "findings": get_investigation_findings_db(inv_id),
            "timeline": get_investigation_timeline_db(inv_id),
            "iocs": get_investigation_iocs_db(inv_id),
        },
    )


@mcp.tool()
@audited
def close_investigation(
    verdict: str,
    confidence: str,
    summary: str,
    investigation_id: str = "",
    detection_source: str = "",
    asset_criticality: str = "",
    mttd_seconds: int = 0,
    kill_chain_summary: str = "",
) -> str:
    """Close investigation with verdict: true_positive | false_positive | undetermined."""
    inv_id = investigation_id or inv_ctx.get_investigation_id()
    if not inv_id:
        return mcp_json({"error": "No investigation id provided."})
    result = close_investigation_db(
        inv_id,
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        detection_source=detection_source or None,
        asset_criticality=asset_criticality or None,
        mttd_seconds=mttd_seconds or None,
        kill_chain_summary=kill_chain_summary or None,
    )
    if not result:
        return mcp_json({"error": f"Investigation {inv_id} not found."})
    inv_ctx.set_investigation_id(None)
    return mcp_json(result)


def _resolve_report_path(file_path: str) -> Path:
    path = Path(file_path.strip())
    if not path.is_absolute():
        path = REPO_ROOT / path
    resolved = path.resolve()
    reports_root = REPORTS_DIR.resolve()
    if resolved != reports_root and reports_root not in resolved.parents:
        raise ValueError("file_path must be a report under reports/")
    if not resolved.is_file():
        raise ValueError(f"report file not found: {resolved}")
    return resolved


def _telegram_notifier():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from connectors.telegram import telegram_notifier

    return telegram_notifier


def _send_report_document(report_path: Path, caption: str, *, as_pdf: bool = True) -> dict[str, Any]:
    upload_path = report_path
    out: dict[str, Any] = {"format": "markdown", "source": str(report_path)}
    if as_pdf:
        try:
            upload_path, pdf_mode = resolve_report_pdf_path(report_path)
            out["format"] = "pdf"
            out["pdf_path"] = str(upload_path)
            out["pdf_mode"] = pdf_mode
        except (RuntimeError, OSError, UnicodeDecodeError, ValueError, FileNotFoundError) as exc:
            out["pdf_error"] = str(exc)
            out["pdf_available"] = pdf_available()
            upload_path = report_path if report_path.suffix.lower() == ".md" else report_path.with_suffix(".md")
            if not upload_path.is_file():
                upload_path = report_path
            out["format"] = "markdown" if upload_path.suffix.lower() == ".md" else "pdf"
    result = _telegram_notifier().send_document(upload_path, caption=caption)
    result.update(out)
    return result


@mcp.tool()
@audited
def generate_report_chart(
    title: str,
    chart_type: str,
    labels_json: str,
    values_json: str,
    report_stem: str = "",
    investigation_id: str = "",
) -> str:
    """Generate a PNG chart and return markdown image embed. labels_json/values_json are JSON arrays."""
    stem = report_stem or report_stem_from_title(investigation_id or title or "report")
    labels = json.loads(labels_json)
    values = json.loads(values_json)
    if not isinstance(labels, list) or not isinstance(values, list):
        return mcp_json({"error": "labels_json and values_json must be JSON arrays"})
    result = generate_chart_png(
        title,
        chart_type,
        [str(x) for x in labels],
        [float(x) for x in values],
        report_stem=stem,
    )
    return mcp_json(result)


@mcp.tool()
@audited
def generate_report_chart_preset(
    preset: str,
    report_stem: str = "",
    hours: int = 24,
    agent_id: str = "",
    investigation_id: str = "",
) -> str:
    """Generate a PNG from a named preset (events_by_channel, alert_level_distribution, cve_by_severity, investigation_timeline)."""
    stem = report_stem or report_stem_from_title(investigation_id or preset)
    inv_id = investigation_id or inv_ctx.get_investigation_id() or ""
    try:
        result = generate_chart_from_preset(
            preset,
            report_stem=stem,
            hours=hours,
            agent_id=agent_id,
            investigation_id=inv_id,
        )
    except ValueError as exc:
        return mcp_json({"error": str(exc)})
    if not result:
        return mcp_json({"generated": False, "preset": preset, "message": "no data"})
    return mcp_json({"generated": True, "preset": preset, **result})


@mcp.tool()
@audited
def save_report(
    title: str,
    markdown: str,
    investigation_id: str = "",
    send_telegram: bool = False,
    as_pdf: bool = False,
) -> str:
    """Save report markdown (auto PNG charts in Visual summary), optional PDF and Telegram (Telegram sends PDF)."""
    inv_id = investigation_id or inv_ctx.get_investigation_id()
    stem = report_stem_from_title(title)
    enriched = enrich_report_markdown(
        markdown,
        title=title,
        investigation_id=inv_id or "",
        report_stem=stem,
    )
    result = save_report_db(
        title=title,
        markdown=enriched["markdown"],
        investigation_id=inv_id or None,
    )
    result["charts_added"] = enriched.get("charts_added", [])
    result["report_stem"] = stem

    report_path = _resolve_report_path(result["file_path"])

    if as_pdf:
        try:
            pdf_path, pdf_mode = resolve_report_pdf_path(report_path)
            result["pdf_path"] = str(pdf_path)
            result["relative_pdf_path"] = str(pdf_path.relative_to(REPO_ROOT))
            result["pdf_mode"] = pdf_mode
        except (RuntimeError, OSError, UnicodeDecodeError, ValueError, FileNotFoundError) as exc:
            result["pdf_error"] = str(exc)
            result["pdf_available"] = pdf_available()

    if send_telegram:
        try:
            result["telegram"] = _send_report_document(
                report_path,
                caption=title,
                as_pdf=True,
            )
        except ValueError as exc:
            result["telegram"] = {"sent": False, "reason": str(exc)}
    return mcp_json(result)


@mcp.tool()
@audited
def convert_report_to_pdf(file_path: str) -> str:
    """Convert a saved markdown report under reports/ to PDF (WeasyPrint; embeds PNG charts)."""
    try:
        report_path = _resolve_report_path(file_path)
    except ValueError as exc:
        return mcp_json({"ok": False, "error": str(exc)})
    if report_path.suffix.lower() == ".pdf":
        return mcp_json(
            {
                "ok": True,
                "source": str(report_path),
                "pdf_path": str(report_path),
                "relative_pdf_path": str(report_path.relative_to(REPO_ROOT)),
                "already_pdf": True,
            },
            indent=2,
        )
    try:
        pdf_path, pdf_mode = resolve_report_pdf_path(report_path)
    except (RuntimeError, OSError, UnicodeDecodeError, ValueError, FileNotFoundError) as exc:
        return mcp_json({"ok": False, "error": str(exc), "pdf_available": pdf_available()})
    return mcp_json(
        {
            "ok": True,
            "source": str(report_path),
            "pdf_path": str(pdf_path),
            "relative_pdf_path": str(pdf_path.relative_to(REPO_ROOT)),
            "pdf_mode": pdf_mode,
        },
        indent=2,
    )


@mcp.tool()
@audited
def send_report_to_telegram(file_path: str, caption: str = "") -> str:
    """Send a saved report to Telegram as PDF. Pass the `.md` path (preferred) or existing `.pdf`. Falls back to .md only if PDF conversion fails."""
    try:
        report_path = _resolve_report_path(file_path)
    except ValueError as exc:
        return mcp_json({"sent": False, "reason": str(exc)})

    try:
        result = _send_report_document(report_path, caption=caption or report_path.stem, as_pdf=True)
    except Exception as exc:
        return mcp_json(
            {"sent": False, "reason": str(exc), "pdf_available": pdf_available()},
            indent=2,
        )
    return mcp_json(result)


@mcp.tool()
@audited
def notify_telegram(message: str) -> str:
    """Send a short text notification to the configured Telegram chat."""
    return mcp_json(_telegram_notifier().send_message(message))


@mcp.tool()
@audited
async def onboard_host_tool(
    ip: str,
    ssh_user: str = "ubuntu",
    ssh_password: str = "",
    agent_name: str = "",
    criticality: str = "medium",
) -> str:
    """Enroll one Linux VM into Wazuh. This is the ONLY supported onboarding path.

    Installs wazuh-agent over SSH, registers via Wazuh REST API, imports key, restarts agent.
    Do not replicate this flow with shell commands — call this tool once per IP and use the JSON result.
    ssh_password: leave empty to use ONBOARD_SSH_PASSWORD from .env.
    """
    result = await onboard_host(
        ip,
        ssh_user,
        ssh_password=ssh_password or None,
        agent_name=agent_name or None,
        criticality=criticality or "medium",
    )
    return mcp_json(result)


@mcp.tool()
@audited
def correlate_alerts(window_hours: int = 24, min_level: int = 3) -> str:
    """Group recent alerts by source IP with attack-phase inference (kill-chain lite)."""
    return mcp_json(correlate_alerts_db(window_hours=window_hours, min_level=min_level))


@mcp.tool()
@audited
def rag_lookup(query: str, limit: int = 5) -> str:
    """Keyword retrieval over local MITRE technique hints and skills markdown."""
    return rag_lookup_json(query, limit=min(limit, 10))


@mcp.tool()
@audited
def list_enrolled_hosts() -> str:
    """List hosts enrolled in LureGuard (from Postgres hosts table)."""
    return mcp_json({"hosts": list_hosts_db()})


@mcp.tool()
@audited
def check_system_update() -> str:
    """Check for upstream LureGuard updates. Never touches .env, secrets/, or reports/."""
    return mcp_json(_check_system_update())


@mcp.tool()
@audited
def apply_system_update() -> str:
    """Apply upstream system-layer update after human confirms. User data is never modified."""
    return mcp_json(_apply_system_update())


@mcp.tool()
@audited
def dismiss_system_update() -> str:
    """Dismiss update prompt until user asks to check again."""
    return mcp_json(_dismiss_system_update())


@mcp.tool()
@audited
def rollback_system_update() -> str:
    """Rollback the last system update from backup branch."""
    return mcp_json(_rollback_system_update())


def main() -> None:
    start_scan_scheduler()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
