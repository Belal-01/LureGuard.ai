"""Human-readable Telegram alert text."""
from __future__ import annotations

import html
from datetime import datetime

from schemas.decision_result import DecisionResult
from schemas.normalized_event import NormalizedEvent

_EVENT_LABELS = {
    "auth_failed": "SSH login failed (bad password or key)",
    "auth_success": "SSH login succeeded",
    "fim_change": "File integrity change",
    "rootkit_detected": "Rootkit / anomaly check",
    "cowrie_session": "Honeypot (Cowrie) activity",
    "generic": "Security event",
}


def _risk_bar(p: float, width: int = 10) -> str:
    filled = max(0, min(width, round(p * width)))
    return "█" * filled + "░" * (width - filled)


def _risk_label(p: float, t1: float, t2: float, decision: str) -> tuple[str, str]:
    pct = p * 100
    if decision == "redirect":
        return "🔴 CRITICAL", f"Attack confidence {pct:.0f}% — redirecting to honeypot"
    if p > t2:
        return "🔴 CRITICAL", f"Attack confidence {pct:.0f}%"
    if p > t1:
        return "🟠 HIGH", f"Suspicious activity {pct:.0f}%"
    return "🟢 LOW", f"Risk {pct:.0f}%"


def _format_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _truncate(text: str, limit: int = 220) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _host_line(event: NormalizedEvent) -> str:
    name = html.escape(event.agent_name or "unknown host")
    parts = [f"<b>Host</b>  <code>{name}</code>"]
    if event.agent_ip:
        parts.append(f"(agent IP <code>{html.escape(event.agent_ip)}</code>)")
    if event.agent_id:
        parts.append(f"id {html.escape(event.agent_id)}")
    return "  ".join(parts)


def _wazuh_rule_line(event: NormalizedEvent) -> str:
    desc = html.escape(event.wazuh_rule_description or "—")
    return f"<b>Wazuh rule</b>  {event.wazuh_rule_id} — {desc} (level {event.wazuh_rule_level})"


def _lureguard_action(decision: str, profile_id: str | None) -> str:
    if decision == "redirect":
        text = "Redirect to honeypot"
        if profile_id:
            text += f" → <code>{html.escape(profile_id)}</code>"
        return text
    if decision == "alert":
        return "Alert — monitor and investigate"
    return "Allow — logged only"


def format_ssh_alert(
    decision: DecisionResult,
    event: NormalizedEvent,
    *,
    t1: float,
    t2: float,
) -> str:
    p = decision.p
    label, subtitle = _risk_label(p, t1, t2, decision.decision)
    bar = _risk_bar(p)
    what = html.escape(_EVENT_LABELS.get(event.event_type, event.event_type))
    client_ip = html.escape(event.src_ip or "unknown")
    user = html.escape(event.username or "—")
    log_line = html.escape(_truncate(event.raw_ref or ""))

    lines = [
        f"<b>{label}</b>",
        f"<i>{html.escape(subtitle)}</i>",
        "",
        f"<b>Category</b>  SSH",
        f"<b>When</b>  {_format_ts(event.ts)}",
        _host_line(event),
        f"<b>What</b>  {what}",
        f"<b>Client</b>  <code>{client_ip}</code>",
        f"<b>User</b>  <code>{user}</code>",
        _wazuh_rule_line(event),
    ]
    if event.location:
        lines.append(f"<b>Log source</b>  <code>{html.escape(event.location)}</code>")
    if log_line:
        lines.append(f"<b>Log line</b>  <code>{log_line}</code>")
    lines.extend(
        [
            "",
            f"<b>Risk</b>  {int(p * 100)}%  <code>{bar}</code>",
            f"<b>LureGuard</b>  {_lureguard_action(decision.decision, decision.profile_id)}",
        ]
    )
    return "\n".join(lines)


def format_fim_alert(event: NormalizedEvent) -> str:
    what = html.escape(_EVENT_LABELS.get(event.event_type, event.event_type))
    path = html.escape(event.syscheck_path or "—")
    change = html.escape(event.syscheck_event or "—")

    lines = [
        f"<b>🟡 {html.escape(event.channel.upper())}</b>",
        "",
        f"<b>Category</b>  FIM",
        f"<b>When</b>  {_format_ts(event.ts)}",
        _host_line(event),
        f"<b>What</b>  {what}",
        _wazuh_rule_line(event),
    ]
    if event.location:
        lines.append(f"<b>Log source</b>  <code>{html.escape(event.location)}</code>")
    if event.syscheck_path:
        lines.append(f"<b>Path</b>  <code>{path}</code>")
        lines.append(f"<b>Change</b>  {change}")
    if event.raw_ref:
        lines.append(f"<b>Log line</b>  <code>{html.escape(_truncate(event.raw_ref))}</code>")
    return "\n".join(lines)


def format_cowrie_alert(event: NormalizedEvent) -> str:
    what = html.escape(_EVENT_LABELS.get(event.event_type, event.event_type))
    lines = [
        f"<b>🟡 COWRIE</b>",
        "",
        f"<b>Category</b>  COWRIE",
        f"<b>When</b>  {_format_ts(event.ts)}",
        _host_line(event),
        f"<b>What</b>  {what}",
    ]
    if event.src_ip:
        lines.append(f"<b>Client</b>  <code>{html.escape(event.src_ip)}</code>")
    if event.username:
        lines.append(f"<b>User</b>  <code>{html.escape(event.username)}</code>")
    if event.location:
        lines.append(f"<b>Log source</b>  <code>{html.escape(event.location)}</code>")
    if event.raw_ref:
        lines.append(f"<b>Log line</b>  <code>{html.escape(_truncate(event.raw_ref))}</code>")
    return "\n".join(lines)


def format_web_alert(event: NormalizedEvent) -> str:
    what = html.escape(_EVENT_LABELS.get(event.event_type, event.event_type))
    lines = [
        f"<b>🟡 WEB</b>",
        "",
        f"<b>Category</b>  WEB",
        f"<b>When</b>  {_format_ts(event.ts)}",
        _host_line(event),
        f"<b>What</b>  {what}",
    ]
    if event.src_ip:
        lines.append(f"<b>Client</b>  <code>{html.escape(event.src_ip)}</code>")
    if event.location:
        lines.append(f"<b>Log source</b>  <code>{html.escape(event.location)}</code>")
    if event.raw_ref:
        lines.append(f"<b>Log line</b>  <code>{html.escape(_truncate(event.raw_ref))}</code>")
    return "\n".join(lines)


def format_windows_alert(event: NormalizedEvent) -> str:
    what = html.escape(_EVENT_LABELS.get(event.event_type, event.event_type))
    lines = [
        f"<b>🟡 WINDOWS</b>",
        "",
        f"<b>Category</b>  WINDOWS",
        f"<b>When</b>  {_format_ts(event.ts)}",
        _host_line(event),
        f"<b>What</b>  {what}",
        _wazuh_rule_line(event),
    ]
    if event.location:
        lines.append(f"<b>Log source</b>  <code>{html.escape(event.location)}</code>")
    if event.raw_ref:
        lines.append(f"<b>Log line</b>  <code>{html.escape(_truncate(event.raw_ref))}</code>")
    return "\n".join(lines)
