"""Multi-event alert correlation by source IP and time window."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from lureguard_mcp.db import search_events
from lureguard_mcp.presentation import infer_attack_phases


def correlate_alerts(
    *,
    window_hours: int = 24,
    min_level: int = 3,
    limit_per_ip: int = 200,
) -> dict[str, Any]:
    since = datetime.utcnow() - timedelta(hours=window_hours)
    events = search_events(min_level=min_level, limit=1000)
    filtered = [e for e in events if e.get("ts") and str(e["ts"]) >= since.isoformat()]

    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in filtered:
        ip = event.get("src_ip")
        if ip:
            by_ip[str(ip)].append(event)

    clusters: list[dict[str, Any]] = []
    for ip, ip_events in sorted(by_ip.items(), key=lambda x: -len(x[1])):
        ip_events = ip_events[:limit_per_ip]
        channels = sorted({e.get("channel") for e in ip_events if e.get("channel")})
        max_level = max((e.get("wazuh_rule_level") or 0 for e in ip_events), default=0)
        clusters.append(
            {
                "src_ip": ip,
                "event_count": len(ip_events),
                "channels": channels,
                "peak_level": max_level,
                "attack_phases": infer_attack_phases(ip_events),
                "first_seen": ip_events[-1].get("ts") if ip_events else None,
                "last_seen": ip_events[0].get("ts") if ip_events else None,
                "sample_rules": list(
                    {
                        e.get("wazuh_rule_description") or f"rule_{e.get('wazuh_rule_id')}"
                        for e in ip_events[:5]
                    }
                ),
            }
        )

    clusters.sort(key=lambda c: (-c["event_count"], -c["peak_level"]))
    return {
        "window_hours": window_hours,
        "min_level": min_level,
        "cluster_count": len(clusters),
        "clusters": clusters[:50],
    }
