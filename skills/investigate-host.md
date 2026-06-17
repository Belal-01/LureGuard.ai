# Mode: investigate-host — Tier-2-lite investigation

## Purpose

Deep-dive a single IP, hostname, or alert subject: timeline, enrichment, host context, kill-chain, graded confidence.

## Workflow

1. `open_investigation(subject="<IP or hostname>", trigger="human", detection_source="human")`
2. `get_event_timeline(ip, window_hours=48)` + `get_alerts_for_ip`
3. `check_ip_reputation` + `check_ip_virustotal` for external IPs
4. `list_agents` → match IP to agent_id → `get_agent_detail(agent_id)` for processes/ports
5. Set `asset_criticality` from host role (K8s CP=critical, web=high, etc.)
6. Build timeline: `add_timeline_event` for each key event (chronological)
7. Pivot if needed:
   - Same `username` → `search_events(username=...)`
   - Same `channel` → `search_events(channel=...)`
   - Related ports/processes from `get_agent_detail`
8. `record_finding` per evidence-backed conclusion with MITRE + IOC fields
9. `get_investigation_artifacts` before close
10. `close_investigation(verdict, confidence, summary, mttd_seconds=, kill_chain_summary=)`
11. If user asked for report → `skills/incident-report.md`

## Kill-chain reconstruction

Map events to phases:
- **Recon** (scan, probe) → T1595
- **Initial access** (exploit, brute force) → T1190 / T1110
- **Execution** (shell, payload) → T1059
- **Persistence** (FIM change) → T1546

State gaps explicitly ("no lateral movement observed in window").

## Output format

Follow Alert Triage Summary in `_shared.md` plus:

- **Timeline narrative** (chronological, cited, with evidence IDs)
- **Host context** (OS, open ports sample, agent status, criticality reasoning)
- **MITRE table** (technique, tactic, evidence ID, confidence)
- **Pivot log** (what you checked and why)

## Edge cases

- IP only in Cowrie channel → honeypot decoy contact; note higher malicious intent
- No agent for IP → investigation is network/log-only; state limitation clearly
- Web server host → also load `skills/investigate-web.md`
