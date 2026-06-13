# Mode: investigate-host — Tier-2-lite investigation

## Purpose

Deep-dive a single IP, hostname, or alert subject: timeline, enrichment, host context, graded confidence.

## Workflow

1. `open_investigation(subject="<IP or hostname>", trigger="human")`
2. `get_event_timeline(ip, window_hours=48)` + `get_alerts_for_ip`
3. `check_ip_reputation` + `check_ip_virustotal` for external IPs
4. `list_agents` → match IP to agent_id → `get_agent_detail(agent_id)` for processes/ports
5. `search_events` for same username or channel if pivot needed
6. `record_finding` for each evidence-backed conclusion
7. `close_investigation` with verdict + confidence + recommended human actions
8. If user asked for report → switch to `skills/incident-report.md`

## Output format

Follow Alert Triage Summary in `_shared.md` plus:

- **Timeline narrative** (chronological, cited)
- **Host context** (OS, open ports sample, agent status)
- **ATT&CK mapping** if applicable

## Edge cases

- IP only in Cowrie channel → note honeypot decoy contact; higher confidence for malicious intent
- No agent for IP → investigation is network/log-only; state limitation clearly
