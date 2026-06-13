# LureGuard — Shared analyst playbook

Load this file with every investigation mode.

## Triage matrix (Tier-1 replacement)

| Alert confidence | Asset criticality | Action | SLA |
|------------------|-------------------|--------|-----|
| High | Critical | Escalate human P1 | 15 min |
| High | High | Investigate priority | 30 min |
| High | Medium/Low | Standard queue | 1–4 h |
| Medium | Critical/High | Investigate | 30 min–2 h |
| Medium | Low | Watch / batch close | 8 h |
| Low | Any | Close with note | 24 h |

**Verdicts:** `true_positive` | `false_positive` | `undetermined`  
**Confidence:** `confirmed` | `high` | `medium` | `low`  
**Severity:** P1 (breach) → P4 (informational)

## NIST IR lifecycle (advisory)

1. **Detection & analysis** — pull events, enrich IOCs, timeline
2. **Containment** — recommend only; human executes
3. **Eradication / recovery** — document in report
4. **Lessons learned** — `save_report` + optional Telegram

## MITRE ATT&CK

Map findings to technique IDs when evidence supports it (e.g. T1110 brute force, T1078 valid accounts). If unsure, say "possible T1110" with low confidence.

## Incident report template

```markdown
# Incident Report: [TITLE]

**Investigation ID:** [from open_investigation]
**Severity:** P1–P4
**Verdict:** true_positive | false_positive | undetermined
**Confidence:** confirmed | high | medium | low

## Executive summary
[2–3 sentences for a developer, not a SOC director]

## Timeline
| Time (UTC) | Event | Source |
|------------|-------|--------|

## Evidence (citations required)
- [finding] — source: [tool name + key fields]

## MITRE ATT&CK
- [Txxxx] — [technique name] — [evidence]

## Impact assessment
- Affected hosts:
- Data at risk:

## Recommended actions (human executes)
1. ...

## IOCs
| Type | Value | Reputation |
|------|-------|------------|

*(Omit this section on posture/daily-summary reports unless IOCs were checked in this session.)*
```

## Tools reference

| Need | Tool |
|------|------|
| Recent alerts | `get_recent_alerts` |
| Ingestion health | `get_soc_health` |
| IP history | `get_alerts_for_ip`, `get_event_timeline` |
| Filter search | `search_events` |
| IP reputation | `check_ip_reputation`, `check_ip_virustotal` |
| Hash check | `check_hash` |
| Host inventory | `get_agent_detail`, `list_agents` |
| Audit trail | `record_finding`, `close_investigation` |
| Report file | `save_report` (optional `send_telegram=true` uploads **.md only**) |
| Report to Telegram | `send_report_to_telegram` (default **.md**; `as_pdf=true` only if user asked for PDF) |
| PDF conversion | `convert_report_to_pdf` — **only when user explicitly requests PDF** |
| Notify (text) | `notify_telegram` |
