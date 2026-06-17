# Mode: daily-summary — Shift handover / daily SOC summary

## Purpose

Produce an analyst-grade shift summary: **what changed, what matters, what to do next** — self-contained for management/Telegram, not a raw Grafana export.

## Report quality bar (mandatory)

Reports go to **Telegram and humans who won't open Grafana**. Include a **Key metrics snapshot** with real numbers from tools (alert volume, fleet health, CVE headline). Then add the narrative layer:

1. **What changed since yesterday** — new alerts, disconnected hosts, posture drift (with counts)
2. **Correlation** — group related events into stories (same IP, same host, same attack type)
3. **Open investigations** — status, next action, owner, SLA
4. **Detection gaps** — events without alerts, missing agent_id, stale scans
5. **Escalation watchlist** — items needing human follow-up tomorrow

**Avoid full dashboard dumps:** don't list every agent row or every CVE — summarize (top risks, fleet counts, top 3–5 CVEs). Every claim cites a tool. Use `get_soc_health`, `get_recent_alerts`, `list_agents`, `get_fleet_posture_summary`, `get_fleet_vulnerability_summary`.

## Workflow

1. `open_investigation(subject="Daily summary [date]", trigger="human", detection_source="scheduled")`
2. `get_soc_health()` — ingestion proof
3. `get_recent_alerts(limit=200, min_level=3)` — last 24h
4. `list_agents` + `list_enrolled_hosts` — fleet deltas (new disconnects, never_connected)
5. `get_fleet_posture_summary()` + `get_fleet_vulnerability_summary()` — CVE/posture headline for metrics snapshot
6. Correlate notable clusters; `record_finding` for each story worth follow-up
7. `add_timeline_event` for the day's key moments (first alert, disconnect, etc.)
8. Draft using output format below; self-score: metrics snapshot + narrative, no full inventory dumps
9. `save_report(title="Daily SOC Summary [date]", markdown="...")` — auto chart PNGs; Telegram via `send_report_to_telegram` is always PDF
10. `close_investigation(verdict="undetermined", confidence="high", summary="...")`

## Output format

```markdown
# LureGuard Daily Summary — [DATE UTC]

**Investigation ID:** [id]  
**Detection source:** scheduled  
**PICERL phase:** Identification

## Executive summary
[3–4 sentences: what changed, what matters, top risk]

## Key metrics snapshot
| Metric | Value | Source |
|--------|-------|--------|
| Alerts (24h) | [N] | get_recent_alerts |
| Fleet | [N] active / [N] disconnected | list_agents |
| CVEs (critical/high) | [N] / [N] | get_fleet_vulnerability_summary |
| Open investigations | [N] | investigations |

Top actionable CVEs (max 5): [CVE-id host package] — cite get_agent_vulnerabilities or fleet summary

## Dashboards (optional drill-down)
- SOC Overview, Fleet, Posture, Agent Activity → http://localhost:3000

## What changed (vs prior shift)
- [delta] — source: [tool]

## Correlated stories (investigate further)
### Story 1: [title]
- **Events:** [correlated IPs/hosts]
- **Assessment:** [TP/FP/undetermined + why]
- **MITRE:** [if applicable]
- **Next action:** [human] — SLA: [time]
- **Evidence:** E01 — [citation]

## Open investigations
| ID | Subject | Status | Next action | Owner | SLA |

## Detection gaps
- [e.g. events without agent_id, 0 alerts despite volume]

## Escalation watchlist
- [items for next shift]

## Recommended actions for next shift
| Priority | Action | Owner | SLA |
```

## Anti-patterns (reject these)

- **Metrics-free report** that says "see Grafana" for alert counts, CVEs, or fleet health — Telegram readers need numbers in the body
- Full fleet inventory table with every agent row (summarize counts + exceptions instead)
- Full CVE dump (hundreds of rows) — use top prioritized actionable CVEs
- Findings without `record_finding` citations
