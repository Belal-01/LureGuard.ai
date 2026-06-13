# Mode: daily-summary — Shift handover / daily SOC summary

## Purpose

Produce a shift-handover style summary for a developer: what happened, what is open, fleet health, ingestion proof.

## Report quality bar (mandatory)

- Lead with **volume + ingestion health** (`get_soc_health`) — last event time, events in 24h, agents reporting
- **Notable items:** only alerts/events worth human follow-up; cite tool output
- **Fleet health:** enrolled agents, Wazuh status, last event per host
- No empty IOC table — omit IOC section unless you checked hashes/IPs this session
- Every claim cites a tool (`get_recent_alerts`, `get_soc_health`, `list_agents`, etc.)

## Workflow

1. `open_investigation(subject="Daily summary", trigger="human")`
2. `get_soc_health()` — ingestion proof and per-agent event counts
3. `get_recent_alerts(limit=200, min_level=3)` — last 24h context
4. `list_agents` + `list_enrolled_hosts` — fleet health
5. Optionally `get_fleet_posture_summary()` — one-line posture headline (actionable CVEs, risky ports)
6. Summarize: total alerts, top categories, open items, stale/missing telemetry
7. `save_report(title="Daily SOC Summary [date]", markdown="...")`
8. `close_investigation(verdict="undetermined", confidence="high", summary="...")`
9. Optional: `notify_telegram` with 5-line summary

## Output format

```markdown
# LureGuard Daily Summary

## Executive summary
[2–3 sentences]

## Ingestion health
| Metric | Value |
| Last event (fleet) | from get_soc_health |
| Events 24h | |
| Agents reporting | |

## Volume
| Metric | Count |
| Alerts (level ≥3) | from get_recent_alerts |

## Notable items (investigate further)
- [item] — source: [tool + fields]

## Fleet health
| Host | Agent ID | Status | Events 24h | Last event |

## Recommended actions for tomorrow
1. ...
```
