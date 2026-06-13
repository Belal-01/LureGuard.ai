# Mode: security-posture — Fleet CVE, exposure, and detection coverage

## Purpose

Answer: *How exposed and monitored is the fleet?* using three pillars cached in **Postgres**:

1. **Vulnerabilities** — Wazuh syscollector packages + OSV.dev, **triaged** (patched/noise filtered, service-aware)
2. **Exposure** — open/listening ports with bind scope (`all_interfaces` vs `localhost`) and K8s-aware scoring
3. **Detection coverage** — FIM, rootcheck, alerts/rules firing in last 24h (correlated by `agent_id`)

**Do not block on live scans.** Read caches first; background scans refresh data.

## Report quality bar (mandatory)

- **Executive summary:** 2–3 sentences — what matters for a developer, not a dashboard dump
- **CVE section:** Max **10 prioritized actionable** CVEs fleet-wide (dedupe by CVE+package). Use `priority_score`, `on_kev`, `service_running` from tool JSON. Never list linux-firmware/snapd noise unless KEV or service running
- **Exposure section:** Separate **listening count** from **risky listening** (`risk_level` medium+). Always show `bind_scope` and `local_address`. Do not say "no risky ports" if medium+ ports exist
- **Detection section:** Use `rules_firing_count` and `events_last_at` — **never** report "silent rules" (catalog minus firing is meaningless)
- **No IOC section** on posture reports — IOCs belong in incident/triage reports only
- **Every finding** must cite tool name + key fields via `record_finding`
- **Do not invent** CVSS, ports, coverage, or patch status

## Prerequisites

- Active agents enrolled (`list_agents`)
- Background scheduler runs every 6h when MCP server starts (or call `trigger_posture_scan`)

## Workflow (fast path — default)

1. `open_investigation(subject="Security posture check", trigger="human")`
2. `list_agents(status=active)` — confirm fleet scope
3. For each active agent (skip `000`):
   - `get_posture_snapshot(agent_id)` — **instant** read of all three Postgres caches
4. If `needs_rescan: true` or `overall_status` is `never_scanned` / `stale`:
   - `trigger_posture_scan(agent_id)` — returns immediately with `job_id`
   - Tell user: scan running in background (~5 min per host); report uses cached data now
   - Optionally `get_posture_scan_status(job_id)` to check progress
5. `get_fleet_posture_summary()` — fleet-wide cache status
6. For findings worth escalating:
   - Actionable CVEs → `get_agent_vulnerabilities(agent_id)` (actionable-only default)
   - Risky ports → `get_agent_exposure(agent_id, risk_level=high)` or `critical`
   - Coverage gaps → `get_agent_detection_coverage(agent_id)`
   - `record_finding` with tool JSON citations
7. `save_report(title="Security Posture [date]", markdown="...", send_telegram=true)` — saves and uploads **.md** (default)
8. `close_investigation(verdict=undetermined, confidence=high, summary="...")`

**PDF:** Never convert or send PDF unless the user explicitly asks.

## When to scan (background only)

| Situation | Action |
|-----------|--------|
| First run / empty cache | `trigger_posture_scan()` for fleet |
| Cache older than 24h (`cache_age_hours > 24`) | `trigger_posture_scan(agent_id)` |
| User asks for fresh data | `trigger_posture_scan(agent_id, force=true)` |
| After patching hosts | `trigger_posture_scan(agent_id)` then re-check snapshot later |

**Never** call `scan_agent_vulnerabilities` synchronously in the posture workflow unless user explicitly requests a blocking scan.

## Output format

```markdown
# Security Posture Report

## Executive summary
[2–3 sentences: top risks, monitoring health, cache freshness]

## Fleet summary
| Agent | Host | Actionable CVE crit/high | Risky ports (med+) | FIM | Rootcheck | Alerts 24h | Last event | Cache |

## Prioritized vulnerabilities (max 10, actionable only)
| Priority | CVE | Package | Agent | Severity | KEV | Service running | Fix version |
Cite: get_agent_vulnerabilities / get_posture_snapshot top_actionable_cves

## Exposure (review open services)
| Port | Process | Agent | Risk | Bind scope | Address |
Note: total listening vs risky_listening from snapshot

## Detection coverage
| Agent | FIM | Rootcheck | Alerts 24h | Rules firing 24h | Last event | Channels active |

## Recommended actions (human executes)
1. Patch KEV / service-bound critical/high CVEs first
2. Restrict or firewall ports with bind_scope=all_interfaces and risk medium+
3. Enable FIM/rootcheck on agents with gaps
4. Re-run `trigger_posture_scan` after changes
```

## Edge cases

| Situation | Action |
|-----------|--------|
| `needs_rescan: true` | Call `trigger_posture_scan`; do not wait — report cached data + note scan in progress |
| Agent 000 (manager) | Skip |
| Empty actionable CVE list | Report "no actionable CVEs after triage" — cite `actionable_counts` vs raw if needed (`include_noise=true`) |
| `events_last_at` null + alerts_24h=0 | Flag possible ingestion gap; cite `get_soc_health` |

## MCP tools (posture)

| Tool | Role |
|------|------|
| `get_posture_snapshot` | Primary — instant 3-pillar read |
| `get_fleet_posture_summary` | Fleet cache status |
| `trigger_posture_scan` | Background refresh (non-blocking) |
| `get_posture_scan_status` | Job progress |
| `get_agent_vulnerabilities` / `get_fleet_vulnerability_summary` | CVE detail (actionable default) |
| `get_agent_exposure` / `get_fleet_exposure_summary` | Port exposure detail |
| `get_agent_detection_coverage` / `get_fleet_detection_coverage` | Detection detail |
| `get_soc_health` | Ingestion proof for daily/posture context |
