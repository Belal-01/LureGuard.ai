# Mode: security-posture — Fleet CVE, exposure, detection, SCA, and users

## Purpose

Answer: *How exposed and monitored is the fleet?* using **five pillars** cached in **Postgres**:

1. **Vulnerabilities** — Wazuh syscollector packages + OSV.dev, **triaged** (patched/noise filtered, service-aware, **EPSS**, **EOL OS** boost)
2. **Exposure** — open/listening ports with bind scope (`all_interfaces` vs `localhost`) and K8s-aware scoring
3. **Detection coverage** — FIM, rootcheck, alerts/rules firing in last 24h (correlated by `agent_id`)
4. **SCA / CIS compliance** — Wazuh Security Configuration Assessment (passed/failed checks, score %)
5. **User inventory** — local accounts from syscollector with risk scoring (uid=0 non-root, interactive shells)

**Do not block on live scans.** Default: read **Postgres cache only** (`get_posture_snapshot`) — fast answers for "what's my posture?"

**Do not** call `trigger_posture_scan` unless the user explicitly asks to rescan/refresh (see `skills/refresh-posture.md`). The 6h background scheduler keeps cache warm without blocking the user.

## Report quality bar (mandatory)

- **Executive summary:** 2–3 sentences — what matters for a developer, not a dashboard dump
- **CVE section:** Max **10 prioritized actionable** CVEs fleet-wide (dedupe by CVE+package). Use `priority_score`, `on_kev`, `epss_score`, `service_running`, `eol_os` from tool JSON. Never list linux-firmware/snapd noise unless KEV or service running
- **Exposure section:** Separate **listening count** from **risky listening** (`risk_level` medium+). Always show `bind_scope` and `local_address`. Do not say "no risky ports" if medium+ ports exist
- **Detection section:** Use `rules_firing_count` and `events_last_at` — **never** report "silent rules" (catalog minus firing is meaningless)
- **SCA section:** Report `score_percent` and top **5 failed** CIS checks per agent (not every check row)
- **User section:** Report risky users (critical/medium+) — uid=0 non-root, interactive shells without login
- **No IOC section** on posture reports — IOCs belong in incident/triage reports only
- **Every finding** must cite tool name + key fields via `record_finding`
- **Do not invent** CVSS, ports, coverage, compliance scores, or patch status

## Prerequisites

- Active agents enrolled (`list_agents`)
- Wazuh SCA module enabled on agents (CIS policies run automatically)
- Background scheduler refreshes cache every 6h when MCP server starts

## Workflow (fast path — default, cache only)

1. `open_investigation(subject="Security posture check", trigger="human")`
2. `list_agents(status=active)` — confirm fleet scope
3. For each active agent (skip `000`):
   - `get_posture_snapshot(agent_id)` — **instant** read of all five Postgres caches
4. If `needs_rescan: true`, `never_scanned`, or stale cache: **report from cache anyway** — note `cache_age_hours` / `overall_status` and tell user they can say **"rescan"** to queue a fresh scan (`refresh-posture.md`). **Do not** call `trigger_posture_scan` unless they ask.
5. `get_fleet_posture_summary()` — fleet-wide cache status
6. For findings worth escalating:
   - Actionable CVEs → `get_agent_vulnerabilities(agent_id)` (actionable-only default)
   - Risky ports → `get_agent_exposure(agent_id, risk_level=high)` or `critical`
   - Coverage gaps → `get_agent_detection_coverage(agent_id)`
   - Failed CIS checks → `get_agent_sca_summary(agent_id)`
   - Risky users → `get_agent_users(agent_id, risk_level=critical)` or `medium`
   - `record_finding` with tool JSON citations
7. `save_report(title="Security Posture [date]", markdown="...", send_telegram=true)` — auto CVE/chart PNGs; Telegram gets PDF
8. `close_investigation(verdict=undetermined, confidence=high, summary="...")`

**PDF:** Telegram delivery is always PDF (`send_report_to_telegram` or `send_telegram=true`). Use `as_pdf=true` / `convert_report_to_pdf` only when the user wants a PDF file saved locally.

## When to scan (explicit user request only)

| Situation | Action |
|-----------|--------|
| User asks posture / CVEs / exposure | **Cache only** — `get_posture_snapshot` |
| User says rescan / refresh / scan now / after patch | `skills/refresh-posture.md` → `trigger_posture_scan` (use `force=true` to rescan fresh cache) |
| Cache empty or stale | Report cache age; **offer** rescan — do not auto-start |
| Background maintenance | 6h scheduler (no user action needed) |

**Never** run `trigger_posture_scan` across the fleet during a routine posture question — it is a heavy indexer (~5 min/host).

## Output format

```markdown
# Security Posture Report

## Executive summary
[2–3 sentences: top risks, monitoring health, cache freshness, EOL OS if any]

## Fleet summary
| Agent | Host | CVE crit/high | Risky ports | SCA % | Risky users | FIM | Alerts 24h | EOL OS | Cache |

## Prioritized vulnerabilities (max 10, actionable only)
| Priority | CVE | EPSS | Package | Agent | Severity | KEV | Service | Fix version |
Cite: get_agent_vulnerabilities / get_posture_snapshot top_actionable_cves

## Exposure (review open services)
| Port | Process | Agent | Risk | Bind scope | Address |

## Detection coverage
| Agent | FIM | Rootcheck | Alerts 24h | Rules firing 24h | Last event |

## SCA / CIS compliance
| Agent | Score % | Failed checks | Top failed check | Remediation hint |
Cite: get_agent_sca_summary / get_fleet_sca_summary

## User / account inventory
| Agent | User | UID | Shell | Risk | Last login |
Cite: get_agent_users (risky users only)

## Recommended actions (human executes)
1. Patch KEV / high-EPSS / service-bound critical/high CVEs first
2. Remediate failed CIS checks on production agents
3. Review uid=0 non-root and stale interactive accounts
4. Restrict or firewall ports with bind_scope=all_interfaces and risk medium+
5. Enable FIM/rootcheck on agents with gaps
6. Plan OS upgrade if `eol_os: true`
7. If user wants updated numbers after changes → offer `refresh-posture.md` (do not auto-scan)
```

## Edge cases

| Situation | Action |
|-----------|--------|
| `needs_rescan: true` | Note in report; offer rescan — do **not** auto-call `trigger_posture_scan` |
| Agent 000 (manager) | Skip |
| No SCA policies | Report "SCA not configured or no policies returned" — cite `get_agent_sca_summary` |
| Empty actionable CVE list | Report "no actionable CVEs after triage" — cite `actionable_counts` vs raw if needed (`include_noise=true`) |
| `events_last_at` null + alerts_24h=0 | Flag possible ingestion gap; cite `get_soc_health` |
| `eol_os: true` | Flag in executive summary; recommend OS upgrade path |

## Container images (Docker apps)

Host-level CVE scan (`get_agent_vulnerabilities`) covers **OS packages on the VM** (dockerd, kernel, nginx on host).

**Not covered by host scan:** npm/Node.js/Python dependencies **inside** Docker image layers.

When user asks about containerized apps (Next.js, Python API, etc.):

1. Identify running image: `get_agent_detail` or ask user for `image_ref`
2. `scan_container_image(agent_id, image_ref)` — Trivy scan via SSH (slow; one image at a time)
3. `get_container_vulnerabilities(agent_id, image_ref)` — read cached results
4. Report top critical/high image CVEs separately from host OS CVEs
5. Call out blast radius if container runs privileged or mounts docker.sock

## MCP tools (posture)

| Tool | Role |
|------|------|
| `get_posture_snapshot` | Primary — instant 5-pillar read |
| `get_fleet_posture_summary` | Fleet cache status |
| `trigger_posture_scan` | **Only** via `refresh-posture.md` when user asks (`force=true` to bypass fresh cache) |
| `get_posture_scan_status` | Job progress (persisted in Postgres) |
| `get_agent_vulnerabilities` / `get_fleet_vulnerability_summary` | CVE detail (actionable default; includes EPSS) |
| `get_agent_exposure` / `get_fleet_exposure_summary` | Port exposure detail |
| `get_agent_detection_coverage` / `get_fleet_detection_coverage` | Detection detail |
| `get_agent_sca_summary` / `get_fleet_sca_summary` | SCA/CIS compliance |
| `get_agent_users` | Local user inventory with risk levels |
| `scan_container_image` / `get_container_vulnerabilities` | Container image CVEs (Trivy) |
| `check_tls` | TLS cert/cipher check for exposed services |
| `get_soc_health` | Ingestion proof for daily/posture context |
