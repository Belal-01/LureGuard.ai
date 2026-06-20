# Architecture

How the pieces connect. MCP runs on your machine, not inside compose. ML runs inside Core, and only for SSH auth events.

## System overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Developer (opencode) + skills/*.md + AGENTS.md                 │
└────────────────────────────┬────────────────────────────────────┘
                             │ stdio MCP
┌────────────────────────────▼────────────────────────────────────┐
│  lureguard_mcp (host .venv)                                       │
│  • MCP tools (alerts, posture, reports, onboard, blocklist)     │
│  • scan_scheduler (6h posture jobs)                               │
│  • alert_watcher (level ≥ AUTO_TRIAGE_LEVEL, default 12)        │
└─────┬──────────────────┬──────────────────┬─────────────────────┘
      │                  │                  │
      ▼                  ▼                  ▼
 Postgres          Wazuh Manager API    SSH → enrolled VMs
 :5433             :55000               (onboard, Trivy, iptables)
      ▲                  ▲
      │                  │
┌─────┴──────────────────┴────────────────────────────────────────┐
│  Docker stack                                                      │
│  wazuh-manager ──integratord──► lureguard-core POST /wazuh/event  │
│  lureguard-core ──ML (SSH auth only)──► decisions                 │
│  grafana ──queries──► postgres                                     │
│  cowrie-dev/db ──logs──► wazuh-manager (honeypot rules)           │
└───────────────────────────────────────────────────────────────────┘
```

---

## Alert ingestion flow

1. Wazuh agent on enrolled host collects logs (SSH, FIM, Docker, web, etc.).
2. Wazuh manager matches rules; **integratord** forwards matching alerts (level ≥ 3, configured groups) to `http://lureguard-core:8080/wazuh/event`.
3. **Core** `collector.normalize_event()` → `decision_policy.process_event()`:
   - All events → Postgres `events`
   - **ML inference only** when `channel == "sshd"` and `event_type` in (`auth_failed`, `auth_success`)
   - ML decisions → Postgres `decisions` (linked via `event_id`)
   - Whitelist hits → allow without ML score
   - High ML score → optional Cowrie DNAT redirect (honeypot)
4. MCP reads `events` (+ joined `decisions` for ML score on SSH rows).

**Not in the hot path:** MCP does not run ML; it queries stored events and Wazuh API.

---

## Wazuh manager configuration (LureGuard-specific)

From `wazuh/ossec.conf`:

- **Integratord** → LureGuard Core (`custom-lureguard` integration)
- **Vulnerability-detection:** disabled (LureGuard uses OSV + Trivy instead)
- **Indexer:** disabled (Postgres + Grafana, not Wazuh Indexer)
- **Cowrie** JSON logs mounted from compose volumes
- **Custom rules** in `wazuh/local_rules.xml` (Cowrie 100001–100003, web heuristics 100010–100012)

Agent template: `wazuh/agent-ossec.conf` (docker-listener, log paths — deployed via `onboard_host_tool`).

---

## MCP server (host-side)

- Started by opencode: `.venv/bin/python -m lureguard_mcp`
- Loads repo `.env` on startup (`lureguard_mcp/config.py`)
- Connects to Postgres at `POSTGRES_HOST` / `POSTGRES_PORT` (default `localhost:5433`)
- Wazuh API at `WAZUH_API_URL` (default `https://localhost:55000`)
- Every tool call logged to `agent_actions` when `@audited`
- Investigation context via `open_investigation` / `close_investigation`

Background threads (same process):

| Component | Interval / trigger | Purpose |
|-----------|-------------------|---------|
| `scan_scheduler` | Every 6 hours | Posture scan all active agents |
| `alert_watcher` | Poll 30s | Events ≥ `AUTO_TRIAGE_LEVEL` → Telegram + `opencode run` triage |

---

## Posture pipeline (six pillars)

`trigger_posture_scan` / scheduler runs per agent:

| Pillar | Scanner | Data source |
|--------|---------|-------------|
| **vulnerabilities** | `vuln_scanner.py` | Wazuh syscollector packages → OSV.dev |
| **exposure** | `exposure_scanner.py` | syscollector ports + syscheck/rootcheck presence |
| **detection_coverage** | `detection_scanner.py` | FIM/rootcheck status, recent alert volume |
| **sca_compliance** | `sca_scanner.py` | Wazuh SCA API (CIS checks) |
| **user_inventory** | `user_scanner.py` | syscollector users + risk heuristics |
| **containers** | `container_posture.py` | Wazuh docker-listener inventory + **Trivy via SSH** on running images |

Cached in Postgres (`cve_findings`, `exposure_findings`, `detection_coverage`, `sca_findings`, `user_findings`, `container_runtime`, `container_cve_findings`).

Instant read: `get_posture_snapshot(agent_id)` — cache stale after 24h (`needs_rescan`).

**Not scanned automatically:** npm deps inside app images without Trivy scan; privileged container flags; dedicated container-escape scoring (document gaps in reports per `skills/_shared.md`).

---

## Investigation lifecycle

```
open_investigation
    → get_recent_alerts / get_event_timeline / get_attack_summary / get_ip_context
    → record_finding (each conclusion cites tool output)
    → add_timeline_event (optional narrative beats)
    → recommend_block_ip (optional — does NOT block)
    → save_report (+ optional Telegram PDF)
close_investigation (verdict + confidence)
```

Artifacts in Postgres: `investigations`, `findings`, `timeline_events`, `iocs`, `agent_actions`, `reports`.

---

## Containment (human-gated)

| Step | Tool | Effect |
|------|------|--------|
| Recommend | `recommend_block_ip` | Row in `blocklist`, `executed=false` |
| Confirm | `confirm_block_ip` | iptables DROP on evidence-scoped hosts (48h events); optional `agent_id` or `fleet_wide=true` + notes |
| List | `list_blocklist` | Pending and executed blocks |

Whitelist mirrors the same pattern: `recommend_whitelist_ip` → `confirm_whitelist_ip` → Core ML cache loads **executed** whitelist rows only. `remove_whitelist_ip` is human-gated like confirm.

Gates: `LUREGUARD_ALLOW_AGENT_BLOCK` / `LUREGUARD_ALLOW_AGENT_WHITELIST` / `LUREGUARD_ALLOW_AGENT_SYSTEM_UPDATE` (default `false` — for automation tests only; MCP chat approval uses default human caller).

SSH: set `LUREGUARD_SSH_STRICT_HOST_KEYS=true` for `StrictHostKeyChecking=accept-new` (lab default remains `no`).

---

## Reports and PDF

1. Agent writes markdown via `save_report`.
2. `enrich_report_markdown` may add `## Visual summary` PNG charts (matplotlib presets from DB).
3. Telegram delivery converts `.md` → PDF via WeasyPrint (or xhtml2pdf fallback).
4. Files under `reports/` (user layer — not touched by updater).

---

## ML classifier scope (honesty)

| In scope | Out of scope |
|----------|--------------|
| SSH `auth_failed` / `auth_success` via Core pipeline | Web, Docker, Cowrie, syscheck, etc. |
| Stored in `decisions` + shown on timeline for SSH rows | Live ML inside MCP tools |
| Pre-trained model in `ml/models/` (ships in repo) | Retrain only via `make train` |

Triage and investigation for **all channels** use LLM + MCP tools, not the sklearn classifier.

---

## Auto-update (system layer)

Same pattern as [career-ops](https://github.com/santifer/career-ops):

- Session start → `check_system_update` (MCP)
- User confirms → `apply_system_update` → git checkout system paths from upstream only
- Rollback → `rollback_system_update` from `backup-pre-update-*` branch

See [`SCRIPTS.md`](SCRIPTS.md) and [`DATA_CONTRACT.md`](../DATA_CONTRACT.md).
