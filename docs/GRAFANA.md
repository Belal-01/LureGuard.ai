# Grafana dashboards

Grafana **11.4** is provisioned from `grafana/provisioning/`. Datasource: Postgres `lureguard-pg` → `postgres:5432` inside Docker (host port **5433**).

Login: http://localhost:3000 — user `admin`, password from `GRAFANA_ADMIN_PASSWORD` (default `admin` in `.env.example`).

All dashboards live in folder **LureGuard**, refresh ~30s.

---

## Dashboards

| UID | Title | Primary Postgres sources |
|-----|-------|--------------------------|
| `lureguard-overview` | LureGuard SOC Overview | `events`, `investigations`, `cve_findings`, `sca_findings`, `user_findings`, `container_*`, `hosts` |
| `lureguard-agent-activity` | LureGuard Agent Activity | `investigations`, `findings`, `agent_actions`, `timeline_events`, `events` |
| `lureguard-fleet-hosts` | LureGuard Fleet and Hosts | `hosts`, `container_runtime` |
| `lureguard-cve-posture` | LureGuard Security Posture | `cve_findings`, `exposure_findings`, `sca_findings`, `user_findings`, `container_cve_findings` |
| `lureguard-containers-assets` | LureGuard Containers and Assets | `container_runtime`, `container_cve_findings`, `hosts` |
| `lureguard-investigation-console` | Investigation Console | `investigations`, `findings`, `timeline_events`, `agent_actions` |
| `lureguard-log-explorer` | Log Explorer | `events` |

JSON definitions: `grafana/provisioning/dashboards/json/*.json`

---

## What Grafana is for vs reports

| Grafana | Reports (`save_report`) |
|---------|-------------------------|
| Live drill-down, full tables, every CVE row | Executive briefing for humans / Telegram |
| Operator exploration | Self-contained metrics + analyst narrative |
| Linked from report footnote | PDF with embedded PNG charts |

Agents should **summarize** Grafana metrics in reports, not paste full inventory dumps (`skills/_shared.md`).

---

## Key panels (by area)

### SOC Overview
- Alert volume and level distribution
- Top source IPs and channels
- Posture summary by host (SCA %, container counts, image CVEs, risky users)
- SLA row: MTTD, MTTR, FPR, pending blocks (from `get_soc_health` metrics / SQL)

### Fleet and Hosts
- Agent counts (active / disconnected)
- Fleet inventory: `criticality`, `eol_os`, container count per host
- Containers & posture snapshot columns

### Containers and Assets
- Running container stats
- Container runtime inventory (JSONB `container_runtime.containers`)
- Image CVE tables from `container_cve_findings` (Trivy via posture scan)

### Security Posture
- Host CVE severity counts, EPSS highlights
- Exposure findings, failed SCA checks, risky users
- Container section (runtime + top image CVEs)

### Agent Activity / Investigation Console
- Open investigations, verdict mix
- Findings and tool-call audit (`agent_actions`)
- Attack timeline with ML scores on SSH-linked events

### Log Explorer
- Filterable `events` table for ad-hoc search

---

## Data prerequisites

Panels show data only when:

| Data | How it appears |
|------|----------------|
| SIEM events | Wazuh integratord → Core → `events` |
| Investigations | Agent `open_investigation` / findings |
| Host CVEs | `trigger_posture_scan` or scheduler (OSV pillar) |
| Container inventory | Wazuh docker-listener on agent → `container_runtime` |
| Container CVEs | Posture scan containers pillar (Trivy over SSH) |
| Host criticality | `onboard_host_tool` or `set_host_criticality` |

Empty container/CVE panels until posture scan succeeds on a Docker host.

---

## Reload after dashboard changes

Provisioning reloads every ~30s. Force refresh:

```bash
docker compose restart grafana
```

UI edits are allowed (`allowUiUpdates: true`) but JSON in git is the source of truth on reprovision.
