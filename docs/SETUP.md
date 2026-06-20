# Setup Guide

Get Docker running, install the host-side MCP venv, pass `make doctor`, open opencode. That's the whole install path.

## Prerequisites

- **Docker** and Docker Compose
- **Python 3.11+** (for host-side MCP venv)
- **[opencode](https://opencode.ai)** CLI (BYO-LLM — default model in `opencode.json` is `opencode/big-pickle`)
- **Git**

Optional:

- **VirusTotal** and **AbuseIPDB** API keys (enrichment tools warn if unset)
- **Telegram** bot token + chat ID (notifications and report delivery)
- **SSH password** for `onboard_host_tool` and iptables block execution (`ONBOARD_SSH_PASSWORD`)

WeasyPrint (PDF reports) may need OS libraries (Pango/Cairo) on some machines; `xhtml2pdf` is the pip-only fallback.

---

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/Belal-01/LureGuard.ai.git
cd LureGuard.ai

cp .env.example .env
# Edit .env — at minimum for full features:
#   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
#   ONBOARD_SSH_PASSWORD (for VM enrollment)
#   VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY (optional intel)
```

### 2. Start the stack

```bash
docker compose up -d
```

This starts:

| Service | Port | Role |
|---------|------|------|
| `postgres` | 5433 | Events, investigations, posture caches |
| `lureguard-core` | 8080 | Wazuh webhook ingest, ML pipeline |
| `wazuh-manager` | 1514/1515/55000 | SIEM, agent enrollment, Manager API |
| `grafana` | 3000 | Dashboards (Postgres datasource) |
| `cowrie-dev` / `cowrie-db` | 2222/2223 | Lab honeypots (optional attack noise) |

The **MCP server is not in Docker**. It runs on the host via opencode (see below).

### 3. Host Python + MCP

```bash
make venv          # pip install -e ".[dev,train,mcp]"
make migrate       # apply Alembic migrations
make doctor        # verify stack + opencode + MCP
```

Expected when healthy:

```
All required checks passed. Run: opencode
```

### 4. Run the analyst

```bash
opencode
```

First prompts:

```
Read skills/triage.md and triage alerts from the last 2 hours
```

```
Read skills/onboard-host.md and protect 192.168.1.100
```

Headless:

```bash
opencode run "Read AGENTS.md and skills/triage.md — triage last hour"
```

---

## opencode configuration

`opencode.json` wires:

- **Instructions:** `AGENTS.md`, `skills/_shared.md`, `skills/opencode-mcp.md`
- **MCP server:** `.venv/bin/python -m lureguard_mcp` (stdio)
- **Postgres from MCP:** `localhost:5433` (published Docker port)
- **Permissions:** bash/edit/write/webfetch **denied** — agent uses **MCP tools only**

Restart opencode after changing `.env` or MCP code.

---

## Slash commands (`.opencode/command/`)

| Command | Loads |
|---------|--------|
| `/triage` | `skills/triage.md` |
| `/investigate` | `skills/investigate-host.md` |
| `/onboard` | `skills/onboard-host.md` |
| `/posture` | `skills/security-posture.md` |
| `/report` | `skills/incident-report.md` |
| `/auto-triage` | auto-triage prompt |
| `/update` | system update flow |

---

## After pull or system update

```bash
make update-check    # or ask opencode to check_system_update
make update          # after you confirm (system files only)
make venv
make migrate
docker compose up -d
# restart opencode
```

User data (`.env`, `secrets/`, `reports/`) is never modified by the updater. See [`DATA_CONTRACT.md`](../DATA_CONTRACT.md).

---

## Verify setup

| Check | Command |
|-------|---------|
| Full health | `make doctor` |
| Unit tests | `make test` |
| SOC metrics | `.venv/bin/python -c "from lureguard_mcp.db import get_soc_health_db; print(get_soc_health_db())"` |
| Grafana | http://localhost:3000 (admin / `GRAFANA_ADMIN_PASSWORD`) |

---

## Common fixes

| Symptom | Fix |
|---------|-----|
| Wazuh API fails in doctor | `docker compose restart wazuh-manager` — check `wazuh/local_rules.xml` is valid XML |
| MCP onboard SSH password error | Set `ONBOARD_SSH_PASSWORD` in `.env`, **restart opencode** |
| `asyncio.run()` onboard error | Quit opencode and restart (stale MCP process) |
| Empty posture / containers | Run `trigger_posture_scan` via MCP; containers need Docker on target + Trivy reachable via SSH |
| PDF fails | `make venv`; WeasyPrint needs OS libs or falls back to xhtml2pdf |
