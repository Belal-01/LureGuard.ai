# LureGuard — Data contract (system vs user layer)

Defines which files **auto-update** from upstream and which are **never touched** by `update-system.py`.

## User layer (NEVER auto-updated)

| Path | Purpose |
|------|---------|
| `.env` | Secrets, Telegram, API keys, SSH password |
| `secrets/` | Docker secret files |
| `reports/` | Generated incident reports and chart PNGs |
| `reports/assets/` | Report chart assets |

**If a path is in the user layer, no update process may read, modify, or delete it.**

## System layer (safe to auto-update)

| Path | Purpose |
|------|---------|
| `AGENTS.md`, `skills/` | Agent constitution and playbooks |
| `lureguard_mcp/`, `core/`, `connectors/` | MCP server and ingest pipeline |
| `wazuh/`, `grafana/provisioning/` | SIEM config and dashboards |
| `migrations/` | Postgres schema |
| `opencode.json`, `.opencode/` | opencode wiring |
| `docker-compose.yml`, `Makefile`, `pyproject.toml` | Stack and tooling |
| `config/core.yaml`, `.env.example` | Default config templates |
| `tests/`, `ml/` | Tests and shipped classifier models |
| `README.md`, `PRODUCT-STATUS.md`, `VERSION` | Docs and version pin |
| `docs/` | Setup, architecture, MCP reference |
| `update-system.py`, `DATA_CONTRACT.md` | Updater itself |

After `make update`, run `make venv && make migrate` if prompted.
