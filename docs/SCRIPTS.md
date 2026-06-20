# Scripts and Make targets

Host-side utilities live in the repo root. Docker services are managed via `docker compose`.

## Quick reference

| Command | Purpose |
|---------|---------|
| `make up` | `docker compose up -d` |
| `make down` | `docker compose down` |
| `make build` | `docker compose build` |
| `make venv` | Create `.venv` + `pip install -e ".[dev,train,mcp]"` |
| `make migrate` | Alembic upgrade head |
| `make doctor` | Stack + opencode + MCP health (`lureguard_mcp.doctor`) |
| `make test` | pytest unit tests (excludes integration) |
| `make test-integration` | pytest integration marker |
| `make lint` | ruff + mypy (optional) |
| `make format` | ruff format |
| `make train` | Retrain SSH classifier → `ml/models/` |
| `make train-quick` | Train on capped sample |
| `make fetch-dataset` | Download ML training dataset |
| `make db-revision m="msg"` | New Alembic revision |
| `make update-check` | `python update-system.py check` (JSON) |
| `make update` | `python update-system.py apply` |
| `make rollback-update` | `python update-system.py rollback` |

---

## doctor

```bash
make doctor
```

**Required checks:** Docker, core containers, Postgres `:5433`, schema, Core `:8080`, Wazuh API auth, integratord hook, `.env`, MCP import, opencode CLI, `opencode.json`, MCP lureguard block, LLM readiness.

**Optional checks:** Grafana `:3000`, threat intel keys, matplotlib/weasyprint for reports.

Implementation: `lureguard_mcp/doctor.py`

---

## update-system.py

Safe updater — **system layer files only**. Never touches `.env`, `secrets/`, or `reports/`.

```bash
python update-system.py check      # JSON status
python update-system.py apply        # after human confirms
python update-system.py rollback     # restore backup branch
python update-system.py dismiss      # suppress prompt until re-check
```

**MCP equivalents** (use in opencode — bash is disabled):

- `check_system_update`
- `apply_system_update`
- `dismiss_system_update`
- `rollback_system_update`

**Apply flow:**

1. Create git branch `backup-pre-update-{VERSION}`
2. `git fetch` canonical repo (`Belal-01/LureGuard.ai`)
3. Checkout only paths listed in `DATA_CONTRACT.md` / `update-system.py` `SYSTEM_PATHS`
4. Abort if any user-layer file changed
5. Run `make venv`
6. Commit updated system files

After apply: `make migrate && docker compose up -d` and restart opencode.

---

## Headless opencode

```bash
opencode run "Read skills/triage.md and triage alerts from the last 2 hours"
```

Used by `alert_watcher` for auto-triage (requires `opencode` in PATH).

---

## Direct Python smoke tests

```bash
# SOC health / SLA
.venv/bin/python -c "from lureguard_mcp.db import get_soc_health_db; import json; print(json.dumps(get_soc_health_db(), indent=2))"

# Posture snapshot (replace agent id)
.venv/bin/python -c "from lureguard_mcp.posture_snapshot import get_posture_snapshot; import json; print(json.dumps(get_posture_snapshot('007'), indent=2)[:2000])"

# IP enrichment (needs API keys for external IPs)
.venv/bin/python -c "from lureguard_mcp.enrichment import get_ip_context; print(get_ip_context('8.8.8.8'))"
```

---

## Docker-only operations

```bash
docker compose logs wazuh-manager --tail 50
docker compose restart wazuh-manager
docker compose exec postgres psql -U lureguard -d lureguard -c '\dt'
```

MCP onboarding and blocklist iptables use **SSH from the host** (not `docker exec` for enrollment).
