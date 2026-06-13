# Mode: onboard-host — Protect a new Linux VM

## Purpose

Enroll a remote Ubuntu/Debian VM into LureGuard/Wazuh. **All work happens inside the `onboard_host_tool` MCP tool** — you orchestrate; you do not implement enrollment yourself.

## Critical rules (opencode — read first)

**NEVER**
- Run `python`, `python3`, or `.venv/bin/python` to call onboarding code directly
- Run `docker exec`, `manage_agents`, `curl` to Wazuh API, or `ssh` to the target VM yourself
- Edit `lureguard_mcp/onboarding.py`, `server.py`, or any repo code to "fix" enrollment
- Retry enrollment with a different method if the tool fails — report the error and stop
- Onboard multiple hosts in parallel — one IP per tool call, sequentially
- Onboard a host without explicit user confirmation when it is a production or Kubernetes node
- Offer "run script directly" or "fix code myself" as alternatives when the MCP tool fails
- Present multi-option menus that include bypassing MCP (there is no option 2)

**ALWAYS**
- Call **`onboard_host_tool`** exactly once per target IP
- Pass `ssh_password` from user chat or rely on `ONBOARD_SSH_PASSWORD` in `.env` (never echo password in findings)
- After the tool returns, verify with **`list_enrolled_hosts`** and **`list_agents`**
- If `success: false` in tool JSON, quote the `error` field verbatim — do not guess root cause
- If you see `asyncio.run() cannot be called from a running event loop`, ask the user to **restart opencode** (see below) — do not edit code

## Prerequisites

- VM reachable via SSH (password in `.env` as `ONBOARD_SSH_PASSWORD` or user provides it)
- Docker stack running (`wazuh-manager` container up, Wazuh API on localhost:55000)
- User provides: VM IP, optional SSH user (default `ubuntu`)

## Workflow

1. `open_investigation(subject="Onboard host <IP>", trigger="human")`
2. **Confirm with user:** IP, SSH user, that they want this specific host enrolled (especially K8s/production nodes)
3. `onboard_host_tool(ip, ssh_user, ssh_password, agent_name)` — **single MCP call; wait for JSON result**
4. `list_enrolled_hosts` — verify new host appears
5. `list_agents` — confirm Wazuh status Active (retry this tool only after 60s if disconnected)
6. `get_agent_detail(agent_id)` — capture OS info for report
7. `record_finding` + `close_investigation` with success/failure
8. Tell user to open Grafana **Fleet & Hosts** dashboard

## What the tool does (for your mental model — do not replicate)

1. Registers agent on Wazuh manager via **Wazuh REST API** (not `manage_agents` CLI)
2. SSH to VM → install `wazuh-agent` if missing → deploy config → import key → restart service
3. Upserts row in Postgres `hosts` table

You do not need to understand Wazuh internals. Call the tool.

## Output format

```markdown
## Host onboarded

- **IP:** 
- **Agent ID:** 
- **Wazuh status:** Active | disconnected
- **Next step:** Generate test traffic or run a scan; ask me to triage alerts
```

## Edge cases

| Situation | Action |
|-----------|--------|
| SSH fails | Report `error` from tool JSON; do not retry blindly |
| Agent registered but not Active | Wait 60s, call `list_agents` again; suggest manager IP / firewall port 1514 |
| Agent already exists on manager | Tool reuses registration (`reused_registration: true`) — still verify Active |
| User lists several IPs | Confirm each IP, then call `onboard_host_tool` once per IP in sequence |
| Tool error mentions API/auth | Tell user to run `make doctor` — do **not** start authd or edit Wazuh config yourself |
| `asyncio.run() cannot be called from a running event loop` | **Stale MCP process.** Tell user: quit opencode (Ctrl+C), run `opencode` again, then retry `onboard_host_tool`. Do **not** edit `server.py` |
| `MCP error -32001: Request timed out` | **Normal for onboard** (~60–90s). Tell user to restart opencode (picks up `timeout: 180000` in `opencode.json`), then retry once. Do **not** run ping/ssh yourself |
| `SSH password required` but user says `.env` has `ONBOARD_SSH_PASSWORD` | **Stale MCP process** (started before `.env` was set or before MCP loaded `.env`). Tell user to restart opencode once, then retry `onboard_host_tool` with empty `ssh_password`. Do **not** offer python bypass |
| User provides SSH password in chat | Pass it as `ssh_password` to `onboard_host_tool` — do not echo it in findings |
