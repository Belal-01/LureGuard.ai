# opencode — MCP behavior (mandatory)

You run inside **opencode** with the **LureGuard MCP server** (`lureguard`). Follow these rules in every session.

## Golden rule

**Use MCP tools. Do not reimplement them in the shell or in Python.**

| Task | Correct action | Wrong action |
|------|----------------|--------------|
| Onboard a VM | `onboard_host_tool` | `python -c`, `docker exec`, `ssh`, edit `server.py` |
| List fleet | `list_agents` | `curl` Wazuh API |
| Triage | `get_recent_alerts` | Query Postgres directly |

## Never offer workarounds

Do **not** present choices like:
- "Fix the code + restart MCP **or** run the script directly"
- "The tool is broken so I'll bypass it"
- "I'll re-apply the async fix in server.py"

There is **one** path: call the MCP tool. If it fails, diagnose using the table below — then ask the **human** to take the single remediation step. You do not edit LureGuard code during onboard workflows (see `skills/onboard-host.md`).

**Symptom:** `onboard_host_tool` returns  
`SSH password required. Set ONBOARD_SSH_PASSWORD in .env or pass ssh_password.`

**Cause:** MCP server was started before `.env` was updated, or opencode needs a restart to reload MCP after config changes. The MCP server **loads `.env` from the repo root on startup** (`lureguard_mcp/config.py`).

**Your response:**
1. If user says `.env` already has `ONBOARD_SSH_PASSWORD`: ask them to **restart opencode** (Ctrl+C, then `opencode`), then call `onboard_host_tool` with empty `ssh_password`.
2. If user gives you the password in chat: pass `ssh_password` to the tool — never repeat it in findings.
3. Do **not** offer shell/python bypasses.

## Stale MCP process (common)

**Symptom:** `onboard_host_tool` returns  
`asyncio.run() cannot be called from a running event loop`

**Cause:** opencode started before the latest MCP code was loaded. The fix (`async def onboard_host_tool` + async-safe `@audited` wrapper) is **already in the repo**.

**Your response (exact playbook):**
1. Tell the user: *"The MCP server is running old code. Please quit opencode completely (Ctrl+C) and run `opencode` again, then ask me to continue onboarding."*
2. **Stop.** Do not edit files. Do not run Python. Do not call docker.
3. After the user confirms restart, call `onboard_host_tool` again for the same IP.

## Other MCP / tool failures

| Error hint | You do | You do not |
|------------|--------|------------|
| SSH / connection | Quote tool JSON `error`; ask user to verify IP/credentials | Retry with raw `ssh` |
| Wazuh API / auth | Ask user to run `make doctor` | Start authd, edit Wazuh config, `curl` API |
| `success: false` | Report verbatim; `close_investigation` | Invent fix; alternate enrollment method |
| Tool missing | Ask user to run `make doctor` and restart opencode | Patch MCP server mid-session |

## Onboard mode

When user says onboard / protect / enroll: load `skills/onboard-host.md` and follow it exactly.

## Reports and PDF (opt-in)

- Default: save and Telegram-send **markdown** (`.md`) only.
- **Never** call `convert_report_to_pdf` or `send_report_to_telegram(..., as_pdf=true)` unless the user **explicitly** asks for PDF (e.g. "send as PDF", "convert to pdf").
- `save_report(..., send_telegram=true)` always sends `.md`, never PDF.
