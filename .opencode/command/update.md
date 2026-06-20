---
description: Check for or apply a LureGuard system update (never touches .env or reports)
---

Read `AGENTS.md` and the **Update Check** section.

If the user asked to update or check for updates:

1. Call **`check_system_update`** and parse the JSON.
2. If `update-available`, ask whether to apply (`.env`, `secrets/`, `reports/` are never touched).
3. If yes → **`apply_system_update`**, then tell them to run `make migrate && docker compose up -d` and restart opencode.
4. If no → **`dismiss_system_update`**.

Do not edit system files manually during an update — use the MCP updater tools only.
