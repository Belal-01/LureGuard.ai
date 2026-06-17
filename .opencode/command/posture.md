---
description: Run fleet security posture — CVE, exposure, detection (cached + background scan)
---

Read `AGENTS.md`, `skills/_shared.md`, `skills/opencode-mcp.md`, and `skills/security-posture.md`.

Run a security posture check across all active agents. Use MCP tools only — no shell bypasses.

**Fast path:** `get_posture_snapshot` per agent (instant from Postgres cache). **Do not** call `trigger_posture_scan` unless the user explicitly asks to rescan — see `skills/refresh-posture.md`.
