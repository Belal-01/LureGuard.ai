---
description: Run fleet security posture — CVE, exposure, detection (cached + background scan)
---

Read `AGENTS.md`, `skills/_shared.md`, `skills/opencode-mcp.md`, and `skills/security-posture.md`.

Run a security posture check across all active agents. Use MCP tools only — no shell bypasses.

**Fast path:** `get_posture_snapshot` per agent (instant from Postgres). If cache stale, call `trigger_posture_scan` and report cached data plus scan-in-progress note. Do not block on live scans.
