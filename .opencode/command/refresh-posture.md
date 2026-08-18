---
description: On-demand CVE / exposure / detection rescan
---

Read `AGENTS.md`, `skills/_shared.md`, `skills/opencode-mcp.md`, and `skills/refresh-posture.md`.

Run a **background posture indexer** (CVE + exposure + detection + SCA + users). Use this when you need **fresh data** — normal posture reads the cache instantly, and the scheduler refreshes in the background.

**Scope:** `$ARGUMENTS` (agent_id or omit for whole fleet, ~5 min per host)
