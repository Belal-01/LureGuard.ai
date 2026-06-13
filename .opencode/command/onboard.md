---
description: Enroll and protect a Linux VM with Wazuh agent
---

Read `AGENTS.md`, `skills/_shared.md`, `skills/opencode-mcp.md`, and `skills/onboard-host.md`.

**Target:** $ARGUMENTS

## Instructions (mandatory)

1. Follow `skills/onboard-host.md` exactly — **no bypasses, no code edits**.
2. Call **`onboard_host_tool`** MCP tool only — never run python, docker exec, ssh, or curl yourself.
3. If tool fails with `asyncio.run() cannot be called from a running event loop`: tell user to quit opencode and run `opencode` again, then retry the tool. Do **not** edit server.py or offer to run Python directly.
4. Confirm with the user before enrolling production or Kubernetes nodes.
5. One IP per tool call. If multiple IPs, ask which to start with.

If `$ARGUMENTS` is empty, ask the user for the VM IP and SSH user (default `ubuntu`).
