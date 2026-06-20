# Skills and modes

LureGuard routes user intent to **skill files** under `skills/`. The agent must load `skills/_shared.md` plus the mode file for every investigation workflow.

Constitution: [`AGENTS.md`](../AGENTS.md)  
MCP behavior: [`skills/opencode-mcp.md`](../skills/opencode-mcp.md)

---

## Mode routing

| User intent | Skill file |
|-------------|------------|
| Triage, review alerts, last hour, shift handover | `skills/triage.md` |
| Investigate IP, host, user, brute force | `skills/investigate-host.md` |
| Web server, Apache, Nginx, HTTP attack | `skills/investigate-web.md` |
| Sweep IOC, hash, domain across fleet | `skills/ioc-sweep.md` |
| Write report, incident summary | `skills/incident-report.md` |
| Protect host, enroll agent, onboard VM | `skills/onboard-host.md` |
| Daily summary, SOC metrics, what happened today | `skills/daily-summary.md` |
| Posture, CVE, vulnerabilities, outdated packages | `skills/security-posture.md` |
| Rescan posture, refresh CVEs, run CVE scan | `skills/refresh-posture.md` |

---

## opencode slash commands

| Command | File | Skill loaded |
|---------|------|--------------|
| `/triage` | `.opencode/command/triage.md` | `skills/triage.md` |
| `/investigate` | `.opencode/command/investigate.md` | `skills/investigate-host.md` |
| `/onboard` | `.opencode/command/onboard.md` | `skills/onboard-host.md` |
| `/posture` | `.opencode/command/posture.md` | `skills/security-posture.md` |
| `/report` | `.opencode/command/report.md` | `skills/incident-report.md` |
| `/auto-triage` | `.opencode/command/auto-triage.md` | triage + untrusted alert block |
| `/update` | `.opencode/command/update.md` | update MCP tools flow |

---

## Shared playbook highlights (`skills/_shared.md`)

- **Reports vs Grafana:** reports must include key metrics + narrative; do not dump full dashboard tables
- **Triage matrix:** alert confidence × asset criticality → SLA targets
- **Verdicts:** `true_positive` | `false_positive` | `undetermined`
- **Confidence:** `confirmed` | `high` | `medium` | `low`
- **Containment:** recommend only; human confirms `confirm_block_ip` / `confirm_whitelist_ip`
- **ML honesty:** classifier is SSH-auth only; MCP handles all other channels
- **Posture gaps:** call out when container image deps were not scanned

---

## Onboard mode (strict)

From `skills/onboard-host.md` and `AGENTS.md`:

- Use **`onboard_host_tool` only**
- Do **not** run shell/python/docker/ssh yourself for enrollment
- Do **not** edit onboarding code mid-session
- If MCP fails: diagnose per `skills/opencode-mcp.md`, ask human to restart opencode

---

## Investigation workflow (all modes)

1. `open_investigation`
2. Load mode skill + `_shared.md`
3. Call MCP tools; `record_finding` for each conclusion
4. `close_investigation` with verdict
5. Optional: `save_report` / Telegram

---

## Auto-triage (`alert_watcher`)

When MCP server starts (`python -m lureguard_mcp`):

- Polls Postgres every 30s for new events with `wazuh_rule_level >= AUTO_TRIAGE_LEVEL` (default **12**)
- Marks event watched, sends Telegram summary
- Spawns `opencode run "Read skills/triage.md …"` with sanitized untrusted alert block

Requires: `opencode` in PATH, Telegram configured for notifications.

---

## Session update check

First message each session → `check_system_update` (see `AGENTS.md`). Same behavior as career-ops updater: ask before `apply_system_update`; never touch user layer.

---

## Headless batch

```bash
opencode run "Read skills/triage.md and triage alerts from the last 2 hours"
```

Any skill can be invoked this way by naming the skill file in the prompt.
