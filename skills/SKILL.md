---
name: lureguard
description: LureGuard AI security analyst — triage, investigate, report, onboard hosts
user-invocable: true
argument-hint: "[triage|investigate|onboard|report|daily]"
---

# LureGuard skill router

<!-- CANONICAL. `.claude/skills/lureguard/SKILL.md` and
     `.agents/skills/lureguard/SKILL.md` are symlinks to this file (SKL-2).
     Edit here. They previously drifted: the .agents copy was missing the
     system-update row, so an agent reading it did not know those tools
     existed. -->

Always read `AGENTS.md`, `skills/_shared.md`, and `skills/opencode-mcp.md` first.

| User says | Load mode |
|-----------|-----------|
| triage, alerts, last hour | `skills/triage.md` |
| investigate, IP, host | `skills/investigate-host.md` |
| IOC, sweep, hash | `skills/ioc-sweep.md` |
| report, incident | `skills/incident-report.md` |
| onboard, protect, enroll | `skills/onboard-host.md` |
| daily, summary, handover | `skills/daily-summary.md` |
| posture, CVE, vulnerabilities, outdated packages | `skills/security-posture.md` |
| update, check for updates | `check_system_update` / `apply_system_update` |

Use LureGuard MCP tools only — never bypass them with shell/python/docker. Open investigation before work. Cite every finding.
