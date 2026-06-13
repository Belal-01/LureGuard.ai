# Mode: ioc-sweep — IOC correlation across fleet

## Purpose

Sweep an indicator (IP, hash, domain, username) across stored events and enrolled hosts.

## Workflow

1. `open_investigation(subject="IOC sweep: <indicator>", trigger="human")`
2. Identify indicator type (IP / hash / username)
3. **IP:** `search_events(ip=...)`, `check_ip_reputation`, `check_ip_virustotal`, `list_agents`
4. **Hash:** `check_hash`, `search_events` if hash appears in syscheck fields
5. **Username:** `search_events(username=...)`
6. For each hit: `record_finding` with event id + timestamp citation
7. `close_investigation` with sweep results table
8. Recommend block/watch only as human actions

## Output format

```markdown
## IOC Sweep: [indicator]

**Type:** IP | hash | username
**Hits in events:** N
**Hits in fleet:** N hosts
**Recommendation:** escalate | monitor | no action
```
