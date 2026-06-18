# Mode: triage — Tier-1 alert triage

## Purpose

Replace Tier-1 SOC analyst: pull recent alerts, dedupe, enrich, assign verdict and priority, build kill-chain stubs, close noise or escalate.

## Workflow

1. `open_investigation(subject="Triage batch [time range]", trigger="human", detection_source="wazuh")`
2. `get_soc_health()` — note ingestion health and MTTD baseline (first alert ts vs now)
3. `get_recent_alerts(limit=100, min_level=3)` — note channels and top IPs
4. Group by `src_ip` + `event_type`; skip obvious duplicates
5. For each distinct cluster (max 10 per session):
   - Determine **asset criticality** — check `list_enrolled_hosts` for `criticality` column first; fall back to `_shared.md` heuristics
   - `get_ip_context(src_ip)` for every unique external IP — **mandatory, not optional**
   - `analyze_web_attack` if channel suggests web (apache/nginx, cowrie web, docker)
   - `add_timeline_event` for first/last event in cluster
   - `record_finding` with verdict, MITRE if applicable, IOC fields
   - Assign P1–P4 using triage matrix
6. `close_investigation` with summary table + `kill_chain_summary` per top cluster
7. Optional: `notify_telegram` if any P1/P2

## Output format

```markdown
## Triage Summary

| IP / Subject | Events | Level | Asset crit. | Verdict | Priority | MITRE | Action |
|--------------|--------|-------|-------------|---------|----------|-------|--------|

## Kill-chain notes (top clusters)
[1–2 sentences per P1/P2 cluster — causality, not raw counts]

## Detection gaps
[Anything notable from get_soc_health]
```

## Edge cases

- Scanner IPs with 100+ failed SSH → likely FP; `record_finding` with verdict FP, MITRE T1595
- Same IP, two Wazuh rules → dedupe to one row
- No events in window → say so; suggest `list_agents` to verify fleet health
- Cowrie channel → honeypot contact; higher malicious intent confidence
