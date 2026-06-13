# Mode: triage — Tier-1 alert triage

## Purpose

Replace Tier-1 SOC analyst: pull recent alerts, dedupe, enrich, assign verdict and priority, close noise or escalate.

## Workflow

1. `open_investigation(subject="Triage batch [time range]", trigger="human", severity="")`
2. `get_recent_alerts(limit=100, min_level=3)` — note channels and top IPs
3. Group by `src_ip` + `event_type`; skip obvious duplicates
4. For each distinct alert cluster (max 10 per session unless user asked for more):
   - `check_ip_reputation` if external IP
   - `record_finding` with citation from tool JSON
   - Assign P1–P4 using triage matrix in `_shared.md`
   - Verdict: TP / FP / undetermined
5. `close_investigation` with summary table of all clusters
6. Optional: `notify_telegram` with short summary if any P1/P2

## Output format

```markdown
## Triage Summary

| IP / Subject | Events | Level | Verdict | Priority | Action |
|--------------|--------|-------|---------|----------|--------|
```

## Edge cases

- Scanner IPs with 100+ failed SSH → likely FP; recommend whitelist note, do not block
- Same IP, two Wazuh rules → dedupe to one row
- No events in window → say so; suggest `list_agents` to verify fleet health
