# Mode: refresh-posture — On-demand CVE / exposure / detection rescan

## Purpose

Run a **background posture indexer** (CVE + exposure + detection + SCA + users) only when the user **explicitly** wants fresh data — not during normal posture or web investigation.

Normal posture (`security-posture.md`) reads **Postgres cache** instantly. The 6h scheduler refreshes cache in the background. This mode is for: "rescan", "refresh CVEs", "run a new scan", "update posture data".

## When to use

- User says: rescan, refresh, update posture, run CVE scan, scan now, after I patched
- User accepts wait (~5 min per host) for fresh inventory

## When NOT to use

- User asks "what's my posture?" / "any CVEs?" / daily summary → use `security-posture.md` (cache only)
- Web incident investigation → use `investigate-web.md` (no scan unless user also asks for CVE refresh)
- Cache is stale or empty → **report cache age + offer rescan**; do not auto-start scan

## Workflow

1. Confirm scope: one `agent_id` or whole fleet (`trigger_posture_scan()` with no agent_id)
2. `trigger_posture_scan(agent_id=..., force=true)` — returns `job_id` immediately
3. Tell user: scan queued, ~5 min per host; cached data unchanged until complete
4. `get_posture_scan_status(job_id)` if user wants progress
5. After scan: `get_posture_snapshot` / `get_agent_vulnerabilities` for updated results
6. Optional: `save_report` if user wants a posture report with fresh data

## Output

```markdown
## Posture rescan queued
- **Job ID:** [job_id]
- **Agents:** [count or id]
- **ETA:** ~[N] minutes
- **Note:** Previous cached data still shown until scan completes. Re-ask or check status for updates.
```
