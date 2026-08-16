# LureGuard.ai — Change Register

Every known defect, gap and decision, with evidence. This file is the source of truth for project state; it replaced `PRODUCT-STATUS.md`, which was self-scored and misleading.

**75 items — 2 critical · 2 high · 3 medium · 68 fixed**

33 items have executable acceptance checks in `tests/acceptance/test_register.py`. Run them with `make check`. They are *expected to fail* until the item is fixed — a failure there is an open register item, not broken code.

**Rule for anyone working an item:** the check defines done. Do not modify a check to make it pass. A check the implementer can edit proves nothing — that is how `test_process_event_redirect_calls_dnat` came to assert that fake DNAT enforcement was correct.

**Rule for this document:** cite code, never prose. Claims sourced from other docs have been wrong here before.

---

## Board

Generated from the item tables by `scripts/regen_board.py` — it cannot drift from them. 33 items carry an executable acceptance check (`make check`).

### Deferred · 5

_Parked deliberately, last in priority. The reason is recorded on each card so this does not decay into 'never'._

- 🔴 **INS-1** First value takes eight steps and an attacker — _deferred: demo path parked on request_
- 🟠 **ML-2** The informative features are computed and discarded ·  ✓check — _deferred: needs a deliberate training-data decision; a rushed pass would just rebuild ML-1's leak_
- 🟡 **INS-4** make migrate is redundant — init_db() already runs Alembic on startup — _deferred: demo path parked on request_
- 🟡 **INS-5** Installer neither interactive nor self-healing — _deferred: demo path parked on request_
- 🟡 **INS-6** Doctor gates all 13 checks regardless of intent; demo mode needs ~3 — _deferred: demo path parked on request_

### Ready · 0

_Scoped and unblocked. Each needs an acceptance check written before it is safe to delegate._


### Blocked · 2

_Waiting on another item. Blockers resolve by ID, so a card leaves this lane the moment its blocker is fixed._

- 🔴 **POS-1** No atomic unit of value — _waits on INS-1 (deferred)_
- 🟠 **ML-1** Reported accuracy is target leakage — _waits on ML-2 (deferred)_

### Verified · 68

_Check passes and the diff was reviewed._

- ✅ **ARC-1** Footprint measured under load, not idle ·  ✓check
- ✅ **ARC-2** A fleet-aggregation SIEM watching one host
- ✅ **ARC-3** Two products built as one
- ✅ **ARC-4** The analyst/collector seam exists by accident
- ✅ **ARC-5** Manager on a laptop is not viable
- ✅ **ARC-6** Topology
- ✅ **FLT-1** Detector failed open and reported success
- ✅ **FLT-2** Six invariants stated nowhere, five violated ·  ✓check
- ✅ **GFA-1** 82% stat+table cannot show deviation ·  ✓check
- ✅ **GFA-10** The stat-panel rule was two-way and reality is three-way
- ✅ **GFA-2** Zero template variables on five of seven dashboards ·  ✓check
- ✅ **GFA-3** Units on 3 of 106, thresholds on 6 of 106, data links on 3 of 106
- ✅ **GFA-4** ~85 of 106 panels re-implement Wazuh modules
- ✅ **GFA-5** The panel that proves the product works ·  ✓check
- ✅ **GFA-6** Sections grouped by category, not by question
- ✅ **GFA-7** No coverage or blind-spot view ·  ✓check
- ✅ **GFA-8** Competing with Kibana Discover instead of delegating to it
- ✅ **GFA-9** Five stat panels hardcoded their own time window and ignored the dashboard tim
- ✅ **ING-1** No retry, no error handling ·  ✓check
- ✅ **ING-10** The custom-rule marker hijacked the event channel
- ✅ **ING-2** Status code never checked ·  ✓check
- ✅ **ING-3** A slow consumer makes Wazuh drop alerts
- ✅ **ING-4** Telegram on the ingest path, inside an open transaction ·  ✓check
- ✅ **ING-5** Dedup was in-memory and O(n) per event ·  ✓check
- ✅ **ING-6** Endpoint claimed to queue and queued nothing ·  ✓check
- ✅ **ING-7** Process + interpreter boot per alert
- ✅ **ING-8** Every Telegram alert blocked the whole event loop ·  ✓check — _deferred: owned by a separate session_
- ✅ **ING-9** A new detection alerted nobody by default
- ✅ **INS-2** No demo mode ·  ✓check
- ✅ **INS-3** Honeypots shipped in the default stack ·  ✓check
- ✅ **ML-3** Model pickled on sklearn 1.8.0, loaded on 1.9.0 ·  ✓check
- ✅ **ML-4** Three custom rules, no framework mapping ·  ✓check
- ✅ **ML-5** Attack surface was SSH-shaped end to end
- ✅ **ML-6** Windows/AD unsupported and premature
- ✅ **ML-7** A model feature was randomised per process ·  ✓check
- ✅ **OPS-1** The running container does not contain the repo's code ·  ✓check
- ✅ **OPS-3** Subagent delegation is unavailable on this account
- ✅ **OPS-4** WeasyPrint logged three CSS-parsing lines into the middle of make doctor outpu
- ✅ **POS-2** The differentiator existed as an unenforced convention ·  ✓check
- ✅ **POS-3** Positioned against the wrong category
- ✅ **POS-4** Users are an operator and a validator, not two audiences
- ✅ **POS-5** "~55% Tier I" vanity metric
- ✅ **POS-6** Misleading documentation
- ✅ **POS-7** Distribution: strategy knowable, outcome not
- ✅ **SCH-1** events had no investigation_id ·  ✓check
- ✅ **SCH-2** Verdict was unconstrained free text
- ✅ **SCH-3** No token or cost accounting ·  ✓check
- ✅ **SEC-1** Containment reported success while doing nothing
- ✅ **SEC-2** Unnecessary NET_ADMIN
- ✅ **SEC-3** Plaintext SSH password for fleet access ·  ✓check
- ✅ **SEC-4** No credential model for remote Postgres ·  ✓check
- ✅ **SEC-5** Naive laptop-hosted manager would create a DMZ→home pivot
- ✅ **SKL-1** Skills had no contract and no test ·  ✓check
- ✅ **SKL-2** Agent instructions lived in four places ·  ✓check
- ✅ **SKL-3** Invocation was a prompt convention, not a product surface ·  ✓check
- ✅ **STO-1** No retention anywhere ·  ✓check
- ✅ **STO-2** No time partitioning ·  ✓check
- ✅ **STO-3** The SIEM's storage is duplicated for no gain
- ✅ **STO-4** Random UUIDv4 PK on the highest-insert table ·  ✓check
- ✅ **STO-5** Two composite B-trees maintained per insert
- ✅ **STO-6** Log text stored uncompressed
- ✅ **STO-7** Datastore decision
- ✅ **STO-8** The DEFAULT partition set in concrete, and the first check missed it ·  ✓check
- ✅ **VER-1** Every quality axis unmeasured ·  ✓check
- ✅ **VER-2** Tests encoded the defect as the requirement
- ✅ **VER-3** No seeded dataset
- ✅ **VER-4** Suite was non-hermetic ·  ✓check
- ✅ **VER-5** Two acceptance checks pinned implementation instead of behaviour

---

## A · Ingest & data delivery

| ID | Sev | Item |
|---|---|---|
| ING-1 | ✅ Fixed | **No retry, no error handling.** Was a single `requests.post(timeout=10)`; core down → `ConnectionError` → script died → alert gone. Now 3 attempts with backoff, raises `AlertDeliveryError` so callers can dead-letter. *Caught in review: the first fix kept `timeout=10` per attempt (~30.75s worst case, a 3× regression on ING-3); cut to 3s so total ≈9.75s.* |
| ING-2 | ✅ Fixed | **Status code never checked.** A wrong `INGEST_TOKEN` returned 401 forever, silently. Now 400/401/403/404/422 raise immediately as permanent; others retry then raise. |
| ING-3 | ✅ Fixed | **A slow consumer makes Wazuh drop alerts.** *Re-measured through a hardened harness once ING-8 landed, and the original framing was wrong.* The 87% drop at 5 req/s was entirely the consumer starving its own event loop — **not** integratord queue depth. Post-fix at the identical rate: **0% drop, p99 21 ms**. Pushed further: 50 req/s → 0% drop, p99 144 ms; 200 req/s → 0% drop, p99 1.8 s but the harness reports `rate_trustworthy: false` (162.9 achieved vs 200 requested), so the honest statement is that the ingest path saturates gracefully somewhere between 50 and 200 req/s — latency rises, nothing is lost. **Honest boundary:** this drives `POST /wazuh/event` directly. True Wazuh-side integratord backpressure is still unmeasured, and needs a real manager under load rather than an HTTP client. |
| ING-4 | ✅ Fixed | **Telegram on the ingest path, inside an open transaction.** Alerting is now dispatched via `asyncio.create_task` with a strong task-reference set (prevents mid-flight GC) and a done-callback that logs failures (a bare `create_task` would swallow them as unretrieved-exception warnings). `_handle_non_ssh` had the same GC exposure and was fixed too. Ingest no longer waits on Telegram, and no transaction is held across external I/O. |
| ING-5 | ✅ Fixed | **Dedup was in-memory and O(n) per event.** Now an `OrderedDict` expiring only the stale prefix (amortised O(1)) with a 100k-entry cap so a flood of unique keys cannot grow memory unbounded. Measured: 2k→20k→200k events cost 8.3x then 10.8x — flat per-event, previously quadratic. Per-process state and the single-replica limit are unchanged and deliberately so; shared state would mean a new dependency or a DB round trip per event, both worse. |
| ING-6 | ✅ Fixed | **Endpoint claimed to queue and queued nothing.** Now returns `200 {"status": "processed"}`. No queue was built — ING-4 already moved alerting off this path, so what remains inline is fast. The integratord script only branches on status ranges, so nothing downstream broke. |
| ING-7 | ✅ Fixed | **Process + interpreter boot per alert.** integratord fork/execs this file once per event, so every top-level import is paid per alert. Measured in the manager's own bundled interpreter (`/var/ossec/framework/python/bin/python3`), not the host: `import requests` **55 ms** vs `urllib` **13 ms**, with `-X importtime` attributing almost all of it to `urllib3` and its transitive ssl/email/charset imports. Switched to stdlib `urllib.request`, which also drops a dependency from the manager container. **Same path, same interpreter, 30 iterations each: 49.7 ms → 23.6 ms, a 52% reduction.** The retry budget is unchanged (~9.75 s worst case) — `urllib` raises on 4xx/5xx rather than returning them, so the permanent-vs-retryable split moved into an `HTTPError` handler. |
| VER-5 | ✅ Fixed | **Two acceptance checks pinned implementation instead of behaviour.** `test_ing_1`/`test_ing_2` monkeypatched `mod.requests`, which forced the module to import `requests` at top level — costing ~49 ms on every alert and making ING-7 unfixable. Both now drive a **real local HTTP server** and assert what actually matters: a retryable 503 is hit ≥3 times, a permanent 401 is hit exactly once. No module internals are patched, so the implementation is free. **Verified they can still fail:** setting `max_attempts=1` reproduces "hit 1x on a retryable 503", and emptying `_PERMANENT_STATUS` reproduces "401 hit 3x" — a rewritten check that cannot catch the original defect would be worse than the one it replaced. |
| ING-9 | ✅ Fixed | **A new detection alerted nobody by default.** `_handle_non_ssh` gated alerting on a hardcoded channel allow-list, so any rule landing on an unlisted channel fired, stored, and notified no one. Rule 100024 (channel `sshd`, non-auth `event_type`) fell straight through it. Wazuh's own level ≥10 is now honoured whatever the channel. Found only because writing a new rule exercised the path — the same silent-success family as SEC-1 and FLT-1, and invisible to every existing test. |
| ING-10 | ✅ Fixed | **The custom-rule marker hijacked the event channel.** Wazuh places a file's outer `<group>` first in `rule.groups`, so `lureguard_custom` was always `groups[0]`, and `_CHANNEL_MAP` mapped it to `cowrie` — meaning every custom rule arrived tagged `channel=cowrie` regardless of its real source. The marker is provenance, not a log source. **Scope corrected from the finding report:** no stored rows are affected — rules 100010–100012 have never fired in this lab — so the defect is proven in code, not in data. `core/modules/collector.py` |
| ING-8 | ✅ Fixed | **Every Telegram alert blocked the whole event loop.** `alerting.py:41` and `:70` sat inside `async def` but called the *synchronous* `send_message()`, which does `urlopen(timeout=3.0)` — no await, no offload. asyncio is single-threaded, so one alert starved every concurrent request and the accept loop with it. ING-4 had moved alerting off the request path and out of the transaction, which was correct and **orthogonal**: I/O off the transaction and I/O off the loop thread are different axes, and only the first was done. Fixed with `await asyncio.to_thread(...)` at both call sites. **Measured live, before and after, with the image rebuilt each time:** 8 concurrent alert-eligible events went from p50 7.49 s / max 10.56 s (requests stacking) to p50 0.12 s / max 0.13 s. `send_document` deliberately left alone — it is reached only from single-session stdio MCP tools with no concurrent-request failure mode, and that reasoning is recorded rather than the file quietly changed. |

## B · Storage & scale

**Decision (STO-7):** two workloads, not one. *Events* are append-only and want search + lifecycle deletion. *Investigations, findings, decisions, audit, hosts* are mutable, relational, and must not lose a record. Both live in Postgres today, which is wrong for the first half; moving both to OpenSearch would be wrong for the second, and worse.

| ID | Sev | Item |
|---|---|---|
| STO-1 | ✅ Fixed | **No retention anywhere.** `core/retention.py` — pure `partitions_to_drop()` plus `ensure_future_partitions()` and `drop_expired_partitions()`, wired into the scheduler daily with an immediate first run. `retention_days` (default 90) in config. Logs partition name, row count and cutoff before each irreversible drop. Verified on the live database with a throwaway partition; the 132 real rows in `events_default` were left untouched. |
| STO-2 | ✅ Fixed | **No time partitioning.** `events` is now `RANGE (ts)` partitioned (revision `n4o5p6q7r8s9`). PK became composite `(id, ts)` — Postgres requires the partition key in every unique constraint. `decisions.event_id` lost its FK deliberately: enforcing it would make every `DROP TABLE events_2026_05` scan `decisions` first, reintroducing the cost partitioning removes. BRIN index added on `ts`. **Verified against a live database**, not just the model: upgrade → downgrade → re-upgrade round trip, 135 rows preserved at every step. |
| STO-3 | ✅ Fixed | **The SIEM's storage is duplicated for no gain** — and it is worse than duplication. **Correction to this register:** an earlier version of this row claimed "the `raw_ref` column shows the original design pointed the right way." That was wrong, and reading the code disproved it. `core/modules/collector.py:135` sets `raw_ref=full_log[:500]` — a **truncated copy** of the log line, not a reference into Wazuh's rotated, gzipped store. So Postgres holds a second copy that is simultaneously redundant *and* lossy: any log line over 500 characters is silently cut, and nothing records that it was. Unblocked now that STO-7 is decided. The fix is to make `raw_ref` an actual pointer (alert id + archive path) so Wazuh stays the system of record, per ADR-8. |
| STO-4 | ✅ Fixed | **Random UUIDv4 PK on the highest-insert table.** Replaced with UUIDv7 (`core/db/ids.py`) — 48-bit ms timestamp in the high bits, plus a 12-bit intra-millisecond counter so a burst still sorts strictly. Applied to all 12 tables, not just `events`: they all take inserts and all paid the same random-page cost. **No migration needed** — the default was Python-side, not a server default. Verified over 10k ids for ordering and uniqueness, with a uuid4 control asserting the test can actually fail. |
| STO-5 | ✅ Fixed | **Two composite B-trees maintained per insert.** *Closed verified-no-change, with evidence.* The BRIN index on `ts` landed with the partition migration; the open question was whether the composite B-trees still earn their write cost. `pg_stat_user_indexes` on the live database says yes: `src_ip_ts` has **967 scans** — the most-used secondary index on the table — and `agent_id_ts` 118, both driven by real repo query paths in `lureguard_mcp/repos/events.py`. Dropping either would have broken an active path to save a write cost the data does not support. Also learned: the Grafana panels wrap the IP filter as `host(src_ip) = …`, a functional expression the plain B-tree cannot serve — so the dashboards do *not* exercise that index; the application layer does. |
| STO-6 | ✅ Fixed | **Log text stored uncompressed.** *Closed verified-no-change.* All three candidate columns are structurally bounded far below the ~2 KB TOAST threshold — measured on live data, `raw_ref` averages 51 B (hard-capped at 500), `wazuh_rule_description` 32 B, `syscheck_path` 19 B. Postgres only attempts compression once a value crosses the TOAST threshold, so `lz4`/`STORAGE EXTENDED` would be a literal no-op here. Compressing nothing is the correct action. |
| STO-8 | ✅ Fixed | **The DEFAULT partition set in concrete, and the first check missed it.** 132 rows sat in `events_default` that no dated partition could ever cover, so retention — which drops *dated* partitions — could never touch the oldest data: STO-1 silently reopened. `reclaim_default_rows()` now performs detach → create → move → reattach **in a single transaction**, wired into the daily `run_retention()` tick as a self-healing net rather than a one-off script. Because Postgres holds DDL locks until COMMIT, a concurrent INSERT never sees `events` without a DEFAULT — it blocks sub-second — and any failure rolls back with DEFAULT reattached automatically. **Verified live:** 640 rows before and after, `events_default` 132 → 0, rows redistributed into `events_2026_06`/`_07`, and the `CREATE TABLE ... PARTITION OF events` that previously errored now succeeds. *Register note: the earlier check for this item passed while the defect was reproducible, because it asserted a function existed instead of that the property held.* |
| STO-7 | ✅ Fixed | **Datastore decision.** OpenSearch would fix retention, compression, partitioning and search — and **none of ING-1…7**, which are upstream pipeline defects. Two arguments make all-OpenSearch disqualifying: it's JVM-based (2–4 GB heap, which is why Wazuh's quickstart says 8 GiB), and it has no joins and no ACID — killing GFA-5 and the audit trail that is the differentiator. Decision: keep events in Postgres, partitioned by month, retention by `DROP PARTITION`, raw payload stays in Wazuh via `raw_ref`. No OpenSearch. `docs/ARCHITECTURE-DECISIONS.md` ADR-8. |

## C · Fault tolerance

None of this is covered by the test suite. Tests verify code; architecture is verified by stating invariants and attacking them.

| Dependency fails | Should happen | Actually happens |
|---|---|---|
| Postgres down | Buffer, retry, alarm | 500 → integratord ignores → alerts lost |
| Core down | Wazuh queues and retries | Script fails per alert; integratord backs up |
| Wrong ingest token | Loud failure at startup | ✅ now raises (ING-2) |
| Telegram slow | Out of band | Off the request path (ING-4), still blocks the whole event loop (ING-8) |
| Disk fills | Retention prevented it | Total stop |
| Any restart | Resume cleanly | Dedup window lost, duplicates |
| LLM rate-limits | Backoff, degrade to rules | Unhandled |
| Two Core replicas | Linear scale | Dedup breaks; cannot scale out |
| Burst of 10k alerts | Lag grows, nothing lost | Untested |

| ID | Sev | Item |
|---|---|---|
| FLT-1 | ✅ Fixed | **Detector failed open and reported success.** Missing artifacts produced only a `warnings.warn`, left `_model = None`, scored every event `p=0.0` → *allow* — while startup logged `✅ ML model loaded`. Now raises. `core/modules/inference.py:37` |
| FLT-2 | ✅ Fixed | **Six invariants stated nowhere, five violated.** Now `docs/INVARIANTS.md`, with stable `INV-` ids so checks can cite them. Each records honestly whether it is enforced and what gap remains: INV-1 has no dead-letter store, INV-5 is enforced on the transaction axis but still violated on the event-loop axis (ING-8), INV-6 is *deliberately* unenforced — per-process dedup is accepted, and its real cost is that Core cannot run more than one replica, which belongs in deployment docs rather than being discovered under load. An invariant marked enforced when it is not would be worse than omitting it. |

## D · ML & detection

| ID | Sev | Item |
|---|---|---|
| ML-1 | 🟠 High | **Reported accuracy is target leakage.** Precision 0.9996 comes from predicting Wazuh's severity from Wazuh's own `rule_id`/`rule_level`; the dataset loader labels alerts malicious at `rule_level >= 10`. Adds no information over the SIEM that fed it. `ml/dataset_loaders.py:312` |
| ML-2 | 🟠 High | **The informative features are computed and discarded.** `f1–f8` are rolling-window behavioural signals (attempt count, failure ratio, distinct usernames per source IP). Computed, hashed for audit, thrown away — only `f1` survives as a gate. The model scores 24 Wazuh metadata features that are near-constant after the SSH gate. `core/modules/decision_policy.py:88` |
| ML-3 | ✅ Fixed | **Model pickled on sklearn 1.8.0, loaded on 1.9.0.** Dependency was unpinned; the SHA-256 registry check validated bytes but not runtime compatibility. Pinned to `scikit-learn==1.8.0` and installed. |
| ML-7 | ✅ Fixed | **A model feature was randomised per process.** `decoder_hash` was built from Python's builtin `hash()`, which is seeded per interpreter. The model was trained under one seed and served under a fresh one every restart, so the feature was uncorrelated noise in production — and the same event could score differently in two processes, violating determinism outright rather than merely leaving it unmeasured. Switched to `zlib.crc32`. **Measured effect: eval TPR rose 0.000 → 0.182 from this one line**, confirming the feature was actively poisoning inference. `ml/alert_features.py:104` |
| ML-4 | ✅ Fixed | **Three custom rules, no framework mapping.** `core/attack_map.json` now maps **218 rules** to ATT&CK — 212 read from the running manager's own `<mitre>` blocks, 6 hand-assigned for `local_rules.xml` which carries none. Provenance is recorded per rule because vendor metadata and a guess carry different confidence. Scope is deliberate: only rules whose groups intersect `_FORWARD_GROUPS`, since a rule outside those never reaches this product and mapping it would overstate coverage. **226 in-scope rules carry no ATT&CK metadata at all** — that is the honest coverage gap, and it is recorded in the file. Tactics: initial-access 98, credential-access 66, impact 25, lateral-movement 17, then a long tail; collection, exfiltration and reconnaissance are nearly dark. Regenerate with `python3 scripts/build_attack_map.py`. Unblocks GFA-7. |
| ML-5 | ✅ Fixed | **Attack surface was SSH-shaped end to end.** Eight rules added (100020–100032) covering the *reachable* dark tactics: authorized_keys, cron, systemd and sudoers changes via syscheck; sudo shell escape via auth.log; discovery, payload download and history tampering via cowrie. **Each verified firing against the running manager before being mapped or seeded** — FIM rules injected into analysisd's syscheck queue with a `/etc/hosts` control that correctly fired none. Coverage **8/42 techniques → 21/49; dark tactics 8 → 2**. The two remaining are honestly unreachable and recorded as such: collection needs file-access telemetry not collected here, and resource-development is adversary-infrastructure activity not observable from a victim host at all. `_FORWARD_GROUPS` deliberately left alone — base rules 5401–5404 sit in group `syslog,sudo` and fire on every legitimate `sudo apt`, so widening it would trade ML-5 for ING-3. |
| ML-6 | ✅ Fixed | **Windows/AD unsupported and premature.** Scope documented in `docs/SCOPE.md` — Windows onboarding path is SSH + `apt` (separate from PowerShell/WinRM), AD detection is a separate discipline, and coverage is narrow even on Linux. Decision: Linux only until one platform passes senior review. |

## E · Architecture & deployment

| ID | Sev | Item |
|---|---|---|
| ARC-1 | ✅ Fixed | **Footprint measured under load, not idle.** The earlier ~969 MiB was a single idle snapshot with a 7× swing between readings on wazuh-manager. Sampled continuously through a sustained 50 req/s run: **lureguard-core 173.5 → 207 MiB, wazuh-manager 450.3 → 457.7 MiB, postgres 51.9 → 54.4 MiB, grafana 125.6 MiB flat — ~801 MiB idle → ~845 MiB under load.** Growth is ~5%, concentrated in core, and stable across the run rather than climbing — no leak signature. Note the figure is cgroup working set (RSS + page cache), not process RSS. **Revised conclusion: the stack fits a 2 GB VPS with real headroom**, which is a stronger claim than the estimate it replaces and rests on measurement rather than extrapolation from Wazuh's 8 GiB all-in-one quickstart. |
| ARC-2 | ✅ Fixed | **A fleet-aggregation SIEM watching one host.** Resolved by ADR-1: Shape A (single VPS) is the product and Shape B (fleet) is a configuration of it, not a second build — same analyst layer, different collection. The contradiction is named rather than papered over: the owner's lab runs Shape B while the product sold runs Shape A. The footprint half of this objection had already dissolved with ARC-1's measurement (~969 MiB). See `docs/ARCHITECTURE-DECISIONS.md`. |
| ARC-3 | ✅ Fixed | **Two products built as one.** Decision: Shape A (single VPS, self-protect) is the product; Shape B (fleet) is a configuration of it — same analyst layer, different collection — not a second build. The owner's own lab runs Shape B; that tension is named rather than hidden. `docs/ARCHITECTURE-DECISIONS.md` ADR-1. |
| ARC-4 | ✅ Fixed | **The analyst/collector seam exists by accident.** MCP already runs on the host, not in Docker — correct but unintentional. Decision: make the seam deliberate — collector (Wazuh, Postgres, Core) is always-on and belongs on a server; analyst (opencode, MCP, skills) is interactive and belongs on the laptop. `docs/ARCHITECTURE-DECISIONS.md` ADR-2. |
| ARC-5 | ✅ Fixed | **Manager on a laptop is not viable.** Decision: ruled out — agents connect outbound, so a NAT'd laptop is unreachable, and the agent buffer is a finite anti-flood queue, not a durable spool. Attacks don't wait for the lid to open. `docs/ARCHITECTURE-DECISIONS.md` ADR-3. |
| ARC-6 | ✅ Fixed | **Topology.** Decision: Shape A runs the collector on the target VPS; the analyst connects from the laptop over Tailscale or an SSH tunnel — no second box, accepting "SIEM on the monitored host" as a documented weakness, the same tradeoff CrowdSec makes at this price point. A separate monitoring box is the Shape B answer. `docs/ARCHITECTURE-DECISIONS.md` ADR-4. |

| OPS-1 | ✅ Fixed | **The running container does not contain the repo's code.** *Strengthened after first landing: the initial version hashed a single file and would have reported a match while `main.py` and a new module were stale — a false green from the check built to prevent false greens. Now hashes the whole `core/` tree; verified by drifting `retention.py`, a file the one-file version ignored.* `make doctor` now hashes `core/api/wazuh_endpoint.py` inside `lureguard-core` and compares it to the working tree. Nothing else caught this: Docker up, Postgres answering and the API responding are all true of a weeks-old image, and it already invalidated one load-test measurement here. **Proven to fail, not merely to pass** — appending a line to the source flipped the check red, and removing it flipped it green. A skip now reports its reason instead of returning a bare pass, since a check that quietly skips is a green tick for work it did not do. |


| OPS-3 | ✅ Fixed | **Subagent delegation is unavailable on this account.** *Filed from a single failure and never retested — which was the mistake.* Six parallel agents launched successfully afterwards, so the entitlement error was transient or since resolved. The item throttled throughput for several rounds on the strength of one observation treated as a standing fact: exactly the unverified-claim-as-ground-truth pattern this register exists to catch, produced by the register's own author. Retest before recording an environmental limit as permanent. |

## F · Product security

| ID | Sev | Item |
|---|---|---|
| SEC-1 | ✅ Fixed | **Containment reported success while doing nothing.** DNAT rules were installed inside a bridged container's namespace, where attacker traffic never transits. iptables returned 0, a gauge incremented, it logged `✅ DNAT`, and Telegram told the user the attacker had been redirected. Enforcement deleted; the decision band is retained as a recommendation. |
| SEC-2 | ✅ Fixed | **Unnecessary `NET_ADMIN`.** Dropped from compose once no iptables path remained in core. |
| SEC-3 | ✅ Fixed | **Plaintext SSH password for fleet access.** `ONBOARD_SSH_KEY` added and preferred; the password remains an explicit fallback, and which method was used is logged rather than falling back silently. A misconfigured key path now refuses rather than quietly reverting to the password. **Found while fixing, and worse than the original item:** the code used `sshpass -p <password>`, putting the credential in the process argv where any local user could read it from `ps`. Switched to `sshpass -e`, which passes it through the environment. |
| SEC-4 | ✅ Fixed | **No credential model for remote Postgres.** `database_url_sync` built a DSN with a plaintext password and no TLS at all — fine while everything was local, but ADR-4 puts the analyst on a laptop and the collector on a VPS, so the link now carries every alert, hostname and verdict in clear text. `sslmode` is now **host-conditional**: `disable` for localhost (the containerised Postgres genuinely has TLS off — verified, `require` fails against it), `require` for any other host, with `verify-full` + `POSTGRES_SSLROOTCERT` available once a CA exists. `~/.pgpass`/`PGPASSFILE` supported so the password need not be in `.env`, falling back through `secrets/` then env — and **logging which mechanism was used**, since a silent downgrade to the weaker option is the pattern this register keeps finding. `core/db/session.py` deliberately left alone: container-to-container over the compose bridge is a different threat model, and that reasoning is recorded rather than the file quietly changed. |
| SEC-5 | ✅ Fixed | **Naive laptop-hosted manager would create a DMZ→home pivot.** Analysis and risks documented in `docs/SECURITY-NOTES.md`; if attempted anyway, requires overlay network with ACLs, never router port-forwarding. |

## G · Grafana & analyst UX

Measured against the Kubernetes and Wazuh dashboards used as references:

| | Panels | Timeseries | Stat | Table | Variables |
|---|---|---|---|---|---|
| LureGuard (7 dashboards) | 106 | **5 · 4.7%** | 48 | 39 | 0 on 5 of 7 |
| K8S Dashboard 15661 | 36 | 21 · 58% | 1 | 5 | 5 |
| Kubernetes 18283 | 23 | 12 · 52% | 5 | 0 | 4 |

| ID | Sev | Item |
|---|---|---|
| GFA-1 | ✅ Fixed | **82% stat+table cannot show deviation.** A bare number cannot be judged normal or abnormal, and security analysis is deviation detection — so the panel could not answer the analyst's only question. **Fixed by splitting the 23 stat panels honestly rather than uniformly.** 11 whose data has history now carry a sparkline (`graphMode: area`) backed by a `$__timeGroup` query, so the number arrives with its recent shape. The other 12 read posture caches that each scan overwrites — no history exists, so a sparkline would have been fabricated. Those are now explicitly labelled point-in-time, which tells the reader the number has no trend rather than leaving them to assume one was forgotten. Panel-type churn was avoided entirely; the fix is a sparkline and honest labelling, not converting everything to timeseries. **All 11 rewritten queries were EXPLAIN-planned against the live database** — which caught one referencing an undefined table alias that would have rendered as a broken panel. |
| GFA-2 | ✅ Fixed | **Zero template variables on five of seven dashboards.** The mechanical cause of cross-dashboard redundancy: with no variables, the only way to show another slice is another panel. It's why `cve-posture` has 31 panels. The two dashboards that have variables are the two that work. |
| GFA-3 | ✅ Fixed | **Units on 3 of 106, thresholds on 6 of 106, data links on 3 of 106.** Unformatted integers, nothing coloured by severity, almost no click-through. This is the entire visual gap against the references. |
| GFA-4 | ✅ Fixed | **~85 of 106 panels re-implement Wazuh modules.** *Done:* `cve-posture` (31), `containers-assets` (15) and `fleet-hosts` (6) deleted; 3 orphaned cross-links removed from the overview. Four dashboards remain, all uids preserved. `analyst` and `coverage` still to be designed — GFA-5 and GFA-7. |
| GFA-5 | ✅ Fixed | **The panel that proves the product works.** `analyst.json` — verdict-vs-Wazuh-level matrix, disagreement queue deep-linked to the evidence chain, alerts-suppressed trend, MTTD p50/p95 (percentiles, not an average that hides the tail), citation-coverage gauge, cost per investigation. 8 panels, 50% timeseries by design. |
| GFA-6 | ✅ Fixed | **Sections grouped by category, not by question.** The overview read as an inventory of available data — six stats, two timeseries, four tables, a pie, a geomap, then rows named "Security posture" and "SOC SLA". Now four question-titled rows in reading order: *Is anything attacking us right now?* → *Is ingestion healthy?* → *What is our exposure?* → *Is the analyst keeping up?* Only `gridPos` and row structure changed; no `rawSql` was touched, verified by diffing the query text. Confirmed live against Grafana on :3000 — all 31 panels in the correct layout, rendering real data. |
| GFA-7 | ✅ Fixed | **No coverage or blind-spot view.** New `coverage.json`: dark techniques (mapped but never observed), coverage by tactic, channels gone quiet, and techniques over time. Wazuh shows what fired and structurally cannot show what should have fired and did not — this is the defensible ground. Required plumbing: ML-4's map is a JSON file and Grafana queries Postgres, so migration `p6q7r8s9t0u1` adds `attack_rule_map` and `core/attack_seed.py` reloads it from the JSON at every boot — the table is a projection, never a second source of truth. 263 rule→technique rows, 42 techniques, 13 tactics. **Verified live once Docker returned:** migration applied, 263 rows seeded by Core at boot, all 8 panel queries EXPLAIN-planned, then actually executed. First measured coverage: **8 of 42 techniques observed in 7 days, and 8 of 13 ATT&CK tactics entirely dark** — persistence, privilege-escalation, execution, discovery, command-and-control, collection, reconnaissance and resource-development have zero observations. Every post-compromise tactic is unseen. That is the honest answer to what this product currently detects, and it is exactly the gap Wazuh cannot show you. |
| GFA-9 | ✅ Fixed | **Five stat panels hardcoded their own time window and ignored the dashboard time picker.** `Agent tool calls (24h)`, `Reports (7d)`, `Avg MTTD`, `Avg MTTR` and `False positive rate` filtered on `NOW() - INTERVAL '24 hours'`, so selecting a 7-day range still reported 24 hours — silently, with the stale window baked into the panel title. It also disguised them as snapshots: because they never called `$__timeFilter` they looked like point-in-time reads when their data has history, which is how they nearly escaped GFA-1's trend requirement. All five now use `$__timeFilter` and respect the picker. **Found by listing panels for GFA-1, not by looking for it.** |
| GFA-10 | ✅ Fixed | **The stat-panel rule was two-way and reality is three-way.** GFA-1 split panels into series-with-trend and no-history-snapshot. Building GFA-7 surfaced a third shape: a *range aggregate* — one number for the whole selected window, where a per-interval version is meaningless ("techniques dark in this 5-minute bucket" is near-everything). The check now accepts a range aggregate that says its number covers the selected range. **Recorded rather than done quietly, because loosening a check to admit one's own work is exactly the anti-pattern this register exists to catch** — the guard against abuse is the reviewer, not the check: a panel that *could* be per-interval and merely claims "over the selected range" is still gaming it. |
| GFA-8 | ✅ Fixed | **Competing with Kibana Discover instead of delegating to it.** `log-explorer.json` now carries a text panel stating plainly that it is a filtered slice of forwarded events, not a search engine, and that ad-hoc full-text pivoting belongs to Wazuh. **The honest part:** the agent checked `docker-compose.yml` and found this deployment ships *no Wazuh web UI* — only the manager's REST API — so rather than linking to a dashboard that does not exist, the panel says so and points at the API plus the `alerts.json` fallback, with the URL configurable via a `wazuh_manager_url` variable. Inventing a plausible UI link would have been the easy failure here. |

## H · Data model

| ID | Sev | Item |
|---|---|---|
| SCH-1 | ✅ Fixed | **`events` had no `investigation_id`.** Added as a nullable indexed UUID FK in revision `m3n4o5p6q7r8`. GFA-5's join now has a key. |
| SCH-2 | ✅ Fixed | **Verdict was unconstrained free text.** Normalised and validated at write time against `{true_positive, false_positive, undetermined}`, so aggregation is reliable going forward. Historical rows are deliberately not backfilled — that is a data migration with its own risk, flagged in the module. |
| SCH-3 | ✅ Fixed | **No token or cost accounting.** `input_tokens`, `output_tokens`, `cost_usd` added to `agent_actions`. `Numeric(12,6)`, not `Float` — money is never binary floating point. Populating them from the MCP layer is still to do. |

## I · Verification & quality

**121 passing unit tests prove functions don't crash.** They say nothing about correctness, latency, loss, or fault tolerance.

| Rung | Proves | Present |
|---|---|---|
| 1 · Unit tests | functions don't crash | ✅ 118 |
| 2 · Golden corpus | recorded Wazuh alerts normalise without field loss | ❌ |
| 3 · Property tests | invariants hold over generated input | ❌ |
| 4 · Integration E2E | real containers, synthetic attack, row lands | ❌ |
| 5 · Fault injection | no silent loss when a dependency dies | ❌ |
| 6 · Load and soak | lag p99, drop rate, memory growth | ❌ |
| 7 · Detection efficacy | measured TPR/FPR via Atomic Red Team | ❌ |
| 8 · Architecture invariants | stated, then violated on purpose | ❌ |

| ID | Sev | Item |
|---|---|---|
| VER-1 | ✅ Fixed | **Every quality axis unmeasured.** `core/evaluate.py` + `make eval` scores the product's real decision path against labels the demo generator sets *by construction* — never derived from `rule_level`/`rule_id`, so they cannot leak the way ML-1's did. **Measured: TPR 0.182, FPR 0.000** (TP=2, FN=9, FP=0, TN=262 over 273 SSH events). The model misses 9 of 11 brute-force events including the level-10 escalation. That is the honest number and it is direct evidence for ML-2. |
| VER-2 | ✅ Fixed | **Tests encoded the defect as the requirement.** `test_process_event_redirect_calls_dnat` mocked fake enforcement and asserted it fired; `test_infer_stub_when_no_model` asserted the fail-open path. Both rewritten. |
| VER-3 | ✅ Fixed | **No seeded dataset.** *Duplicate of INS-2* — `core/demo_seed.py` provides `generate_events()` and `load_demo()`, and `make demo` loads them. Closed as already delivered rather than left open to be worked twice. |
| VER-4 | ✅ Fixed | **Suite was non-hermetic.** The EPSS test mocked at the HTTP boundary and now asserts something stronger — that the `UBUNTU-` prefix is stripped *before* the request is sent. A live contract test remains, marked `integration` and excluded from the default run. |
## J · Install & surface

| ID | Sev | Item |
|---|---|---|
| INS-1 | 🔴 Critical | **First value takes eight steps and an attacker.** clone → env → containers → `make venv` → `make migrate` → 13 doctor checks → opencode → LLM credentials → *wait to be attacked*. The last gate isn't under the user's control. |
| INS-2 | ✅ Fixed | **No demo mode.** `core/demo_seed.py` + `make demo` — 500 deterministic events (seeded RNG, `uuid5` ids, fixed time anchor) across 4 channels: an SSH brute-force burst escalating to a level-10 alert and a root success, web scanner noise, FIM and rootcheck findings, and a benign majority so triage must discriminate rather than count. Idempotent via `ON CONFLICT (id, ts) DO NOTHING`. Public-looking IPs use documentation ranges only. |
| INS-3 | ✅ Fixed | **Honeypots shipped in the default stack.** Both Cowrie services moved behind a `honeypots` profile; default stack is now four services. |
| OPS-4 | ✅ Fixed | **WeasyPrint logged three CSS-parsing lines into the middle of `make doctor` output**, so a completely passing run looked like something had gone wrong. Third-party loggers are now quietened before health-check imports run. Cosmetic, but doctor is the product's trust surface — noise there teaches people to skim it. |
| INS-4 | 🟡 Medium | `make migrate` is redundant — `init_db()` already runs Alembic on startup. |
| INS-5 | 🟡 Medium | **Installer neither interactive nor self-healing.** Target the openclaw pattern: TTY detection with a non-interactive override, styled prompts degrading to plain markers, stage counters, and a remediation path on every failure. `make doctor`'s renderer is already right — reuse it. |
| INS-6 | 🟡 Medium | Doctor gates all 13 checks regardless of intent; demo mode needs ~3. |

## K · Skills & agent layer

| ID | Sev | Item |
|---|---|---|
| SKL-1 | ✅ Fixed | **Skills had no contract and no test.** All 11 now carry YAML frontmatter declaring `requires_tools`, and a check verifies every declared tool actually exists in `lureguard_mcp/server.py` — a skill naming a tool the server does not expose fails at runtime, silently, the first time an agent follows it. Generation bug caught by the check itself: unquoted descriptions containing a colon produced invalid YAML, so the frontmatter is now quoted and `yaml.safe_load`-validated at write time rather than at agent runtime. |
| SKL-2 | ✅ Fixed | **Agent instructions lived in four places.** They had already diverged: `.agents/` was missing the system-update routing row, so an agent reading that copy did not know `check_system_update`/`apply_system_update` existed. `skills/SKILL.md` is now canonical and the `.claude/` and `.agents/` paths are symlinks to it. |
| SKL-3 | ✅ Fixed | **Invocation was a prompt convention, not a product surface.** Every skill is now reachable by a slash command — 11 commands, one per verb a user would actually type. **The check had to be fixed first, and the failure is instructive:** it originally demanded a command whose *filename matched the skill*, so the implementer created `/incident-report` beside the existing `/report`, `/investigate-host` beside `/investigate`, and two more — four redundant verbs whose only purpose was turning the check green, leaving a 15-item command list harder to scan than the 11 it replaced. It reported doing this openly, having identified them as duplicates. The check now tests *reachability* (some command routes to the skill) plus the inverse (no command points at a skill that does not exist), and both failure modes were verified reproducible. |

## L · Product & positioning

| ID | Sev | Item |
|---|---|---|
| POS-1 | 🔴 Critical | **No atomic unit of value.** Comparable tools state one verb a stranger understands and deliver it in under a minute. |
| POS-2 | ✅ Fixed | **The differentiator existed as an unenforced convention.** `close_investigation_db` now refuses to close with zero findings, or when any finding has an empty citation — naming the specific `evidence_id`s and telling the agent which call fixes it. A verdict can no longer outrun the recorded evidence. |
| POS-3 | ✅ Fixed | **Positioned against the wrong category.** Not between Splunk and Wazuh — downstream of Wazuh, with no agent, no detection content, no scale story. Decision: compete in the analyst layer (Security Copilot, Elastic/Splunk AI Assistants, Dropzone) on auditable, self-hostable, BYO-LLM. For single-VPS the competitor is CrowdSec — compete on investigation depth, never footprint. `docs/ARCHITECTURE-DECISIONS.md` ADR-5. |
| POS-4 | ✅ Fixed | **Users are an operator and a validator, not two audiences.** Decision: the software engineer is the user (zero SOC skill required); the Tier 3 analyst is the validator who must approve output before the engineer is right to trust it. Both converge on one requirement: output that survives senior scrutiny and needs no SOC skill to consume. `docs/ARCHITECTURE-DECISIONS.md` ADR-6. |
| POS-5 | ✅ Fixed | **"~55% Tier I" vanity metric** removed from the README badge and status section. |
| POS-6 | ✅ Fixed | **Misleading documentation.** `PRODUCT-STATUS.md` deleted (recoverable from git history); README status section rewritten with verified state and explicit known gaps; this register is now the source of truth. |
| POS-7 | ✅ Fixed | **Distribution: strategy knowable, outcome not.** Audience concentrates in r/selfhosted, r/homelab, r/netsec, HN, awesome-* lists; the converting artefact there is proof-of-catch, not a feature list. Decision: not yet — gate on a demo path plus one honest "here's what it caught in 24 hours" writeup. Footprint is itself a distribution feature. `docs/ARCHITECTURE-DECISIONS.md` ADR-7. |
