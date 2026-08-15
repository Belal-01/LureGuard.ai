# LureGuard.ai — Change Register

Every known defect, gap and decision, with evidence. This file is the source of truth for project state; it replaced `PRODUCT-STATUS.md`, which was self-scored and misleading.

**70 items — 5 critical · 14 high · 17 medium · 34 fixed**

26 items have executable acceptance checks in `tests/acceptance/test_register.py`. Run them with `make check`. They are *expected to fail* until the item is fixed — a failure there is an open register item, not broken code.

**Rule for anyone working an item:** the check defines done. Do not modify a check to make it pass. A check the implementer can edit proves nothing — that is how `test_process_event_redirect_calls_dnat` came to assert that fake DNAT enforcement was correct.

**Rule for this document:** cite code, never prose. Claims sourced from other docs have been wrong here before.

---

## Board

Generated from the item tables by `scripts/regen_board.py` — it cannot drift from them. 26 items carry an executable acceptance check (`make check`).

### Deferred · 6

_Parked deliberately, last in priority. The reason is recorded on each card so this does not decay into 'never'._

- 🔴 **ING-8** Every Telegram alert blocks the whole event loop ·  ✓check — _deferred: owned by a separate session_
- 🔴 **INS-1** First value takes eight steps and an attacker — _deferred: demo path parked on request_
- 🟠 **ML-2** The informative features are computed and discarded ·  ✓check — _deferred: needs a deliberate training-data decision; a rushed pass would just rebuild ML-1's leak_
- 🟡 **INS-4** make migrate is redundant — init_db() already runs Alembic on startup — _deferred: demo path parked on request_
- 🟡 **INS-5** Installer neither interactive nor self-healing — _deferred: demo path parked on request_
- 🟡 **INS-6** Doctor gates all 13 checks regardless of intent; demo mode needs ~3 — _deferred: demo path parked on request_

### Ready · 23

_Scoped and unblocked. Each needs an acceptance check written before it is safe to delegate._

- 🔴 **ARC-2** A fleet-aggregation SIEM watching one host
- 🟠 **ARC-3** Two products built as one
- 🟠 **ARC-4** The analyst/collector seam exists by accident
- 🟠 **ARC-5** Manager on a laptop is not viable
- 🟠 **FLT-2** Six invariants stated nowhere, five violated
- 🟠 **OPS-1** The running container does not contain the repo's code
- 🟠 **OPS-3** Subagent delegation is unavailable on this account
- 🟠 **POS-3** Positioned against the wrong category
- 🟠 **POS-4** Users are an operator and a validator, not two audiences
- 🟠 **SKL-1** Skills have no contract and no test
- 🟠 **STO-7** Datastore decision
- 🟡 **ARC-6** Topology
- 🟡 **GFA-6** Sections group by category, not by question
- 🟡 **GFA-7** No coverage or blind-spot view
- 🟡 **GFA-8** Competing with Kibana Discover instead of delegating to it. Own the decision l
- 🟡 **ING-7** Process + interpreter boot per alert
- 🟡 **ML-5** Attack surface is SSH-shaped end to end
- 🟡 **ML-6** Windows/AD unsupported and premature
- 🟡 **POS-7** Distribution: strategy knowable, outcome not
- 🟡 **SEC-5** Naive laptop-hosted manager would create a DMZ→home pivot
- 🟡 **STO-5** Partly done
- 🟡 **STO-6** Log text uncompressed — TOAST only engages above ~2 KB. Log data compresses 10
- 🟡 **STO-8** The DEFAULT partition sets in concrete — blocks the retention job

### Blocked · 7

_Waiting on another item. Blockers resolve by ID, so a card leaves this lane the moment its blocker is fixed._

- 🔴 **ING-3** A slow consumer makes Wazuh drop alerts — _waits on ING-8 (deferred)_
- 🔴 **POS-1** No atomic unit of value — _waits on INS-1 (deferred)_
- 🟠 **ML-1** Reported accuracy is target leakage — _waits on ML-2 (deferred)_
- 🟠 **SEC-4** No credential model for remote Postgres — _waits on ARC-6_
- 🟠 **STO-3** The SIEM's storage is duplicated for no gain — _waits on STO-7_
- 🟡 **ARC-1** Footprint still not measured under load ·  ✓check — _waits on ING-8 (deferred)_
- 🟡 **SKL-3** Invocation is a prompt convention, not a product surface — _waits on SKL-1_

### Verified · 34

_Check passes and the diff was reviewed._

- ✅ **FLT-1** Detector failed open and reported success
- ✅ **GFA-1** 82% stat+table cannot show deviation ·  ✓check
- ✅ **GFA-2** Zero template variables on five of seven dashboards ·  ✓check
- ✅ **GFA-3** Units on 3 of 106, thresholds on 6 of 106, data links on 3 of 106
- ✅ **GFA-4** ~85 of 106 panels re-implement Wazuh modules
- ✅ **GFA-5** The panel that proves the product works ·  ✓check
- ✅ **GFA-9** Five stat panels hardcoded their own time window and ignored the dashboard tim
- ✅ **ING-1** No retry, no error handling ·  ✓check
- ✅ **ING-2** Status code never checked ·  ✓check
- ✅ **ING-4** Telegram on the ingest path, inside an open transaction ·  ✓check
- ✅ **ING-5** Dedup was in-memory and O(n) per event ·  ✓check
- ✅ **ING-6** Endpoint claimed to queue and queued nothing ·  ✓check
- ✅ **INS-2** No demo mode ·  ✓check
- ✅ **INS-3** Honeypots shipped in the default stack ·  ✓check
- ✅ **ML-3** Model pickled on sklearn 1.8.0, loaded on 1.9.0 ·  ✓check
- ✅ **ML-4** Three custom rules, no framework mapping ·  ✓check
- ✅ **ML-7** A model feature was randomised per process ·  ✓check
- ✅ **POS-2** The differentiator existed as an unenforced convention ·  ✓check
- ✅ **POS-5** "~55% Tier I" vanity metric
- ✅ **POS-6** Misleading documentation
- ✅ **SCH-1** events had no investigation_id ·  ✓check
- ✅ **SCH-2** Verdict was unconstrained free text
- ✅ **SCH-3** No token or cost accounting ·  ✓check
- ✅ **SEC-1** Containment reported success while doing nothing
- ✅ **SEC-2** Unnecessary NET_ADMIN
- ✅ **SEC-3** Plaintext SSH password for fleet access ·  ✓check
- ✅ **SKL-2** Agent instructions lived in four places ·  ✓check
- ✅ **STO-1** No retention anywhere ·  ✓check
- ✅ **STO-2** No time partitioning ·  ✓check
- ✅ **STO-4** Random UUIDv4 PK on the highest-insert table ·  ✓check
- ✅ **VER-1** Every quality axis unmeasured ·  ✓check
- ✅ **VER-2** Tests encoded the defect as the requirement
- ✅ **VER-3** No seeded dataset
- ✅ **VER-4** Suite was non-hermetic ·  ✓check

---

## A · Ingest & data delivery

| ID | Sev | Item |
|---|---|---|
| ING-1 | ✅ Fixed | **No retry, no error handling.** Was a single `requests.post(timeout=10)`; core down → `ConnectionError` → script died → alert gone. Now 3 attempts with backoff, raises `AlertDeliveryError` so callers can dead-letter. *Caught in review: the first fix kept `timeout=10` per attempt (~30.75s worst case, a 3× regression on ING-3); cut to 3s so total ≈9.75s.* |
| ING-2 | ✅ Fixed | **Status code never checked.** A wrong `INGEST_TOKEN` returned 401 forever, silently. Now 400/401/403/404/422 raise immediately as permanent; others retry then raise. |
| ING-3 | 🔴 Critical | **A slow consumer makes Wazuh drop alerts.** Now observed, and the framing was wrong: the consumer falls over from its own alerting path (ING-8), not from integratord's queue depth. 5 req/s is enough to drop 87%. Wazuh-side backpressure remains unmeasured and is the smaller half of this item — fix ING-8 first, then re-measure against real integratord behaviour. |
| ING-4 | ✅ Fixed | **Telegram on the ingest path, inside an open transaction.** Alerting is now dispatched via `asyncio.create_task` with a strong task-reference set (prevents mid-flight GC) and a done-callback that logs failures (a bare `create_task` would swallow them as unretrieved-exception warnings). `_handle_non_ssh` had the same GC exposure and was fixed too. Ingest no longer waits on Telegram, and no transaction is held across external I/O. |
| ING-5 | ✅ Fixed | **Dedup was in-memory and O(n) per event.** Now an `OrderedDict` expiring only the stale prefix (amortised O(1)) with a 100k-entry cap so a flood of unique keys cannot grow memory unbounded. Measured: 2k→20k→200k events cost 8.3x then 10.8x — flat per-event, previously quadratic. Per-process state and the single-replica limit are unchanged and deliberately so; shared state would mean a new dependency or a DB round trip per event, both worse. |
| ING-6 | ✅ Fixed | **Endpoint claimed to queue and queued nothing.** Now returns `200 {"status": "processed"}`. No queue was built — ING-4 already moved alerting off this path, so what remains inline is fast. The integratord script only branches on status ranges, so nothing downstream broke. |
| ING-7 | 🟡 Medium | **Process + interpreter boot per alert.** ~50–100 ms floor before any work. |
| ING-8 | 🔴 Critical | **Every Telegram alert blocks the whole event loop.** `core/modules/alerting.py:41` and `:70` call `telegram_notifier.send_message()` synchronously; `connectors/telegram.py:66` is `request.urlopen(req, timeout=self.timeout_seconds)` — blocking I/O with no `asyncio.to_thread`/executor offload, default 3.0s (`TELEGRAM_TIMEOUT_SECONDS`). ING-4 moved this off the request path into `asyncio.create_task`, but asyncio is single-threaded: a task that blocks stalls the one loop thread shared by every in-flight request *and* by the accept loop. The fix relocated the stall, it did not remove it. **Measured against a rebuilt image**, so not OPS-1: 5 req/s at `POST /wazuh/event` → 87% drop rate at a 10s client timeout with p50 pinned at the ceiling; 20 req/s → 98%. Core's logs showed multi-second gaps between successive request completions and were still draining queued alert tasks at ~1 every 2–3s more than five minutes after load generation stopped — a sustained backlog, not a transient blip. RSS flat at ~162 MiB throughout, so this is loop starvation, not a leak. Every web/syscheck/rootcheck/sshd event is alert-eligible, so ordinary traffic triggers it. Fix: `await asyncio.to_thread(...)` at both call sites, or make `connectors/telegram.py` use `httpx.AsyncClient` — `httpx` is already imported there (`connectors/telegram.py:9`). The other two callers are unaffected and need no change: `lureguard_mcp/server.py:922` is a sync FastMCP tool and `lureguard_mcp/alert_watcher.py:27` runs on its own thread. Check: `test_ing_8_alerting_does_not_block_the_event_loop`. |

## B · Storage & scale

**Decision (STO-7):** two workloads, not one. *Events* are append-only and want search + lifecycle deletion. *Investigations, findings, decisions, audit, hosts* are mutable, relational, and must not lose a record. Both live in Postgres today, which is wrong for the first half; moving both to OpenSearch would be wrong for the second, and worse.

| ID | Sev | Item |
|---|---|---|
| STO-1 | ✅ Fixed | **No retention anywhere.** `core/retention.py` — pure `partitions_to_drop()` plus `ensure_future_partitions()` and `drop_expired_partitions()`, wired into the scheduler daily with an immediate first run. `retention_days` (default 90) in config. Logs partition name, row count and cutoff before each irreversible drop. Verified on the live database with a throwaway partition; the 132 real rows in `events_default` were left untouched. |
| STO-2 | ✅ Fixed | **No time partitioning.** `events` is now `RANGE (ts)` partitioned (revision `n4o5p6q7r8s9`). PK became composite `(id, ts)` — Postgres requires the partition key in every unique constraint. `decisions.event_id` lost its FK deliberately: enforcing it would make every `DROP TABLE events_2026_05` scan `decisions` first, reintroducing the cost partitioning removes. BRIN index added on `ts`. **Verified against a live database**, not just the model: upgrade → downgrade → re-upgrade round trip, 135 rows preserved at every step. |
| STO-3 | 🟠 High | **The SIEM's storage is duplicated for no gain.** Wazuh already stores every alert, rotated and gzipped, with working retention. `raw_ref` shows the original design pointed the right way. |
| STO-4 | ✅ Fixed | **Random UUIDv4 PK on the highest-insert table.** Replaced with UUIDv7 (`core/db/ids.py`) — 48-bit ms timestamp in the high bits, plus a 12-bit intra-millisecond counter so a burst still sorts strictly. Applied to all 12 tables, not just `events`: they all take inserts and all paid the same random-page cost. **No migration needed** — the default was Python-side, not a server default. Verified over 10k ids for ordering and uniqueness, with a uuid4 control asserting the test can actually fail. |
| STO-5 | 🟡 Medium | **Partly done.** The BRIN index on `ts` landed with the partition migration (`ix_events_ts_brin`). What remains is whether both composite B-trees `(src_ip, ts)` and `(agent_id, ts)` still earn their write cost now that partitioning prunes by time — needs the query evidence from the dashboards before removing either. |
| STO-6 | 🟡 Medium | Log text uncompressed — TOAST only engages above ~2 KB. Log data compresses 10–20×. |
| STO-8 | 🟡 Medium | **The DEFAULT partition sets in concrete — blocks the retention job.** Verified on the live database: 132 historical rows landed in `events_default`, and Postgres then refuses any overlapping dated partition — `ERROR: updated partition constraint for default partition "events_default" would be violated by some row`. The retention job cannot simply `CREATE TABLE events_2026_06 PARTITION OF events`; it must `DETACH` the default, create the dated partition, move matching rows across, and re-attach. Alternatively back-fill dated partitions for the existing range so DEFAULT stays empty and serves only as the missing-partition safety net it was intended to be. **Found by running the migration, not by the acceptance check** — model introspection cannot see this. |
| STO-7 | 🟠 High | **Datastore decision.** OpenSearch would fix retention, compression, partitioning and search — and **none of ING-1…7**, which are upstream pipeline defects. Two arguments make all-OpenSearch disqualifying: it's JVM-based (2–4 GB heap, which is why Wazuh's quickstart says 8 GiB), and it has no joins and no ACID — killing GFA-5 and the audit trail that is the differentiator. Note Wazuh Indexer *is* OpenSearch and isn't deployed (compose declares six services, CVE data comes from OSV — `docker-compose.yml`, `lureguard_mcp/vuln_scanner.py:27`). **Decision: keep events in Postgres, partition by month, retention by `DROP PARTITION`, raw payload stays in Wazuh via `raw_ref`. No OpenSearch.** |

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
| FLT-2 | 🟠 High | **Six invariants stated nowhere, five violated.** No alert acknowledged unless committed · no verdict without a model (fixed) · no claim without a citation · no unbounded growth · no external I/O in a transaction · restart changes nothing. |

## D · ML & detection

| ID | Sev | Item |
|---|---|---|
| ML-1 | 🟠 High | **Reported accuracy is target leakage.** Precision 0.9996 comes from predicting Wazuh's severity from Wazuh's own `rule_id`/`rule_level`; the dataset loader labels alerts malicious at `rule_level >= 10`. Adds no information over the SIEM that fed it. `ml/dataset_loaders.py:312` |
| ML-2 | 🟠 High | **The informative features are computed and discarded.** `f1–f8` are rolling-window behavioural signals (attempt count, failure ratio, distinct usernames per source IP). Computed, hashed for audit, thrown away — only `f1` survives as a gate. The model scores 24 Wazuh metadata features that are near-constant after the SSH gate. `core/modules/decision_policy.py:88` |
| ML-3 | ✅ Fixed | **Model pickled on sklearn 1.8.0, loaded on 1.9.0.** Dependency was unpinned; the SHA-256 registry check validated bytes but not runtime compatibility. Pinned to `scikit-learn==1.8.0` and installed. |
| ML-7 | ✅ Fixed | **A model feature was randomised per process.** `decoder_hash` was built from Python's builtin `hash()`, which is seeded per interpreter. The model was trained under one seed and served under a fresh one every restart, so the feature was uncorrelated noise in production — and the same event could score differently in two processes, violating determinism outright rather than merely leaving it unmeasured. Switched to `zlib.crc32`. **Measured effect: eval TPR rose 0.000 → 0.182 from this one line**, confirming the feature was actively poisoning inference. `ml/alert_features.py:104` |
| ML-4 | ✅ Fixed | **Three custom rules, no framework mapping.** `core/attack_map.json` now maps **218 rules** to ATT&CK — 212 read from the running manager's own `<mitre>` blocks, 6 hand-assigned for `local_rules.xml` which carries none. Provenance is recorded per rule because vendor metadata and a guess carry different confidence. Scope is deliberate: only rules whose groups intersect `_FORWARD_GROUPS`, since a rule outside those never reaches this product and mapping it would overstate coverage. **226 in-scope rules carry no ATT&CK metadata at all** — that is the honest coverage gap, and it is recorded in the file. Tactics: initial-access 98, credential-access 66, impact 25, lateral-movement 17, then a long tail; collection, exfiltration and reconnaissance are nearly dark. Regenerate with `python3 scripts/build_attack_map.py`. Unblocks GFA-7. |
| ML-5 | 🟡 Medium | **Attack surface is SSH-shaped end to end** — features are literally `is_sshd`, `decoder_sshd`. |
| ML-6 | 🟡 Medium | **Windows/AD unsupported and premature.** Onboarding is SSH + `apt`; AD detection is a separate discipline. Deferred deliberately until one platform passes a senior review. |

## E · Architecture & deployment

| ID | Sev | Item |
|---|---|---|
| ARC-1 | 🟡 Medium | **Footprint still not measured under load.** A harness exists (`core/loadtest.py`, `make loadtest`, pure `summarise()` under check) but the first run's numbers were read wrong: 98.5% drop and p50 14.9s were dismissed as a harness bug because a direct `curl` returned **202 in 2ms**. That curl was a single idle request against a stale image (OPS-1); the drop rate was real. Re-run against a rebuilt image reproduced it at 5 req/s and the cause is ING-8. Harness stands corrected — a p50 above the client timeout still needs explaining (queued connects are counted from send, not from accept), but it is a reporting detail, not the reason the numbers looked bad. Idle figure of ~969 MiB stands; under-load footprint measured flat at ~162 MiB RSS for core itself. |
| ARC-2 | 🔴 Critical | **A fleet-aggregation SIEM watching one host.** Wazuh manager exists to receive from many agents. The footprint argument behind this dissolved with ARC-1; the conceptual objection stands. |
| ARC-3 | 🟠 High | **Two products built as one.** *Decision: Shape A (single VPS, self-protect) is the product. Shape B (fleet) is a configuration of it — same analyst layer, different collection — not a second build.* |
| ARC-4 | 🟠 High | **The analyst/collector seam exists by accident.** MCP already runs on the host, not in Docker — correct but unintentional. Collector is always-on and belongs on a server; analyst is interactive and belongs on the laptop. Splitting there also yields two small installers instead of one large one. |
| ARC-5 | 🟠 High | **Manager on a laptop is not viable.** Agents connect outbound, so a NAT'd laptop is unreachable; the agent buffer is a finite anti-flood queue, not a durable spool. Attacks don't wait for the lid to open. |
| ARC-6 | 🟡 Medium | **Topology.** *Decision: Shape A runs the collector on the target VPS; the analyst connects from the laptop over Tailscale or an SSH tunnel. No second box. This accepts "SIEM on the monitored host" — a real weakness, documented rather than hidden, and the same tradeoff CrowdSec makes at this price point. A separate monitoring box is the Shape B answer.* |

| OPS-1 | 🟠 High | **The running container does not contain the repo's code.** `lureguard-core` returns `202` from the ingest endpoint while the source declares `200` — the image predates the ING-6 fix. Every measurement taken against the live stack therefore tested an unknown older build. There is no rebuild step in the test or check path, so this can silently invalidate any future load or E2E result. |


| OPS-3 | 🟠 High | **Subagent delegation is unavailable on this account.** Five parallel streams (ML-1/2, STO-4/5, SEC-3, ML-4, SKL-*) all terminated immediately with `Your organization has disabled Claude subscription access for Claude Code`. Not transient and not prompt-related — retrying reproduces it. Everything in this round was completed serially instead. Needs an Anthropic API key or an admin enabling access before parallel work is possible again. |

## F · Product security

| ID | Sev | Item |
|---|---|---|
| SEC-1 | ✅ Fixed | **Containment reported success while doing nothing.** DNAT rules were installed inside a bridged container's namespace, where attacker traffic never transits. iptables returned 0, a gauge incremented, it logged `✅ DNAT`, and Telegram told the user the attacker had been redirected. Enforcement deleted; the decision band is retained as a recommendation. |
| SEC-2 | ✅ Fixed | **Unnecessary `NET_ADMIN`.** Dropped from compose once no iptables path remained in core. |
| SEC-3 | ✅ Fixed | **Plaintext SSH password for fleet access.** `ONBOARD_SSH_KEY` added and preferred; the password remains an explicit fallback, and which method was used is logged rather than falling back silently. A misconfigured key path now refuses rather than quietly reverting to the password. **Found while fixing, and worse than the original item:** the code used `sshpass -p <password>`, putting the credential in the process argv where any local user could read it from `ps`. Switched to `sshpass -e`, which passes it through the environment. |
| SEC-4 | 🟠 High | **No credential model for remote Postgres.** MCP assumes `localhost:5433`; splitting analyst from collector needs auth, TLS and secret distribution that don't exist. |
| SEC-5 | 🟡 Medium | **Naive laptop-hosted manager would create a DMZ→home pivot.** If taken, must be an overlay network with ACLs, never router port-forwarding. |

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
| GFA-6 | 🟡 Medium | Sections group by category, not by question. |
| GFA-7 | 🟡 Medium | **No coverage or blind-spot view.** ATT&CK matrix, silent channels, agents gone quiet. A broken log path is invisible in Wazuh — genuinely defensible ground. |
| GFA-9 | ✅ Fixed | **Five stat panels hardcoded their own time window and ignored the dashboard time picker.** `Agent tool calls (24h)`, `Reports (7d)`, `Avg MTTD`, `Avg MTTR` and `False positive rate` filtered on `NOW() - INTERVAL '24 hours'`, so selecting a 7-day range still reported 24 hours — silently, with the stale window baked into the panel title. It also disguised them as snapshots: because they never called `$__timeFilter` they looked like point-in-time reads when their data has history, which is how they nearly escaped GFA-1's trend requirement. All five now use `$__timeFilter` and respect the picker. **Found by listing panels for GFA-1, not by looking for it.** |
| GFA-8 | 🟡 Medium | Competing with Kibana Discover instead of delegating to it. Own the decision layer; link out for the haystack. |

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
| INS-4 | 🟡 Medium | `make migrate` is redundant — `init_db()` already runs Alembic on startup. |
| INS-5 | 🟡 Medium | **Installer neither interactive nor self-healing.** Target the openclaw pattern: TTY detection with a non-interactive override, styled prompts degrading to plain markers, stage counters, and a remediation path on every failure. `make doctor`'s renderer is already right — reuse it. |
| INS-6 | 🟡 Medium | Doctor gates all 13 checks regardless of intent; demo mode needs ~3. |

## K · Skills & agent layer

| ID | Sev | Item |
|---|---|---|
| SKL-1 | 🟠 High | **Skills have no contract and no test**, so nothing prevents drift. Each should declare required MCP tools and carry a golden test run headless against the seeded dataset, asserting citations and expected verdict. |
| SKL-2 | ✅ Fixed | **Agent instructions lived in four places.** They had already diverged: `.agents/` was missing the system-update routing row, so an agent reading that copy did not know `check_system_update`/`apply_system_update` existed. `skills/SKILL.md` is now canonical and the `.claude/` and `.agents/` paths are symlinks to it. |
| SKL-3 | 🟡 Medium | Invocation is a prompt convention, not a product surface. |

## L · Product & positioning

| ID | Sev | Item |
|---|---|---|
| POS-1 | 🔴 Critical | **No atomic unit of value.** Comparable tools state one verb a stranger understands and deliver it in under a minute. |
| POS-2 | ✅ Fixed | **The differentiator existed as an unenforced convention.** `close_investigation_db` now refuses to close with zero findings, or when any finding has an empty citation — naming the specific `evidence_id`s and telling the agent which call fixes it. A verdict can no longer outrun the recorded evidence. |
| POS-3 | 🟠 High | **Positioned against the wrong category.** Not between Splunk and Wazuh — downstream of Wazuh, with no agent, no detection content, no scale story. *Decision: compete in the analyst layer* (Security Copilot, Elastic/Splunk AI Assistants, Dropzone) on auditability + self-hostable + BYO-LLM. For single-VPS the competitor is CrowdSec — compete on investigation depth, never footprint. |
| POS-4 | 🟠 High | **Users are an operator and a validator, not two audiences.** The software engineer is the user (zero SOC skill required); the Tier 3 analyst is the auditor who must approve output before the engineer is right to trust it. Both converge on one requirement: output that survives senior scrutiny and needs no SOC skill to consume. |
| POS-5 | ✅ Fixed | **"~55% Tier I" vanity metric** removed from the README badge and status section. |
| POS-6 | ✅ Fixed | **Misleading documentation.** `PRODUCT-STATUS.md` deleted (recoverable from git history); README status section rewritten with verified state and explicit known gaps; this register is now the source of truth. |
| POS-7 | 🟡 Medium | **Distribution: strategy knowable, outcome not.** Audience concentrates in r/selfhosted, r/homelab, r/netsec, HN, awesome-* lists. The converting artefact is proof-of-catch, not a feature list — which this product already produces as a report. *Decision: not yet* — gate on demo mode plus one honest "here's what it caught in 24 hours" writeup. Footprint is itself a distribution feature. |
