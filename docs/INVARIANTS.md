# Architectural invariants

Properties this system must hold. They are not tested by asserting that functions
return the right value — they are stated here, and then deliberately attacked.

This exists because **121 passing unit tests proved only that functions do not
crash**. Every serious defect found in this codebase — a containment path that
logged success while doing nothing, a detector that failed open, alerts dropped
silently for want of a status-code check — passed the suite comfortably. Tests
verify code. Invariants verify architecture, and until now they lived only in
conversation, which meant they could not be checked, handed over, or regression-
guarded.

Each invariant has a stable id so a check can cite it. `make check` enforces the
ones marked **enforced**; the rest name the gap honestly rather than implying
coverage that does not exist.

---

## INV-1 · No alert is acknowledged unless it is committed

**Status: enforced.**

The ingest endpoint must not tell Wazuh it handled an alert that is not durably
stored. It previously returned `202 {"status": "queued"}` while queueing nothing
— a durability claim the code could not honour.

Now returns `200 {"status": "processed"}`, and the integratord hook treats any
non-2xx as a delivery failure with bounded retries (ING-1, ING-2, ING-6).

*Remaining gap:* there is no dead-letter store. A sustained Core outage still
loses alerts after the retry budget expires — the hook raises so a caller
*could* dead-letter, but nothing does yet.

## INV-2 · No verdict without a model

**Status: enforced.**

A detector that cannot score must not emit confident verdicts. Missing model
artifacts used to produce a `warnings.warn`, leave `_model = None`, and score
every event `p=0.0` → *allow* — while startup logged `✅ ML model loaded`. Fail
open, with a green checkmark.

`load_model()` now raises; Core refuses to start without a detector (FLT-1).

## INV-3 · No claim without a citation

**Status: enforced.**

The product's differentiator. An investigation must not close with a verdict
that no recorded evidence supports. Stated in `AGENTS.md` from the beginning and
enforced nowhere, which made it a convention rather than a guarantee.

`close_investigation_db` now refuses to close when there are no findings, or when
any finding carries an empty citation (POS-2).

## INV-4 · Nothing grows without bound

**Status: enforced.**

Anything that accumulates per event must have a ceiling, or the system dies of
disk rather than of load.

- `events` is `RANGE (ts)` partitioned; retention drops whole partitions (STO-1,
  STO-2)
- ingest dedup is capped at 100k entries with amortised expiry (ING-5)

*Remaining gap:* partition **creation** is the other half. A missing partition
makes `INSERT` fail, which is a silent ingest outage — the exact failure class
this document exists to prevent. See STO-8.

## INV-5 · No external I/O inside a transaction

**Status: enforced, with a known violation of its spirit.**

An outbound HTTP call must not hold a database transaction open, and must not sit
on the request path that Wazuh's integratord is waiting on.

Telegram alerting is now dispatched via `asyncio.create_task` with a strong task
reference and a failure-logging callback (ING-4).

*Known violation:* the dispatched call is still **synchronous** —
`connectors/telegram.py` uses `urllib.request.urlopen`, so it blocks the entire
event loop for every concurrent request, not merely its own task (ING-8). The
transaction is no longer held; the loop still stalls. Getting I/O off the
transaction and getting it off the event loop are separate axes, and only the
first is done.

## INV-6 · Restart changes nothing

**Status: not enforced — deliberately.**

State that matters must survive a process restart.

Ingest dedup and alert dedup are per-process and are lost on restart, so a
restart can re-ingest duplicates. This is accepted, not overlooked: shared state
would mean a new dependency (Redis) or a database round trip on the ingest hot
path, both worse than the duplicates they would prevent.

**The real consequence is scale, not correctness:** because dedup is per-process,
Core cannot run more than one replica. That constraint is a design decision, and
it belongs in the deployment documentation rather than being discovered under
load.

---

## How to add one

An invariant earns a place here when violating it produces a failure that a unit
test would not catch — silent data loss, a false claim, unbounded growth,
something that only appears under concurrency or restart. If a normal test can
catch it, it is a test, not an invariant.

State it as a property, give it the next `INV-` id, say honestly whether it is
enforced, and name the remaining gap. **An invariant listed as enforced when it
is not is worse than not listing it** — that is precisely the defect this
codebase kept producing.
