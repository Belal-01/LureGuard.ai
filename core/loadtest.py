"""
ARC-1 / ING-3 load harness.

`summarise()` is pure — a list of {"latency_s": float, "ok": bool, "outcome":
str} results in, percentiles + drop rate + outcome breakdown out. No network,
no clock, so it's testable without any infrastructure running (see
tests/acceptance/test_register.py). `summarise_memory()` is the same idea for
memory samples.

`run()` is the async driver: it discards a warm-up burst, then POSTs synthetic
Wazuh alerts at a configurable rate for a configurable duration, sampling
`docker stats` for a target container throughout, and collects per-request
results plus the memory samples. Payloads are built from
core/demo_seed.generate_events() (the existing deterministic, realistic event
generator — INS-2) converted into the *raw* Wazuh alert JSON shape that
wazuh/integrations/custom-lureguard.py actually POSTs (rule/agent/data/
full_log), not the normalized `events` row shape demo_seed itself returns.

    PYTHONPATH=core:. python -m loadtest --rate 20 --duration 30
    make loadtest RATE=20 DURATION=30

Known defects this version fixes (see docs/CHANGE-REGISTER.md ARC-1 / ING-3):
  - achieved dispatch rate was never checked against the requested rate, so a
    saturated event loop or a slow server could silently degrade the test to
    "as fast as the server allows" while still being reported as `--rate`.
  - drop_rate collapsed timeouts, connection refusals, and HTTP error
    statuses into one `ok=False` bucket, hiding which failure mode was
    actually happening (server backpressure vs. client-side network issue).
  - there was no warm-up, so connection-setup / first-call overhead landed
    inside the reported percentiles.
  - memory was 3 point-in-time `docker stats` snapshots stitched together by
    a racy background shell subprocess in the Makefile, not sampled
    throughout the run — exactly the "single reading is a guess" problem
    ARC-1 already flagged for the idle number.
"""
from __future__ import annotations

import argparse
import asyncio
import re
import time
from datetime import datetime, timezone

import httpx

# Marker prepended to full_log so inserted rows are easy to find and delete
# afterwards: DELETE FROM events WHERE raw_ref LIKE '[loadtest]%';
TAG = "[loadtest]"

_GROUPS_BY_CHANNEL = {
    "sshd": ["sshd"],
    "web": ["web"],
    "syscheck": ["syscheck"],
    "rootcheck": ["rootcheck"],
    "cowrie": ["lureguard_custom"],
    "docker": ["docker"],
}

# Requests discarded before measurement starts — pays connection setup and
# first-call (JIT-ish) costs outside the reported percentiles.
DEFAULT_WARMUP = 10

# How often to sample container memory during the measured window.
DEFAULT_MEM_INTERVAL_S = 2.0

# If achieved dispatch rate falls more than this fraction below the
# requested rate, the run is flagged as not measuring what it claims to.
RATE_SHORTFALL_WARN = 0.10

_MEM_UNIT_TO_MIB = {
    "B": 1 / 1048576, "KB": 1 / 1024, "KiB": 1 / 1024,
    "MB": 1, "MiB": 1,
    "GB": 1024, "GiB": 1024,
    "TB": 1024 * 1024, "TiB": 1024 * 1024,
}


def summarise(results: list[dict]) -> dict:
    """Pure: [{"latency_s": float, "ok": bool, "outcome": str}, ...] ->
    percentiles, drop rate, and an outcome breakdown.

    latency_s covers every dispatched request, including ones that failed —
    a request that timed out still spent its full wait, and dropping it from
    the percentiles would flatter the result. `outcome` distinguishes *why*
    a request failed (timeout / connection_error / http_error) instead of
    collapsing everything into `ok=False`; results without an "outcome" key
    (e.g. the fixed sample in the acceptance test) fall back to ok/unknown.
    """
    sent = len(results)
    if sent == 0:
        return {"p50_s": 0.0, "p95_s": 0.0, "p99_s": 0.0, "drop_rate": 0.0, "sent": 0, "outcomes": {}}

    latencies = sorted(r["latency_s"] for r in results)
    failed = sum(1 for r in results if not r.get("ok"))

    outcomes: dict[str, int] = {}
    for r in results:
        kind = r.get("outcome") or ("ok" if r.get("ok") else "unknown")
        outcomes[kind] = outcomes.get(kind, 0) + 1

    def pct(p: float) -> float:
        idx = min(len(latencies) - 1, round(p * (len(latencies) - 1)))
        return latencies[idx]

    return {
        "p50_s": pct(0.50),
        "p95_s": pct(0.95),
        "p99_s": pct(0.99),
        "drop_rate": failed / sent,
        "sent": sent,
        "outcomes": outcomes,
    }


def summarise_memory(samples: list[dict]) -> dict:
    """Pure: [{"t": float, "mib": float}, ...] -> min/mean/max MiB over the
    sampling window.

    `mib` comes from `docker stats` MemUsage, which is cgroup working-set
    memory (RSS + page cache), not process RSS alone — real memory pressure,
    but not directly comparable to e.g. `ps`. Say so in the caller's output.
    """
    if not samples:
        return {"samples": 0, "min_mib": 0.0, "mean_mib": 0.0, "max_mib": 0.0}
    vals = [s["mib"] for s in samples]
    return {
        "samples": len(vals),
        "min_mib": min(vals),
        "mean_mib": sum(vals) / len(vals),
        "max_mib": max(vals),
    }


def _parse_mem_usage(line: str) -> float | None:
    """'401.8MiB / 7.817GiB' -> 401.8 (MiB, the used side). None if unparseable."""
    if not line:
        return None
    used = line.split("/", 1)[0].strip()
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", used)
    if not m:
        return None
    return float(m.group(1)) * _MEM_UNIT_TO_MIB.get(m.group(2), 1.0)


def _to_wazuh_alert(row: dict, ts: datetime) -> dict:
    """Convert one core.demo_seed normalized-row dict into the raw alert JSON
    shape schemas.wazuh_alert.WazuhAlert / modules.collector.normalize_event
    expect (see wazuh/integrations/custom-lureguard.py's _normalize_alert)."""
    channel = row.get("channel", "unknown")
    data = {}
    if row.get("src_ip"):
        data["srcip"] = row["src_ip"]
    if row.get("username"):
        data["srcuser"] = row["username"]
    data["status"] = "success" if row.get("success") else "failed"

    alert = {
        "timestamp": ts.isoformat(),
        "rule": {
            "id": row.get("wazuh_rule_id", 0),
            "level": row.get("wazuh_rule_level", 0),
            "description": row.get("wazuh_rule_description") or "",
            "groups": _GROUPS_BY_CHANNEL.get(channel, ["unknown"]),
        },
        "agent": {
            "id": row.get("agent_id") or "000",
            "name": row.get("agent_name") or "",
            "ip": row.get("agent_ip") or "",
        },
        "data": data,
        "full_log": f"{TAG} {row.get('raw_ref') or ''}",
        "location": f"/var/log/{channel}",
    }
    if channel == "syscheck" and row.get("syscheck_path"):
        alert["syscheck"] = {
            "path": row["syscheck_path"],
            "event": row.get("syscheck_event") or "modified",
            "sha256_after": row.get("syscheck_sha256_after") or "",
        }
    return alert


async def _send_one(client: httpx.AsyncClient, url: str, token: str, payload: dict) -> dict:
    """One request. latency_s is measured around the whole attempt — including
    a timeout's full wait — so summarise() never has to guess what a failure
    cost. `outcome` separates timeout / connection_error / http_error instead
    of collapsing them into a single ok=False, per ING-3: a slow-consumer
    backpressure signal looks nothing like a refused connection."""
    t0 = time.perf_counter()
    status = None
    try:
        resp = await client.post(
            url, json=payload, headers={"X-LureGuard-Token": token}, timeout=10.0
        )
        status = resp.status_code
        outcome = "ok" if status == 200 else "http_error"
    except httpx.TimeoutException:
        outcome = "timeout"
    except httpx.HTTPError:
        outcome = "connection_error"
    return {
        "latency_s": time.perf_counter() - t0,
        "ok": outcome == "ok",
        "outcome": outcome,
        "status": status,
    }


async def _sample_memory(
    container: str, interval_s: float, samples: list[dict], stop: asyncio.Event
) -> None:
    """Background task: append a {"t", "mib"} sample every interval_s until
    `stop` is set. Shells out to `docker stats` (a subprocess, not a blocking
    call) so it never stalls the event loop the request ticker's timing
    depends on.

    ponytail: polls the docker CLI instead of the containers stats HTTP API.
    Fine at a couple of samples/sec; switch to the API if sub-second
    granularity is ever needed.
    """
    while not stop.is_set():
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate()
            mib = _parse_mem_usage(out.decode().strip())
            if mib is not None:
                samples.append({"t": time.monotonic(), "mib": mib})
        except OSError:
            pass  # docker CLI unavailable — memory section just stays empty
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
        except asyncio.TimeoutError:
            pass


async def run(
    rate: float,
    duration: float,
    url: str,
    token: str,
    warmup: int = DEFAULT_WARMUP,
    mem_container: str | None = "wazuh-manager",
    mem_interval_s: float = DEFAULT_MEM_INTERVAL_S,
) -> dict:
    """Fire POST `url` at `rate` req/s for `duration` seconds (after a
    discarded warm-up), cycling through demo_seed's deterministic event pool,
    while sampling `mem_container` memory throughout. Returns
        {"results": [...], "elapsed_s": float, "memory_samples": [...]}
    Feed "results" to summarise() and "memory_samples" to summarise_memory().

    ponytail: fixed-interval ticker spawning one task per tick, not a real
    token-bucket/worker-pool scheduler. Fine up to a few hundred req/s — the
    caller is expected to compare achieved vs. requested rate (main() does)
    rather than trust --rate blindly; if you need sustained three-digit
    rates with tight timing, upgrade the scheduler.
    """
    from demo_seed import generate_events

    rows = generate_events(warmup + max(500, int(rate * duration) + 10))
    interval = 1.0 / rate if rate > 0 else 0.0
    limits = httpx.Limits(max_connections=300, max_keepalive_connections=50)

    async with httpx.AsyncClient(limits=limits) as client:
        # Warm-up: discarded, so first-request overhead doesn't leak into
        # the measured percentiles.
        if warmup > 0:
            warm_tasks = [
                asyncio.create_task(
                    _send_one(client, url, token, _to_wazuh_alert(rows[i], datetime.now(timezone.utc)))
                )
                for i in range(warmup)
            ]
            await asyncio.gather(*warm_tasks)

        stop = asyncio.Event()
        memory_samples: list[dict] = []
        mem_task = (
            asyncio.create_task(_sample_memory(mem_container, mem_interval_s, memory_samples, stop))
            if mem_container
            else None
        )

        pool_size = len(rows) - warmup
        tasks: list[asyncio.Task] = []
        start = time.monotonic()
        i = 0
        while time.monotonic() - start < duration:
            row = rows[warmup + (i % pool_size)]
            payload = _to_wazuh_alert(row, datetime.now(timezone.utc))
            tasks.append(asyncio.create_task(_send_one(client, url, token, payload)))
            i += 1
            if interval:
                await asyncio.sleep(interval)
        results = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - start

        stop.set()
        if mem_task:
            await mem_task

    return {"results": list(results), "elapsed_s": elapsed, "memory_samples": memory_samples}


def main() -> None:
    import json
    import sys

    sys.path[:0] = ["."]
    from config import ingest_token

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rate", type=float, default=20.0, help="requests/sec")
    p.add_argument("--duration", type=float, default=30.0, help="seconds")
    p.add_argument("--url", default="http://localhost:8080/wazuh/event")
    p.add_argument("--token", default=ingest_token() or "lureguard-dev-ingest-token")
    p.add_argument("--warmup", type=int, default=DEFAULT_WARMUP,
                    help="requests discarded before measuring")
    p.add_argument("--mem-container", default="wazuh-manager",
                    help="container to sample memory from throughout the run; "
                         "empty string disables sampling")
    p.add_argument("--mem-interval", type=float, default=DEFAULT_MEM_INTERVAL_S,
                    help="seconds between memory samples")
    args = p.parse_args()

    outcome = asyncio.run(run(
        args.rate, args.duration, args.url, args.token,
        warmup=args.warmup,
        mem_container=args.mem_container or None,
        mem_interval_s=args.mem_interval,
    ))

    summary = summarise(outcome["results"])
    summary["target_rate"] = args.rate
    summary["elapsed_s"] = outcome["elapsed_s"]
    summary["achieved_rate"] = summary["sent"] / outcome["elapsed_s"] if outcome["elapsed_s"] else 0.0
    summary["warmup_requests"] = args.warmup

    if args.rate > 0:
        shortfall = 1 - (summary["achieved_rate"] / args.rate)
        summary["rate_shortfall_pct"] = round(shortfall * 100, 1)
        summary["rate_trustworthy"] = shortfall <= RATE_SHORTFALL_WARN
    else:
        summary["rate_shortfall_pct"] = 0.0
        summary["rate_trustworthy"] = True

    mem = summarise_memory(outcome["memory_samples"])
    mem["container"] = args.mem_container
    mem["note"] = "docker stats MemUsage = cgroup working set (RSS + page cache), not process RSS"
    summary["memory"] = mem

    print(json.dumps(summary, indent=2))
    if not summary["rate_trustworthy"]:
        print(
            f"WARNING: achieved rate {summary['achieved_rate']:.1f} req/s is "
            f"{summary['rate_shortfall_pct']}% below the requested {args.rate} req/s "
            "over the actual elapsed window — this run measures the server's "
            "own speed, not its behavior at the requested rate. Lower --rate, "
            "raise duration, or investigate why dispatch fell behind before "
            "trusting these numbers.",
            file=sys.stderr,
        )


def _demo() -> None:
    """Smallest self-check for the pure logic."""
    s = summarise([
        {"latency_s": 0.01, "ok": True, "outcome": "ok"},
        {"latency_s": 0.02, "ok": True, "outcome": "ok"},
        {"latency_s": 0.30, "ok": True, "outcome": "ok"},
        {"latency_s": 0.05, "ok": False, "outcome": "timeout"},
    ])
    assert s["sent"] == 4
    assert s["drop_rate"] == 0.25
    assert s["p50_s"] <= s["p95_s"] <= s["p99_s"]
    assert s["outcomes"] == {"ok": 3, "timeout": 1}
    assert summarise([])["sent"] == 0

    # Results without an "outcome" key (the acceptance test's fixed sample)
    # must not crash summarise() — falls back to ok/unknown.
    s2 = summarise([{"latency_s": 0.01, "ok": True}, {"latency_s": 0.02, "ok": False}])
    assert s2["outcomes"] == {"ok": 1, "unknown": 1}

    mem = summarise_memory([{"t": 0.0, "mib": 100.0}, {"t": 1.0, "mib": 200.0}])
    assert mem["min_mib"] == 100.0 and mem["max_mib"] == 200.0 and mem["mean_mib"] == 150.0
    assert summarise_memory([])["samples"] == 0

    assert abs(_parse_mem_usage("401.8MiB / 7.817GiB") - 401.8) < 1e-9
    assert _parse_mem_usage("1.5GiB / 7GiB") == 1536.0
    assert _parse_mem_usage("") is None

    alert = _to_wazuh_alert(
        {"channel": "sshd", "src_ip": "192.0.2.5", "username": "root", "success": False,
         "wazuh_rule_id": 5710, "wazuh_rule_level": 5, "wazuh_rule_description": "d",
         "agent_id": "001", "agent_name": "a", "agent_ip": "10.0.0.1", "raw_ref": "r"},
        datetime.now(timezone.utc),
    )
    assert alert["data"]["srcip"] == "192.0.2.5"
    assert alert["rule"]["groups"] == ["sshd"]
    assert alert["full_log"].startswith(TAG)


if __name__ == "__main__":
    _demo()
    main()
