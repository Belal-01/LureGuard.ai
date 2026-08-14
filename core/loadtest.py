"""
ARC-1 / ING-3 load harness.

`summarise()` is pure — a list of {"latency_s": float, "ok": bool} results in,
percentiles + drop rate out. No network, no clock, so it's testable without
any infrastructure running (see tests/acceptance/test_register.py).

`run()` is the async driver: it POSTs synthetic Wazuh alerts at a configurable
rate for a configurable duration and collects those same per-request results.
Payloads are built from core/demo_seed.generate_events() (the existing
deterministic, realistic event generator — INS-2) converted into the *raw*
Wazuh alert JSON shape that wazuh/integrations/custom-lureguard.py actually
POSTs (rule/agent/data/full_log), not the normalized `events` row shape
demo_seed itself returns.

    PYTHONPATH=core:. python -m loadtest --rate 20 --duration 30
    make loadtest RATE=20 DURATION=30
"""
from __future__ import annotations

import argparse
import asyncio
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


def summarise(results: list[dict]) -> dict:
    """Pure: [{"latency_s": float, "ok": bool}, ...] -> percentiles + drop rate."""
    sent = len(results)
    if sent == 0:
        return {"p50_s": 0.0, "p95_s": 0.0, "p99_s": 0.0, "drop_rate": 0.0, "sent": 0}

    latencies = sorted(r["latency_s"] for r in results)
    failed = sum(1 for r in results if not r.get("ok"))

    def pct(p: float) -> float:
        idx = min(len(latencies) - 1, round(p * (len(latencies) - 1)))
        return latencies[idx]

    return {
        "p50_s": pct(0.50),
        "p95_s": pct(0.95),
        "p99_s": pct(0.99),
        "drop_rate": failed / sent,
        "sent": sent,
    }


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
    t0 = time.perf_counter()
    try:
        resp = await client.post(
            url, json=payload, headers={"X-LureGuard-Token": token}, timeout=10.0
        )
        ok = resp.status_code < 300
    except httpx.HTTPError:
        ok = False
    return {"latency_s": time.perf_counter() - t0, "ok": ok}


async def run(rate: float, duration: float, url: str, token: str) -> list[dict]:
    """Fire POST `url` at `rate` req/s for `duration` seconds, cycling through
    demo_seed's deterministic event pool. Returns per-request results — feed
    to summarise().

    ponytail: fixed-interval ticker spawning one task per tick, not a real
    token-bucket/worker-pool scheduler. Fine up to a few hundred req/s; if you
    need sustained three-digit rates with tight timing, upgrade the scheduler.
    """
    from demo_seed import generate_events

    rows = generate_events(max(500, int(rate * duration) + 10))
    interval = 1.0 / rate if rate > 0 else 0.0

    tasks: list[asyncio.Task] = []
    async with httpx.AsyncClient() as client:
        start = time.monotonic()
        i = 0
        while time.monotonic() - start < duration:
            row = rows[i % len(rows)]
            payload = _to_wazuh_alert(row, datetime.now(timezone.utc))
            tasks.append(asyncio.create_task(_send_one(client, url, token, payload)))
            i += 1
            if interval:
                await asyncio.sleep(interval)
        results = await asyncio.gather(*tasks)
    return list(results)


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
    args = p.parse_args()

    results = asyncio.run(run(args.rate, args.duration, args.url, args.token))
    summary = summarise(results)
    summary["target_rate"] = args.rate
    summary["achieved_rate"] = summary["sent"] / args.duration if args.duration else 0.0
    print(json.dumps(summary, indent=2))


def _demo() -> None:
    """Smallest self-check for the pure logic."""
    s = summarise([
        {"latency_s": 0.01, "ok": True}, {"latency_s": 0.02, "ok": True},
        {"latency_s": 0.30, "ok": True}, {"latency_s": 0.05, "ok": False},
    ])
    assert s["sent"] == 4
    assert s["drop_rate"] == 0.25
    assert s["p50_s"] <= s["p95_s"] <= s["p99_s"]
    assert summarise([])["sent"] == 0
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
