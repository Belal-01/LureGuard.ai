"""
Acceptance checks for the LureGuard change register.

These are NOT unit tests. Each one encodes the definition of "done" for a
register item and is EXPECTED TO FAIL until that item is actually fixed.
`make test` excludes them; run them with `make check`.

Rules for anyone (human or agent) working a register item:
  1. The check defines done. Make it pass by changing the product.
  2. DO NOT modify a check to make it pass. A check the implementer can edit
     proves nothing — that is how tests/test_decision_policy.py came to assert
     that fake DNAT enforcement was correct.
  3. Every check names its register ID so a failure maps to a decision.
"""
from __future__ import annotations

import importlib.util
import json
import re
import warnings
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.acceptance

REPO = Path(__file__).resolve().parents[2]
DASHBOARDS = REPO / "grafana" / "provisioning" / "dashboards" / "json"
INTEGRATION = REPO / "wazuh" / "integrations" / "custom-lureguard.py"

# Panel types that render a number and therefore need a unit + severity colouring.
NUMERIC_PANELS = {"stat", "gauge", "bargauge", "timeseries"}


def _walk(panels):
    for p in panels:
        yield p
        yield from _walk(p.get("panels", []))


def _all_panels():
    for f in sorted(DASHBOARDS.glob("*.json")):
        for p in _walk(json.loads(f.read_text(encoding="utf-8")).get("panels", [])):
            yield f.name, p


def _load_integration():
    spec = importlib.util.spec_from_file_location("custom_lureguard", INTEGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── A · Ingest ────────────────────────────────────────────────────────────────

def _stub_server(status: int):
    """A real HTTP server that records hits and returns `status`.

    VER-5: these checks used to monkeypatch `mod.requests`, which forced the
    module to import requests at top level — pinning the HTTP library into the
    contract and costing ~49ms per alert that ING-7 could not remove. The
    requirement was always behavioural: retry transport failures, fail fast on
    permanent rejections. Driving a real server asserts exactly that and leaves
    the implementation free.
    """
    import http.server
    import threading

    hits: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, hits, f"http://127.0.0.1:{srv.server_port}/wazuh/event"


def _free_port() -> int:
    """A port with nothing listening — connecting to it fails at transport."""
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_ing_1_alert_delivery_retries_and_signals_failure():
    """ING-1: a transport failure must retry, then signal — never vanish."""
    mod = _load_integration()

    # 5xx is retryable: the server is reachable but unhealthy.
    srv, hits, url = _stub_server(503)
    try:
        with pytest.raises(Exception) as exc:
            mod._post_alert({"rule": {}}, url, api_key="t", backoff_seconds=0.01)
    finally:
        srv.shutdown()

    assert len(hits) >= 3, (
        f"ING-1: no retry — the endpoint was hit {len(hits)}x on a retryable 503. "
        "A single failure currently loses the alert permanently."
    )
    assert not isinstance(exc.value, SystemExit), (
        "ING-1: must raise a catchable delivery error, not sys.exit — the caller "
        "needs a chance to dead-letter the alert."
    )

    # And a genuine transport failure (nothing listening) must behave the same.
    dead = f"http://127.0.0.1:{_free_port()}/wazuh/event"
    with pytest.raises(Exception) as exc2:
        mod._post_alert({"rule": {}}, dead, api_key="t", backoff_seconds=0.01)
    assert not isinstance(exc2.value, SystemExit), (
        "ING-1: a connection failure must raise a catchable error, not exit."
    )


def test_ing_2_non_2xx_response_is_treated_as_failure():
    """ING-2: a 401 from a wrong INGEST_TOKEN must be loud, and must not burn
    the retry budget — the request arrived and was permanently rejected."""
    mod = _load_integration()

    srv, hits, url = _stub_server(401)
    try:
        with pytest.raises(Exception) as exc:
            mod._post_alert({"rule": {}}, url, api_key="wrong", backoff_seconds=0.01)
    finally:
        srv.shutdown()

    assert not isinstance(exc.value, SystemExit), (
        "ING-2: must signal a delivery failure the caller can act on."
    )
    assert len(hits) == 1, (
        f"ING-2: a 401 is permanent, but the endpoint was hit {len(hits)}x. "
        "Retrying a bad token wastes integratord's time budget (ING-3)."
    )


# ── B · Storage ───────────────────────────────────────────────────────────────

def test_sto_2_events_table_is_time_partitioned():
    """STO-2: retention must be DROP PARTITION, not a bulk DELETE."""
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from db.models import Event

    kwargs = next(
        (a for a in getattr(Event, "__table_args__", ()) if isinstance(a, dict)), {}
    )
    assert kwargs.get("postgresql_partition_by", "").lower().startswith("range"), (
        "STO-2: events is an unpartitioned heap table. Retention would need a bulk "
        "DELETE (WAL amplification, index bloat, VACUUM FULL to reclaim disk). "
        "Declare postgresql_partition_by='RANGE (ts)'."
    )


# ── D · ML ────────────────────────────────────────────────────────────────────

def test_ml_3_model_loads_without_version_mismatch():
    """ML-3: a cross-version unpickle may silently produce invalid results."""
    joblib = pytest.importorskip("joblib")
    model = REPO / "ml" / "models" / "model.joblib"
    if not model.exists():
        pytest.skip("model artifact not present")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        joblib.load(model)

    mismatches = [w for w in caught if "InconsistentVersionWarning" in type(w.message).__name__]
    assert not mismatches, (
        f"ML-3: model was pickled by a different scikit-learn than the one loading it "
        f"({mismatches[0].message}). Pin scikit-learn and retrain, or ship a version-"
        "matched artifact. The SHA-256 registry check does not catch this."
    )


# ── G · Grafana ───────────────────────────────────────────────────────────────

def test_gfa_3a_numeric_panels_declare_a_unit():
    offenders = [
        f"{f}:{p.get('title')}"
        for f, p in _all_panels()
        if p.get("type") in NUMERIC_PANELS
        and not p.get("fieldConfig", {}).get("defaults", {}).get("unit")
    ]
    assert not offenders, (
        f"GFA-3: {len(offenders)} numeric panels render raw integers with no unit. "
        f"First few: {offenders[:5]}"
    )


def test_gfa_3b_numeric_panels_declare_severity_thresholds():
    offenders = [
        f"{f}:{p.get('title')}"
        for f, p in _all_panels()
        if p.get("type") in NUMERIC_PANELS
        and len(
            p.get("fieldConfig", {}).get("defaults", {}).get("thresholds", {}).get("steps", [])
        )
        < 2
    ]
    assert not offenders, (
        f"GFA-3: {len(offenders)} numeric panels have no multi-step thresholds, so "
        f"nothing is coloured by severity. First few: {offenders[:5]}"
    )


def test_gfa_2_every_dashboard_has_template_variables():
    bare = []
    for f in sorted(DASHBOARDS.glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        if not d.get("templating", {}).get("list"):
            bare.append(f.name)
    assert not bare, (
        f"GFA-2: {len(bare)} dashboards have zero template variables: {bare}. "
        "Without variables the only way to show another slice is another panel — "
        "this is the mechanical cause of the cross-dashboard redundancy."
    )


# ── H · Data model ────────────────────────────────────────────────────────────

def test_sch_1_events_link_to_investigations():
    """SCH-1: gates the verdict-vs-Wazuh-level panel (GFA-5), which is a join."""
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from db.models import Event

    assert "investigation_id" in {c.name for c in Event.__table__.columns}, (
        "SCH-1: events cannot be joined to investigations, so agent verdict cannot "
        "be compared to Wazuh rule level — the one dashboard Wazuh cannot produce."
    )


def test_sch_3_tool_calls_record_token_cost():
    """SCH-3: cost per triage is a quality axis with no data source."""
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from db.models import AgentAction

    cols = {c.name for c in AgentAction.__table__.columns}
    assert cols & {"input_tokens", "output_tokens", "cost_usd"}, (
        f"SCH-3: agent_actions records duration_ms but no token or cost fields "
        f"(has: {sorted(cols)}). Cost per triage has no source."
    )


# ── J · Install ───────────────────────────────────────────────────────────────

def test_ins_3_honeypots_are_not_in_the_default_stack():
    """INS-3: cowrie is lab noise by default, especially now the redirect path is gone."""
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose.get("services", {})
    unprofiled = [
        name
        for name, svc in services.items()
        if "cowrie" in name and not svc.get("profiles")
    ]
    assert not unprofiled, (
        f"INS-3: {unprofiled} start with the default stack. Put them behind a compose "
        "profile so the base footprint drops by two containers."
    )


# ══════════════════════════════════════════════════════════════════════════════
# Sprint 1
# ══════════════════════════════════════════════════════════════════════════════

def test_ing_4_telegram_is_off_the_ingest_critical_path():
    """ING-4: an external HTTP call must not block ingest or hold a transaction.

    Today `process_event` awaits `send_alert()` to completion and `get_db`
    commits only after the handler returns, so a slow Telegram both blocks the
    response past integratord's timeout and holds a Postgres transaction open.
    Alerting must be dispatched (queued / scheduled), not awaited inline.
    """
    import asyncio
    import sys
    import time
    from unittest.mock import AsyncMock, patch

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    import numpy as np
    from modules.decision_policy import process_event, update_whitelist
    from schemas.normalized_event import NormalizedEvent

    async def slow_alert(*a, **kw):
        await asyncio.sleep(2.0)

    async def run():
        event = NormalizedEvent(
            src_ip="10.0.0.5", channel="sshd", event_type="auth_failed", username="root"
        )
        with (
            patch("modules.inference.infer", return_value={"p": 0.95, "model_version": "t"}),
            patch("modules.feature_extractor.extract_ssh_features") as feats,
            patch("modules.decision_policy.crud.insert_event", new=AsyncMock()),
            patch("modules.decision_policy.crud.insert_decision", new=AsyncMock()),
            patch("modules.alerting.send_alert", new=slow_alert),
        ):
            f = np.ones(8, dtype=np.float32)
            f[0] = 10.0
            feats.return_value = f
            update_whitelist([])
            t0 = time.perf_counter()
            await process_event(event, AsyncMock())
            return time.perf_counter() - t0

    elapsed = asyncio.run(run())
    assert elapsed < 0.5, (
        f"ING-4: process_event took {elapsed:.2f}s with a 2s alerting call — it is "
        "awaiting Telegram inline, inside the request and the open transaction. "
        "Dispatch alerting instead of awaiting it."
    )


def test_sto_1_retention_selects_partitions_to_drop():
    """STO-1: retention must exist and pick the right partitions.

    Pure logic — given the partition names on the table and a retention window,
    which get dropped. Must never select the DEFAULT partition (dropping it
    discards every row outside the dated ranges) and must respect STO-8: rows
    stranded in DEFAULT block creation of an overlapping dated partition.
    """
    from datetime import datetime

    try:
        from core.retention import partitions_to_drop
    except ImportError:
        import sys

        sys.path[:0] = [str(REPO / "core"), str(REPO)]
        try:
            from retention import partitions_to_drop
        except ImportError:
            raise AssertionError(
                "STO-1: no retention module. Expected `partitions_to_drop(names, "
                "retention_days, now)` in core/retention.py — events now partitions "
                "by month (STO-2) but nothing ever drops one."
            )

    names = [
        "events_2026_03", "events_2026_04", "events_2026_05",
        "events_2026_06", "events_2026_07", "events_2026_08", "events_default",
    ]
    now = datetime(2026, 8, 14)
    got = set(partitions_to_drop(names, retention_days=90, now=now))

    assert "events_default" not in got, (
        "STO-1: DEFAULT must never be dropped — it holds every row outside the "
        "dated ranges."
    )
    assert "events_2026_03" in got and "events_2026_04" in got, (
        f"STO-1: partitions older than the window should be dropped, got {sorted(got)}"
    )
    assert "events_2026_08" not in got and "events_2026_07" not in got, (
        f"STO-1: in-window partitions must be kept, got {sorted(got)}"
    )


def test_ins_2_demo_dataset_generates_realistic_events():
    """INS-2: the product must do something on minute one without an attacker."""
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    try:
        from demo_seed import generate_events
    except ImportError:
        raise AssertionError(
            "INS-2: no demo dataset. Expected `generate_events(n)` in "
            "core/demo_seed.py returning normalized event dicts, plus a `make demo` "
            "target. Without it nothing can be demonstrated, evaluated, or used to "
            "test a skill."
        )

    rows = generate_events(500)
    assert len(rows) >= 500, f"INS-2: asked for 500 events, got {len(rows)}"

    channels = {r.get("channel") for r in rows}
    assert len(channels) >= 3, (
        f"INS-2: only channels {channels} — a demo with one channel cannot "
        "exercise triage across alert types."
    )
    assert any(int(r.get("wazuh_rule_level") or 0) >= 10 for r in rows), (
        "INS-2: no high-severity events, so the dataset cannot demonstrate triage."
    )
    ips = {r.get("src_ip") for r in rows}
    assert len(ips) >= 10, f"INS-2: only {len(ips)} distinct source IPs"


def test_pos_2_close_investigation_rejects_uncited_findings():
    """POS-2: the differentiator, made a hard invariant instead of a convention.

    "No conclusion without tool output" is stated in AGENTS.md and enforced
    nowhere. An investigation must not be closeable with a verdict that no
    recorded finding supports.
    """
    import inspect

    from lureguard_mcp.repos import investigations as inv

    fn = getattr(inv, "close_investigation_db", None)
    assert fn is not None, "POS-2: close_investigation_db not found"

    src = inspect.getsource(fn)
    guards = ("citation", "finding", "uncited", "evidence")
    assert any(g in src.lower() for g in guards), (
        "POS-2: close_investigation_db accepts any verdict without checking that a "
        "cited finding supports it. Reject closure when the investigation has no "
        "findings, or any finding lacks a citation."
    )


def test_ver_4_epss_test_is_hermetic():
    """VER-4: the suite must not depend on a live third-party API."""
    import inspect
    import socket
    from unittest.mock import patch

    import tests.test_posture_uplift as mod

    fn = mod.test_fetch_epss_batch_ubuntu_prefixed_ids

    def no_net(*a, **kw):
        raise AssertionError("live network call")

    # Supply fixtures ourselves — we invoke the test directly, so pytest is not
    # here to inject them.
    mp = pytest.MonkeyPatch()
    kwargs = {"monkeypatch": mp} if "monkeypatch" in inspect.signature(fn).parameters else {}

    try:
        with patch.object(socket, "socket", no_net), patch.object(
            socket, "create_connection", no_net
        ):
            fn(**kwargs)
    except AssertionError as exc:
        if "live network call" in str(exc):
            raise AssertionError(
                "VER-4: test_fetch_epss_batch_ubuntu_prefixed_ids reaches "
                "api.first.org over the network. The suite is non-hermetic: the "
                "passing count is unstable and it fails offline. Mock the HTTP "
                "boundary; keep one opt-in contract test for the real API."
            ) from None
        raise
    finally:
        mp.undo()


def test_gfa_5_analyst_dashboard_exists():
    """GFA-5: the one view a SIEM structurally cannot produce."""
    path = DASHBOARDS / "analyst.json"
    assert path.exists(), (
        "GFA-5: no analyst dashboard. Wazuh shows what happened; it cannot show "
        "what was concluded, on what evidence, and whether it was right. Needs a "
        "verdict-vs-Wazuh-rule-level view and a disagreement queue deep-linked to "
        "the evidence chain."
    )
    d = json.loads(path.read_text(encoding="utf-8"))
    blob = json.dumps(d).lower()
    assert d.get("templating", {}).get("list"), "GFA-5: analyst dashboard has no variables"
    assert "verdict" in blob and "wazuh_rule_level" in blob, (
        "GFA-5: the dashboard must actually join agent verdict against Wazuh rule "
        "level — that comparison is the whole point."
    )


# ══════════════════════════════════════════════════════════════════════════════
# Sprint 2 — measurement
# ══════════════════════════════════════════════════════════════════════════════

def test_ing_5_dedup_does_not_degrade_quadratically():
    """ING-5: the stale-key prune scans the whole dict on EVERY event.

    At 1k events/sec that is ~60k comparisons per event inside the 60s window —
    the ingest hot path gets slower the busier it gets, which is exactly backwards.
    Amortise the prune (bounded structure / expiry on read) so cost per event is
    flat, and cap memory so the window cannot grow without limit.
    """
    import sys
    import time

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from modules import ingest_dedup

    def burst(n: int) -> float:
        ingest_dedup.reset()
        t0 = time.perf_counter()
        for i in range(n):
            ingest_dedup.is_duplicate_wazuh_event(f"10.0.{i // 256}.{i % 256}", i, f"2026-08-14T00:00:{i % 60:02d}")
        return time.perf_counter() - t0

    small = burst(2_000)
    large = burst(20_000)
    ingest_dedup.reset()

    # 10x the events should cost roughly 10x, not 100x. Generous ceiling so this
    # measures the algorithm, not the machine.
    ratio = large / max(small, 1e-6)
    assert ratio < 30, (
        f"ING-5: 2k events took {small:.3f}s, 20k took {large:.3f}s — {ratio:.0f}x for "
        "10x the load. The per-event prune is O(n); cost per event must stay flat."
    )


def test_ing_6_ingest_response_does_not_claim_to_queue():
    """ING-6: the endpoint returns 202 {"status": "queued"} and queues nothing.

    Either queue it or say what actually happened. Claiming a durability
    property the code does not have is the same defect class as the DNAT that
    logged success while doing nothing.
    """
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from api.wazuh_endpoint import router

    route = next(r for r in router.routes if getattr(r, "path", None) == "/wazuh/event")

    # Behavioural, not source-text: an earlier version of this check grepped the
    # module for the literal string, which constrained how the docstring could be
    # worded and would have passed on a rename that kept the lie.
    assert route.status_code != 202, (
        "ING-6: the handler declares 202 Accepted, which promises the work was "
        "handed off. Normalize, inference and the DB write all run inline before "
        "the response. Return a status that describes what actually happened, or "
        "introduce a real queue behind it."
    )


def test_ver_1_eval_harness_reports_the_quality_axes():
    """VER-1: every quality axis is unmeasured, and absent reads as zero.

    The demo dataset (INS-2) is labelled by construction — we know which events
    are the brute-force burst and which are benign — so detection efficacy is
    measurable without waiting to be attacked. Nobody in this category publishes
    these numbers; a reproducible `make eval` is therefore a differentiator, not
    table stakes.
    """
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    try:
        from evaluate import run_eval
    except ImportError:
        raise AssertionError(
            "VER-1: no evaluation harness. Expected `run_eval()` in core/evaluate.py "
            "returning measured quality metrics, plus a `make eval` target. Without "
            "it the honest answer to 'how good is it' stays 'unknown'."
        )

    report = run_eval()
    required = {"true_positive_rate", "false_positive_rate", "events_evaluated"}
    missing = required - set(report)
    assert not missing, f"VER-1: eval report missing {sorted(missing)}; got {sorted(report)}"

    assert report["events_evaluated"] > 0, "VER-1: evaluated nothing"
    for k in ("true_positive_rate", "false_positive_rate"):
        assert 0.0 <= report[k] <= 1.0, f"VER-1: {k}={report[k]} is not a rate"
    assert report["true_positive_rate"] != 1.0 or report["false_positive_rate"] != 0.0, (
        "VER-1: a perfect score on the first run is a leak, not a result — the same "
        "mistake as ML-1's 0.9996 precision. Verify the labels are not derived from "
        "the thing being scored."
    )


def test_arc_1_load_harness_measures_ingest_under_pressure():
    """ARC-1 + ING-3: footprint and backpressure are still estimates.

    ARC-1's ~969 MiB is an idle snapshot with a 7x swing between readings, and
    ING-3's claim that a slow consumer makes Wazuh drop alerts has never been
    measured against integratord's real queue depth. Both need a load driver.
    """
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    try:
        from loadtest import summarise
    except ImportError:
        raise AssertionError(
            "ARC-1/ING-3: no load harness. Expected `summarise(results)` in "
            "core/loadtest.py returning latency percentiles and a drop rate, plus a "
            "`make loadtest` target that drives POST /wazuh/event at a configurable "
            "rate. Assurance rung 6 — nothing above it can be trusted without it."
        )

    sample = [
        {"latency_s": 0.01, "ok": True}, {"latency_s": 0.02, "ok": True},
        {"latency_s": 0.30, "ok": True}, {"latency_s": 0.05, "ok": False},
    ]
    s = summarise(sample)
    required = {"p50_s", "p95_s", "p99_s", "drop_rate", "sent"}
    missing = required - set(s)
    assert not missing, f"ARC-1: summary missing {sorted(missing)}; got {sorted(s)}"
    assert s["sent"] == 4
    assert s["drop_rate"] == pytest.approx(0.25), (
        f"ARC-1: 1 of 4 requests failed, drop_rate should be 0.25, got {s['drop_rate']}"
    )
    assert s["p50_s"] <= s["p95_s"] <= s["p99_s"], "ARC-1: percentiles out of order"


def test_ml_7_features_are_deterministic_across_processes():
    """ML-7: `decoder_hash` is built from Python's builtin hash(), which is
    randomized per process (PYTHONHASHSEED).

    Consequences, in order of severity:
      1. The model was trained under one seed and is served under a fresh random
         one every restart, so this feature is uncorrelated noise in production.
      2. The same event scored in two processes can yield different features and
         therefore different verdicts — determinism, a quality axis this product
         claims to care about, is not merely unmeasured but violated.

    Use a stable hash (hashlib / zlib.crc32), not builtin hash().
    """
    import subprocess
    import sys

    code = (
        "import sys; sys.path[:0]=['.']; "
        "from ml.alert_features import decoder_hash_value; "
        "print(decoder_hash_value('sshd'))"
    )
    seen = {
        subprocess.run(
            [sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True
        ).stdout.strip()
        for _ in range(3)
    }
    assert len(seen) == 1, (
        f"ML-7: decoder_hash_value('sshd') returned {sorted(seen)} across three "
        "processes. A model feature must not change when the process restarts."
    )


def test_ing_8_alerting_does_not_block_the_event_loop(monkeypatch):
    """ING-8: alerting calls a blocking urlopen from inside the event loop.

    ING-4 moved Telegram off the request path into asyncio.create_task, but
    asyncio is single-threaded — a task that blocks on I/O stalls every other
    request and the accept loop with it. Measured: 5 req/s against
    POST /wazuh/event dropped 87%. Offload the send (asyncio.to_thread, or
    httpx.AsyncClient in connectors/telegram.py).
    """
    import asyncio
    import importlib
    import sys
    import time
    import types

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from modules import alerting

    # conftest's autouse _no_real_telegram fixture replaces these two coroutines
    # with AsyncMocks; reload to get the real ones back. Without this the check
    # measures a mock and always passes.
    importlib.reload(alerting)

    # Stand in for the network: 0.5s of blocking I/O, well under the 3s default
    # TELEGRAM_TIMEOUT_SECONDS this would really spend on a slow Telegram.
    def blocking_send(message, **kwargs):
        time.sleep(0.5)
        return {"sent": True}

    monkeypatch.setattr(alerting, "telegram_notifier", types.SimpleNamespace(send_message=blocking_send))
    monkeypatch.setattr(alerting, "should_send_telegram", lambda *a, **k: True)
    monkeypatch.setattr(alerting, "format_fim_alert", lambda event: "alert")
    event = types.SimpleNamespace(channel="syscheck", event_type="file_change", src_ip="192.0.2.1")

    async def measure() -> float:
        ticks: list[float] = []

        async def ticker():
            while True:
                ticks.append(time.perf_counter())
                await asyncio.sleep(0.01)

        t = asyncio.create_task(ticker())
        await asyncio.sleep(0.05)  # let the ticker settle
        await alerting.send_non_ssh_alert(event)
        await asyncio.sleep(0.05)  # let the ticker record a post-send tick
        t.cancel()
        return max(b - a for a, b in zip(ticks, ticks[1:]))

    stall = asyncio.run(measure())
    assert stall < 0.2, (
        f"ING-8: sending one alert starved the event loop for {stall:.2f}s. Every "
        "other in-flight request and every new connection waits that long, on every "
        "alert-eligible event. Run the blocking send off the loop thread."
    )


# ══════════════════════════════════════════════════════════════════════════════
# Sprint 4 — parallel streams
# ══════════════════════════════════════════════════════════════════════════════

def test_ml_2_behavioural_features_reach_the_model():
    """ML-2: f1–f8 are computed, hashed for audit, then thrown away.

    The rolling-window signals (attempt count, failure ratio, distinct usernames
    per source IP) are the only features that carry brute-force information.
    Today only f1 survives, as a threshold gate, while the model scores 24 Wazuh
    metadata features that are near-constant once the SSH gate has applied.

    The property that matters: two events with IDENTICAL Wazuh metadata but
    different attack history must score differently. If they don't, the model is
    blind to behaviour no matter what it is trained on.
    """
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from modules import feature_extractor, inference
    from schemas.normalized_event import NormalizedEvent

    def score(n_prior: int) -> float:
        feature_extractor.reset() if hasattr(feature_extractor, "reset") else None
        from runtime import window_store

        window_store.reset_extractor()
        ev = None
        for i in range(n_prior):
            ev = NormalizedEvent(src_ip="203.0.113.9", channel="sshd",
                                 event_type="auth_failed", username=f"user{i}")
            feature_extractor.extract_ssh_features(ev)
        ev = NormalizedEvent(src_ip="203.0.113.9", channel="sshd",
                             event_type="auth_failed", username="root")
        x = feature_extractor.extract_ssh_features(ev)
        from ml.alert_features import featurize_normalized_event

        row = featurize_normalized_event(ev)
        row = dict(row)
        for i, v in enumerate(x, start=1):
            row.setdefault(f"f{i}", float(v))
        return inference.infer_event(row)["p"]

    quiet, sustained = score(1), score(40)
    assert abs(sustained - quiet) > 1e-6, (
        f"ML-2: a single failed login and a 40-attempt username sweep from the same "
        f"IP both score {quiet:.6f}. The behavioural features never reach the model, "
        "so it cannot distinguish a typo from a brute-force run."
    )


def test_sto_4_event_ids_are_time_ordered():
    """STO-4: random UUIDv4 on the highest-insert table splits B-tree pages."""
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from db.models import Event

    default = Event.__table__.c.id.default
    assert default is not None, "STO-4: events.id has no default"
    gen = default.arg
    ids = [str(gen({}) if callable(gen) else gen) for _ in range(50)]
    ordered = sum(1 for a, b in zip(ids, ids[1:]) if a < b)
    assert ordered >= 45, (
        f"STO-4: only {ordered}/49 consecutive generated ids increase — the key is "
        "random, so every insert lands on an arbitrary page. Use UUIDv7/ULID or a "
        "bigint identity so inserts append."
    )


def test_sec_3_ssh_supports_key_auth_without_a_password():
    """SEC-3: a plaintext fleet password will not survive a senior review."""
    import inspect

    from lureguard_mcp import ssh_remote

    src = inspect.getsource(ssh_remote)
    assert any(k in src for k in ("client_keys", "private_key", "key_path", "identity")), (
        "SEC-3: ssh_remote offers no key-based path — ONBOARD_SSH_PASSWORD in .env is "
        "the only way to reach the fleet, and it is used to push iptables rules."
    )


def test_ml_4_wazuh_rules_map_to_attack_techniques():
    """ML-4: unmapped coverage is invisible coverage, and gates GFA-7."""
    import json as _json

    candidates = [REPO / "core" / "attack_map.json", REPO / "wazuh" / "attack_map.json",
                  REPO / "lureguard_mcp" / "attack_map.json"]
    path = next((p for p in candidates if p.exists()), None)
    assert path is not None, (
        "ML-4: no ATT&CK mapping. Wazuh's rules already cover techniques, but nothing "
        "records which — so coverage cannot be shown (GFA-7) or measured."
    )
    doc = _json.loads(path.read_text(encoding="utf-8"))
    # Tolerate either a flat rule->mapping dict or a {_meta, rules} document —
    # the requirement is the mapping, not the envelope.
    m = doc.get("rules", doc) if isinstance(doc, dict) else doc
    m = {k: v for k, v in m.items() if not k.startswith("_")}
    assert len(m) >= 10, f"ML-4: only {len(m)} rules mapped"

    tids, sources = [], set()
    for v in m.values():
        entries = v.get("attack", v) if isinstance(v, dict) else v
        if isinstance(v, dict) and "source" in v:
            sources.add(v["source"])
        for t in entries if isinstance(entries, list) else [entries]:
            tids.append(t if isinstance(t, str) else t.get("technique", ""))

    assert all(re.match(r"^T\d{4}(\.\d{3})?$", t) for t in tids if t), (
        f"ML-4: technique ids must look like T1110 / T1110.001; got {tids[:5]}"
    )
    # Provenance must survive: a mapping read from Wazuh's own metadata and one
    # assigned by hand carry very different confidence, and flattening them
    # would let guesses masquerade as vendor data.
    assert sources, "ML-4: no `source` recorded — provenance of each mapping must be visible"


def test_skl_2_agent_instructions_have_one_source():
    """SKL-2: four locations means three of them are silently stale."""
    dupes = [p for p in (REPO / ".claude/skills/lureguard/SKILL.md",
                         REPO / ".agents/skills/lureguard/SKILL.md")
             if p.exists() and not p.is_symlink()]
    assert not dupes, (
        f"SKL-2: {[str(p.relative_to(REPO)) for p in dupes]} are real files duplicating "
        "the same router. Keep one canonical copy and symlink or generate the rest."
    )


def test_gfa_1_stat_panels_carry_a_baseline():
    """GFA-1: a bare number cannot be judged normal or abnormal.

    Security analysis is deviation detection — the analyst's only real question
    is "is this different from usual?". A stat panel showing `47` cannot answer
    it. Grafana's stat panel draws a sparkline behind the number when
    options.graphMode is "area"/"line", which turns a point reading into a
    reading plus its recent shape — the cheapest honest fix, no panel-type churn.

    A sparkline needs a series to draw, so the panel's query must group by time.
    Setting graphMode on a query that returns one scalar row yields a flat line,
    which looks like a baseline while carrying no information — the same class
    of defect as every other item in this register.

    Not every stat can have one, and pretending otherwise would be its own
    defect. Panels reading the posture caches (cve_findings, sca_findings,
    user_findings, hosts, container_cve_findings, blocklist) show current state:
    those tables are overwritten by each scan, so no history exists and a
    sparkline drawn over them would be fabricated. Those must instead say in
    their description that they are point-in-time, so the reader knows the
    number has no trend rather than assuming one was omitted.

    So: time-scoped panels must show their trend; snapshot panels must admit
    they are snapshots. Silence is what is not allowed.
    """
    bare, scalar, unlabelled, hardcoded = [], [], [], []
    for f, p in _all_panels():
        if p.get("type") != "stat":
            continue
        name = f"{f}:{p.get('title')}"
        sql = " ".join(t.get("rawSql", "") for t in p.get("targets", [])).lower()
        grouped = any(k in sql for k in ("$__timegroup", "date_trunc", "time_bucket"))
        time_scoped = "$__timefilter" in sql or grouped
        has_spark = p.get("options", {}).get("graphMode") in ("area", "line")

        # GFA-9: a hardcoded window silently ignores the dashboard time picker.
        # Select 7 days and the panel still reports 24 hours — and because it
        # never calls $__timeFilter it also *looks* like a snapshot when its
        # data has history, which is how these escaped the trend requirement.
        if "interval '" in sql and "$__timefilter" not in sql:
            hardcoded.append(name)

        # Three shapes, not two. Refined while building the coverage dashboard
        # (GFA-7), which surfaced the third:
        #   series          -> per-interval value; show the trend
        #   range aggregate -> one number for the whole selected window, where
        #                      a per-interval version is meaningless ("techniques
        #                      dark in this 5-minute bucket" is near-everything)
        #   snapshot        -> current state, no history exists
        # A range aggregate must say the number covers the selected range, so
        # the reader knows what window they are looking at. It is not a general
        # escape from the trend requirement: a panel that CAN be per-interval
        # and simply says "over the selected range" is still gaming this, and
        # the reviewer, not the check, is the guard there.
        desc_l = (p.get("description") or "").lower()
        range_agg = "selected range" in desc_l

        if time_scoped and not range_agg:
            if not has_spark:
                bare.append(name)
            elif not grouped:
                scalar.append(name)
        elif time_scoped:
            pass  # labelled range aggregate
        else:
            desc = (p.get("description") or "").lower()
            if not any(k in desc for k in ("point-in-time", "snapshot", "current state")):
                unlabelled.append(name)

    assert not bare, (
        f"GFA-1: {len(bare)} time-scoped stat panels render a bare number with no "
        f"baseline, though their data has history. First few: {bare[:5]}"
    )
    assert not scalar, (
        f"GFA-1: {len(scalar)} stat panels declare a sparkline but their query "
        f"returns a single scalar, so the line is flat and meaningless — a visual "
        f"implying information it does not have. First few: {scalar[:5]}"
    )
    assert not unlabelled, (
        f"GFA-1: {len(unlabelled)} snapshot stat panels neither show a trend nor say "
        f"they cannot. Mark them point-in-time so a reader knows the number has no "
        f"history. First few: {unlabelled[:5]}"
    )
    assert not hardcoded, (
        f"GFA-9: {len(hardcoded)} stat panels hardcode their own time window and "
        f"ignore the dashboard time picker — select 7 days and they still report 24 "
        f"hours. Use $__timeFilter. First few: {hardcoded[:5]}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# Sprint 5 — parallel batch
# ══════════════════════════════════════════════════════════════════════════════

def test_flt_2_invariants_are_stated_and_enforced():
    """FLT-2: six architectural invariants existed nowhere and five were violated.

    You do not test architecture — you state invariants and then try to break
    them. That list was carried in conversation and in this register's prose,
    which means it could not be checked, handed over, or regression-guarded.
    """
    doc = REPO / "docs" / "INVARIANTS.md"
    assert doc.exists(), (
        "FLT-2: no invariants document. The six properties this system must hold "
        "(no alert acknowledged unless committed; no verdict without a model; no "
        "claim without a citation; no unbounded growth; no external I/O inside a "
        "transaction; restart changes nothing) are stated nowhere in the repo."
    )
    text = doc.read_text(encoding="utf-8")
    required = ["committed", "model", "citation", "growth", "transaction", "restart"]
    missing = [k for k in required if k not in text.lower()]
    assert not missing, f"FLT-2: invariants doc omits {missing}"
    assert "INV-" in text, "FLT-2: invariants need stable ids so checks can cite them"


def test_skl_1_skills_declare_tools_that_exist():
    """SKL-1: a skill referencing a tool the server does not expose is broken
    the moment an agent runs it, and nothing catches that today."""
    server = (REPO / "lureguard_mcp" / "server.py").read_text(encoding="utf-8")
    exposed = set(re.findall(r"^def ([a-z_][a-z0-9_]*)\(", server, re.M))
    exposed |= set(re.findall(r'name="([a-z_][a-z0-9_]*)"', server))

    skills = [p for p in (REPO / "skills").glob("*.md") if p.name != "SKILL.md"]
    assert skills, "SKL-1: no skills found"

    no_fm, bad_tools = [], []
    for p in skills:
        head = p.read_text(encoding="utf-8")
        if not head.startswith("---"):
            no_fm.append(p.name)
            continue
        fm = yaml.safe_load(head.split("---", 2)[1]) or {}
        tools = fm.get("requires_tools") or []
        for t in tools:
            if t not in exposed:
                bad_tools.append(f"{p.name}:{t}")

    assert not no_fm, (
        f"SKL-1: {len(no_fm)} skills have no frontmatter contract, so nothing "
        f"declares what they need or verifies it still exists: {no_fm[:6]}"
    )
    assert not bad_tools, (
        f"SKL-1: skills reference MCP tools the server does not expose — these "
        f"fail at runtime, silently, the first time an agent follows them: {bad_tools[:6]}"
    )


def test_ops_1_doctor_detects_stale_container_code():
    """OPS-1: the running container did not contain the repo's code.

    This silently invalidates anything measured against the live stack — a load
    test against a stale image reports the old code's behaviour with entirely
    convincing numbers. It has already happened once in this project.
    """
    src = (REPO / "lureguard_mcp" / "doctor.py").read_text(encoding="utf-8")
    assert "stale" in src.lower() or "image" in src.lower(), (
        "OPS-1: `make doctor` verifies Docker is up, Postgres answers and the API "
        "responds — but never that the running container was built from the code in "
        "the working tree. Add a check so a stale image is loud, not silent."
    )


def test_sto_8_stranded_default_rows_can_be_migrated():
    """STO-8: DEFAULT sets in concrete, and the earlier check missed it.

    The previous version asserted `ensure_future_partitions` existed and that
    the module mentioned "default". Both were true while the actual defect stood
    — verified live: rows remain in `events_default`, and
    `CREATE TABLE events_2026_06 PARTITION OF events` still fails with
    "updated partition constraint for default partition would be violated by
    some row". A check that passes while its defect is reproducible is the thing
    this whole register exists to eliminate.

    The property that matters: there is a way to reclaim rows stranded in
    DEFAULT into dated partitions, so retention can eventually drop them. Rows
    that can never leave DEFAULT can never be dropped, which is STO-1 reopened
    by the back door.
    """
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    import retention

    fn = next((getattr(retention, n, None) for n in
               ("backfill_default_rows", "migrate_default_partition",
                "reclaim_default_rows") if getattr(retention, n, None)), None)
    assert fn is not None, (
        "STO-8: nothing can reclaim rows stranded in events_default. Postgres "
        "refuses to create any dated partition overlapping them, so those rows "
        "are permanently undroppable — retention silently stops applying to the "
        "oldest data in the table."
    )

    months = getattr(retention, "months_spanned", None)
    assert months is not None, (
        "STO-8: the month range to backfill must be computable without a "
        "database, so the selection logic is testable on its own."
    )
    from datetime import datetime

    got = months(datetime(2026, 6, 27), datetime(2026, 8, 3))
    assert got == ["2026_06", "2026_07", "2026_08"], (
        f"STO-8: months_spanned should cover every month touched by the stranded "
        f"rows, got {got}"
    )


def test_sec_4_remote_postgres_has_a_credential_model():
    """SEC-4: MCP hardcodes localhost:5433 with credentials in plaintext.

    ADR-4 puts the collector on the target and the analyst on a laptop, so the
    database stops being local. Today there is no TLS setting and no way to
    supply a credential that is not a plaintext password in .env.
    """
    import inspect

    from lureguard_mcp import config

    # Scope to the Postgres URL builder specifically. An earlier version of this
    # check grepped the whole module for "ssl" and passed on wazuh_verify_ssl —
    # a setting for a different service entirely. A check that can be satisfied
    # by an unrelated function is a false green.
    src = inspect.getsource(config.database_url_sync)
    assert "sslmode" in src, (
        "SEC-4: database_url_sync builds a Postgres URL with no sslmode. Under "
        "ADR-4 the analyst connects across a network, so an unencrypted link "
        "carries every alert, hostname and finding in clear text."
    )
    url = config.database_url_sync()
    assert "sslmode=" in url, (
        f"SEC-4: the built connection string carries no sslmode: {url.split('@')[-1]}"
    )


def test_skl_3_every_skill_is_reachable_by_command():
    """SKL-3: invocation was `Read skills/triage.md and ...` — a prompt
    convention that asks the user to know where a file lives.

    The property is *reachability*, not name-matching. An earlier version of
    this check required a command whose filename matched the skill, and an
    implementer duly created `/incident-report` alongside the existing
    `/report`, `/investigate-host` alongside `/investigate`, and two more — four
    redundant verbs that exist only to satisfy a check, making the command list
    harder to scan than before. A skill reached by `/report` does not need a
    second command named after its file.
    """
    skills = {p.stem for p in (REPO / "skills").glob("*.md")
              if p.name not in {"SKILL.md", "_shared.md", "opencode-mcp.md"}}
    commands = {p: p.read_text(encoding="utf-8")
                for p in (REPO / ".opencode" / "command").glob("*.md")}
    assert commands, "SKL-3: no slash commands at all"

    unreachable = sorted(
        sk for sk in skills
        if not any(f"skills/{sk}.md" in body for body in commands.values())
    )
    assert not unreachable, (
        f"SKL-3: {len(unreachable)} skills cannot be reached by any slash command, "
        f"so the only way in is to name a file path: {unreachable}"
    )

    # And the inverse: a command routing to a skill that no longer exists is a
    # dead verb the user will type once and never again.
    dead = sorted(
        p.name for p, body in commands.items()
        for ref in re.findall(r"skills/([a-z_-]+)\.md", body)
        if not (REPO / "skills" / f"{ref}.md").exists()
    )
    assert not dead, f"SKL-3: commands route to skills that do not exist: {dead}"


def test_gfa_7_coverage_dashboard_shows_blind_spots():
    """GFA-7: Wazuh shows what fired. It cannot show what should have fired and
    did not — which is the genuinely defensible ground against a SIEM."""
    path = DASHBOARDS / "coverage.json"
    assert path.exists(), (
        "GFA-7: no coverage dashboard. ML-4's ATT&CK mapping now exists, so "
        "technique coverage and silent channels are finally showable."
    )
    d = json.loads(path.read_text(encoding="utf-8"))
    blob = json.dumps(d).lower()
    assert d.get("templating", {}).get("list"), "GFA-7: coverage dashboard has no variables"
    assert "technique" in blob or "attack" in blob, (
        "GFA-7: the dashboard must show ATT&CK technique coverage"
    )
    assert "silent" in blob or "no events" in blob or "last_event" in blob, (
        "GFA-7: must surface channels configured but producing nothing — a broken "
        "log path is invisible in Wazuh, and that is the gap worth owning."
    )


# ══════════════════════════════════════════════════════════════════════════════
# ML rebuild — rules for SSH, classifier for web
# ══════════════════════════════════════════════════════════════════════════════

def test_ml_1_model_features_exclude_wazuh_verdict_fields():
    """ML-1: the model must not be fed Wazuh's own answer.

    The shipped model scored `rule_level`, `rule_id` and `decoder_hash` and
    reported 0.9996 precision — it had learned to predict Wazuh's severity from
    Wazuh's severity. On the web corpus the same trap is sharper: a pure
    `rule_id` lookup table scores **98.36%** across 1.7M rows, because only
    seven rule_ids exist there. Excluding those fields is the only way the leak
    is structurally impossible rather than merely avoided this time.
    """
    import json as _json

    reg = REPO / "ml" / "models" / "model_registry.json"
    if not reg.exists():
        pytest.skip("no model registry")
    cols = _json.loads(reg.read_text(encoding="utf-8")).get("feature_columns", [])
    assert cols, "ML-1: registry declares no feature_columns"

    banned = {c for c in cols if any(
        k in c.lower() for k in ("rule_level", "rule_id", "decoder", "wazuh"))}
    assert not banned, (
        f"ML-1: the feature set contains Wazuh's own verdict: {sorted(banned)}. "
        "Any accuracy measured on these is a lookup of what the SIEM already said."
    )


def test_ml_8_ssh_path_is_rule_driven_not_model_gated():
    """ML-8: the classifier could suppress an alert Wazuh had already escalated.

    Wazuh rule 5712 fires at level 10 on 8 failures in 120s from one source —
    exactly the behaviour f1/f3 were built to compute. The model sat between
    that detection and the operator, and `_apply_min_attempts_gate` could clamp
    p below t1 when our 300s window held fewer events than Wazuh's 120s one.
    Measured: a confirmed level-10 brute force with model p=0.95 resolved to
    `allow` and sent nothing.

    A Wazuh detection must never be silently discarded by our own scoring.
    """
    import sys
    import warnings

    warnings.filterwarnings("ignore")
    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    import importlib

    from modules import decision_policy

    importlib.reload(decision_policy)

    # Whatever the internals, a level-10 Wazuh event must reach the operator.
    from schemas.normalized_event import NormalizedEvent

    ev = NormalizedEvent(
        src_ip="203.0.113.9", channel="sshd", event_type="auth_failed",
        username="root", wazuh_rule_id=5712, wazuh_rule_level=10,
    )
    assert hasattr(decision_policy, "should_alert"), (
        "ML-8: no single place decides whether an event reaches the operator. "
        "Expose should_alert(event, ...) so the Wazuh-level floor is one rule, "
        "not a condition scattered across the SSH and non-SSH branches."
    )
    assert decision_policy.should_alert(ev) is True, (
        "ML-8: a level-10 Wazuh brute-force detection did not produce an alert. "
        "Rules detect; our scoring must not be able to veto them."
    )


def test_ml_9_alert_carries_evidence_not_just_a_verdict():
    """ML-9: the alert led with a model probability and omitted every fact.

    Rendered today it says 'Suspicious activity 83%' and draws an 83% bar — a
    number from the model this rebuild is retiring — while the attempt count
    sits unused in `reason`. A reader cannot call false-positive from it,
    because it contains a verdict and no evidence.
    """
    import sys
    import warnings

    warnings.filterwarnings("ignore")
    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from modules import alert_format
    from schemas.normalized_event import NormalizedEvent

    ev = NormalizedEvent(
        src_ip="203.0.113.9", channel="sshd", event_type="auth_failed",
        username="root", agent_name="web-01", agent_id="007",
        wazuh_rule_id=5712, wazuh_rule_level=10,
        wazuh_rule_description="sshd: brute force trying to get access",
    )
    fn = getattr(alert_format, "format_evidence_alert", None)
    assert fn is not None, (
        "ML-9: no evidence-first alert formatter. The operator needs attempts, "
        "window, usernames tried and whether the source is new — not a score."
    )
    body = re.sub(r"<[^>]+>", "", fn(ev, attempts=12, window_seconds=240,
                                     usernames=["root", "admin", "oracle"],
                                     first_seen_days=3))
    low = body.lower()
    for token in ("12", "root", "admin", "203.0.113.9", "5712"):
        assert token in body, f"ML-9: alert omits {token!r} — evidence, not decoration"
    assert "%" not in body or "confidence" not in low, (
        "ML-9: the alert still leads with a probability. Lead with what happened."
    )


def test_ml_10_model_scores_web_but_cannot_override_the_wazuh_floor():
    """ML-10: the classifier is wired to web, and only below the level-10 floor.

    Decision: web is scored by the model, SSH by rules. Today every web event
    alerts unconditionally (`return True`), which is the FPR=1.000 baseline in
    `make eval` — the model's job there is discrimination, not detection.

    The constraint that keeps this from reopening ML-8: a Wazuh level-10
    detection alerts whatever the model thinks. ML-8 was the model vetoing a
    confirmed brute force; suppressing a blanket alert-on-everything is a
    different thing, and the floor is what separates them.

    This matters because the model is known not to generalise — held-out, it
    produced 52 false positives on a benign pattern it had not seen, against 6
    for the rule. It may filter noise. It may not overrule a rule that fired.
    """
    import sys
    import warnings

    warnings.filterwarnings("ignore")
    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    import importlib

    from modules import decision_policy

    importlib.reload(decision_policy)
    decision_policy.update_whitelist([])
    from schemas.normalized_event import NormalizedEvent

    def web(level: int) -> NormalizedEvent:
        return NormalizedEvent(
            src_ip="203.0.113.50", channel="web", event_type="generic",
            wazuh_rule_id=31151, wazuh_rule_level=level,
        )

    scorer = getattr(decision_policy, "score_web_event", None)
    assert scorer is not None, (
        "ML-10: web is not scored. `should_alert` returns True for every web "
        "event, so the trained model contributes nothing and the channel alerts "
        "on all traffic. Add score_web_event(event) and consult it below the floor."
    )

    # The floor is absolute: a level-10 detection alerts even if the model
    # is certain the traffic is benign.
    assert decision_policy.should_alert(web(10)) is True, (
        "ML-10: a Wazuh level-10 web detection did not alert. The model must "
        "never overrule a rule that fired — that is ML-8."
    )
    assert decision_policy.should_alert(web(12)) is True

    # Below the floor the model is consulted, so the outcome must be able to
    # differ. If it cannot, nothing was wired.
    import unittest.mock as m

    with m.patch.object(decision_policy, "score_web_event", return_value=0.99):
        noisy = decision_policy.should_alert(web(5))
    with m.patch.object(decision_policy, "score_web_event", return_value=0.01):
        quiet = decision_policy.should_alert(web(5))
    assert noisy is True and quiet is False, (
        f"ML-10: model score does not change the outcome below the floor "
        f"(scanner={noisy}, benign={quiet}) — the classifier is not consulted."
    )


def test_ml_11_nothing_can_suppress_a_rule_confirmed_detection():
    """ML-11 (reversed): no score may take away an alert a rule raised.

    This check previously asserted the opposite — that the model *could*
    suppress level-10 web noise, bounded by confidence, a level cap, and a
    written record. That was a defensible feature for the model it was built
    around: a web-noise estimator whose low scores meant "this web traffic
    looks benign".

    The shipped model (2026-08-17) is not that model. It detects
    post-exploitation and is trained with scan and flood phases excluded, so it
    scores ordinary web traffic near zero *by construction* — p=0.005 on a
    routine event. Under the old branch that reads as maximum confidence to
    suppress, and every level-10 web detection was silently dropped. ML-10's
    check caught it.

    The lesson is not "suppression was tuned wrong". It is that suppression
    coupled the alerting path to what a particular model meant by a low score,
    and nothing re-checked that meaning when the model was replaced. The
    replacement invariant has no such coupling: whatever the model is, whatever
    it scores, a rule-confirmed detection reaches the operator.

    Asserted as a property over the whole score range, not as the absence of a
    branch — a future suppressor reintroduced anywhere below the floor fails
    here without needing this test to know where it was written.
    """
    import sys
    import unittest.mock as m

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from modules import decision_policy as dp
    from schemas.normalized_event import NormalizedEvent

    dp.update_whitelist([])

    def web(level: int) -> NormalizedEvent:
        return NormalizedEvent(
            src_ip="203.0.113.50", channel="web", event_type="generic",
            wazuh_rule_id=31151, wazuh_rule_level=level,
        )

    event = web(10)

    for score in (0.0, 0.001, 0.01, 0.05, 0.099, 0.1, 0.5, 0.99, 1.0):
        with m.patch.object(dp, "score_web_event", return_value=score):
            assert dp.should_alert(event) is True, (
                f"ML-11: a level-10 detection was suppressed at model score {score}. "
                "No score may remove an alert a rule raised — that is ML-8."
            )

    # And the same must hold above the old cap, where it always did.
    for level in (10, 11, 12, 13, 15):
        ev = web(level)
        with m.patch.object(dp, "score_web_event", return_value=0.0):
            assert dp.should_alert(ev) is True, (
                f"ML-11: level-{level} detection suppressed at score 0.0"
            )


def test_ml_12_trained_on_a_published_dataset_with_window_labels():
    """ML-12: replace self-generated training data with AIT-ADS.

    The model was trained on scenarios we wrote ourselves — 45 web attack rows
    from 2 distinct source IPs per seed. It could only recognise attacks
    someone had already thought of, and "benign" meant the four patterns we
    invented; held out, it produced 52 false positives against 6 for the rule.

    AIT-ADS (Zenodo 8263181, CC-BY-4.0) is 2.29M real Wazuh alerts across 8
    independent testbeds, with ground truth given as attack-phase start/end
    times in labels.csv.

    Two properties matter, and both are asserted here:

    1. **Labels come from time windows, not severity.** An alert is an attack
       if its timestamp falls inside a labelled phase — independent of
       rule_level, rule_id and decoder. That makes ML-1's leak impossible by
       construction rather than avoided by discipline. The old loader fell back
       to `rule_level >= 10 -> attack`, which is the leak restated as a label.

    2. **Evaluation is cross-testbed.** Training and evaluating on the same
       environment measures memorisation. Holding out whole scenarios is the
       only honest generalisation number this project can produce.
    """
    import json as _json

    reg = REPO / "ml" / "models" / "model_registry.json"
    if not reg.exists():
        pytest.skip("no model registry")
    r = _json.loads(reg.read_text(encoding="utf-8"))

    ds = _json.dumps(r.get("datasets", {})).lower()
    assert "ait" in ds, (
        f"ML-12: the model is not trained on AIT-ADS. datasets={r.get('datasets')}. "
        "Self-generated scenarios only contain attacks their author thought of."
    )

    held = r.get("held_out_scenarios") or r.get("eval_scenarios")
    trained = r.get("train_scenarios")
    assert held and trained, (
        "ML-12: registry must record which testbeds were trained on and which "
        "were held out — a generalisation claim is unreadable without it."
    )
    assert not (set(held) & set(trained)), (
        f"ML-12: scenarios appear in both train and eval: {set(held) & set(trained)}"
    )
    assert len(held) >= 2, f"ML-12: only {len(held)} held-out testbed(s); need >= 2"

    # The label source must be the published ground truth, never severity.
    src = (REPO / "ml" / "dataset_loaders.py").read_text(encoding="utf-8")
    ait = src[src.index("_ait_alert_label"):] if "_ait_alert_label" in src else src
    ait = ait[:ait.index("\ndef ", 10)] if "\ndef " in ait[10:] else ait
    assert "rule" not in ait or "level" not in ait, (
        "ML-12: AIT labelling still consults the Wazuh rule level. Ground truth "
        "is labels.csv attack windows; deriving the label from severity is the "
        "leak wearing a different hat."
    )

    # Features stay behavioural.
    banned = [c for c in r.get("feature_columns", [])
              if any(k in c.lower() for k in ("rule_level", "rule_id", "decoder", "wazuh"))]
    assert not banned, f"ML-12: Wazuh verdict fields back in the feature set: {banned}"


def test_arc_8_feature_window_is_bounded_under_flood():
    """ARC-8: one loud source must not be able to slow the sensor down.

    f1..f6 are computed by scanning the per-IP window, so before the cap the
    per-event cost grew with the window and the window grew with the
    attacker's rate: 8,745 ev/s at 2 req/s but 505 ev/s at 60 req/s. That
    curve means ~175 req/s from a single source saturates a core — the
    detector degrades fastest exactly when it is being attacked.

    Asserts the property, not the symbol: feed the same extractor at a slow
    and a fast rate and require the fast one to stay within a small factor of
    the slow one. A future refactor that reintroduces an unbounded scan fails
    here even if MAX_WINDOW_EVENTS is still spelled somewhere in the file.
    """
    import time
    from datetime import datetime, timezone

    from ml.extractor import LureGuardExtractor

    def throughput(rate: int, n: int = 6000) -> float:
        ex = LureGuardExtractor(window_seconds=300)
        base = 1_700_000_000.0
        stamps = [
            datetime.fromtimestamp(base + i / rate, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
            for i in range(n)
        ]
        start = time.perf_counter()
        for s in stamps:
            ex.update_from_raw("203.0.113.9", "u", "failed", s)
        return n / (time.perf_counter() - start)

    slow, fast = throughput(2), throughput(120)

    # Bound the *window*, using a small explicit cap so this check stays fast
    # whatever the shipped default is. Driving `MAX_WINDOW_EVENTS + 500` events
    # instead would make the check itself hang when the cap is removed, which
    # is a hang, not a failure — a check has to fail cleanly to be worth having.
    ex = LureGuardExtractor(window_seconds=300, max_window_events=500)
    base = 1_700_000_000.0
    for i in range(2000):
        ex.update_from_raw(
            "203.0.113.9", "u", "failed",
            datetime.fromtimestamp(base + i / 120, timezone.utc)
            .isoformat().replace("+00:00", "Z"),
        )
    held = len(ex.ip_history["203.0.113.9"])
    assert held <= 500, (
        f"window held {held:,} events with a 500 cap — unbounded scan is back"
    )
    # Generous factor: this asserts "bounded", not a latency budget, so it does
    # not turn into a flaky benchmark on a loaded CI box.
    assert fast >= slow / 6, (
        f"throughput collapses under load: {slow:,.0f} ev/s at 2 req/s vs "
        f"{fast:,.0f} ev/s at 120 req/s — per-event cost still scales with the window"
    )
