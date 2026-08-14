"""
INS-2: deterministic demo dataset.

`generate_events(n)` returns n dicts shaped exactly like the `events` table
(core/db/models.py) — the same fields `modules/collector.py` fills in from a
real Wazuh alert — so a triage skill can't tell demo data from live data.

Story told by the dataset (so triage has something to discriminate, not just
count):
  - an SSH brute-force burst from one public IP against many usernames,
    escalating to a "multiple auth failures" alert (level 10), ending in a
    successful login — the classic escalation
  - web scanner noise: many 404s hammered from one IP
  - FIM/syscheck changes and a rootcheck finding
  - a majority of benign, low-level events so triage has to discriminate

All public-looking source IPs are drawn from the documentation/test ranges
(RFC 5737 / RFC 3849 equivalents: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — never real-world addresses, since this ships in a public
repo.

Deterministic: everything is derived from a fixed RNG seed and a fixed
anchor timestamp, so the same call always produces byte-identical output —
that's what makes a golden test against it possible.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta

SEED = 1337
ANCHOR = datetime(2026, 8, 14, 9, 0, 0)  # fixed instant, not datetime.now() — see module docstring
_NAMESPACE = uuid.UUID("f3b1c1d0-0000-4000-8000-000000000002")  # fixed namespace for deterministic ids

_USERNAMES = [
    "root", "admin", "ubuntu", "postgres", "deploy", "test",
    "oracle", "backup", "git", "jenkins", "www-data", "vagrant",
]
_PUBLIC_IPS = (
    [f"192.0.2.{i}" for i in range(2, 30)]
    + [f"198.51.100.{i}" for i in range(2, 30)]
    + [f"203.0.113.{i}" for i in range(2, 30)]
)
_PRIVATE_IPS = [f"10.0.0.{i}" for i in range(2, 40)] + [f"192.168.1.{i}" for i in range(2, 40)]

# (agent_id, agent_name, agent_ip, profile_id) — profile_id mirrors
# collector._PROFILE_KEYWORDS matching on agent_name.
_AGENTS = [
    ("001", "dev-server-01", "10.0.0.10", "dev-server"),
    ("002", "db-server-01", "10.0.0.11", "db-server"),
    ("003", "web-01", "10.0.0.12", None),
]

_WEB_PATHS = ["/wp-login.php", "/.env", "/admin", "/phpmyadmin", "/.git/config", "/etc/passwd"]
_FIM_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/cron.d/root", "/usr/bin/sshd", "/etc/ssh/sshd_config"]


def _det_id(tag: str) -> uuid.UUID:
    """Deterministic UUID from a stable tag — makes rows re-generatable and
    re-runnable inserts idempotent via ON CONFLICT on the (id, ts) PK."""
    return uuid.uuid5(_NAMESPACE, tag)


def generate_events(n: int = 500, seed: int = SEED) -> list[dict]:
    """Return >= n normalized event dicts, keyed exactly like the `events`
    table columns, telling a deterministic demo story.

    ponytail: fixed handful of story shapes (brute force / scan / FIM /
    rootcheck / benign), not a general event-type generator — extend the
    `_burst_*` helpers below when the demo needs a new scenario.
    """
    rng = random.Random(seed)
    window_start = ANCHOR - timedelta(hours=36)
    rows: list[dict] = []

    def base(idx: int, ts: datetime, **kw) -> dict:
        row = {
            "id": _det_id(f"{seed}:{idx}"),
            "ts": ts,
            "src_ip": None,
            "src_port": None,
            "channel": "unknown",
            "event_type": "generic",
            "username": None,
            "success": False,
            "profile_id": None,
            "wazuh_rule_id": 0,
            "wazuh_rule_level": 0,
            "wazuh_rule_description": None,
            "agent_id": None,
            "agent_name": None,
            "agent_ip": None,
            "ingestion_path": "wazuh",
            "syscheck_path": None,
            "syscheck_event": None,
            "syscheck_sha256_after": None,
            "raw_ref": "",
            "geo_country": None,
            "geo_city": None,
            "investigation_id": None,
            # VER-1: ground truth for the eval harness (core/evaluate.py) — set
            # only by the generator, on rows it built as the SSH brute-force
            # scenario. Never derived from wazuh_rule_id/wazuh_rule_level or
            # any other field the scorer consumes, or the label and the
            # feature would share a source (the ML-1 target-leakage mistake).
            # Not a real `events` column — load_demo() strips it before insert.
            "is_attack_scenario": False,
        }
        row.update(kw)
        return row

    idx = 0

    def add(ts: datetime, **kw) -> None:
        nonlocal idx
        rows.append(base(idx, ts, **kw))
        idx += 1

    # ── SSH brute-force burst: one attacker IP, many usernames, escalating
    # to a "multiple failures" high-severity rule, ending in a success. ──
    attacker_ip = rng.choice(_PUBLIC_IPS)
    agent_id, agent_name, agent_ip, profile_id = _AGENTS[0]
    burst_start = window_start + timedelta(hours=3, minutes=12)
    tried_users = rng.sample(_USERNAMES, k=9)
    for i, user in enumerate(tried_users):
        ts = burst_start + timedelta(seconds=8 * i)
        add(
            ts, src_ip=attacker_ip, src_port=rng.randint(1024, 65535),
            channel="sshd", event_type="auth_failed", username=user, success=False,
            profile_id=profile_id, wazuh_rule_id=5710, wazuh_rule_level=5,
            wazuh_rule_description="sshd: Attempt to login using a non-existent user",
            agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip,
            raw_ref=f"Failed password for invalid user {user} from {attacker_ip} port {rng.randint(1024, 65535)} ssh2",
            is_attack_scenario=True,
        )
    escalate_ts = burst_start + timedelta(seconds=8 * len(tried_users) + 4)
    add(
        escalate_ts, src_ip=attacker_ip, channel="sshd", event_type="auth_failed",
        username=tried_users[-1], success=False, profile_id=profile_id,
        wazuh_rule_id=5712, wazuh_rule_level=10,
        wazuh_rule_description="sshd: brute force trying to get access to the system",
        agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip,
        raw_ref=f"pam_unix(sshd:auth): multiple authentication failures from {attacker_ip}",
        is_attack_scenario=True,
    )
    success_ts = escalate_ts + timedelta(seconds=20)
    add(
        success_ts, src_ip=attacker_ip, src_port=rng.randint(1024, 65535),
        channel="sshd", event_type="auth_success", username="root", success=True,
        profile_id=profile_id, wazuh_rule_id=5715, wazuh_rule_level=3,
        wazuh_rule_description="sshd: Authentication success",
        agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip,
        raw_ref=f"Accepted password for root from {attacker_ip} port {rng.randint(1024, 65535)} ssh2",
        is_attack_scenario=True,
    )

    # ── Web scanner noise: one IP hammering 404s across many paths. ──
    scanner_ip = rng.choice([ip for ip in _PUBLIC_IPS if ip != attacker_ip])
    _, web_agent_name, web_agent_ip, _ = _AGENTS[2]
    scan_start = window_start + timedelta(hours=10, minutes=5)
    for i in range(35):
        ts = scan_start + timedelta(seconds=3 * i)
        path = rng.choice(_WEB_PATHS)
        add(
            ts, src_ip=scanner_ip, src_port=rng.randint(1024, 65535),
            channel="web", event_type="web_scan", success=False,
            wazuh_rule_id=31151, wazuh_rule_level=5,
            wazuh_rule_description="Multiple web server 400 error codes from same source ip",
            agent_id=_AGENTS[2][0], agent_name=web_agent_name, agent_ip=web_agent_ip,
            raw_ref=f'{scanner_ip} - - "GET {path} HTTP/1.1" 404 162',
        )

    # ── FIM / syscheck changes. ──
    fim_start = window_start + timedelta(hours=18)
    for i in range(14):
        ts = fim_start + timedelta(minutes=17 * i)
        path = rng.choice(_FIM_PATHS)
        ev = rng.choice(["modified", "added"])
        agent_id, agent_name, agent_ip, profile_id = rng.choice(_AGENTS)
        add(
            ts, channel="syscheck", event_type="fim_change", profile_id=profile_id,
            wazuh_rule_id=550, wazuh_rule_level=7,
            wazuh_rule_description="Integrity checksum changed",
            agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip,
            syscheck_path=path, syscheck_event=ev,
            syscheck_sha256_after=uuid.uuid5(_NAMESPACE, f"sha:{i}").hex + uuid.uuid5(_NAMESPACE, f"sha2:{i}").hex[:24],
            raw_ref=f"File '{path}' {ev}",
        )

    # ── Rootcheck findings. ──
    root_start = window_start + timedelta(hours=22, minutes=40)
    for i in range(8):
        ts = root_start + timedelta(minutes=23 * i)
        agent_id, agent_name, agent_ip, profile_id = rng.choice(_AGENTS)
        add(
            ts, channel="rootcheck", event_type="rootkit_detected", profile_id=profile_id,
            wazuh_rule_id=510, wazuh_rule_level=7,
            wazuh_rule_description="Host-based anomaly detection event",
            agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip,
            raw_ref="Application 'ldd' file '/usr/bin/ldd' malformed",
        )

    # ── Benign majority: low-level sshd/web noise, spread across the whole
    # window, so triage has to discriminate rather than just count events. ──
    story_count = len(rows)
    benign_needed = max(0, n - story_count)
    for i in range(benign_needed):
        ts = window_start + timedelta(seconds=rng.randint(0, 36 * 3600))
        agent_id, agent_name, agent_ip, profile_id = rng.choice(_AGENTS)
        ip_pool = _PUBLIC_IPS if rng.random() < 0.4 else _PRIVATE_IPS
        src_ip = rng.choice(ip_pool)
        if rng.random() < 0.6:
            user = rng.choice(_USERNAMES)
            add(
                ts, src_ip=src_ip, src_port=rng.randint(1024, 65535),
                channel="sshd", event_type="auth_success", username=user, success=True,
                profile_id=profile_id, wazuh_rule_id=5715, wazuh_rule_level=3,
                wazuh_rule_description="sshd: Authentication success",
                agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip,
                raw_ref=f"Accepted password for {user} from {src_ip} port {rng.randint(1024, 65535)} ssh2",
            )
        else:
            add(
                ts, src_ip=src_ip, src_port=rng.randint(1024, 65535),
                channel="web", event_type="web_error", success=False,
                profile_id=profile_id, wazuh_rule_id=31100, wazuh_rule_level=3,
                wazuh_rule_description="Web server 400 error code",
                agent_id=_AGENTS[2][0], agent_name=_AGENTS[2][1], agent_ip=_AGENTS[2][2],
                raw_ref=f'{src_ip} - - "GET /index.html HTTP/1.1" 404 162',
            )

    rows.sort(key=lambda r: r["ts"])
    return rows


async def load_demo() -> int:
    """Load the demo dataset into Postgres. Idempotent: ids are deterministic
    (uuid5 of seed+index) and the events PK is (id, ts), so a re-run inserts
    the same rows and ON CONFLICT DO NOTHING makes it a no-op the second time.

    Bypasses crud.insert_event's geo-IP lookup on purpose — that call hits a
    real network API per public IP, which would make `make demo` slow and
    non-deterministic for something that's supposed to work offline in
    under two minutes.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from db.models import Event
    from db.session import AsyncSessionLocal

    rows = generate_events(500)
    # is_attack_scenario is eval-harness ground truth (VER-1), not an events
    # column — strip it before the insert.
    db_rows = [{k: v for k, v in r.items() if k != "is_attack_scenario"} for r in rows]
    async with AsyncSessionLocal() as session:
        # One multi-row VALUES statement (not executemany) so RETURNING
        # reports exactly which rows were newly inserted vs skipped.
        stmt = (
            pg_insert(Event)
            .values(db_rows)
            .on_conflict_do_nothing(index_elements=["id", "ts"])
            .returning(Event.id)
        )
        result = await session.execute(stmt)
        inserted = len(result.fetchall())
        await session.commit()
    return inserted


if __name__ == "__main__":
    import asyncio

    n = asyncio.run(load_demo())
    print(f"demo: inserted {n} new event(s) (existing rows left untouched)")
