"""Project core/attack_map.json into the attack_rule_map table (GFA-7).

The JSON produced by ML-4 is the source of truth. This copies it into Postgres
so Grafana can join it against `events.wazuh_rule_id` — a dashboard cannot read
a file. Reloaded wholesale at startup, so the table can never drift from the
JSON: there is exactly one place to edit a mapping.
"""
from __future__ import annotations

import json
from pathlib import Path

from loguru import logger
from sqlalchemy import text

_MAP = Path(__file__).resolve().parent / "attack_map.json"


def _rows() -> list[dict]:
    if not _MAP.is_file():
        return []
    rules = json.loads(_MAP.read_text(encoding="utf-8")).get("rules", {})
    out: list[dict] = []
    for rid, entry in rules.items():
        try:
            rule_id = int(rid)
        except (TypeError, ValueError):
            continue
        seen = set()
        for a in entry.get("attack", []):
            tech, tac = a.get("technique"), a.get("tactic")
            if not tech or (rule_id, tech) in seen:
                continue  # PK is (rule_id, technique) — a rule may repeat one
            seen.add((rule_id, tech))
            out.append({
                "wazuh_rule_id": rule_id,
                "technique": tech,
                "tactic": tac or "unknown",
                "description": (entry.get("description") or "")[:500],
                "source": entry.get("source", "unknown"),
            })
    return out


async def load_attack_map(db) -> int:
    """Truncate-and-reload. Returns rows loaded."""
    rows = _rows()
    if not rows:
        logger.warning("attack map: core/attack_map.json missing or empty — coverage dashboard will be blank")
        return 0
    await db.execute(text("TRUNCATE attack_rule_map"))
    await db.execute(
        text(
            "INSERT INTO attack_rule_map "
            "(wazuh_rule_id, technique, tactic, description, source) "
            "VALUES (:wazuh_rule_id, :technique, :tactic, :description, :source)"
        ),
        rows,
    )
    await db.commit()
    logger.info(f"✅ ATT&CK map loaded ({len(rows)} rule→technique rows)")
    return len(rows)


def demo() -> None:
    rows = _rows()
    assert rows, "attack_map.json produced no rows"
    keys = {(r["wazuh_rule_id"], r["technique"]) for r in rows}
    assert len(keys) == len(rows), "duplicate (rule_id, technique) would violate the PK"
    assert all(r["technique"].startswith("T") for r in rows), "malformed technique id"
    print(f"ok — {len(rows)} rows, {len({r['technique'] for r in rows})} techniques, "
          f"{len({r['tactic'] for r in rows})} tactics")


if __name__ == "__main__":
    demo()
