"""Integration tests for investigation findings/timeline/ioc persistence."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta

import pytest

pytestmark = pytest.mark.integration


def _pg_available() -> bool:
    try:
        from lureguard_mcp.db import get_conn

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False


@pytest.fixture
def investigation_id():
    if not _pg_available():
        pytest.skip("DATABASE_URL postgres not configured")
    from lureguard_mcp.db import close_investigation_db, open_investigation

    inv = open_investigation(
        trigger="test",
        subject=f"lifecycle-test-{uuid.uuid4().hex[:8]}",
        severity="P3",
        detection_source="pytest",
        asset_criticality="low",
    )
    yield inv["id"]
    try:
        close_investigation_db(
            inv["id"],
            verdict="false_positive",
            confidence="high",
            summary="test cleanup",
        )
    except Exception:
        pass


@pytest.mark.skipif(not _pg_available(), reason="DATABASE_URL postgres not configured")
def test_record_finding_creates_evidence_and_ioc(investigation_id: str):
    from lureguard_mcp.db import (
        get_investigation_findings_db,
        get_investigation_iocs_db,
        record_finding,
    )

    result = record_finding(
        investigation_id,
        "SQLi probe in access log",
        "analyze_web_attack: primary_attack_type=sqli",
        mitre_technique="T1190",
        mitre_tactic="Initial Access",
        severity="P3",
        verdict="true_positive",
        confidence="medium",
        ioc_type="ip",
        ioc_value="203.0.113.55",
    )
    assert result["evidence_id"] == "E01"

    findings = get_investigation_findings_db(investigation_id)
    assert len(findings) >= 1
    assert findings[0]["evidence_id"] == "E01"
    assert findings[0]["mitre_technique"] == "T1190"

    iocs = get_investigation_iocs_db(investigation_id)
    assert any(i["type"] == "ip" and "203" in i["value"] for i in iocs)
    assert any("[.]" in (i.get("defanged") or "") for i in iocs)


@pytest.mark.skipif(not _pg_available(), reason="DATABASE_URL postgres not configured")
def test_timeline_and_close_fields(investigation_id: str):
    from lureguard_mcp.db import (
        add_timeline_event,
        close_investigation_db,
        get_investigation_timeline_db,
    )

    ts = datetime.utcnow() - timedelta(minutes=5)
    add_timeline_event(
        investigation_id,
        ts_event=ts,
        description="Scanner hit /wp-admin",
        phase="identification",
        source="search_events",
    )
    timeline = get_investigation_timeline_db(investigation_id)
    assert len(timeline) >= 1
    assert timeline[0]["phase"] == "identification"

    closed = close_investigation_db(
        investigation_id,
        verdict="true_positive",
        confidence="high",
        summary="Web probe blocked by WAF",
        detection_source="wazuh",
        asset_criticality="high",
        mttd_seconds=120,
        kill_chain_summary="Recon → exploit attempt → blocked",
    )
    assert closed["status"] == "closed"
    assert closed["mttd_seconds"] == 120
    assert "Recon" in (closed.get("kill_chain_summary") or "")
