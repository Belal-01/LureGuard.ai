"""
POST /wazuh/event
Receives alerts from Wazuh integratord and kicks off the pipeline.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.ingest_auth import verify_ingest_token
from api.metrics_endpoint import events_total
from db.session import get_db
from modules.collector import normalize_event
from modules.decision_policy import process_event
from modules.ingest_dedup import is_duplicate_wazuh_event
from schemas.wazuh_alert import WazuhAlert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/wazuh", tags=["wazuh"])


@router.post("/event", status_code=202)
async def receive_wazuh_event(
    alert: WazuhAlert,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(verify_ingest_token),
):
    """
    Main ingestion endpoint.
    Wazuh integratord calls this for every matching alert.
    """
    try:
        if is_duplicate_wazuh_event(
            alert.data.get("srcip"),
            alert.rule_id,
            alert.timestamp,
        ):
            return {"status": "deduplicated", "event_id": None}

        event = normalize_event(alert)
        await process_event(event, db)
        events_total.labels(source=event.channel or "unknown").inc()
        return {"status": "queued", "event_id": str(event.id)}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to process Wazuh event")
        raise HTTPException(status_code=500, detail="Failed to process event")
