"""Shared-secret auth for Wazuh integratord POST /wazuh/event."""

from __future__ import annotations

from fastapi import Header, HTTPException
from loguru import logger

from config import ingest_allow_unauthenticated, ingest_token


def verify_ingest_token(x_lureguard_token: str | None = Header(default=None)) -> None:
    expected = ingest_token()
    if not expected:
        if ingest_allow_unauthenticated():
            logger.warning(
                "INGEST_TOKEN not set — accepting unauthenticated ingest "
                "(set INGEST_TOKEN or INGEST_ALLOW_UNAUTHENTICATED=false for production)"
            )
            return
        raise HTTPException(
            status_code=503,
            detail="Ingest authentication not configured (set INGEST_TOKEN)",
        )
    if not x_lureguard_token or x_lureguard_token != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing X-LureGuard-Token")
