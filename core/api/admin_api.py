"""
Admin API — Bearer Token protected.
Endpoints: thresholds · whitelist · panic-flush · model registry · health.
"""
from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db.session import get_db

router = APIRouter(prefix="/config", tags=["admin"])
security = HTTPBearer()

# ── Auth helper ──────────────────────────────────────────
def _verify_token(creds: HTTPAuthorizationCredentials = Security(security)):
    from pathlib import Path
    token_file = Path("/run/secrets/admin_token")
    expected = token_file.read_text().strip() if token_file.exists() else "dev-token"
    if creds.credentials != expected:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Thresholds ───────────────────────────────────────────
@router.get("/thresholds")
def get_thresholds(_=Depends(_verify_token)):
    return {"t1": settings.thresholds.t1, "t2": settings.thresholds.t2}


@router.put("/thresholds")
def update_thresholds(t1: float, t2: float, _=Depends(_verify_token)):
    """Update ML redirect thresholds in memory only (not persisted to core.yaml)."""
    assert 0 < t1 < t2 < 1, "Must satisfy: 0 < T1 < T2 < 1"
    settings.thresholds.t1 = t1
    settings.thresholds.t2 = t2
    return {
        "status": "updated",
        "t1": t1,
        "t2": t2,
        "persisted": False,
        "note": "Runtime-only until restart; edit config/core.yaml for durable values.",
    }


# ── Whitelist (Postgres) ─────────────────────────────────
@router.get("/whitelist")
async def list_whitelist(db: AsyncSession = Depends(get_db), _=Depends(_verify_token)):
    from db import crud

    rows = await crud.list_whitelist_entries(db)
    return {
        "entries": [
            {
                "ip": str(row.ip),
                "reason": row.reason,
                "added_by": row.added_by,
                "added_at": row.added_at.isoformat() if row.added_at else None,
            }
            for row in rows
        ]
    }


@router.post("/whitelist")
async def add_whitelist(
    ip: str,
    reason: str | None = None,
    db: AsyncSession = Depends(get_db),
    _=Depends(_verify_token),
):
    import ipaddress

    from db import crud
    from runtime.whitelist import refresh_whitelist_from_db

    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    row = await crud.add_whitelist_ip(db, ip.strip(), reason=reason, added_by="admin")
    await crud.append_audit(
        db, "admin", "whitelist.add", {}, {"ip": str(row.ip), "reason": reason}
    )
    await refresh_whitelist_from_db(db)
    return {"status": "added", "ip": str(row.ip)}


@router.delete("/whitelist/{ip}")
async def delete_whitelist(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(_verify_token),
):
    from db import crud
    from runtime.whitelist import refresh_whitelist_from_db

    removed = await crud.remove_whitelist_ip(db, ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in whitelist")
    await crud.append_audit(db, "admin", "whitelist.remove", {"ip": ip}, {})
    await refresh_whitelist_from_db(db)
    return {"status": "removed", "ip": ip}


# ── Panic flush ──────────────────────────────────────────
@router.post("/panic-flush")
def panic_flush(_=Depends(_verify_token)):
    """Remove ALL iptables DNAT rules created by LureGuard."""
    from modules.enforcer import flush_all_dnat
    flush_all_dnat()
    return {"status": "flushed"}


@router.post("/reset-feature-window")
def reset_feature_window(_=Depends(_verify_token)):
    """Clear in-memory SSH attempt counters (after testing / false positives)."""
    from modules.ingest_dedup import reset as reset_ingest_dedup
    from runtime.window_store import reset_extractor

    reset_extractor()
    reset_ingest_dedup()
    return {"status": "feature_window_cleared"}


# ── Health ───────────────────────────────────────────────
@router.get("/health", include_in_schema=False)
async def health(db: AsyncSession = Depends(get_db)):
    # TODO: ping each subsystem
    return {"db": "ok", "ml": "ok"}
