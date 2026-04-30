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
    assert 0 < t1 < t2 < 1, "Must satisfy: 0 < T1 < T2 < 1"
    settings.thresholds.t1 = t1
    settings.thresholds.t2 = t2
    return {"status": "updated", "t1": t1, "t2": t2}


# ── Panic flush ──────────────────────────────────────────
@router.post("/panic-flush")
def panic_flush(_=Depends(_verify_token)):
    """Remove ALL iptables DNAT rules created by LureGuard."""
    from modules.enforcer import flush_all_dnat
    flush_all_dnat()
    return {"status": "flushed"}


# ── Health ───────────────────────────────────────────────
@router.get("/health", include_in_schema=False)
async def health(db: AsyncSession = Depends(get_db)):
    # TODO: ping each subsystem
    return {"db": "ok", "ml": "ok", "llm": settings.llm.provider}
