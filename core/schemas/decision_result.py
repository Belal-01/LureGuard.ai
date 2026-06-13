"""Decision result schema."""
import uuid
from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel


class DecisionResult(BaseModel):
    id: uuid.UUID
    session_id: Optional[uuid.UUID] = None
    ts: datetime
    decision: Literal["allow", "alert", "redirect"]
    p: float
    score: float
    t1: float
    t2: float
    model_version: str
    features_hash: str
    profile_id: Optional[str] = None
    reason: str
