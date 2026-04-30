"""Decision and summary result schemas."""
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


class SummaryResult(BaseModel):
    text: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0
    provider: str
    model: str
    latency_ms: int = 0
    status: Literal["OK", "DISABLED", "FAILED"]
    error: Optional[str] = None
    prompt_hash: str = ""
